"""Asyncio TCP server for raw APDU communication.

Each TCP port maps to one eUICC (by EID). The server accepts connections,
reads raw APDU bytes, dispatches to the ES10 handlers, and writes back
APDU response bytes.
"""

import asyncio
import structlog
from .tcp_protocol import ApduFrameParser, ApduSegmentBuffer
from .apdu_codec import (
    ApduCodec, ApduCommand,
    INS_SELECT, INS_STORE_DATA, INS_GET_DATA,
    SW_OK, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND,
    SW_INS_NOT_SUPPORTED,
)

logger = structlog.get_logger()

# ISD-R Application Identifier
ISDR_AID = bytes.fromhex("A0000005591010FFFFFFFF8900001000")


class ApduConnectionHandler:
    """Per-connection state: handles one TCP client's APDU session."""

    def __init__(self, eid: str, dispatcher):
        self.eid = eid
        self.dispatcher = dispatcher
        self.frame_parser = ApduFrameParser()
        self.segment_buffer = ApduSegmentBuffer()
        self.isd_selected = False

    def handle_apdu(self, cmd: ApduCommand) -> bytes:
        """Process a single APDU command, return response bytes."""
        if cmd.ins == INS_SELECT:
            return self._handle_select(cmd)
        elif cmd.ins == INS_STORE_DATA:
            return self._handle_store_data(cmd)
        elif cmd.ins == INS_GET_DATA:
            return ApduCodec.encode_error(0x6985)  # conditions not satisfied
        elif cmd.ins == 0xC0:  # GET RESPONSE
            return ApduCodec.encode_error(0x6985)
        else:
            logger.debug("unsupported_ins", ins=hex(cmd.ins), cla=hex(cmd.cla))
            return ApduCodec.encode_error(0x6D00)  # INS not supported

    def _handle_select(self, cmd: ApduCommand) -> bytes:
        """Handle SELECT command to open ISD-R."""
        aid = cmd.data
        if aid == ISDR_AID or (len(aid) >= 8 and ISDR_AID.startswith(aid)):
            self.isd_selected = True
            self.segment_buffer.reset()
            logger.info("isd_selected", eid=self.eid)
            return ApduCodec.encode_response()
        self.isd_selected = False
        return ApduCodec.encode_error(0x6A82)

    def _handle_store_data(self, cmd: ApduCommand) -> bytes:
        """Handle STORE DATA — reassemble segments, dispatch to ES10."""
        if not self.isd_selected:
            return ApduCodec.encode_error(0x6985)

        complete, total_len = self.segment_buffer.add_segment(cmd)

        if not complete:
            return ApduCodec.encode_response()

        # All segments received — assemble and dispatch
        complete_data = self.segment_buffer.get_complete()
        self.segment_buffer.reset()

        # Dispatch to ES10 handlers via the dispatcher
        response = self.dispatcher.dispatch(self.eid, complete_data)

        # If response is large, segment it for TCP transport
        if len(response) > 255:
            return response  # TCP can handle larger responses directly
        return response


class ApduTcpServer:
    """Multi-port TCP server for APDU communication.

    Each TCP port is mapped to one EID. Clients connect to a specific
    port to interact with that eUICC instance.
    """

    def __init__(
        self,
        host: str,
        port_map: dict[int, str],
        dispatchers: dict,  # eid -> Es10Dispatcher
    ):
        self.host = host
        self.port_map = port_map  # port -> eid
        self.dispatchers = dispatchers  # eid -> Es10Dispatcher
        self._servers: list[asyncio.AbstractServer] = []
        self._running = False

    async def start(self):
        """Start TCP servers on all configured ports."""
        self._running = True
        for port, eid in self.port_map.items():
            server = await asyncio.start_server(
                lambda r, w, p=port: self._handle_client(r, w, p),
                self.host,
                port,
            )
            self._servers.append(server)
            logger.info("tcp_server_started", host=self.host, port=port, eid=eid)

    async def stop(self):
        """Stop all TCP servers gracefully."""
        self._running = False
        for server in self._servers:
            server.close()
            await server.wait_closed()
        self._servers.clear()
        logger.info("tcp_servers_stopped")

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port: int,
    ):
        """Handle one connected TCP client."""
        eid = self.port_map[port]
        dispatcher = self.dispatchers.get(eid)
        if dispatcher is None:
            logger.error("no_dispatcher_for_eid", eid=eid)
            writer.close()
            return

        handler = ApduConnectionHandler(eid, dispatcher)

        addr = writer.get_extra_info("peername")
        logger.info("tcp_client_connected", eid=eid, addr=addr, port=port)

        try:
            while self._running:
                data = await reader.read(4096)
                if not data:
                    break

                # Parse frames and handle each APDU
                for cmd in handler.frame_parser.feed(data):
                    response = handler.handle_apdu(cmd)
                    writer.write(response)

                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        except Exception as e:
            logger.error("tcp_handler_error", eid=eid, error=str(e))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.info("tcp_client_disconnected", eid=eid, addr=addr)
