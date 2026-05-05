"""TCP stream → APDU frame extraction.

TCP is a stream protocol; APDUs are variable-length messages. This module
provides a stateful parser that buffers incoming bytes and yields complete
APDU frames as they become available.

Handles:
- Single APDU per read
- Multiple APDUs in one read (coalesced)
- Single APDU split across reads (fragmented)
- Multi-segment STORE DATA reassembly (P1 bit 7 for last block)
"""

from dataclasses import dataclass, field
from .apdu_codec import ApduCommand, ApduCodec, INS_SELECT, INS_STORE_DATA


@dataclass
class ApduSegmentBuffer:
    """Reassembles multi-segment STORE DATA commands.

    In SGP.22, large ES10 commands (e.g., AuthenticateServer with
    certificates) are split across multiple STORE DATA APDUs.
    """
    segments: list[bytes] = field(default_factory=list)
    expected_block: int = 0
    isd_selected: bool = False

    def add_segment(self, cmd: ApduCommand) -> tuple[bool, int]:
        """Add a segment. Returns (command_complete, total_bytes)."""
        if cmd.p2 != self.expected_block:
            self.reset()
            return False, 0

        self.segments.append(cmd.data)
        self.expected_block += 1

        if cmd.is_last_block():
            return True, sum(len(s) for s in self.segments)

        return False, 0

    def get_complete(self) -> bytes:
        return b"".join(self.segments)

    def reset(self):
        self.segments.clear()
        self.expected_block = 0


class ApduFrameParser:
    """Buffers TCP bytes and extracts complete APDU frames.

    Usage:
        parser = ApduFrameParser()
        for cmd in parser.feed(incoming_bytes):
            response = handle(cmd)
    """

    def __init__(self, max_buffer: int = 65536):
        self._buffer = bytearray()
        self._max_buffer = max_buffer

    def feed(self, data: bytes) -> list[ApduCommand]:
        """Feed new bytes, return list of complete ApduCommands extracted."""
        self._buffer.extend(data)

        if len(self._buffer) > self._max_buffer:
            self._buffer.clear()
            return []

        frames: list[ApduCommand] = []

        while True:
            size = ApduCodec.frame_size(bytes(self._buffer))
            if size is None or size == 0:
                break

            if len(self._buffer) < size:
                break

            # Extract exact frame bytes
            frame_bytes = bytes(self._buffer[:size])
            del self._buffer[:size]

            cmd = ApduCodec.decode(frame_bytes)
            if cmd is not None:
                frames.append(cmd)

        return frames

    def reset(self):
        self._buffer.clear()
