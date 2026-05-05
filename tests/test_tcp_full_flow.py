"""End-to-end TCP APDU integration test.

Starts the simulator TCP server and tests the full APDU round-trip:
SELECT ISD-R → GetEID → GetEuiccInfo1 → GetEuiccChallenge chain.
"""
import asyncio
import pytest
import tempfile
import pathlib
import structlog
import logging

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING)
)

from app.transport.tcp_server import ApduTcpServer
from app.transport.apdu_codec import ApduCodec
from app.models.euicc import EuiccState
from app.crypto.certificates import CertificateInfrastructure
from app.services.euicc_manager import EuiccInstance
from app.services.apdu_dispatcher import Es10Dispatcher

ISDR_AID = bytes.fromhex("A0000005591010FFFFFFFF8900001000")


@pytest.fixture
def eid():
    return "89049032123451234512345678901235"


@pytest.fixture
def instance(eid):
    euicc = EuiccState(eid=eid, default_smdp_address="smdp.example.com")
    tmp = pathlib.Path(tempfile.mkdtemp())
    pki = CertificateInfrastructure(tmp)
    pki.initialize(eid)
    return EuiccInstance(euicc, pki)


@pytest.fixture
def dispatcher(instance):
    return Es10Dispatcher(instance)


async def _start_server(port, eid, dispatcher):
    server = ApduTcpServer("127.0.0.1", {port: eid}, {eid: dispatcher})
    await server.start()
    return server


class TestTcpRoundTrip:
    async def test_select_and_get_eid(self, eid, instance, dispatcher):
        """Full TCP round-trip: SELECT ISD-R → GetEID."""
        port = 19000
        server = ApduTcpServer("127.0.0.1", {port: eid}, {eid: dispatcher})
        await server.start()

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            # 1. SELECT ISD-R
            select_apdu = ApduCodec.build_select(ISDR_AID)
            writer.write(select_apdu)
            await writer.drain()
            resp = await reader.read(256)
            assert resp == bytes.fromhex("9000"), f"SELECT failed: {resp.hex()}"

            # 2. GetEID via STORE DATA
            store_apdu = ApduCodec.build_store_data(0x91, 0x00, bytes.fromhex("BF3E0000"))
            writer.write(store_apdu)
            await writer.drain()
            resp = await reader.read(256)
            assert resp.endswith(bytes.fromhex("9000")), f"GetEID failed: {resp.hex()}"

            # EID bytes should be in the response
            eid_bytes = bytes.fromhex(eid)
            assert eid_bytes in resp

            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()

    async def test_get_euicc_info1(self, eid, instance, dispatcher):
        """SELECT → GetEuiccInfo1."""
        port = 19001
        server = ApduTcpServer("127.0.0.1", {port: eid}, {eid: dispatcher})
        await server.start()

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            # SELECT
            writer.write(ApduCodec.build_select(ISDR_AID))
            await writer.drain()
            resp = await reader.read(256)
            assert resp == bytes.fromhex("9000")

            # GetEuiccInfo1
            writer.write(ApduCodec.build_store_data(0x91, 0x00, bytes.fromhex("BF200000")))
            await writer.drain()
            resp = await reader.read(256)
            assert resp.endswith(bytes.fromhex("9000"))

            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()

    async def test_multi_segment_reassembly(self, eid, instance, dispatcher):
        """Multi-segment STORE DATA reassembly."""
        port = 19002
        server = ApduTcpServer("127.0.0.1", {port: eid}, {eid: dispatcher})
        await server.start()

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            # SELECT
            writer.write(ApduCodec.build_select(ISDR_AID))
            await writer.drain()
            resp = await reader.read(256)
            assert resp == bytes.fromhex("9000")

            # Block 0: not last (P1=0x11), contains BF3E tag
            writer.write(ApduCodec.build_store_data(0x11, 0x00, bytes.fromhex("BF3E")))
            await writer.drain()
            resp = await reader.read(256)
            assert resp == bytes.fromhex("9000"), f"Block 0 ACK failed: {resp.hex()}"

            # Block 1: last (P1=0x91), contains remaining TLV bytes
            writer.write(ApduCodec.build_store_data(0x91, 0x01, bytes.fromhex("0000")))
            await writer.drain()
            resp = await reader.read(256)
            assert resp.endswith(bytes.fromhex("9000")), f"Block 1 failed: {resp.hex()}"

            # Full GetEID response should be assembled
            eid_bytes = bytes.fromhex(eid)
            assert eid_bytes in resp

            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()

    async def test_no_select_fails(self, eid, instance, dispatcher):
        """Sending STORE DATA without SELECT should fail."""
        port = 19003
        server = ApduTcpServer("127.0.0.1", {port: eid}, {eid: dispatcher})
        await server.start()

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            # Send STORE DATA without SELECT first
            writer.write(ApduCodec.build_store_data(0x91, 0x00, bytes.fromhex("BF3E0000")))
            await writer.drain()
            resp = await reader.read(256)
            assert resp == bytes.fromhex("6985"), f"Expected 6985 (conditions not satisfied): {resp.hex()}"

            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()
