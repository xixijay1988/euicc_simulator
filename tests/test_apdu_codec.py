"""Unit tests for APDU codec (ISO 7816-4 encoding/decoding)."""
import pytest
from app.transport.apdu_codec import (
    ApduCodec, ApduCommand,
    SW_OK, SW_WRONG_LENGTH, SW_INS_NOT_SUPPORTED,
    INS_SELECT, INS_STORE_DATA,
)


class TestApduCodec:
    def test_decode_case1(self):
        """Case 1: CLA INS P1 P2 (no data, no Le)."""
        cmd = ApduCodec.decode(bytes.fromhex("80E29100"))
        assert cmd is not None
        assert cmd.cla == 0x80
        assert cmd.ins == 0xE2
        assert cmd.p1 == 0x91
        assert cmd.p2 == 0x00
        assert cmd.data == b""
        assert cmd.le is None

    def test_decode_case3(self):
        """Case 3: CLA INS P1 P2 Lc Data."""
        cmd = ApduCodec.decode(bytes.fromhex("80E2910004BF3E0000"))
        assert cmd is not None
        assert cmd.lc == 4
        assert cmd.data == bytes.fromhex("BF3E0000")
        assert cmd.is_last_block()

    def test_decode_incomplete(self):
        """Incomplete buffer returns None."""
        cmd = ApduCodec.decode(bytes.fromhex("80E2"))
        assert cmd is None

    def test_decode_select_isr(self):
        """SELECT ISD-R APDU."""
        apdu = bytes.fromhex("80A4040010A0000005591010FFFFFFFF8900001000")
        cmd = ApduCodec.decode(apdu)
        assert cmd is not None
        assert cmd.ins == INS_SELECT
        assert cmd.data == bytes.fromhex("A0000005591010FFFFFFFF8900001000")

    def test_encode_response(self):
        """Response data + SW."""
        resp = ApduCodec.encode_response(bytes.fromhex("BF3E10"), sw=0x9000)
        assert resp == bytes.fromhex("BF3E109000")

    def test_encode_error(self):
        """Error SW only."""
        resp = ApduCodec.encode_error(0x6D00)
        assert resp == bytes.fromhex("6D00")

    def test_build_select(self):
        """Build SELECT APDU."""
        aid = bytes.fromhex("A0000005591010FFFFFFFF8900001000")
        apdu = ApduCodec.build_select(aid)
        assert apdu[:4] == bytes.fromhex("80A40400")
        assert apdu[4] == 0x10  # Lc
        assert apdu[5:] == aid

    def test_build_store_data(self):
        """Build STORE DATA APDU."""
        data = bytes.fromhex("BF3E0000")
        apdu = ApduCodec.build_store_data(0x91, 0x00, data)
        assert apdu == bytes.fromhex("80E2910004BF3E0000")

    def test_block_number(self):
        """Block number from P2."""
        cmd = ApduCodec.decode(bytes.fromhex("80E2110104BF3E0000"))
        assert cmd is not None
        assert cmd.block_number() == 1
        assert not cmd.is_last_block()  # P1=0x11, no bit 7

    def test_case_detection(self):
        """ISO 7816 case detection."""
        c1 = ApduCodec.decode(bytes.fromhex("80E29100"))  # Case 1
        assert c1.case == 1

        c3 = ApduCodec.decode(bytes.fromhex("80E2910004BF3E0000"))  # Case 3
        assert c3.case == 3
