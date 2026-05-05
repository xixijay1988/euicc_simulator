"""Unit tests for TCP APDU protocol (frame parsing from stream)."""
import pytest
from app.transport.tcp_protocol import ApduFrameParser, ApduSegmentBuffer
from app.transport.apdu_codec import ApduCommand


class TestApduFrameParser:
    def test_single_frame(self):
        parser = ApduFrameParser()
        frames = parser.feed(bytes.fromhex("80E2910004BF3E0000"))
        assert len(frames) == 1
        assert frames[0].ins == 0xE2
        assert frames[0].data == bytes.fromhex("BF3E0000")

    def test_multiple_frames(self):
        """Two complete APDUs in one read."""
        parser = ApduFrameParser()
        combined = (
            bytes.fromhex("80E2910004BF3E0000") +
            bytes.fromhex("80E2910004BF3E0000")
        )
        frames = parser.feed(combined)
        assert len(frames) == 2

    def test_fragmented_frame(self):
        """Single APDU split across multiple reads."""
        parser = ApduFrameParser()
        apdu = bytes.fromhex("80E2910004BF3E0000")

        # Feed first 3 bytes
        frames = parser.feed(apdu[:3])
        assert len(frames) == 0

        # Feed rest
        frames = parser.feed(apdu[3:])
        assert len(frames) == 1
        assert frames[0].data == bytes.fromhex("BF3E0000")

    def test_select_apdu(self):
        parser = ApduFrameParser()
        frames = parser.feed(
            bytes.fromhex("80A4040010A0000005591010FFFFFFFF8900001000")
        )
        assert len(frames) == 1
        assert frames[0].ins == 0xA4

    def test_empty_data(self):
        parser = ApduFrameParser()
        frames = parser.feed(b"")
        assert len(frames) == 0

    def test_reset(self):
        parser = ApduFrameParser()
        parser.feed(bytes.fromhex("80E291"))
        parser.reset()
        assert parser.feed(b"") == []


class TestApduSegmentBuffer:
    def test_single_segment_last(self):
        buf = ApduSegmentBuffer()
        cmd = ApduCommand(
            cla=0x80, ins=0xE2, p1=0x91, p2=0x00,
            data=bytes.fromhex("BF3E0000")
        )
        complete, total = buf.add_segment(cmd)
        assert complete
        assert total == 4
        assert buf.get_complete() == bytes.fromhex("BF3E0000")

    def test_multi_segment(self):
        buf = ApduSegmentBuffer()
        # Block 0, not last
        cmd1 = ApduCommand(
            cla=0x80, ins=0xE2, p1=0x11, p2=0x00,
            data=bytes.fromhex("BF380080")
        )
        complete, _ = buf.add_segment(cmd1)
        assert not complete

        # Block 1, last
        cmd2 = ApduCommand(
            cla=0x80, ins=0xE2, p1=0x91, p2=0x01,
            data=bytes.fromhex("AABBCCDD")
        )
        complete, _ = buf.add_segment(cmd2)
        assert complete
        assert buf.get_complete() == bytes.fromhex("BF380080AABBCCDD")

    def test_block_mismatch_resets(self):
        buf = ApduSegmentBuffer()
        cmd = ApduCommand(
            cla=0x80, ins=0xE2, p1=0x11, p2=0x05,  # Wrong block number
            data=bytes.fromhex("BF3E0000")
        )
        complete, _ = buf.add_segment(cmd)
        assert not complete
        # Buffer should be reset
        assert buf.expected_block == 0
        assert len(buf.segments) == 0
