"""ISO 7816-4 APDU Encoding/Decoding.

Handles all four APDU cases:
  Case 1: CLA INS P1 P2              (no data, no Le)
  Case 2: CLA INS P1 P2 Le           (no data, expected response)
  Case 3: CLA INS P1 P2 Lc Data      (command data, no Le)
  Case 4: CLA INS P1 P2 Lc Data Le   (command data + expected response)

Reference: ISO 7816-3 §12, ISO 7816-4 §5
"""

from dataclasses import dataclass, field

# Status words
SW_OK = bytes([0x90, 0x00])
SW_WRONG_LENGTH = bytes([0x67, 0x00])
SW_WRONG_DATA = bytes([0x6A, 0x80])
SW_CONDITIONS_NOT_SATISFIED = bytes([0x69, 0x85])
SW_FILE_NOT_FOUND = bytes([0x6A, 0x82])
SW_WRONG_P1P2 = bytes([0x6A, 0x86])
SW_INS_NOT_SUPPORTED = bytes([0x6D, 0x00])
SW_CLA_NOT_SUPPORTED = bytes([0x6E, 0x00])
SW_INTERNAL_ERROR = bytes([0x6F, 0x00])

# Well-known CLA bytes
CLA_GP = 0x80  # GlobalPlatform
CLA_GP_SECURE = 0x84  # GlobalPlatform with secure messaging
CLA_ISO = 0x00  # ISO 7816 basic

# Well-known INS bytes
INS_SELECT = 0xA4
INS_STORE_DATA = 0xE2
INS_GET_DATA = 0xCA
INS_GET_RESPONSE = 0xC0


@dataclass
class ApduCommand:
    """Parsed APDU command."""
    cla: int        # Class byte
    ins: int        # Instruction byte
    p1: int         # Parameter 1
    p2: int         # Parameter 2
    data: bytes = field(default_factory=bytes)   # Command data (Lc bytes)
    le: int | None = None   # Expected response length (0 means 256 for extended)

    @property
    def lc(self) -> int:
        return len(self.data)

    @property
    def case(self) -> int:
        """Determine the ISO 7816-4 case number."""
        if self.data and self.le is not None:
            return 4
        elif self.data:
            return 3
        elif self.le is not None:
            return 2
        else:
            return 1

    def is_last_block(self) -> bool:
        """Check P1 bit 7 (last block indicator for STORE DATA)."""
        return bool(self.p1 & 0x80)

    def block_number(self) -> int:
        """Get block number from P2."""
        return self.p2


class ApduCodec:
    """Encode and decode ISO 7816-4 APDU messages."""

    @staticmethod
    def decode(raw: bytes) -> ApduCommand | None:
        """Parse raw APDU bytes into a structured command.

        Returns None if the buffer is too short for a complete APDU header.
        """
        if len(raw) < 4:
            return None

        cla = raw[0]
        ins = raw[1]
        p1 = raw[2]
        p2 = raw[3]

        data = b""
        le = None
        remaining = raw[4:]

        # ISO 7816-3 APDU parsing
        if len(remaining) == 0:
            # Case 1: no body
            pass
        elif len(remaining) == 1:
            # Case 2: Le only (short length)
            le = remaining[0]
            if le == 0:
                le = 256  # 0x00 means 256 in short format
        else:
            # Case 3 or 4: Lc + Data [+ Le]
            lc = remaining[0]
            if lc == 0:
                # Extended length: next 2 bytes are Lc
                if len(remaining) >= 3:
                    lc = (remaining[1] << 8) | remaining[2]
                    data_start = 3
                else:
                    return None
            else:
                data_start = 1

            data_end = data_start + lc
            if len(raw) < 4 + data_start + lc:
                return None  # Incomplete data

            data = raw[4 + data_start : 4 + data_end]

            # Check for Le after data.
            # Heuristic: if the byte after data is a known CLA (0x80, 0x84,
            # 0x00), it's likely the start of the next APDU, not Le.
            le_start = 4 + data_end
            if len(raw) > le_start:
                maybe_le = raw[le_start]
                if maybe_le in (0x80, 0x84, 0x00, 0x0C, 0x04):
                    pass  # Looks like CLA — don't consume
                else:
                    le = maybe_le
                    if le == 0:
                        le = 256

        return ApduCommand(cla=cla, ins=ins, p1=p1, p2=p2, data=data, le=le)

    @staticmethod
    def frame_size(raw: bytes) -> int | None:
        """Calculate the exact size of the first complete APDU in the buffer.

        Returns the number of bytes to consume, or None if incomplete.
        Used by ApduFrameParser for stream splitting.
        """
        if len(raw) < 4:
            return None

        # Check minimum body
        if len(raw) == 4:
            return 4  # Case 1

        lc = raw[4]
        if lc == 0:
            # Extended length Lc
            if len(raw) < 7:
                return None
            lc = (raw[5] << 8) | raw[6]
            body_start = 7
            lc_consumed = 3
        else:
            body_start = 5
            lc_consumed = 1

        total = 4 + lc_consumed + lc

        if len(raw) < total:
            return None

        # Check for trailing Le (non-CLA byte after data)
        if len(raw) > total:
            maybe_le = raw[total]
            if maybe_le not in (0x80, 0x84, 0x00, 0x0C, 0x04):
                total += 1

        return total

    @classmethod
    def minimum_frame_size(cls, raw: bytes) -> int | None:
        """Return the minimum number of bytes needed for a complete APDU frame.

        Returns None if the frame can't be determined yet (need more data).
        Returns the exact size once enough bytes are available.
        """
        if len(raw) < 4:
            return None  # Need at least the header

        # Case 1: fixed 4 bytes
        if len(raw) == 4:
            # Could be Case 1, or we haven't received the body yet
            return None

        lc_byte = raw[4]

        if lc_byte == 0:
            # Extended length Lc — need 2 more bytes for actual Lc
            if len(raw) < 7:
                return None
            lc = (raw[5] << 8) | raw[6]
            body_start = 7
            lc_consumed = 3
        else:
            lc = lc_byte
            body_start = 5
            lc_consumed = 1

        return 4 + lc_consumed + lc

    @staticmethod
    def encode_response(data: bytes = b"", sw: int = 0x9000) -> bytes:
        """Build a response APDU: [data] + SW1 + SW2."""
        sw_bytes = bytes([(sw >> 8) & 0xFF, sw & 0xFF])
        return data + sw_bytes

    @staticmethod
    def encode_error(sw: int) -> bytes:
        """Build an error response with just status word."""
        return bytes([(sw >> 8) & 0xFF, sw & 0xFF])

    @staticmethod
    def build_select(aid: bytes) -> bytes:
        """Build a SELECT APDU command."""
        lc = len(aid)
        return bytes([CLA_GP, INS_SELECT, 0x04, 0x00, lc]) + aid

    @staticmethod
    def build_store_data(p1: int, p2: int, data: bytes) -> bytes:
        """Build a STORE DATA APDU command."""
        lc = len(data)
        return bytes([CLA_GP, INS_STORE_DATA, p1, p2, lc]) + data
