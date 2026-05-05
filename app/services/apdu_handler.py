"""
APDU Transport Layer — STORE DATA command processing.

Handles the GlobalPlatform STORE DATA APDU commands that carry
ES10 messages between the IPA and the eUICC ISD-R.

APDU Format:
  CLA: 80 (GlobalPlatform)
  INS: E2 (STORE DATA)
  P1:  Block management flags
       - 0x91 = last block + BER-TLV
       - 0x11 = more blocks + BER-TLV
  P2:  Block number (sequential)
  Data: ASN.1 DER-encoded ES10 command TLV

ISD-R AID: A0 00 00 05 59 10 10 FF FF FF FF 89 00 00 01 00
"""

import structlog
from dataclasses import dataclass, field

logger = structlog.get_logger()

# ISD-R Application Identifier
ISDR_AID = bytes.fromhex("A0000005591010FFFFFFFF8900001000")

# Status words
SW_OK = bytes.fromhex("9000")
SW_WRONG_DATA = bytes.fromhex("6A80")
SW_CONDITIONS_NOT_SATISFIED = bytes.fromhex("6985")
SW_FILE_NOT_FOUND = bytes.fromhex("6A82")
SW_WRONG_P1P2 = bytes.fromhex("6A86")
SW_WRONG_LENGTH = bytes.fromhex("6700")
SW_INTERNAL_ERROR = bytes.fromhex("6F00")

# ES10 command tags (first bytes identify the command)
# SGP.22 v3.1 + SGP.32 v1.2 full coverage
ES10_TAGS = {
    # ES10b — Profile Download & Authentication
    0xBF20: "GetEuiccInfo1",
    0xBF22: "GetEuiccInfo2",
    0xBF2E: "GetEuiccChallenge",
    0xBF38: "AuthenticateServer",
    0xBF21: "PrepareDownload",
    0xBF36: "LoadBoundProfilePackage",
    0xBF41: "CancelSession",
    0xBF43: "GetEUICCInformation",
    # ES10b — Notifications
    0xBF28: "ListNotification",
    0xBF2F: "RemoveNotificationFromList",
    # ES10c — Profile Management
    0xBF2D: "GetProfilesInfo",
    0xBF31: "EnableProfile",
    0xBF32: "DisableProfile",
    0xBF33: "DeleteProfile",
    0xBF3E: "GetEID",
    0xBF34: "eUICCMemoryReset",
    0xBF29: "SetNickname",
    # ES10a — Configuration
    0xBF3C: "GetEuiccConfiguredAddresses",
    0xBF3F: "SetDefaultDpAddress",
    # SGP.32 IoT (ES10b extended)
    0xBF50: "LoadEuiccPackage",
    0xBF52: "GetEimConfigurationData",
    0xBF55: "GetEimConfigurationDataSGP32",
    0xBF56: "GetCertsSGP32",
    0xBF57: "AddInitialEim",
    0xBF2B: "RetrieveNotificationsListSGP32",
    0xBF58: "ProfileRollback",
    0xBF59: "ConfigureAutoProfileEnabling",
    0xBF5A: "EnableUsingDD",
}


@dataclass
class ApduSegmentBuffer:
    """Reassembles multi-segment STORE DATA commands."""
    segments: list[bytes] = field(default_factory=list)
    expected_block: int = 0
    complete: bool = False

    def add_segment(self, p1: int, p2: int, data: bytes) -> bool:
        """
        Add a segment to the buffer.

        Returns True if this was the last segment.
        """
        if p2 != self.expected_block:
            logger.warning(
                "block_number_mismatch",
                expected=self.expected_block,
                received=p2,
            )
            return False

        self.segments.append(data)
        self.expected_block += 1

        # Check if this is the last block (bit 7 of P1)
        if p1 & 0x80:
            self.complete = True
            return True

        return False

    def get_complete_data(self) -> bytes:
        """Return the reassembled complete data."""
        return b"".join(self.segments)

    def reset(self):
        """Reset the buffer for a new command."""
        self.segments.clear()
        self.expected_block = 0
        self.complete = False


class ApduProcessor:
    """
    Processes APDU commands directed to the eUICC ISD-R.

    This simulates the eUICC's APDU interface:
    1. SELECT ISD-R (open logical channel)
    2. STORE DATA commands carrying ES10 messages
    3. Response APDUs with results
    """

    def __init__(self):
        self.selected_aid: bytes | None = None
        self.logical_channel: int = 0
        self.segment_buffer = ApduSegmentBuffer()

    def process_apdu(self, apdu: bytes) -> bytes:
        """
        Process a raw APDU command and return the response.

        Args:
            apdu: Complete command APDU bytes (CLA + INS + P1 + P2 + Lc + Data [+ Le])

        Returns:
            Response data + SW1 SW2
        """
        if len(apdu) < 4:
            return SW_WRONG_LENGTH

        cla = apdu[0]
        ins = apdu[1]
        p1 = apdu[2]
        p2 = apdu[3]

        # Extract data field
        data = b""
        if len(apdu) > 5:
            lc = apdu[4]
            data = apdu[5 : 5 + lc]

        # Route by instruction
        if ins == 0xA4:  # SELECT
            return self._handle_select(data)
        elif ins == 0xE2:  # STORE DATA
            return self._handle_store_data(p1, p2, data)
        elif ins == 0xCA:  # GET DATA
            return self._handle_get_data(p1, p2)
        else:
            return SW_CONDITIONS_NOT_SATISFIED

    def _handle_select(self, aid: bytes) -> bytes:
        """Handle SELECT command to open the ISD-R."""
        if aid == ISDR_AID or aid == ISDR_AID[:8]:  # Full or partial AID match
            self.selected_aid = ISDR_AID
            logger.info("isdr_selected", aid=aid.hex())
            return SW_OK
        return SW_FILE_NOT_FOUND

    def _handle_store_data(self, p1: int, p2: int, data: bytes) -> bytes:
        """
        Handle STORE DATA command (carries ES10 messages).

        Returns the command tag and assembled data for processing
        by the ES10 handlers.
        """
        if self.selected_aid != ISDR_AID:
            return SW_CONDITIONS_NOT_SATISFIED

        is_last = self.segment_buffer.add_segment(p1, p2, data)

        if not is_last:
            # More segments expected, acknowledge this one
            return SW_OK

        # All segments received — reassemble and identify command
        complete_data = self.segment_buffer.get_complete_data()
        self.segment_buffer.reset()

        return complete_data + SW_OK

    def _handle_get_data(self, p1: int, p2: int) -> bytes:
        """Handle GET DATA command (used for some ES10 queries)."""
        return SW_CONDITIONS_NOT_SATISFIED

    @staticmethod
    def identify_command(data: bytes) -> tuple[int, str, bytes]:
        """
        Identify an ES10 command from its TLV data.

        Returns:
            (tag, command_name, inner_data)
        """
        if len(data) < 2:
            return 0, "Unknown", data

        # Multi-byte tag (BF xx)
        if data[0] == 0xBF:
            tag = (data[0] << 8) | data[1]
            # Parse length
            offset = 2
            length, len_bytes = _parse_der_length(data[offset:])
            offset += len_bytes
            inner_data = data[offset : offset + length]
        else:
            tag = data[0]
            offset = 1
            length, len_bytes = _parse_der_length(data[offset:])
            offset += len_bytes
            inner_data = data[offset : offset + length]

        command_name = ES10_TAGS.get(tag, f"Unknown(0x{tag:04X})")
        return tag, command_name, inner_data

    @staticmethod
    def build_response_apdu(tag: int, response_data: bytes) -> bytes:
        """
        Build a response APDU with the given tag and data.

        Format: Tag + Length + Data + SW(9000)
        """
        tlv = _build_tlv(tag, response_data)
        return tlv + SW_OK

    @staticmethod
    def segment_response(data: bytes, max_segment_size: int = 255) -> list[bytes]:
        """
        Segment a large response into multiple APDU-sized chunks.

        Each chunk is max_segment_size bytes of data.
        Used for responses larger than a single APDU (e.g., BPP, profiles list).
        """
        segments = []
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + max_segment_size]
            segments.append(chunk)
            offset += max_segment_size
        return segments


def _parse_der_length(data: bytes) -> tuple[int, int]:
    """
    Parse a DER length field.

    Returns (length_value, bytes_consumed).
    """
    if not data:
        return 0, 0

    if data[0] < 0x80:
        return data[0], 1
    elif data[0] == 0x81:
        return data[1], 2
    elif data[0] == 0x82:
        return (data[1] << 8) | data[2], 3
    elif data[0] == 0x83:
        return (data[1] << 16) | (data[2] << 8) | data[3], 4
    return 0, 0


def _build_tlv(tag: int, data: bytes) -> bytes:
    """Build a TLV with proper DER length encoding."""
    # Tag bytes
    if tag > 0xFF:
        tag_bytes = tag.to_bytes(2, "big")
    else:
        tag_bytes = tag.to_bytes(1, "big")

    # Length bytes
    length = len(data)
    if length < 0x80:
        len_bytes = bytes([length])
    elif length < 0x100:
        len_bytes = bytes([0x81, length])
    elif length < 0x10000:
        len_bytes = bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        len_bytes = bytes([
            0x83,
            (length >> 16) & 0xFF,
            (length >> 8) & 0xFF,
            length & 0xFF,
        ])

    return tag_bytes + len_bytes + data
