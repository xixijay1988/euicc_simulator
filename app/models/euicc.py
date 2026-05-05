"""
eUICC state model — the virtual secure element.

Represents the internal state of a simulated eUICC:
- EID and configured addresses
- Installed profile slots
- eIM associations
- Notification queue
- Session state for active download
"""

import os
import time
from enum import Enum
from dataclasses import dataclass, field


class ProfileState(str, Enum):
    DISABLED = "disabled"
    ENABLED = "enabled"


class ProfileClass(str, Enum):
    TEST = "test"
    PROVISIONING = "provisioning"
    OPERATIONAL = "operational"


@dataclass
class ProfileSlot:
    """A profile installed on the eUICC."""
    iccid: bytes  # 10 bytes, BCD-encoded
    isdp_aid: bytes  # ISD-P Application Identifier
    state: ProfileState = ProfileState.DISABLED
    profile_name: str = ""
    service_provider_name: str = ""
    profile_nickname: str = ""
    profile_class: ProfileClass = ProfileClass.OPERATIONAL
    notification_address: str = ""
    policy_rules: bytes = b""
    profile_data: bytes = b""  # Decrypted profile elements

    def iccid_string(self) -> str:
        """Convert BCD ICCID bytes to string (with nibble swap)."""
        hex_str = self.iccid.hex()
        result = ""
        for i in range(0, len(hex_str), 2):
            result += hex_str[i + 1] + hex_str[i]
        return result.rstrip("f").upper()


@dataclass
class EimAssociation:
    """eIM association stored on the eUICC."""
    eim_id: str
    eim_fqdn: str = ""
    counter_value: int = 0
    association_token: int = 0
    supported_protocol: int = 0  # 0=httpsRetrieval


@dataclass
class Notification:
    """Pending notification on the eUICC."""
    seq_number: int
    operation: str  # install, enable, disable, delete
    notification_address: str
    iccid: bytes | None = None


@dataclass
class DownloadSession:
    """Active profile download session state."""
    transaction_id: bytes
    server_address: str
    euicc_challenge: bytes
    server_challenge: bytes | None = None
    server_public_key: object = None  # EllipticCurvePublicKey, captured during AuthenticateServer
    euicc_signature1: bytes = b""  # the eUICC's own signature1 — needed as TBS suffix for smdpSignature2
    euicc_otpk_private: object = None  # EllipticCurvePrivateKey
    euicc_otpk_public: bytes = b""
    smdp_otpk_public: bytes = b""
    session_keys: object = None  # SessionKeys
    authenticated: bool = False
    prepared: bool = False


@dataclass
class EuiccState:
    """
    Complete state of a simulated eUICC.

    This represents everything stored in the secure element:
    profiles, keys, configuration, and session state.
    """
    # Identity
    eid: str  # 32-digit EID string

    # Version information (per SGP.22 EuiccInfo)
    svn: tuple[int, int, int] = (3, 1, 0)  # SGP.22 version
    profile_version: tuple[int, int, int] = (2, 3, 1)  # Profile package version
    firmware_version: tuple[int, int, int] = (1, 0, 0)
    platform_label: str = "ConnectX-eUICC-Simulator"

    # IoT extensions (SGP.32)
    ipa_mode: int = 0  # 0=IPAd (device-based)
    iot_version: tuple[int, int, int] = (1, 2, 0)  # SGP.32 version

    # Memory (bytes)
    total_nvm: int = 512 * 1024  # 512KB NVM
    free_nvm: int = 480 * 1024
    total_volatile: int = 8 * 1024  # 8KB RAM
    free_volatile: int = 7 * 1024

    # Configured addresses (ES10a)
    default_smdp_address: str = ""
    root_ds_address: str = ""

    # Profile slots
    profiles: list[ProfileSlot] = field(default_factory=list)
    max_profiles: int = 8

    # eIM associations
    eim_associations: list[EimAssociation] = field(default_factory=list)

    # Notification queue
    notifications: list[Notification] = field(default_factory=list)
    _notification_seq: int = 0

    # Active download session (only one at a time)
    active_session: DownloadSession | None = None

    # Capabilities
    uicc_capability: bytes = b"\x07\x73"  # contactlessSupport, uiccCLF, etc.
    rsp_capability: bytes = b"\x04\x90"  # additionalProfile, testProfileSupport

    def get_enabled_profile(self) -> ProfileSlot | None:
        """Get the currently enabled profile, if any."""
        for p in self.profiles:
            if p.state == ProfileState.ENABLED:
                return p
        return None

    def find_profile_by_iccid(self, iccid: bytes) -> ProfileSlot | None:
        """Find a profile by its ICCID bytes."""
        for p in self.profiles:
            if p.iccid == iccid:
                return p
        return None

    def find_profile_by_aid(self, aid: bytes) -> ProfileSlot | None:
        """Find a profile by its ISD-P AID."""
        for p in self.profiles:
            if p.isdp_aid == aid:
                return p
        return None

    def next_notification_seq(self) -> int:
        """Generate the next notification sequence number."""
        self._notification_seq += 1
        return self._notification_seq

    def add_notification(
        self, operation: str, address: str, iccid: bytes | None = None
    ) -> Notification:
        """Add a notification to the pending queue."""
        notif = Notification(
            seq_number=self.next_notification_seq(),
            operation=operation,
            notification_address=address,
            iccid=iccid,
        )
        self.notifications.append(notif)
        return notif

    def allocate_isdp_aid(self) -> bytes:
        """Generate a unique ISD-P AID for a new profile."""
        # ISD-P AID format: A0000005591010FFFFFFFF8900001X00
        # where X increments for each profile
        profile_num = len(self.profiles) + 1
        aid_hex = f"A0000005591010FFFFFFFF890000{profile_num:02X}00"
        return bytes.fromhex(aid_hex)

    def version_to_bytes(self, version: tuple[int, int, int]) -> bytes:
        """Convert version tuple to 3-byte encoding."""
        return bytes(version)

    def ext_card_resource_bytes(self) -> bytes:
        """
        Encode extCardResource per SGP.22.

        Format: Tag 82 (free NVM) + Tag 83 (free volatile memory)
        Each is a 3-byte integer.
        """
        nvm = self.free_nvm.to_bytes(3, "big")
        vol = self.free_volatile.to_bytes(3, "big")
        return b"\x82\x03" + nvm + b"\x83\x03" + vol
