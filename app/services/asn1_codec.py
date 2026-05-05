"""
ASN.1 DER Codec — Central encoding/decoding service.

Compiles the RSPDefinitions ASN.1 schema and provides typed
encode/decode methods for all ES10 messages.

All TBS (to-be-signed) data goes through this codec to ensure
canonical DER encoding, which is required for ECDSA signatures
to be interoperable with real SM-DP+ and eIM servers.
"""

from __future__ import annotations

import base64
from pathlib import Path
from functools import lru_cache

import asn1tools
import structlog

logger = structlog.get_logger()

# Schema file path
SCHEMA_PATH = Path(__file__).parent.parent.parent / "asn1_schemas" / "rsp_definitions.asn"


@lru_cache(maxsize=1)
def _compile_schema() -> asn1tools.CompiledFile:
    """Compile the ASN.1 schema once and cache it."""
    schema = asn1tools.compile_files(str(SCHEMA_PATH), "der")
    logger.info("asn1_schema_compiled", types=len(schema.types))
    return schema


class Asn1Codec:
    """
    Typed ASN.1 DER codec for GSMA RSP messages.

    Usage:
        codec = Asn1Codec()
        der_bytes = codec.encode_server_signed1(data_dict)
        decoded = codec.decode_server_signed1(der_bytes)
    """

    def __init__(self):
        self.schema = _compile_schema()

    # =================================================================
    # Generic encode/decode
    # =================================================================

    def encode(self, type_name: str, data: dict | tuple) -> bytes:
        """Encode any RSP type to DER bytes."""
        return self.schema.encode(type_name, data)

    def decode(self, type_name: str, der_bytes: bytes) -> dict | tuple:
        """Decode DER bytes to a Python dict/tuple."""
        return self.schema.decode(type_name, der_bytes)

    def encode_base64(self, type_name: str, data: dict | tuple) -> str:
        """Encode to base64-encoded DER (for JSON transport)."""
        return base64.b64encode(self.encode(type_name, data)).decode("ascii")

    def decode_base64(self, type_name: str, b64_string: str) -> dict | tuple:
        """Decode from base64-encoded DER."""
        return self.decode(type_name, base64.b64decode(b64_string))

    # =================================================================
    # ES10b — TBS Encoding (canonical DER for signing)
    # =================================================================

    def encode_server_signed1(self, data: dict) -> bytes:
        """
        Encode ServerSigned1 to canonical DER for signature verification.

        This is the exact byte sequence that the SM-DP+ signed.
        """
        return self.schema.encode("ServerSigned1", data)

    def encode_euicc_signed1(self, data: dict) -> bytes:
        """
        Encode EuiccSigned1 to canonical DER for eUICC signing.

        The eUICC signs this to prove its identity to the SM-DP+.
        """
        return self.schema.encode("EuiccSigned1", data)

    def encode_euicc_signed2(self, data: dict) -> bytes:
        """
        Encode EuiccSigned2 to canonical DER for signing.

        Contains the eUICC OTPK for session key derivation.
        """
        return self.schema.encode("EuiccSigned2", data)

    def encode_cancel_session_signed(self, data: dict) -> bytes:
        """Encode EuiccCancelSessionSigned for signing."""
        return self.schema.encode("EuiccCancelSessionSigned", data)

    def encode_smdp_signed2(self, data: dict) -> bytes:
        """Encode SmdpSigned2 for signature verification."""
        return self.schema.encode("SmdpSigned2", data)

    # =================================================================
    # ES10b — Full Response Encoding
    # =================================================================

    def encode_euicc_info1(self, data: dict) -> bytes:
        """Encode EuiccInfo1 (BF20) response."""
        return self.schema.encode("EuiccInfo1", data)

    def encode_euicc_info2(self, data: dict) -> bytes:
        """Encode EuiccInfo2 (BF22) response."""
        return self.schema.encode("EuiccInfo2", data)

    def encode_euicc_challenge(self, data: dict) -> bytes:
        """Encode EuiccChallenge (BF2E) response."""
        return self.schema.encode("EuiccChallenge", data)

    def encode_authenticate_server_response(self, data: tuple) -> bytes:
        """
        Encode AuthenticateServerResponse (BF38).

        Args:
            data: ('authenticateResponseOk', {...}) or ('authenticateResponseError', {...})
        """
        return self.schema.encode("AuthenticateServerResponse", data)

    def encode_prepare_download_response(self, data: tuple) -> bytes:
        """
        Encode PrepareDownloadResponse (BF21).

        Args:
            data: ('downloadResponseOk', {...}) or ('downloadResponseError', {...})
        """
        return self.schema.encode("PrepareDownloadResponse", data)

    def encode_profile_installation_result(self, data: dict) -> bytes:
        """Encode ProfileInstallationResult (BF37)."""
        return self.schema.encode("ProfileInstallationResult", data)

    def encode_profile_installation_result_data(self, data: dict) -> bytes:
        """Encode ProfileInstallationResultData for signing."""
        return self.schema.encode("ProfileInstallationResultData", data)

    def encode_cancel_session_response(self, data: tuple) -> bytes:
        """Encode CancelSessionResponse (BF41)."""
        return self.schema.encode("CancelSessionResponse", data)

    # =================================================================
    # ES10c — Profile Management Encoding
    # =================================================================

    def encode_profile_info_list_response(self, data: tuple) -> bytes:
        """Encode ProfileInfoListResponse (BF2D)."""
        return self.schema.encode("ProfileInfoListResponse", data)

    def encode_enable_profile_response(self, data: dict) -> bytes:
        """Encode EnableProfileResponse (BF31)."""
        return self.schema.encode("EnableProfileResponse", data)

    def encode_disable_profile_response(self, data: dict) -> bytes:
        """Encode DisableProfileResponse (BF32)."""
        return self.schema.encode("DisableProfileResponse", data)

    def encode_delete_profile_response(self, data: dict) -> bytes:
        """Encode DeleteProfileResponse (BF33)."""
        return self.schema.encode("DeleteProfileResponse", data)

    def encode_get_eid_response(self, data: dict) -> bytes:
        """Encode GetEIDResponse (BF3E)."""
        return self.schema.encode("GetEIDResponse", data)

    def encode_memory_reset_response(self, data: dict) -> bytes:
        """Encode EuiccMemoryResetResponse (BF34)."""
        return self.schema.encode("EuiccMemoryResetResponse", data)

    def encode_nickname_response(self, data: dict) -> bytes:
        """Encode SetNicknameResponse (BF29)."""
        return self.schema.encode("SetNicknameResponse", data)

    # =================================================================
    # ES10a — Configuration Encoding
    # =================================================================

    def encode_configured_addresses(self, data: dict) -> bytes:
        """Encode EuiccConfiguredAddresses (BF3C)."""
        return self.schema.encode("EuiccConfiguredAddresses", data)

    def encode_set_dp_address_response(self, data: dict) -> bytes:
        """Encode SetDefaultDpAddressResponse (BF3F)."""
        return self.schema.encode("SetDefaultDpAddressResponse", data)

    # =================================================================
    # Notifications
    # =================================================================

    def encode_notification_metadata(self, data: dict) -> bytes:
        """Encode NotificationMetadata."""
        return self.schema.encode("NotificationMetadata", data)

    def encode_list_notification_response(self, data: tuple) -> bytes:
        """Encode ListNotificationResponse (BF28)."""
        return self.schema.encode("ListNotificationResponse", data)

    # =================================================================
    # SGP.32 IoT / ESipa
    # =================================================================

    def encode_eim_config_data_list(self, data: list) -> bytes:
        """Encode EimConfigurationDataList."""
        return self.schema.encode("EimConfigurationDataList", data)

    def encode_provide_eim_package_result(self, data: tuple) -> bytes:
        """
        Encode ProvideEimPackageResult (BF50).

        Args:
            data: ('euiccPackageResult', {...}) | ('ipaEuiccDataResponse', {...}) | etc.
        """
        return self.schema.encode("ProvideEimPackageResult", data)

    def encode_ipa_euicc_data_response(self, data: dict) -> bytes:
        """Encode IpaEuiccDataResponse standalone."""
        return self.schema.encode("IpaEuiccDataResponse", data)

    def encode_profile_download_trigger_result(self, data: dict) -> bytes:
        """Encode ProfileDownloadTriggerResult."""
        return self.schema.encode("ProfileDownloadTriggerResult", data)

    def encode_eim_acknowledgements(self, data: dict) -> bytes:
        """Encode EimAcknowledgements."""
        return self.schema.encode("EimAcknowledgements", data)

    # =================================================================
    # Decoding helpers
    # =================================================================

    def decode_server_signed1(self, der_bytes: bytes) -> dict:
        """Decode ServerSigned1 from DER."""
        return self.schema.decode("ServerSigned1", der_bytes)

    def decode_authenticate_server_request(self, der_bytes: bytes) -> dict:
        """Decode AuthenticateServerRequest (BF38) from DER."""
        return self.schema.decode("AuthenticateServerRequest", der_bytes)

    def decode_prepare_download_request(self, der_bytes: bytes) -> dict:
        """Decode PrepareDownloadRequest (BF21) from DER."""
        return self.schema.decode("PrepareDownloadRequest", der_bytes)

    def decode_bound_profile_package(self, der_bytes: bytes) -> dict:
        """Decode BoundProfilePackage (BF36) from DER."""
        return self.schema.decode("BoundProfilePackage", der_bytes)

    def decode_smdp_signed2(self, der_bytes: bytes) -> dict:
        """Decode SmdpSigned2 from DER."""
        return self.schema.decode("SmdpSigned2", der_bytes)
