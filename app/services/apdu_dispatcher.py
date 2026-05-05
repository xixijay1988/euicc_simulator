"""ES10 APDU Dispatcher — bridges raw APDU data to ES10 handlers.

This is the core integration module. It takes assembled TLV command data
from the APDU layer, identifies the ES10 command by tag, decodes the
ASN.1 payload, calls the correct handler method, encodes the response
back to DER, and wraps it in the appropriate APDU response TLV.
"""

import structlog

from ..services.apdu_handler import ApduProcessor, ES10_TAGS
from ..services.asn1_codec import Asn1Codec
from ..es10.es10b import Es10bHandler
from ..es10.es10c import Es10cHandler
from ..es10.es10a import Es10aHandler
from ..es10.es10b_iot import Es10bIotHandler

logger = structlog.get_logger()


class Es10Dispatcher:
    """Routes ES10 commands from APDU data to the correct handler.

    Each eUICC instance has one dispatcher. The dispatch() method
    takes assembled STORE DATA payload (TLV command data) and returns
    the TLV response to be sent back as an APDU response.
    """

    def __init__(self, euicc_instance):
        """
        Args:
            euicc_instance: EuiccInstance with .euicc, .pki, .es10a/.es10b/.es10c/.es10b_iot
        """
        self.euicc_instance = euicc_instance
        self.codec = Asn1Codec()

        # Handler shortcuts
        self.es10b = euicc_instance.es10b    # type: Es10bHandler
        self.es10c = euicc_instance.es10c    # type: Es10cHandler
        self.es10a = euicc_instance.es10a    # type: Es10aHandler
        self.es10b_iot = euicc_instance.es10b_iot  # type: Es10bIotHandler

    def dispatch(self, eid: str, command_data: bytes) -> bytes:
        """Process assembled STORE DATA payload, return TLV response.

        Args:
            eid: The EID being addressed (for logging)
            command_data: Assembled TLV bytes from STORE DATA segments

        Returns:
            TLV response bytes (tag + length + value + 9000) or error SW
        """
        tag, cmd_name, inner_data = ApduProcessor.identify_command(command_data)

        if tag == 0:
            logger.warning("unknown_command", eid=eid, data_hex=command_data[:32].hex())
            return ApduProcessor.build_response_apdu(0xBF3E, self.codec.encode(
                "GetEIDResponse", {"eid": b"\x00" * 16}
            ))

        logger.info("es10_dispatch", eid=eid, tag=hex(tag), cmd=cmd_name)

        try:
            response_data = self._execute(tag, cmd_name, inner_data, eid)
        except Exception as e:
            logger.error("dispatch_error", eid=eid, cmd=cmd_name, error=str(e))
            return bytes([0x6F, 0x00])  # SW_INTERNAL_ERROR

        if response_data is None:
            return bytes([0x6A, 0x80])  # SW_WRONG_DATA

        return ApduProcessor.build_response_apdu(tag, response_data)

    # ------------------------------------------------------------------
    # Command dispatch
    # ------------------------------------------------------------------

    def _execute(self, tag: int, cmd_name: str, inner_data: bytes, eid: str) -> bytes | None:
        """Route by tag to the correct handler method."""

        # ---- ES10b: Profile Download & Auth (GetEuiccInfo1) ----
        if tag == 0xBF20:  # GetEuiccInfo1
            return self._handle_get_info1()

        # ---- ES10b: Profile Download & Auth (GetEuiccInfo2) ----
        elif tag == 0xBF22:  # GetEuiccInfo2
            return self._handle_get_info2()

        # ---- ES10b: GetEuiccChallenge ----
        elif tag == 0xBF2E:  # GetEuiccChallenge
            return self._handle_get_challenge()

        # ---- ES10b: AuthenticateServer ----
        elif tag == 0xBF38:  # AuthenticateServer
            return self._handle_authenticate_server(inner_data)

        # ---- ES10b: PrepareDownload ----
        elif tag == 0xBF21:  # PrepareDownload
            return self._handle_prepare_download(inner_data)

        # ---- ES10b: LoadBoundProfilePackage ----
        elif tag == 0xBF36:  # LoadBoundProfilePackage
            return self._handle_load_bpp(inner_data)

        # ---- ES10b: CancelSession ----
        elif tag == 0xBF41:  # CancelSession
            return self._handle_cancel_session(inner_data)

        # ---- ES10b: ListNotification ----
        elif tag == 0xBF28:  # ListNotification
            return self._handle_list_notifications(inner_data)

        # ---- ES10b: RemoveNotificationFromList (SGP.22 v3.1) ----
        elif tag == 0xBF2F:  # RemoveNotificationFromList
            return self._handle_remove_notification(inner_data)

        # ---- SGP.32 ES10b: RetrieveNotificationsList (BF2B) ----
        elif tag == 0xBF2B:
            return self._handle_retrieve_notifications_sgp32(inner_data)

        # ---- ES10b: GetEUICCInformation (SGP.22 v3.0+) ----
        elif tag == 0xBF43:  # GetEUICCInformation
            return self._handle_get_euicc_information()

        # ---- ES10c: GetEID ----
        elif tag == 0xBF3E:  # GetEID
            return self._handle_get_eid()

        # ---- ES10c: GetProfilesInfo ----
        elif tag == 0xBF2D:  # GetProfilesInfo
            return self._handle_get_profiles(inner_data)

        # ---- ES10c: EnableProfile ----
        elif tag == 0xBF31:  # EnableProfile
            return self._handle_enable_profile(inner_data)

        # ---- ES10c: DisableProfile ----
        elif tag == 0xBF32:  # DisableProfile
            return self._handle_disable_profile(inner_data)

        # ---- ES10c: DeleteProfile ----
        elif tag == 0xBF33:  # DeleteProfile
            return self._handle_delete_profile(inner_data)

        # ---- ES10c: eUICCMemoryReset ----
        elif tag == 0xBF34:  # eUICCMemoryReset
            return self._handle_memory_reset(inner_data)

        # ---- ES10c: SetNickname ----
        elif tag == 0xBF29:  # SetNickname
            return self._handle_set_nickname(inner_data)

        # ---- SGP.32 ES10c: ProfileRollback (BF58) ----
        elif tag == 0xBF58:
            return self._handle_profile_rollback(inner_data)

        # ---- SGP.32 ES10c: ConfigureAutoProfileEnabling (BF59) ----
        elif tag == 0xBF59:
            return self._handle_configure_auto_enable(inner_data)

        # ---- SGP.32 ES10c: EnableUsingDD (BF5A) ----
        elif tag == 0xBF5A:
            return self._handle_enable_using_dd()

        # ---- ES10a: GetEuiccConfiguredAddresses ----
        elif tag == 0xBF3C:  # GetEuiccConfiguredAddresses
            return self._handle_get_addresses()

        # ---- ES10a: SetDefaultDpAddress ----
        elif tag == 0xBF3F:  # SetDefaultDpAddress
            return self._handle_set_dp_address(inner_data)

        # ---- SGP.32 IoT: ProvideEimPackageResult / ESep ----
        elif tag == 0xBF50:  # ProvideEimPackageResult / LoadEuiccPackage
            return self._handle_iot_package(inner_data)

        # ---- SGP.32 IoT: GetEimConfigurationData ----
        elif tag == 0xBF52:  # GetEimConfigurationData
            return self._handle_get_eim_config()

        # ---- SGP.32 IoT: GetEimConfigurationData (BF55, §5.9.18) ----
        elif tag == 0xBF55:
            return self._handle_get_eim_config_sgp32()

        # ---- SGP.32 IoT: GetCerts (BF56, §5.9.10) ----
        elif tag == 0xBF56:
            return self._handle_get_certs_sgp32(inner_data)

        # ---- SGP.32 IoT: AddInitialEim (BF57, §5.9.4) ----
        elif tag == 0xBF57:
            return self._handle_add_initial_eim(inner_data)

        else:
            logger.warning("unhandled_es10_tag", tag=hex(tag), cmd=cmd_name)
            return None

    # ==================================================================
    # ES10b Handlers
    # ==================================================================

    def _handle_get_info1(self) -> bytes:
        result = self.es10b.get_euicc_info1()
        return self.codec.encode("EuiccInfo1", result)

    def _handle_get_info2(self) -> bytes:
        result = self.es10b.get_euicc_info2()
        return self.codec.encode("EuiccInfo2", result)

    def _handle_get_challenge(self) -> bytes:
        result = self.es10b.get_euicc_challenge()
        return self.codec.encode("EuiccChallenge", result)

    def _handle_authenticate_server(self, inner_data: bytes) -> bytes | None:
        try:
            request = self.codec.decode("AuthenticateServerRequest", inner_data)
        except Exception as e:
            logger.error("decode_auth_server_failed", error=str(e))
            return None

        server_signed1 = request.get("serverSigned1", {})
        server_signature1 = request.get("serverSignature1", b"")
        euicc_ci_pkid = request.get("euiccCiPKIdToBeUsed", b"")
        server_cert_der = request.get("serverCertificate", b"")
        ctx_params1 = request.get("ctxParams1")

        result = self.es10b.authenticate_server(
            server_signed1=server_signed1,
            server_signature1=server_signature1,
            euicc_ci_pkid=euicc_ci_pkid,
            server_certificate_der=server_cert_der,
            ctx_params1=ctx_params1,
        )

        if "authenticateResponseError" in result:
            error_data = result["authenticateResponseError"]
            response = ("authenticateResponseError", error_data)
        else:
            ok_data = result["authenticateResponseOk"]
            response = ("authenticateResponseOk", {
                "euiccSigned1": ok_data["euiccSigned1"],
                "euiccSignature1": ok_data["euiccSignature1"],
                "euiccCertificate": ok_data["euiccCertificate"],
                "eumCertificate": ok_data["eumCertificate"],
            })

        return self.codec.encode("AuthenticateServerResponse", response)

    def _handle_prepare_download(self, inner_data: bytes) -> bytes | None:
        try:
            request = self.codec.decode("PrepareDownloadRequest", inner_data)
        except Exception as e:
            logger.error("decode_prepare_dl_failed", error=str(e))
            return None

        smdp_signed2 = request.get("smdpSigned2", {})
        smdp_signature2 = request.get("smdpSignature2", b"")
        hash_cc = request.get("hashCc")
        smdp_cert_der = request.get("smdpCertificate")

        result = self.es10b.prepare_download(
            smdp_signed2=smdp_signed2,
            smdp_signature2=smdp_signature2,
            hash_cc=hash_cc,
            smdp_certificate_der=smdp_cert_der,
        )

        if "downloadResponseError" in result:
            error_data = result["downloadResponseError"]
            response = ("downloadResponseError", error_data)
        else:
            ok_data = result["downloadResponseOk"]
            response = ("downloadResponseOk", {
                "euiccSigned2": ok_data["euiccSigned2"],
                "euiccSignature2": ok_data["euiccSignature2"],
            })

        return self.codec.encode("PrepareDownloadResponse", response)

    def _handle_load_bpp(self, inner_data: bytes) -> bytes | None:
        try:
            bpp_data = self.codec.decode("BoundProfilePackage", inner_data)
        except Exception as e:
            logger.error("decode_bpp_failed", error=str(e))
            return None

        result = self.es10b.load_bound_profile_package(bpp_data)
        return self.codec.encode("ProfileInstallationResult", result)

    def _handle_cancel_session(self, inner_data: bytes) -> bytes | None:
        try:
            request = self.codec.decode("CancelSessionRequest", inner_data)
        except Exception as e:
            logger.error("decode_cancel_session_failed", error=str(e))
            return None

        transaction_id = request.get("transactionId", b"\x00" * 16)
        reason = request.get("reason", 0)

        result = self.es10b.cancel_session(transaction_id, reason)
        return self.codec.encode("CancelSessionResponse", result)

    def _handle_list_notifications(self, inner_data: bytes) -> bytes | None:
        result = self.es10b.list_notifications()
        if "notificationMetadataList" in result:
            return self.codec.encode("ListNotificationResponse", ("notificationMetadataList", result["notificationMetadataList"]))
        else:
            return self.codec.encode("ListNotificationResponse", ("listNotificationsResultError", result.get("listNotificationsResultError", 1)))

    def _handle_remove_notification(self, inner_data: bytes) -> bytes | None:
        """RemoveNotificationFromList — BF2F."""
        try:
            request = self.codec.decode("RemoveNotificationFromListRequest", inner_data)
        except Exception as e:
            logger.error("decode_remove_notification_failed", error=str(e))
            return None

        seq_number = request.get("seqNumber", 0)
        result = self.es10b.remove_notification(seq_number)
        return self.codec.encode("RemoveNotificationFromListResponse", result)

    def _handle_retrieve_notifications_sgp32(self, inner_data: bytes) -> bytes | None:
        """RetrieveNotificationsList — BF2B (SGP.32 §5.9.11)."""
        try:
            request = self.codec.decode("SGP32-RetrieveNotificationsListRequest", inner_data)
            search_criteria = request.get("searchCriteria")
        except Exception:
            search_criteria = None

        result = self.es10b.retrieve_notifications_list_sgp32(search_criteria)
        if "notificationsListResultError" in result:
            return self.codec.encode(
                "SGP32-RetrieveNotificationsListResponse",
                ("notificationsListResultError", result["notificationsListResultError"])
            )
        return self.codec.encode(
            "SGP32-RetrieveNotificationsListResponse",
            ("notificationList", result["notificationList"])
        )

    def _handle_get_euicc_information(self) -> bytes:
        """GetEUICCInformation — BF43 (SGP.22 v3.0+)."""
        result = self.es10b.get_euicc_information()
        return self.codec.encode("GetEUICCInformationResponse", ("euiccInformationOk", result))

    # ==================================================================
    # ES10c Handlers
    # ==================================================================

    def _handle_get_eid(self) -> bytes:
        result = self.es10c.get_eid()
        return self.codec.encode("GetEIDResponse", result)

    def _handle_get_profiles(self, inner_data: bytes) -> bytes | None:
        # GetProfilesInfo has no request body — inner_data is either empty
        # or contains optional filter parameters encoded as simple TLV
        result = self.es10c.get_profiles_info()
        # asn1tools CHOICE expects (alternative_name, value) tuple
        return self.codec.encode("ProfileInfoListResponse", ("profileInfoListOk", result["profileInfoListOk"]))

    def _handle_enable_profile(self, inner_data: bytes) -> bytes | None:
        try:
            request = self.codec.decode("EnableProfileRequest", inner_data)
        except Exception as e:
            logger.error("decode_enable_profile_failed", error=str(e))
            return None

        iccid = request.get("iccid")
        aid = request.get("isdpAid")
        refresh = request.get("refreshFlag", True)

        result = self.es10c.enable_profile(iccid=iccid, aid=aid, refresh=refresh)
        return self.codec.encode("EnableProfileResponse", result)

    def _handle_disable_profile(self, inner_data: bytes) -> bytes | None:
        try:
            request = self.codec.decode("DisableProfileRequest", inner_data)
        except Exception as e:
            logger.error("decode_disable_profile_failed", error=str(e))
            return None

        iccid = request.get("iccid")
        aid = request.get("isdpAid")
        refresh = request.get("refreshFlag", True)

        result = self.es10c.disable_profile(iccid=iccid, aid=aid, refresh=refresh)
        return self.codec.encode("DisableProfileResponse", result)

    def _handle_delete_profile(self, inner_data: bytes) -> bytes | None:
        try:
            request = self.codec.decode("DeleteProfileRequest", inner_data)
        except Exception as e:
            logger.error("decode_delete_profile_failed", error=str(e))
            return None

        iccid = request.get("iccid")
        aid = request.get("isdpAid")

        result = self.es10c.delete_profile(iccid=iccid, aid=aid)
        return self.codec.encode("DeleteProfileResponse", result)

    def _handle_memory_reset(self, inner_data: bytes) -> bytes | None:
        try:
            request = self.codec.decode("EuiccMemoryResetRequest", inner_data)
        except Exception as e:
            logger.error("decode_memory_reset_failed", error=str(e))
            return None

        reset_options = request.get("resetOptions")
        result = self.es10c.euicc_memory_reset(reset_options)
        return self.codec.encode("EuiccMemoryResetResponse", result)

    def _handle_set_nickname(self, inner_data: bytes) -> bytes | None:
        try:
            request = self.codec.decode("SetNicknameRequest", inner_data)
        except Exception as e:
            logger.error("decode_set_nickname_failed", error=str(e))
            return None

        iccid = request.get("iccid", b"")
        nickname = request.get("profileNickname", "")

        result = self.es10c.set_nickname(iccid, nickname)
        return self.codec.encode("SetNicknameResponse", result)

    def _handle_profile_rollback(self, inner_data: bytes) -> bytes | None:
        """ProfileRollback — BF58 (SGP.32 §5.9.16)."""
        try:
            request = self.codec.decode("ProfileRollbackRequest", inner_data)
        except Exception as e:
            logger.error("decode_rollback_failed", error=str(e))
            return None

        refresh_flag = request.get("refreshFlag", False)
        result = self.es10c.profile_rollback(refresh_flag)
        return self.codec.encode("ProfileRollbackResponse", result)

    def _handle_configure_auto_enable(self, inner_data: bytes) -> bytes | None:
        """ConfigureAutoProfileEnabling — BF59 (SGP.32 §5.9.17)."""
        try:
            request = self.codec.decode("ConfigureAutoProfileEnablingRequest", inner_data)
        except Exception as e:
            logger.error("decode_auto_enable_failed", error=str(e))
            return None

        auto_flag = request.get("autoEnableFlag") is not None
        smdp_oid = str(request.get("smdpOid", "")) if request.get("smdpOid") else None
        smdp_address = request.get("smdpAddress")

        result = self.es10c.configure_auto_enable(auto_flag, smdp_oid, smdp_address)
        return self.codec.encode("ConfigureAutoProfileEnablingResponse", result)

    def _handle_enable_using_dd(self) -> bytes:
        """EnableUsingDD — BF5A (SGP.32 §5.9.15)."""
        result = self.es10c.enable_using_dd()
        return self.codec.encode("EnableUsingDDResponse", result)

    # ==================================================================
    # ES10a Handlers
    # ==================================================================

    def _handle_get_addresses(self) -> bytes:
        result = self.es10a.get_euicc_configured_addresses()
        return self.codec.encode("EuiccConfiguredAddresses", result)

    def _handle_set_dp_address(self, inner_data: bytes) -> bytes | None:
        try:
            request = self.codec.decode("SetDefaultDpAddressRequest", inner_data)
        except Exception as e:
            logger.error("decode_set_dp_address_failed", error=str(e))
            return None

        address = request.get("defaultDpAddress", "")
        result = self.es10a.set_default_smdp(address)
        return self.codec.encode("SetDefaultDpAddressResponse", result)

    # ==================================================================
    # SGP.32 IoT Handlers
    # ==================================================================

    def _handle_iot_package(self, inner_data: bytes) -> bytes | None:
        """Handle LoadEuiccPackage for SGP.32 IoT (PSMO/eCO via ESep)."""
        try:
            request = self.codec.decode("ProvideEimPackageResult", inner_data)
        except Exception as e:
            logger.error("decode_iot_package_failed", error=str(e))
            return None

        result = self.es10b_iot.load_euicc_package(request)
        return self.codec.encode("ProvideEimPackageResult", result)

    def _handle_get_eim_config(self) -> bytes:
        result = self.es10b_iot.get_eim_configuration_data()
        return self.codec.encode("EimConfigurationDataList", result["eimConfigurationDataList"])

    def _handle_get_eim_config_sgp32(self) -> bytes:
        """GetEimConfigurationData — BF55 (SGP.32 §5.9.18)."""
        result = self.es10b_iot.get_eim_config_sgp32()
        return self.codec.encode("GetEimConfigurationDataResponse", result)

    def _handle_get_certs_sgp32(self, inner_data: bytes) -> bytes | None:
        """GetCerts — BF56 (SGP.32 §5.9.10)."""
        try:
            request = self.codec.decode("GetCertsRequestSGP32", inner_data)
        except Exception as e:
            logger.error("decode_get_certs_failed", error=str(e))
            return None

        euicc_ci_pkid = request.get("euiccCiPKId")
        result = self.es10b_iot.get_certs_sgp32(euicc_ci_pkid)
        return self.codec.encode("GetCertsResponseSGP32", ("certs", result["certs"]))

    def _handle_add_initial_eim(self, inner_data: bytes) -> bytes | None:
        """AddInitialEim — BF57 (SGP.32 §5.9.4)."""
        try:
            request = self.codec.decode("AddInitialEimRequest", inner_data)
        except Exception as e:
            logger.error("decode_add_initial_eim_failed", error=str(e))
            return None

        eim_configs = request.get("eimConfigurationDataList", [])
        result = self.es10b_iot.add_initial_eim(eim_configs)
        return self.codec.encode("AddInitialEimResponse", ("addInitialEimOk", result["addInitialEimOk"]))
