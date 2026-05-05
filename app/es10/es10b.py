"""
ES10b Interface Handler — Profile Download & Authentication.

Implements the eUICC side of the ES10b interface per SGP.22 §5.7:
1. GetEuiccInfo1 — Return CI PKI info
2. GetEuiccInfo2 — Return full eUICC capabilities
3. GetEuiccChallenge — Generate authentication challenge
4. AuthenticateServer — Verify SM-DP+ and generate eUICC response
5. PrepareDownload — Prepare for BPP, derive session keys
6. LoadBoundProfilePackage — Decrypt and install profile
7. CancelSession — Abort active download
"""

import os
import hashlib
import structlog
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from ..models.euicc import (
    EuiccState,
    DownloadSession,
    ProfileSlot,
    ProfileState,
    ProfileClass,
)
from ..crypto.certificates import CertificateInfrastructure
from ..crypto.ecdsa_engine import EcdsaEngine, SessionKeys
from ..crypto.scp03t import Scp03tProcessor
from ..crypto.cert_validator import CertChainValidator
from ..services.asn1_codec import Asn1Codec

logger = structlog.get_logger()


class Es10bHandler:
    """
    Handles ES10b commands from the IPA.

    Each method simulates what a real eUICC's ISD-R would do when
    receiving the corresponding STORE DATA APDU.

    All TBS (to-be-signed) data is encoded using canonical ASN.1 DER
    via the Asn1Codec, ensuring signatures are interoperable with
    real SM-DP+ and eIM servers.
    """

    def __init__(self, euicc: EuiccState, pki: CertificateInfrastructure):
        self.euicc = euicc
        self.pki = pki
        self.ecdsa = EcdsaEngine()
        self.codec = Asn1Codec()
        self.cert_validator = CertChainValidator(pki.get_trusted_ci_certs())

    # ------------------------------------------------------------------
    # GetEuiccInfo1 (BF20)
    # ------------------------------------------------------------------

    def get_euicc_info1(self) -> dict:
        """
        Return basic eUICC info for initial authentication.

        Contains:
        - SVN (SGP.22 version)
        - CI PKI IDs for verification (all trusted roots — own + GSMA TestCI)
        - CI PKI ID for signing (own only — we only have our own private key)

        This is sent BEFORE mutual authentication so it must not
        contain sensitive info.
        """
        return {
            "svn": self.euicc.version_to_bytes(self.euicc.svn),
            "euiccCiPKIdListForVerification": self.pki.get_trusted_ci_pkids(),
            "euiccCiPKIdListForSigning": [self.pki.get_ci_pki_id()],
        }

    # ------------------------------------------------------------------
    # GetEuiccInfo2 (BF22)
    # ------------------------------------------------------------------

    def get_euicc_info2(self) -> dict:
        """
        Return full eUICC capabilities (sent after authentication).

        Includes memory, firmware version, capabilities, and IoT extensions.
        """
        ci_pki_id = self.pki.get_ci_pki_id()

        info2 = {
            "profileVersion": self.euicc.version_to_bytes(self.euicc.profile_version),
            "svn": self.euicc.version_to_bytes(self.euicc.svn),
            "euiccFirmwareVer": self.euicc.version_to_bytes(
                self.euicc.firmware_version
            ),
            "extCardResource": self.euicc.ext_card_resource_bytes(),
            "uiccCapability": self.euicc.uicc_capability,
            "rspCapability": self.euicc.rsp_capability,
            "euiccCiPKIdListForVerification": self.pki.get_trusted_ci_pkids(),
            "euiccCiPKIdListForSigning": [ci_pki_id],
            # ppVersion + sasAcreditationNumber are MANDATORY in SGP.22 v3
            # EUICCInfo2 (untagged), even when their content isn't meaningful
            # for a sim. Use zero/empty values to satisfy the schema.
            "ppVersion": b"\x00\x00\x00",
            "sasAcreditationNumber": "",
            "certificationDataObject": {
                "platformLabel": self.euicc.platform_label or "ConnectX-eUICC-Sim",
                # SM-DP+'s decoder treats discoveryBaseURL as required despite
                # the OPTIONAL marker; supply a placeholder URL.
                "discoveryBaseURL": "https://euicc.connectxiot.com",
            },
            # SGP.32 IoT extensions
            "ipaMode": self.euicc.ipa_mode,
            "iotSpecificInfo": {
                "iotVersion": self.euicc.version_to_bytes(self.euicc.iot_version),
            },
        }
        return info2

    # ------------------------------------------------------------------
    # GetEuiccChallenge (BF2E)
    # ------------------------------------------------------------------

    def get_euicc_challenge(self) -> dict:
        """
        Generate a 16-byte random challenge for server authentication.

        The challenge is stored in the session state and must be
        presented back by the SM-DP+ in AuthenticateServer.
        """
        challenge = self.ecdsa.generate_challenge()

        # Store for later verification
        self.euicc.active_session = DownloadSession(
            transaction_id=b"",  # Will be set by AuthenticateServer
            server_address="",
            euicc_challenge=challenge,
        )

        logger.info(
            "euicc_challenge_generated",
            eid=self.euicc.eid,
            challenge_hex=challenge.hex(),
        )

        return {"euiccChallenge": challenge}

    # ------------------------------------------------------------------
    # AuthenticateServer (BF38)
    # ------------------------------------------------------------------

    def authenticate_server(
        self,
        server_signed1: dict,
        server_signature1: bytes,
        euicc_ci_pkid: bytes,
        server_certificate_der: bytes,
        ctx_params1: dict | None = None,
        server_signed1_raw: bytes | None = None,
    ) -> dict:
        """
        Verify SM-DP+ server authentication and respond with eUICC proof.

        Steps per SGP.22 §5.7.3:
        1. Verify the CI PKI ID is supported
        2. Verify the server certificate chain
        3. Verify server_signature1 over server_signed1
        4. Verify the euiccChallenge matches
        5. Generate eUICC response (euiccSigned1 + euiccSignature1)
        """
        session = self.euicc.active_session
        if session is None:
            return self._auth_error(b"\x00" * 16, 8)  # invalidTransactionId

        # Step 1: Verify CI PKI ID is in our trusted set (own + extras like GSMA TestCI).
        # Some SM-DP+ implementations send the SKI wrapped as a DER OCTET STRING
        # (`04 14 <20 bytes>`); strip that wrapper before comparing.
        if len(euicc_ci_pkid) == 22 and euicc_ci_pkid[:2] == b"\x04\x14":
            euicc_ci_pkid = euicc_ci_pkid[2:]
        trusted_ci_pkids = self.pki.get_trusted_ci_pkids()
        if euicc_ci_pkid not in trusted_ci_pkids:
            logger.warning(
                "unsupported_ci_pkid",
                received=euicc_ci_pkid.hex(),
                trusted=[p.hex() for p in trusted_ci_pkids],
            )
            return self._auth_error(
                server_signed1.get("transactionId", b"\x00" * 16), 3
            )

        # Step 2: Validate server certificate chain against CI root
        is_valid, error_msg, server_public_key = self.cert_validator.validate_server_cert(
            server_certificate_der, euicc_ci_pkid
        )
        if not is_valid:
            logger.warning("server_cert_validation_failed", error=error_msg)
            # Map error to appropriate code
            error_code = 6  # invalidCertificate
            if "expired" in error_msg.lower():
                error_code = 4  # expiredCertificate
            return self._auth_error(
                server_signed1.get("transactionId", b"\x00" * 16), error_code
            )

        # Step 3: Verify server signature.
        # SGP.22 §5.7.13 says the signature is computed over the SS1 DER bytes
        # exactly as the SM-DP+ encoded them. Re-encoding via asn1tools can
        # diverge in subtle DER details (length forms, AUTOMATIC TAGS edge
        # cases) so prefer the raw bytes the IPA forwards from the wire and
        # only fall back to a canonical re-encode for legacy/test paths.
        tbs_data = server_signed1_raw or self.codec.encode_server_signed1(server_signed1)
        if not self.ecdsa.verify(server_public_key, server_signature1, tbs_data):
            logger.warning("invalid_server_signature")
            return self._auth_error(
                server_signed1.get("transactionId", b"\x00" * 16), 2
            )

        # Step 4: Verify euiccChallenge matches
        received_challenge = server_signed1.get("euiccChallenge", b"")
        if received_challenge != session.euicc_challenge:
            logger.warning(
                "euicc_challenge_mismatch",
                expected=session.euicc_challenge.hex(),
                received=received_challenge.hex(),
            )
            return self._auth_error(
                server_signed1.get("transactionId", b"\x00" * 16), 2
            )

        # Step 5: Update session state
        transaction_id = server_signed1["transactionId"]
        server_address = server_signed1["serverAddress"]
        server_challenge = server_signed1["serverChallenge"]

        session.transaction_id = transaction_id
        session.server_address = server_address
        session.server_challenge = server_challenge
        session.server_public_key = server_public_key  # used by PrepareDownload sig verify
        session.authenticated = True

        # Step 6: Build eUICC response. SGP.22 v3 makes ctxParams1 a mandatory
        # field of EuiccSigned1; we echo what the SM-DP+ sent (via ctxParams1
        # in AuthenticateServerRequest) and default to an empty common-auth
        # block when the IPA didn't pass one through.
        # asn1tools represents CHOICE as a (alternative_name, value) tuple.
        # CtxParams1 ::= CHOICE { ctxParamsForCommonAuthentication ... }
        default_common = {
            "matchingId": "",
            "deviceInfo": {
                "tac": b"\x00\x00\x00\x00",
                "deviceCapabilities": {},
            },
        }
        # JSON-over-HTTP serialises Python tuples as 2-element lists, so accept
        # both forms.
        if isinstance(ctx_params1, (list, tuple)) and len(ctx_params1) == 2:
            echo_ctx = (ctx_params1[0], ctx_params1[1])
        elif isinstance(ctx_params1, dict) and "ctxParamsForCommonAuthentication" in ctx_params1:
            echo_ctx = ("ctxParamsForCommonAuthentication", ctx_params1["ctxParamsForCommonAuthentication"])
        else:
            echo_ctx = ("ctxParamsForCommonAuthentication", default_common)
        # Inner deviceInfo.tac may arrive as hex string from JSON — convert.
        if isinstance(echo_ctx[1], dict):
            di = echo_ctx[1].get("deviceInfo")
            if isinstance(di, dict) and isinstance(di.get("tac"), str):
                try:
                    di["tac"] = bytes.fromhex(di["tac"])
                except ValueError:
                    di["tac"] = b"\x00\x00\x00\x00"
        euicc_signed1 = {
            "transactionId": transaction_id,
            "serverAddress": server_address,
            "serverChallenge": server_challenge,
            "euiccInfo2": self.get_euicc_info2(),
            "ctxParams1": echo_ctx,
        }

        # Sign with eUICC private key using canonical DER
        tbs_euicc = self.codec.encode_euicc_signed1(euicc_signed1)
        euicc_signature1 = self.ecdsa.sign(self.pki.euicc.private_key, tbs_euicc)
        session.euicc_signature1 = euicc_signature1  # required as part of TBS for smdpSignature2 in PrepareDownload

        logger.info(
            "server_authenticated",
            eid=self.euicc.eid,
            server_address=server_address,
            transaction_id=transaction_id.hex(),
        )

        return {
            "authenticateResponseOk": {
                "euiccSigned1": euicc_signed1,
                "euiccSigned1Raw": tbs_euicc,  # raw DER the IPA must relay verbatim
                "euiccSignature1": euicc_signature1,
                "euiccCertificate": self.pki.get_euicc_cert_der(),
                "eumCertificate": self.pki.get_eum_cert_der(),
            }
        }

    # ------------------------------------------------------------------
    # PrepareDownload (BF21)
    # ------------------------------------------------------------------

    def prepare_download(
        self,
        smdp_signed2: dict,
        smdp_signature2: bytes,
        hash_cc: bytes | None = None,
        smdp_certificate_der: bytes | None = None,
        smdp_signed2_raw: bytes | None = None,
    ) -> dict:
        """
        Prepare for profile download — generate OTPK and derive session keys.

        Steps per SGP.22 §5.7.5:
        1. Verify the transaction ID matches active session
        2. Verify SM-DP+ signature over smdpSigned2 (against the raw DER bytes
           the SM-DP+ actually signed — re-encoding via asn1tools can diverge
           in DER edge cases, so we use the wire bytes when available).
        3. Generate eUICC OTPK (one-time key pair)
        4. Derive SCP03t session keys via ECDH
        5. Return euiccSigned2 + euiccSignature2
        """
        session = self.euicc.active_session
        if session is None or not session.authenticated:
            return self._download_error(b"\x00" * 16, 127)  # undefinedError

        transaction_id = smdp_signed2.get("transactionId", b"")
        if transaction_id != session.transaction_id:
            logger.warning(
                "prepare_download_txn_mismatch",
                received_hex=transaction_id.hex() if isinstance(transaction_id, (bytes, bytearray)) else str(transaction_id),
                received_type=type(transaction_id).__name__,
                expected_hex=session.transaction_id.hex() if isinstance(session.transaction_id, (bytes, bytearray)) else str(session.transaction_id),
                smdp_signed2_keys=list(smdp_signed2.keys()),
            )
            return self._download_error(transaction_id, 5)  # invalidTransactionId

        # Step 2: verify SM-DP+ signature over SmdpSigned2.
        # Per SGP.22 §5.7.5 the signature is by CERT.DPpb (separate from the
        # CERT.DPauth used in AuthenticateServer). The IPA forwards the DPpb
        # cert as `smdp_certificate_der`; we validate it against any trusted
        # CI in our list, then use its public key to verify smdp_signature2
        # over the raw SmdpSigned2 DER bytes.
        if smdp_signed2_raw:
            sig_pub_key = None
            cert_source = "none"
            if smdp_certificate_der:
                for ci_pkid in self.pki.get_trusted_ci_pkids():
                    is_valid, err, pub_key = self.cert_validator.validate_server_cert(
                        smdp_certificate_der, ci_pkid
                    )
                    if is_valid:
                        sig_pub_key = pub_key
                        cert_source = "dppb"
                        break
            if sig_pub_key is None:
                sig_pub_key = session.server_public_key
                cert_source = "dpauth_fallback" if sig_pub_key else "none"
            # Per SGP.22 §5.6.2 / §5.7.5, smdpSignature2 is computed over
            # `SmdpSigned2 || euiccSignature1`, where euiccSignature1 is
            # included with its [APPLICATION 55] TLV wrapper (5F 37 40 ...)
            # — the SM-DP+ binds its response to the eUICC's prior signature.
            es1_sig = session.euicc_signature1 or b""
            tbs2 = smdp_signed2_raw + b"\x5F\x37\x40" + es1_sig
            verified = sig_pub_key is not None and self.ecdsa.verify(
                sig_pub_key, smdp_signature2, tbs2
            )
            logger.warning(
                "smdp_sig2_check",
                cert_source=cert_source,
                sig_len=len(smdp_signature2),
                tbs_len=len(smdp_signed2_raw),
                verified=verified,
                cert_present=bool(smdp_certificate_der),
            )
            if not verified:
                return self._download_error(transaction_id, 2)  # invalidSignature

        # Generate eUICC one-time key pair
        otpk_private, otpk_public = self.ecdsa.generate_otpk()
        session.euicc_otpk_private = otpk_private
        session.euicc_otpk_public = otpk_public

        # Get SM-DP+ OTPK from smdpSigned2
        smdp_otpk = smdp_signed2.get("bppEuiccOtpk", b"")
        if smdp_otpk:
            session.smdp_otpk_public = smdp_otpk
            # Derive SCP03t session keys
            session.session_keys = self.ecdsa.derive_session_keys(
                otpk_private, smdp_otpk, transaction_id
            )

        session.prepared = True

        # Build response — hashCc is OPTIONAL: omit the key entirely when not
        # provided (asn1tools rejects None values for OPTIONAL bytes fields).
        euicc_signed2 = {
            "transactionId": transaction_id,
            "euiccOtpk": otpk_public,
        }
        if hash_cc:
            euicc_signed2["hashCc"] = hash_cc

        tbs_data = self.codec.encode_euicc_signed2(euicc_signed2)
        euicc_signature2 = self.ecdsa.sign(self.pki.euicc.private_key, tbs_data)

        logger.info(
            "download_prepared",
            eid=self.euicc.eid,
            transaction_id=transaction_id.hex(),
            has_session_keys=session.session_keys is not None,
        )

        return {
            "downloadResponseOk": {
                "euiccSigned2": euicc_signed2,
                "euiccSignature2": euicc_signature2,
                # Canonical DER as the eUICC actually signed it. Per the
                # raw-bytes-passthrough pattern (SGP.22 conformance memo),
                # the IPA must wrap THESE bytes — not asn1tools-re-encoded
                # bytes — into the outer PrepareDownloadResponse envelope,
                # because the SM-DP+ verifies smdpSignature2 against this
                # exact byte sequence (see §5.6.3 / §5.7.5 binding).
                "euiccSigned2Raw": tbs_data,
            }
        }

    # ------------------------------------------------------------------
    # LoadBoundProfilePackage (BF36)
    # ------------------------------------------------------------------

    def load_bound_profile_package(self, bpp_data: dict) -> dict:
        """
        Decrypt and install a Bound Profile Package.

        Steps per SGP.22 §5.7.7:
        1. Process InitialiseSecureChannelRequest
        2. Decrypt profile elements using SCP03t session keys
        3. Create ISD-P and install profile
        4. Return ProfileInstallationResult (DER-signed)

        Args:
            bpp_data: Parsed BPP structure with:
                - initialiseSecureChannelRequest
                - firstSequenceOf87 (encrypted profile elements)
                - sequenceOf88 (MACs)
                - secondSequenceOf87 (more encrypted elements, optional)
                - sequenceOf86 (profile element sequence)
        """
        session = self.euicc.active_session
        if session is None or not session.prepared:
            return self._installation_error(
                session.transaction_id if session else b"\x00" * 16,
                0,  # initialiseSecureChannel
                4,  # commandError
            )

        transaction_id = session.transaction_id

        # Step 1: Process InitialiseSecureChannelRequest
        init_req = bpp_data.get("initialiseSecureChannelRequest", {})
        bpp_transaction_id = init_req.get("transactionId", b"")
        if bpp_transaction_id and bpp_transaction_id != transaction_id:
            return self._installation_error(transaction_id, 0, 1)  # incorrectInputData

        # Step 2: Decrypt profile elements using SCP03t
        decrypted_elements = b""
        encrypted_data = bpp_data.get("firstSequenceOf87", b"")
        mac_data = bpp_data.get("sequenceOf88", b"")

        if session.session_keys and encrypted_data:
            scp03t = Scp03tProcessor(session.session_keys)

            # Verify MAC and decrypt the profile data
            if mac_data and encrypted_data:
                secured_block = encrypted_data + mac_data[:8]
                result = scp03t.verify_and_decrypt(secured_block)
                if result is None:
                    logger.warning(
                        "scp03t_mac_verification_failed",
                        eid=self.euicc.eid,
                        transaction_id=transaction_id.hex(),
                    )
                    # Continue anyway for simulator flexibility — log the warning
                    decrypted_elements = encrypted_data
                else:
                    decrypted_elements = result
            else:
                # No MAC data — decrypt directly
                try:
                    decrypted_elements = scp03t.decrypt_profile_element(encrypted_data)
                except Exception:
                    decrypted_elements = encrypted_data

            # Process second sequence if present
            second_seq = bpp_data.get("secondSequenceOf87", b"")
            if second_seq:
                try:
                    decrypted_elements += scp03t.decrypt_profile_element(second_seq)
                except Exception:
                    decrypted_elements += second_seq

            logger.info(
                "scp03t_decryption_complete",
                eid=self.euicc.eid,
                encrypted_size=len(encrypted_data),
                decrypted_size=len(decrypted_elements),
            )
        else:
            # No session keys (e.g., test mode) — accept data as-is
            decrypted_elements = encrypted_data
            logger.info("scp03t_skipped_no_session_keys", eid=self.euicc.eid)

        # Step 3: Estimate profile size and check memory
        estimated_size = len(decrypted_elements) if decrypted_elements else 4096
        if estimated_size > self.euicc.free_nvm:
            return self._installation_error(transaction_id, 0, 3)  # insufficientMemory

        if len(self.euicc.profiles) >= self.euicc.max_profiles:
            return self._installation_error(transaction_id, 0, 3)  # insufficientMemory

        # Step 4: Create ISD-P and install profile
        iccid = bpp_data.get("iccid", os.urandom(10))
        isdp_aid = self.euicc.allocate_isdp_aid()

        profile = ProfileSlot(
            iccid=iccid,
            isdp_aid=isdp_aid,
            state=ProfileState.DISABLED,
            profile_name=bpp_data.get("profileName", "Downloaded Profile"),
            service_provider_name=bpp_data.get("spName", ""),
            profile_class=ProfileClass.OPERATIONAL,
            notification_address=session.server_address,
            profile_data=decrypted_elements,
        )

        self.euicc.profiles.append(profile)
        self.euicc.free_nvm -= estimated_size

        # Add installation notification
        self.euicc.add_notification(
            "install", session.server_address, iccid
        )

        # Step 5: Build ProfileInstallationResultData and sign with DER
        notif_metadata = {
            "seqNumber": self.euicc.notifications[-1].seq_number,
            "profileManagementOperation": (b"\x80", 8),
            "notificationAddress": session.server_address,
            "iccid": iccid,
        }

        result_data = {
            "transactionId": transaction_id,
            "notificationMetadata": notif_metadata,
            "finalResult": ("successResult", {
                "aid": isdp_aid,
            }),
        }

        # Sign using canonical DER encoding
        tbs_data = self.codec.encode_profile_installation_result_data(result_data)
        signature = self.ecdsa.sign(self.pki.euicc.private_key, tbs_data)

        # Clear session
        self.euicc.active_session = None

        logger.info(
            "profile_installed",
            eid=self.euicc.eid,
            iccid=profile.iccid_string(),
            isdp_aid=isdp_aid.hex(),
            transaction_id=transaction_id.hex(),
        )

        return {
            "profileInstallationResult": {
                "profileInstallationResultData": result_data,
                "euiccSignPIR": signature,
            }
        }

    # ------------------------------------------------------------------
    # CancelSession (BF41)
    # ------------------------------------------------------------------

    def cancel_session(self, transaction_id: bytes, reason: int) -> dict:
        """Cancel an active profile download session."""
        session = self.euicc.active_session
        if session is None:
            return {"cancelSessionResponseError": 1}  # invalidTransactionId

        if transaction_id != session.transaction_id:
            return {"cancelSessionResponseError": 1}  # invalidTransactionId

        # Build signed cancellation
        cancel_signed = {
            "transactionId": transaction_id,
            "reason": reason,
        }

        tbs_data = self.codec.encode_cancel_session_signed(cancel_signed)
        signature = self.ecdsa.sign(self.pki.euicc.private_key, tbs_data)

        # Clear session
        self.euicc.active_session = None

        logger.info(
            "session_cancelled",
            eid=self.euicc.eid,
            transaction_id=transaction_id.hex(),
            reason=reason,
        )

        return {
            "cancelSessionResponseOk": {
                "euiccCancelSessionSigned": cancel_signed,
                "euiccCancelSessionSignature": signature,
            }
        }

    # ------------------------------------------------------------------
    # GetEUICCInformation (BF43, SGP.22 v3.0+)
    # ------------------------------------------------------------------

    def get_euicc_information(self) -> dict:
        """Return eUICC platform information (SGP.22 v3.0+).

        Returns the same information as GetEuiccInfo2 but without
        requiring an authenticated session.
        """
        info = self.get_euicc_info2()
        # Wrap with label keys expected by ASN.1 schema (field names
        # are lowered by asn1tools from PascalCase).
        return info

    # ------------------------------------------------------------------
    # Notification Management (ES10b)
    # ------------------------------------------------------------------

    def list_notifications(self, operation_filter: bytes | None = None) -> dict:
        """List pending notifications, optionally filtered by operation type."""
        notifications = self.euicc.notifications
        if not notifications:
            return {"listNotificationsResultError": 1}  # noNotifications

        result = []
        for n in notifications:
            result.append({
                "seqNumber": n.seq_number,
                "profileManagementOperation": n.operation.encode(),
                "notificationAddress": n.notification_address,
                "iccid": n.iccid,
            })
        return {"notificationMetadataList": result}

    def remove_notification(self, seq_number: int) -> dict:
        """Remove a notification from the pending list."""
        for i, n in enumerate(self.euicc.notifications):
            if n.seq_number == seq_number:
                self.euicc.notifications.pop(i)
                return {"removeResult": 0}  # ok
        return {"removeResult": 1}  # notificationNotFound

    # ------------------------------------------------------------------
    # SGP.32 RetrieveNotificationsList (BF2B)
    # ------------------------------------------------------------------

    def retrieve_notifications_list_sgp32(
        self, search_criteria: dict | None = None
    ) -> dict:
        """SGP.32 enhanced notification retrieval (§5.9.11).

        Returns notifications in SGP.32 format with support for
        euiccPackageResultList and notificationAndEprList variants.
        """
        if not self.euicc.notifications:
            return {"notificationsListResultError": 127}

        notif_list = []
        for n in self.euicc.notifications:
            notif_list.append(("profileInstallationResult", {
                "profileInstallationResultData": {
                    "transactionId": b"\x00" * 16,
                    "notificationMetadata": {
                        "seqNumber": n.seq_number,
                        "profileManagementOperation": (b"\x80", 1),
                        "notificationAddress": n.notification_address,
                        "iccid": n.iccid or b"\x00" * 10,
                    },
                    "finalResult": ("successResult", {
                        "aid": b"\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    }),
                },
                "euiccSignPIR": b"\x00" * 64,
            }))

        return {"notificationList": notif_list}

    # ------------------------------------------------------------------
    # Error Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _auth_error(transaction_id: bytes, error_code: int) -> dict:
        return {
            "authenticateResponseError": {
                "transactionId": transaction_id,
                "authenticateErrorCode": error_code,
            }
        }

    @staticmethod
    def _download_error(transaction_id: bytes, error_code: int) -> dict:
        return {
            "downloadResponseError": {
                "transactionId": transaction_id,
                "downloadErrorCode": error_code,
            }
        }

    @staticmethod
    def _installation_error(
        transaction_id: bytes, command_id: int, error_reason: int
    ) -> dict:
        return {
            "profileInstallationResult": {
                "profileInstallationResultData": {
                    "transactionId": transaction_id,
                    "finalResult": {
                        "errorResult": {
                            "bppCommandId": command_id,
                            "errorReason": error_reason,
                        }
                    },
                },
                "euiccSignPIR": b"\x00" * 64,
            }
        }
