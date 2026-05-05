"""
ES10c Interface Handler — Local Profile Management.

Implements the eUICC side of ES10c per SGP.22 §5.6:
- GetProfilesInfo — List installed profiles
- EnableProfile — Activate a profile
- DisableProfile — Deactivate a profile
- DeleteProfile — Remove a profile
- GetEID — Return the eUICC identifier
- eUICCMemoryReset — Factory reset
- SetNickname — Set profile nickname
"""

import structlog

from ..models.euicc import EuiccState, ProfileState, ProfileClass
from ..crypto.certificates import CertificateInfrastructure
from ..crypto.ecdsa_engine import EcdsaEngine

logger = structlog.get_logger()


class Es10cHandler:
    """Handles ES10c commands for local profile management."""

    def __init__(self, euicc: EuiccState, pki: CertificateInfrastructure):
        self.euicc = euicc
        self.pki = pki
        self.ecdsa = EcdsaEngine()

    # ------------------------------------------------------------------
    # GetProfilesInfo (BF2D)
    # ------------------------------------------------------------------

    def get_profiles_info(
        self,
        iccid: bytes | None = None,
        aid: bytes | None = None,
        profile_class: int | None = None,
    ) -> dict:
        """
        List profiles installed on the eUICC.

        Can filter by ICCID, ISD-P AID, or profile class.
        Returns all profiles if no filter specified.
        """
        profiles = self.euicc.profiles

        if iccid:
            profiles = [p for p in profiles if p.iccid == iccid]
        elif aid:
            profiles = [p for p in profiles if p.isdp_aid == aid]
        elif profile_class is not None:
            class_map = {0: "test", 1: "provisioning", 2: "operational"}
            class_name = class_map.get(profile_class)
            if class_name:
                profiles = [p for p in profiles if p.profile_class.value == class_name]

        profile_list = []
        for p in profiles:
            info = {
                "iccid": p.iccid.hex() if isinstance(p.iccid, (bytes, bytearray)) else p.iccid,
                "isdpAid": p.isdp_aid.hex() if isinstance(p.isdp_aid, (bytes, bytearray)) else p.isdp_aid,
                "profileState": 1 if p.state == ProfileState.ENABLED else 0,
                "profileName": p.profile_name,
                "serviceProviderName": p.service_provider_name,
                "profileClass": {"test": 0, "provisioning": 1, "operational": 2}[
                    p.profile_class.value
                ],
            }
            if p.profile_nickname:
                info["profileNickname"] = p.profile_nickname
            profile_list.append(info)

        return {"profileInfoListOk": profile_list}

    # ------------------------------------------------------------------
    # EnableProfile (BF31)
    # ------------------------------------------------------------------

    def enable_profile(
        self, iccid: bytes | None = None, aid: bytes | None = None, refresh: bool = True
    ) -> dict:
        """
        Enable (activate) a profile.

        Only one profile can be enabled at a time.
        The currently enabled profile is automatically disabled.
        """
        profile = None
        if iccid:
            profile = self.euicc.find_profile_by_iccid(iccid)
        elif aid:
            profile = self.euicc.find_profile_by_aid(aid)

        if profile is None:
            return {"enableResult": 1}  # iccidOrAidNotFound

        if profile.state == ProfileState.ENABLED:
            return {"enableResult": 4}  # wrongProfileReenabling

        # Disable currently enabled profile
        current = self.euicc.get_enabled_profile()
        if current:
            current.state = ProfileState.DISABLED
            self.euicc.add_notification(
                "disable", current.notification_address, current.iccid
            )
            logger.info(
                "profile_disabled",
                eid=self.euicc.eid,
                iccid=current.iccid_string(),
            )

        # Enable the requested profile
        profile.state = ProfileState.ENABLED
        self.euicc.add_notification(
            "enable", profile.notification_address, profile.iccid
        )

        logger.info(
            "profile_enabled",
            eid=self.euicc.eid,
            iccid=profile.iccid_string(),
        )

        return {"enableResult": 0}  # ok

    # ------------------------------------------------------------------
    # DisableProfile (BF32)
    # ------------------------------------------------------------------

    def disable_profile(
        self, iccid: bytes | None = None, aid: bytes | None = None, refresh: bool = True
    ) -> dict:
        """Disable (deactivate) a profile."""
        profile = None
        if iccid:
            profile = self.euicc.find_profile_by_iccid(iccid)
        elif aid:
            profile = self.euicc.find_profile_by_aid(aid)

        if profile is None:
            return {"disableResult": 1}  # iccidOrAidNotFound

        if profile.state != ProfileState.ENABLED:
            return {"disableResult": 2}  # profileNotInEnabledState

        profile.state = ProfileState.DISABLED
        self.euicc.add_notification(
            "disable", profile.notification_address, profile.iccid
        )

        logger.info(
            "profile_disabled",
            eid=self.euicc.eid,
            iccid=profile.iccid_string(),
        )

        return {"disableResult": 0}  # ok

    # ------------------------------------------------------------------
    # DeleteProfile (BF33)
    # ------------------------------------------------------------------

    def delete_profile(
        self, iccid: bytes | None = None, aid: bytes | None = None
    ) -> dict:
        """Permanently delete a profile from the eUICC."""
        profile = None
        if iccid:
            profile = self.euicc.find_profile_by_iccid(iccid)
        elif aid:
            profile = self.euicc.find_profile_by_aid(aid)

        if profile is None:
            return {"deleteResult": 1}  # iccidOrAidNotFound

        if profile.state == ProfileState.ENABLED:
            return {"deleteResult": 2}  # profileNotInDisabledState

        # Remove and reclaim memory
        self.euicc.profiles.remove(profile)
        self.euicc.free_nvm += len(profile.profile_data) if profile.profile_data else 4096

        self.euicc.add_notification(
            "delete", profile.notification_address, profile.iccid
        )

        logger.info(
            "profile_deleted",
            eid=self.euicc.eid,
            iccid=profile.iccid_string(),
        )

        return {"deleteResult": 0}  # ok

    # ------------------------------------------------------------------
    # GetEID (BF3E)
    # ------------------------------------------------------------------

    def get_eid(self) -> dict:
        """Return the 32-digit EID."""
        # EID is 16 bytes (32 hex digits)
        eid_bytes = bytes.fromhex(self.euicc.eid)
        return {"eid": eid_bytes}

    # ------------------------------------------------------------------
    # eUICCMemoryReset (BF34)
    # ------------------------------------------------------------------

    def euicc_memory_reset(self, reset_options: bytes | None = None) -> dict:
        """
        Reset eUICC memory.

        Options (bit flags):
        - bit 0: delete operational profiles
        - bit 1: delete field-loaded test profiles
        - bit 2: reset default SM-DP+ address
        """
        delete_operational = True
        delete_test = True
        reset_address = True

        if reset_options and len(reset_options) >= 1:
            flags = reset_options[0]
            delete_operational = bool(flags & 0x80)
            delete_test = bool(flags & 0x40)
            reset_address = bool(flags & 0x20)

        deleted_count = 0

        profiles_to_keep = []
        for p in self.euicc.profiles:
            keep = False
            if p.state == ProfileState.ENABLED:
                keep = True  # Cannot delete enabled profile via reset
            elif p.profile_class == ProfileClass.PROVISIONING:
                keep = True  # Never delete provisioning profiles
            elif p.profile_class == ProfileClass.TEST and not delete_test:
                keep = True
            elif p.profile_class == ProfileClass.OPERATIONAL and not delete_operational:
                keep = True

            if keep:
                profiles_to_keep.append(p)
            else:
                deleted_count += 1

        self.euicc.profiles = profiles_to_keep

        if reset_address:
            self.euicc.default_smdp_address = ""

        if deleted_count == 0 and not reset_address:
            return {"resetResult": 1}  # nothingToDelete

        # Recalculate free memory
        used = sum(
            len(p.profile_data) if p.profile_data else 4096
            for p in self.euicc.profiles
        )
        self.euicc.free_nvm = self.euicc.total_nvm - used

        logger.info(
            "euicc_memory_reset",
            eid=self.euicc.eid,
            deleted_profiles=deleted_count,
            reset_address=reset_address,
        )

        return {"resetResult": 0}  # ok

    # ------------------------------------------------------------------
    # SGP.32 eUICCMemoryReset (enhanced, BF34)
    # ------------------------------------------------------------------

    def euicc_memory_reset_sgp32(self, reset_options: tuple) -> dict:
        """SGP.32 enhanced memory reset with eIM and auto-enable options.

        Args:
            reset_options: (bytes, int) BIT STRING tuple
        """
        # Parse bit flags
        opts_bytes, _ = reset_options
        flags = opts_bytes[0] if opts_bytes else 0
        delete_operational = bool(flags & 0x80)
        delete_test = bool(flags & 0x40)
        reset_address = bool(flags & 0x20)
        reset_eim = bool(flags & 0x10)
        reset_auto_enable = bool(flags & 0x08)

        result = self.euicc_memory_reset(
            (bytes([flags & 0xE0]), 3) if opts_bytes else None
        )

        reset_result = result.get("resetResult", 0)

        # Handle eIM reset
        eim_result = None
        if reset_eim:
            self.euicc.eim_associations.clear()
            eim_result = 0  # ok
        elif reset_result == 1:
            eim_result = 1  # nothingToDelete

        # Handle auto-enable reset
        aec_result = None
        if reset_auto_enable:
            aec_result = 0  # ok

        resp = {"resetResult": reset_result}
        if eim_result is not None:
            resp["resetEimResult"] = eim_result
        if aec_result is not None:
            resp["resetAutoEnableConfigResult"] = aec_result
        return resp

    # ------------------------------------------------------------------
    # ProfileRollback (SGP.32 BF58)
    # ------------------------------------------------------------------

    def profile_rollback(self, refresh_flag: bool) -> dict:
        """Roll back the most recent profile operation.

        SGP.32 §5.9.16. In a full implementation this would revert
        the last PSMO operation. For the simulator, we return ok
        if there's an active session to cancel.
        """
        if self.euicc.active_session:
            self.euicc.active_session = None
            return {"cmdResult": 0}  # ok
        return {"cmdResult": 7}  # commandError — nothing to rollback

    # ------------------------------------------------------------------
    # ConfigureAutoProfileEnabling (SGP.32 BF59)
    # ------------------------------------------------------------------

    def configure_auto_enable(
        self,
        auto_enable_flag: bool = False,
        smdp_oid: str | None = None,
        smdp_address: str | None = None,
    ) -> dict:
        """Configure automatic profile enabling.

        SGP.32 §5.9.17. In the simulator this is a no-op that
        always returns ok.
        """
        return {"configAutoEnableResult": 0}  # ok

    # ------------------------------------------------------------------
    # EnableUsingDD (SGP.32 BF5A)
    # ------------------------------------------------------------------

    def enable_using_dd(self) -> dict:
        """Enable profile using Device Discovery.

        SGP.32 §5.9.15. In the simulator this returns
        autoEnableNotAvailable since we don't simulate DD.
        """
        return {"enableUsingDDResult": 1}  # autoEnableNotAvailable

    # ------------------------------------------------------------------
    # SetNickname (BF29)
    # ------------------------------------------------------------------

    def set_nickname(self, iccid: bytes, nickname: str) -> dict:
        """Set a user-friendly nickname for a profile."""
        profile = self.euicc.find_profile_by_iccid(iccid)
        if profile is None:
            return {"setNicknameResult": 1}  # iccidNotFound

        profile.profile_nickname = nickname

        logger.info(
            "nickname_set",
            eid=self.euicc.eid,
            iccid=profile.iccid_string(),
            nickname=nickname,
        )

        return {"setNicknameResult": 0}  # ok
