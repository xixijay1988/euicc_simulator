"""
eUICC Manager — Central orchestrator for the eUICC simulator.

Manages multiple virtual eUICC instances, each with its own:
- EID, certificates, and crypto keys
- Profile slots
- eIM associations
- Session state

This is the service layer that the API endpoints call into.
"""

import structlog
from pathlib import Path
from ..models.euicc import EuiccState, ProfileSlot, ProfileState, ProfileClass, EimAssociation
from ..crypto.certificates import CertificateInfrastructure
from ..es10.es10a import Es10aHandler
from ..es10.es10b import Es10bHandler
from ..es10.es10c import Es10cHandler
from ..es10.es10b_iot import Es10bIotHandler
from ..services.apdu_handler import ApduProcessor

logger = structlog.get_logger()


class EuiccInstance:
    """A single virtual eUICC with all its handlers."""

    def __init__(self, euicc: EuiccState, pki: CertificateInfrastructure):
        self.euicc = euicc
        self.pki = pki
        self.es10a = Es10aHandler(euicc)
        self.es10b = Es10bHandler(euicc, pki)
        self.es10c = Es10cHandler(euicc, pki)
        self.es10b_iot = Es10bIotHandler(euicc, pki)
        self.apdu = ApduProcessor()


class EuiccManager:
    """
    Manages multiple virtual eUICC instances.

    Each eUICC has a unique EID and its own PKI chain.
    The manager handles creation, lookup, and persistence.
    """

    def __init__(self, base_certs_dir: str | Path):
        self.base_certs_dir = Path(base_certs_dir)
        self.instances: dict[str, EuiccInstance] = {}

    def create_euicc(
        self,
        eid: str,
        default_smdp_address: str = "",
        eim_id: str | None = None,
        eim_fqdn: str | None = None,
        preloaded_profiles: list[dict] | None = None,
    ) -> EuiccInstance:
        """
        Create a new virtual eUICC instance.

        Args:
            eid: 32-digit EID string
            default_smdp_address: Pre-configured SM-DP+ address
            eim_id: Initial eIM ID to associate
            eim_fqdn: eIM server FQDN
            preloaded_profiles: List of profile dicts to pre-install
        """
        if eid in self.instances:
            logger.info("euicc_already_exists", eid=eid)
            return self.instances[eid]

        # Create state
        euicc = EuiccState(
            eid=eid,
            default_smdp_address=default_smdp_address,
        )

        # Add initial eIM association if provided
        if eim_id:
            euicc.eim_associations.append(EimAssociation(
                eim_id=eim_id,
                eim_fqdn=eim_fqdn or "",
                counter_value=0,
                association_token=0,
                supported_protocol=0,
            ))

        # Pre-install profiles if provided
        if preloaded_profiles:
            for p in preloaded_profiles:
                iccid_hex = p.get("iccid", "89000000000000000000")
                # BCD encode ICCID (nibble swap)
                iccid_bcd = self._string_to_bcd_iccid(iccid_hex)
                profile = ProfileSlot(
                    iccid=iccid_bcd,
                    isdp_aid=euicc.allocate_isdp_aid(),
                    state=ProfileState(p.get("state", "disabled")),
                    profile_name=p.get("name", "Test Profile"),
                    service_provider_name=p.get("spName", "ConnectX IoT"),
                    profile_class=ProfileClass(p.get("class", "operational")),
                    notification_address=default_smdp_address,
                )
                euicc.profiles.append(profile)

        # Initialize PKI
        certs_dir = self.base_certs_dir / eid
        pki = CertificateInfrastructure(certs_dir)
        pki.initialize(eid)

        instance = EuiccInstance(euicc, pki)
        self.instances[eid] = instance

        logger.info(
            "euicc_created",
            eid=eid,
            profiles=len(euicc.profiles),
            eim_associations=len(euicc.eim_associations),
        )

        return instance

    def get_euicc(self, eid: str) -> EuiccInstance | None:
        """Get an existing eUICC instance by EID."""
        return self.instances.get(eid)

    def list_euiccs(self) -> list[dict]:
        """List all virtual eUICCs with summary info."""
        result = []
        for eid, inst in self.instances.items():
            e = inst.euicc
            result.append({
                "eid": eid,
                "profiles": len(e.profiles),
                "enabledProfile": (
                    e.get_enabled_profile().iccid_string()
                    if e.get_enabled_profile()
                    else None
                ),
                "eimAssociations": len(e.eim_associations),
                "freeNvm": e.free_nvm,
                "firmwareVersion": ".".join(str(v) for v in e.firmware_version),
                "hasActiveSession": e.active_session is not None,
            })
        return result

    def create_euicc_from_state(self, euicc: EuiccState) -> EuiccInstance:
        """
        Create an eUICC instance from a pre-populated state object.
        Used when loading persisted state from database.
        """
        if euicc.eid in self.instances:
            return self.instances[euicc.eid]

        certs_dir = self.base_certs_dir / euicc.eid
        pki = CertificateInfrastructure(certs_dir)
        pki.initialize(euicc.eid)

        instance = EuiccInstance(euicc, pki)
        self.instances[euicc.eid] = instance

        logger.info(
            "euicc_loaded",
            eid=euicc.eid,
            profiles=len(euicc.profiles),
            eim_associations=len(euicc.eim_associations),
        )
        return instance

    def delete_euicc(self, eid: str) -> bool:
        """Remove a virtual eUICC instance."""
        if eid in self.instances:
            del self.instances[eid]
            logger.info("euicc_deleted", eid=eid)
            return True
        return False

    def create_test_euiccs(self, smdp_address: str, eim_fqdn: str) -> None:
        """Create a set of test eUICCs with sample data."""

        # eUICC 1: Two profiles, one enabled
        self.create_euicc(
            eid="89049032123451234512345678901235",
            default_smdp_address=smdp_address,
            eim_id="EIM-89049032123451234512345678901235",
            eim_fqdn=eim_fqdn,
            preloaded_profiles=[
                {
                    "iccid": "8901234567890123456F",
                    "name": "ConnectX IoT Profile 1",
                    "spName": "ConnectX IoT",
                    "state": "enabled",
                    "class": "operational",
                },
                {
                    "iccid": "8901234567890123457F",
                    "name": "ConnectX IoT Profile 2",
                    "spName": "ConnectX IoT",
                    "state": "disabled",
                    "class": "operational",
                },
            ],
        )

        # eUICC 2: Empty, ready for profile download
        self.create_euicc(
            eid="89049032123451234512345678901236",
            default_smdp_address=smdp_address,
            eim_id="EIM-89049032123451234512345678901236",
            eim_fqdn=eim_fqdn,
        )

        # eUICC 3: No eIM, no profiles (bootstrap scenario)
        self.create_euicc(
            eid="89049032123451234512345678901237",
            default_smdp_address=smdp_address,
        )

        logger.info("test_euiccs_created", count=3)

    @staticmethod
    def _string_to_bcd_iccid(iccid_str: str) -> bytes:
        """
        Convert ICCID string to BCD-encoded bytes (with nibble swap).

        Example: "8901234567890123456F" -> bytes with nibble-swapped BCD
        """
        # Pad to 20 chars if needed
        iccid_str = iccid_str.ljust(20, "F")
        # Nibble swap: swap each pair of hex digits
        result = bytearray()
        for i in range(0, len(iccid_str), 2):
            high = iccid_str[i]
            low = iccid_str[i + 1] if i + 1 < len(iccid_str) else "F"
            result.append((int(low, 16) << 4) | int(high, 16))
        return bytes(result)
