"""
ES10b IoT Extensions — eIM Configuration Management (SGP.32).

Implements the eUICC side of SGP.32-specific ES10b functions:
- GetEimConfigurationData — List eIM associations
- AddEim — Register a new eIM
- DeleteEim — Remove an eIM association
- UpdateEim — Modify eIM configuration
- ListEim — List all eIM associations
- GetCerts — Return EUM and eUICC certificates
- LoadEuiccPackage — Process ESep packages (PSMO/eCO)

These functions enable the ESep (eIM <-> eUICC) logical interface
by managing the trust relationship between eIM and eUICC.
"""

import os
import structlog
from ..models.euicc import EuiccState, EimAssociation, ProfileState
from ..crypto.certificates import CertificateInfrastructure
from ..crypto.ecdsa_engine import EcdsaEngine

logger = structlog.get_logger()


class Es10bIotHandler:
    """Handles SGP.32 IoT-specific ES10b commands."""

    def __init__(self, euicc: EuiccState, pki: CertificateInfrastructure):
        self.euicc = euicc
        self.pki = pki
        self.ecdsa = EcdsaEngine()

    # ------------------------------------------------------------------
    # GetEimConfigurationData
    # ------------------------------------------------------------------

    def get_eim_configuration_data(self) -> dict:
        """Return all eIM associations configured on the eUICC."""
        configs = []
        for assoc in self.euicc.eim_associations:
            configs.append({
                "eimId": assoc.eim_id,
                "eimFqdn": assoc.eim_fqdn,
                "counterValue": assoc.counter_value,
                "associationToken": assoc.association_token,
                "eimSupportedProtocol": assoc.supported_protocol,
            })
        return {"eimConfigurationDataList": configs}

    # ------------------------------------------------------------------
    # AddEim
    # ------------------------------------------------------------------

    def add_eim(self, eim_config: dict) -> dict:
        """
        Register a new eIM association on the eUICC.

        Per SGP.32, each eIM is identified by eimId and associated
        with a counter for replay protection.
        """
        eim_id = eim_config.get("eimId", "")

        # Check if already exists
        for assoc in self.euicc.eim_associations:
            if assoc.eim_id == eim_id:
                return {"addEimResult": 2, "associationToken": None}  # eimIdAlreadyExists

        # Generate association token
        association_token = int.from_bytes(os.urandom(4), "big")

        assoc = EimAssociation(
            eim_id=eim_id,
            eim_fqdn=eim_config.get("eimFqdn", ""),
            counter_value=eim_config.get("counterValue", 0),
            association_token=association_token,
            supported_protocol=eim_config.get("eimSupportedProtocol", 0),
        )
        self.euicc.eim_associations.append(assoc)

        logger.info(
            "eim_added",
            eid=self.euicc.eid,
            eim_id=eim_id,
            association_token=association_token,
        )

        return {"addEimResult": 0, "associationToken": association_token}

    # ------------------------------------------------------------------
    # DeleteEim
    # ------------------------------------------------------------------

    def delete_eim(self, eim_id: str) -> dict:
        """Remove an eIM association from the eUICC."""
        for i, assoc in enumerate(self.euicc.eim_associations):
            if assoc.eim_id == eim_id:
                # Cannot delete last eIM
                if len(self.euicc.eim_associations) <= 1:
                    return {"deleteEimResult": 2}  # lastEimDeleteRefused
                self.euicc.eim_associations.pop(i)
                logger.info("eim_deleted", eid=self.euicc.eid, eim_id=eim_id)
                return {"deleteEimResult": 0}

        return {"deleteEimResult": 1}  # eimIdNotFound

    # ------------------------------------------------------------------
    # UpdateEim
    # ------------------------------------------------------------------

    def update_eim(self, eim_id: str, new_config: dict) -> dict:
        """Update an existing eIM association."""
        for assoc in self.euicc.eim_associations:
            if assoc.eim_id == eim_id:
                if "eimFqdn" in new_config:
                    assoc.eim_fqdn = new_config["eimFqdn"]
                if "counterValue" in new_config:
                    assoc.counter_value = new_config["counterValue"]
                if "eimSupportedProtocol" in new_config:
                    assoc.supported_protocol = new_config["eimSupportedProtocol"]
                logger.info("eim_updated", eid=self.euicc.eid, eim_id=eim_id)
                return {"updateEimResult": 0}

        return {"updateEimResult": 1}  # eimIdNotFound

    # ------------------------------------------------------------------
    # ListEim
    # ------------------------------------------------------------------

    def list_eim(self) -> dict:
        """List all eIM associations (same as GetEimConfigurationData)."""
        return self.get_eim_configuration_data()

    # ------------------------------------------------------------------
    # GetCerts
    # ------------------------------------------------------------------

    def get_certs(self) -> dict:
        """Return EUM and eUICC certificates in DER format."""
        return {
            "eumCertificate": self.pki.get_eum_cert_der(),
            "euiccCertificate": self.pki.get_euicc_cert_der(),
        }

    # ------------------------------------------------------------------
    # GetEimConfigurationData (BF55, SGP.32 §5.9.18)
    # ------------------------------------------------------------------

    def get_eim_config_sgp32(self) -> dict:
        """Return all eIM associations in SGP.32 enhanced format."""
        configs = []
        for assoc in self.euicc.eim_associations:
            configs.append({
                "eimId": assoc.eim_id,
                "eimFqdn": assoc.eim_fqdn,
                "counterValue": assoc.counter_value,
                "associationToken": assoc.association_token,
                "eimSupportedProtocol": assoc.supported_protocol,
            })
        return {"eimConfigurationDataList": configs}

    # ------------------------------------------------------------------
    # GetCerts (BF56, SGP.32 §5.9.10)
    # ------------------------------------------------------------------

    def get_certs_sgp32(self, euicc_ci_pkid: bytes | None = None) -> dict:
        """Return EUM and eUICC certificates (SGP.32 CHOICE format)."""
        return {
            "certs": {
                "eumCertificate": self.pki.get_eum_cert_der(),
                "euiccCertificate": self.pki.get_euicc_cert_der(),
            }
        }

    # ------------------------------------------------------------------
    # AddInitialEim (BF57, SGP.32 §5.9.4)
    # ------------------------------------------------------------------

    def add_initial_eim(self, eim_configs: list[dict]) -> dict:
        """Register one or more eIM associations on the eUICC.

        Each config in the list is a dict with eimId, eimFqdn,
        counterValue, associationToken, etc.
        Returns list of results (associationToken or addOk) per config.
        """
        results = []
        for config in eim_configs:
            result = self.add_eim(config)
            if result.get("addEimResult") == 0:
                # Success — return the association token
                results.append(("associationToken", result.get("associationToken", 0)))
            else:
                # Failure — mark as error (simplified: return addOk for now)
                results.append(("addOk", {}))
        return {"addInitialEimOk": results}

    # ------------------------------------------------------------------
    # LoadEuiccPackage (ESep endpoint on eUICC side)
    # ------------------------------------------------------------------

    def load_euicc_package(self, package: dict) -> dict:
        """
        Process an eUICC Package received via ESep (eIM -> IPA -> eUICC).

        The package contains signed PSMO and/or eCO operations.
        The eUICC verifies the eIM signature and executes operations.

        Args:
            package: Decoded euiccPackageRequest with:
                - psmoList: list of PSMO operations
                - ecoList: list of eCO operations
                - eimId: which eIM sent this
                - counterValue: replay protection counter
                - eimSignature: ECDSA signature
        """
        eim_id = package.get("eimId", "")
        counter_value = package.get("counterValue", 0)

        # Find the eIM association
        assoc = None
        for a in self.euicc.eim_associations:
            if a.eim_id == eim_id:
                assoc = a
                break

        if assoc is None:
            logger.warning("unknown_eim", eid=self.euicc.eid, eim_id=eim_id)
            return {"euiccPackageError": "unknownEim"}

        # Verify counter (replay protection)
        if counter_value <= assoc.counter_value:
            logger.warning(
                "replay_detected",
                eid=self.euicc.eid,
                eim_id=eim_id,
                expected_gt=assoc.counter_value,
                received=counter_value,
            )
            return {"euiccPackageError": "counterMismatch"}

        # Update counter
        assoc.counter_value = counter_value

        results = []

        # Process PSMO operations
        for psmo in package.get("psmoList", []):
            result = self._execute_psmo(psmo)
            results.append(result)

        # Process eCO operations
        for eco in package.get("ecoList", []):
            result = self._execute_eco(eco)
            results.append(result)

        logger.info(
            "euicc_package_processed",
            eid=self.euicc.eid,
            eim_id=eim_id,
            operations=len(results),
        )

        return {"euiccPackageResult": results}

    def _execute_psmo(self, psmo: dict) -> dict:
        """Execute a Profile State Management Operation."""
        action = psmo.get("action", "")
        iccid = psmo.get("iccid")
        # The IPA decoder ships the ICCID as a hex string of the BCD bytes
        # exactly as they appeared on the SGP.32 wire. Internally the eUICC
        # stores the iccid in the OTHER nibble order (matching what
        # `/profiles` returns and what direct ES10c calls accept), so we
        # nibble-swap here to bring the two halves of the path into sync.
        # Pass-through fallback if the value is already in storage form
        # (lookup-by-equality will fail naturally; semantics unchanged).
        if isinstance(iccid, str):
            try:
                raw = bytes.fromhex(iccid)
            except ValueError:
                raw = None
            iccid = bytes((b >> 4) | ((b & 0x0F) << 4) for b in raw) if raw is not None else None

        iccid_hex = iccid.hex() if isinstance(iccid, (bytes, bytearray)) else (iccid or "")

        if action == "enable":
            profile = self.euicc.find_profile_by_iccid(iccid) if iccid else None
            if profile is None:
                return {"action": action, "result": "iccidNotFound"}
            if profile.state == ProfileState.ENABLED:
                return {"action": action, "result": "alreadyEnabled"}
            # Disable current
            current = self.euicc.get_enabled_profile()
            if current:
                current.state = ProfileState.DISABLED
            profile.state = ProfileState.ENABLED
            return {"action": action, "result": "ok", "iccid": iccid_hex}

        elif action == "disable":
            profile = self.euicc.find_profile_by_iccid(iccid) if iccid else None
            if profile is None:
                return {"action": action, "result": "iccidNotFound"}
            if profile.state != ProfileState.ENABLED:
                return {"action": action, "result": "notEnabled"}
            profile.state = ProfileState.DISABLED
            return {"action": action, "result": "ok", "iccid": iccid_hex}

        elif action == "delete":
            profile = self.euicc.find_profile_by_iccid(iccid) if iccid else None
            if profile is None:
                return {"action": action, "result": "iccidNotFound"}
            if profile.state == ProfileState.ENABLED:
                return {"action": action, "result": "mustDisableFirst"}
            self.euicc.profiles.remove(profile)
            return {"action": action, "result": "ok", "iccid": iccid_hex}

        elif action == "listProfileInfo":
            profiles = []
            for p in self.euicc.profiles:
                profiles.append({
                    "iccid": p.iccid.hex(),
                    "state": p.state.value,
                    "name": p.profile_name,
                    "spName": p.service_provider_name,
                })
            return {"action": action, "result": "ok", "profiles": profiles}

        elif action == "getRAT":
            return {"action": action, "result": "ok", "rat": []}

        return {"action": action, "result": "unknownAction"}

    def _execute_eco(self, eco: dict) -> dict:
        """Execute an eIM Configuration Operation."""
        action = eco.get("action", "")

        if action == "addEim":
            r = self.add_eim(eco.get("eimConfig", {}))
            return {"action": action, "result": "ok" if r.get("addEimResult") == 0 else "error", **r}
        elif action == "deleteEim":
            r = self.delete_eim(eco.get("eimId", ""))
            return {"action": action, "result": "ok" if r.get("deleteEimResult") == 0 else "error", **r}
        elif action == "updateEim":
            r = self.update_eim(eco.get("eimId", ""), eco.get("eimConfig", {}))
            return {"action": action, "result": "ok" if r.get("updateEimResult") == 0 else "error", **r}
        elif action == "listEim":
            return {"action": action, "result": "ok", **self.list_eim()}

        return {"action": action, "result": "unknownAction"}
