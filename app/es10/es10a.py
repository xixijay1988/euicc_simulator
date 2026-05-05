"""
ES10a Interface Handler — eUICC Configuration.

Implements the eUICC side of ES10a per SGP.22 §5.5:
- GetEuiccConfiguredAddresses — Return SM-DP+ and SM-DS addresses
- SetDefaultDpAddress — Update default SM-DP+ address
"""

import structlog
from ..models.euicc import EuiccState

logger = structlog.get_logger()


class Es10aHandler:
    """Handles ES10a commands for eUICC configuration."""

    def __init__(self, euicc: EuiccState):
        self.euicc = euicc

    def get_euicc_configured_addresses(self) -> dict:
        """Return the configured SM-DP+ and SM-DS addresses."""
        return {
            "defaultDpAddress": self.euicc.default_smdp_address,
            "rootDsAddress": self.euicc.root_ds_address,
        }

    def set_default_dp_address(self, address: str) -> dict:
        """Set the default SM-DP+ address."""
        self.euicc.default_smdp_address = address
        logger.info(
            "default_dp_address_set",
            eid=self.euicc.eid,
            address=address,
        )
        return {"setDefaultDpAddressResult": 0}  # ok
