"""
Laravel seed client.

On startup, the eUICC simulator fetches /api/seed from the Laravel frontend
(euicc.connectxiot.com) to re-hydrate its device list. Laravel is the
source of truth for device definitions; this process restores state after
a restart without requiring manual re-creation.

Protected by a shared secret (SIM_SEED_TOKEN).
"""

import httpx
import structlog

from ..models.euicc import EimAssociation, EuiccState, ProfileClass, ProfileSlot, ProfileState
from .euicc_manager import EuiccManager

logger = structlog.get_logger()


async def reseed_from_laravel(
    mgr: EuiccManager,
    seed_url: str,
    seed_token: str,
    timeout: float = 10.0,
) -> int:
    """
    Fetch the device list from Laravel and hydrate EuiccManager.

    Returns the number of devices loaded. 0 means Laravel was reachable but
    empty. A negative value means the fetch failed — caller decides whether
    to fall back to test data.
    """
    if not seed_url:
        logger.info("reseed_skipped_no_url")
        return -1

    headers = {"Authorization": f"Bearer {seed_token}"} if seed_token else {}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(seed_url, headers=headers)
            resp.raise_for_status()
            payload = resp.json()
    except Exception as e:
        logger.warning("reseed_fetch_failed", url=seed_url, error=str(e))
        return -1

    devices = payload.get("devices", [])
    loaded = 0

    for d in devices:
        eid = d.get("eid")
        if not eid or len(eid) != 32:
            logger.warning("reseed_invalid_eid", eid=eid)
            continue

        if eid in mgr.instances:
            # Already loaded from persisted state — skip, don't overwrite
            continue

        try:
            mgr.create_euicc(
                eid=eid.upper(),
                default_smdp_address=d.get("default_smdp_address", "") or "",
                preloaded_profiles=d.get("preloaded_profiles") or None,
            )
            inst = mgr.get_euicc(eid.upper())
            # Merge any additional eIM associations
            for a in d.get("eim_associations", []):
                inst.euicc.eim_associations.append(
                    EimAssociation(
                        eim_id=a.get("eim_id", ""),
                        eim_fqdn=a.get("eim_fqdn", ""),
                        counter_value=int(a.get("counter_value", 0) or 0),
                        association_token=0,
                        supported_protocol=int(a.get("supported_protocol", 0) or 0),
                    )
                )
            loaded += 1
        except Exception as e:
            logger.warning("reseed_create_failed", eid=eid, error=str(e))

    logger.info("reseed_complete", loaded=loaded, total=len(devices))
    return loaded
