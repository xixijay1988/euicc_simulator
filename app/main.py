"""eSIM Simulator — FastAPI application entry point.

Starts both:
- TCP server for raw APDU (primary interface)
- HTTP server for REST API (debug/management)
- Multi-EID support via EuiccManager
"""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import SimConfig
from .transport.tcp_server import ApduTcpServer
from .services.euicc_manager import EuiccManager
from .services.apdu_dispatcher import Es10Dispatcher
from .models.database import init_db, load_persisted_euiccs, persist_euiccs

logger = structlog.get_logger()

# Globals
config: SimConfig = None
euicc_manager: EuiccManager = None
dispatchers: dict[str, Es10Dispatcher] = {}
tcp_server: ApduTcpServer = None


def setup_euiccs():
    """Initialize eUICC instances from config."""
    global euicc_manager, dispatchers

    certs_dir = Path(config.certs_dir).resolve()
    euicc_manager = EuiccManager(certs_dir)

    # Create test eUICCs with sample data
    euicc_manager.create_test_euiccs(
        smdp_address="smdpplus.connectxiot.com",
        eim_fqdn="eim.connectxiot.com",
    )

    # Build dispatcher for each EID
    for eid, instance in euicc_manager.instances.items():
        dispatchers[eid] = Es10Dispatcher(instance)

    logger.info("euiccs_initialized", count=len(euicc_manager.instances))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle for FastAPI + TCP server."""
    global config, tcp_server

    # Load config
    config = SimConfig.from_yaml()

    # Init database
    await init_db(config.database_url)

    # Setup eUICCs
    setup_euiccs()

    # Load persisted state
    await load_persisted_euiccs(euicc_manager)

    # Start TCP server
    port_map = {}
    for inst in euicc_manager.instances.values():
        port = config.server.tcp_start_port
        # Assign sequential ports if multiple EIDs
        offset = len(port_map)
        port_map[port + offset] = inst.euicc.eid

    tcp_server = ApduTcpServer(
        host=config.server.host,
        port_map=port_map,
        dispatchers=dispatchers,
    )
    await tcp_server.start()
    logger.info("tcp_server_ready", ports=list(port_map.keys()))

    yield

    # Shutdown
    if tcp_server:
        await tcp_server.stop()
    await persist_euiccs(euicc_manager)
    logger.info("simulator_shutdown_complete")


app = FastAPI(
    title="GSMA eSIM Simulator",
    description="Virtual eUICC with raw APDU over TCP (primary) + HTTP REST (debug)",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================================================================
# Health / Info
# =====================================================================

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/info")
async def info():
    return {
        "name": "GSMA eSIM Simulator",
        "version": "0.1.0",
        "euiccs": len(euicc_manager.instances) if euicc_manager else 0,
        "tcp_ports": list(tcp_server.port_map.keys()) if tcp_server else [],
    }


# =====================================================================
# APDU Debug Endpoint (hex-encoded HTTP POST)
# =====================================================================

@app.post("/api/apdu/{eid}")
async def apdu_debug(eid: str, body: dict):
    """Debug endpoint: send raw hex-encoded APDU via HTTP, get hex response."""
    if euicc_manager is None:
        return {"error": "not_initialized"}, 503

    instance = euicc_manager.get_euicc(eid)
    if instance is None:
        return {"error": "eid_not_found"}, 404

    apdu_hex = body.get("apdu", "")
    try:
        apdu_bytes = bytes.fromhex(apdu_hex)
    except ValueError:
        return {"error": "invalid_hex"}, 400

    # Build dispatcher on-demand if needed
    if eid not in dispatchers:
        dispatchers[eid] = Es10Dispatcher(instance)

    dispatcher = dispatchers[eid]
    dispatcher_instance = dispatchers.get(eid)

    # Use ApduProcessor directly for HTTP debug
    apdu = instance.apdu
    response = apdu.process_apdu(apdu_bytes)

    # If response is data + 9000, try ES10 dispatch
    if len(response) > 2 and response[-2:] == bytes.fromhex("9000"):
        data = response[:-2]
        if data:
            es10_response = dispatcher.dispatch(eid, data)
            return {"response": es10_response.hex()}

    return {"response": response.hex()}


# =====================================================================
# Management Endpoints
# =====================================================================

@app.get("/api/euiccs")
async def list_euiccs():
    """List all virtual eUICCs."""
    if euicc_manager is None:
        return {"euiccs": []}
    return {"euiccs": euicc_manager.list_euiccs()}


@app.get("/api/euiccs/{eid}")
async def get_euicc(eid: str):
    """Get eUICC details."""
    if euicc_manager is None:
        return {"error": "not_initialized"}, 503

    instance = euicc_manager.get_euicc(eid)
    if instance is None:
        return {"error": "eid_not_found"}, 404

    euicc = instance.euicc
    return {
        "eid": euicc.eid,
        "svn": ".".join(str(v) for v in euicc.svn),
        "profiles": [
            {
                "iccid": p.iccid_string(),
                "state": p.state.value,
                "name": p.profile_name,
                "aid": p.isdp_aid.hex(),
            }
            for p in euicc.profiles
        ],
        "eim_associations": [
            {"eimId": a.eim_id, "eimFqdn": a.eim_fqdn, "counter": a.counter_value}
            for a in euicc.eim_associations
        ],
        "notifications": len(euicc.notifications),
        "hasActiveSession": euicc.active_session is not None,
        "freeNvm": euicc.free_nvm,
        "defaultSmdp": euicc.default_smdp_address,
    }


# =====================================================================
# ES10 Direct REST API (for debug/testing)
# =====================================================================

@app.get("/api/es10/{eid}/euicc-info1")
async def get_euicc_info1(eid: str):
    instance = _get_instance(eid)
    if isinstance(instance, tuple):
        return instance
    result = instance.es10b.get_euicc_info1()
    return {"status": "ok", "data": {
        "svn": result["svn"].hex(),
        "ciPkidsForVerification": [p.hex() for p in result["euiccCiPKIdListForVerification"]],
        "ciPkidsForSigning": [p.hex() for p in result["euiccCiPKIdListForSigning"]],
    }}


@app.get("/api/es10/{eid}/euicc-challenge")
async def get_euicc_challenge(eid: str):
    instance = _get_instance(eid)
    if isinstance(instance, tuple):
        return instance
    result = instance.es10b.get_euicc_challenge()
    return {"status": "ok", "challenge": result["euiccChallenge"].hex()}


@app.get("/api/es10/{eid}/eid")
async def get_eid(eid: str):
    instance = _get_instance(eid)
    if isinstance(instance, tuple):
        return instance
    result = instance.es10c.get_eid()
    return {"status": "ok", "eid": result["eid"].hex()}


@app.get("/api/es10/{eid}/profiles")
async def get_profiles(eid: str):
    instance = _get_instance(eid)
    if isinstance(instance, tuple):
        return instance
    result = instance.es10c.get_profiles_info()
    return {"status": "ok", "profiles": result}


def _get_instance(eid: str):
    if euicc_manager is None:
        return {"error": "not_initialized"}, 503
    instance = euicc_manager.get_euicc(eid)
    if instance is None:
        return {"error": "eid_not_found"}, 404
    return instance
