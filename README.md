# euicc-simulator

Virtual eUICC (embedded Universal Integrated Circuit Card) simulator implementing
**GSMA SGP.22 v3.1** (Consumer RSP) and **SGP.32 v1.2** (IoT RSP) specifications.

Communicates via **raw binary APDU over TCP** (primary) and **hex-encoded APDU
over HTTP** (debug). Designed for integration testing of IPAd (IoT Profile
Assistant) modules without physical eSIM hardware.

```bash
# Quick start
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/uvicorn app.main:app --port 8100
```

---

## Architecture

```
IPAd / LPA client
  │  raw APDU (ISO 7816-4) over TCP
  ▼
┌─────────────────────────────┐
│  TCP Server (asyncio)        │  Port 9000+N → EID mapping
│  ApduFrameParser             │  Stream → complete APDU frames
└──────────┬──────────────────┘
           ▼
┌─────────────────────────────┐
│  ApduProcessor               │  SELECT ISD-R / STORE DATA / GET DATA
│  ApduSegmentBuffer           │  Multi-segment reassembly (P1 bit 7)
└──────────┬──────────────────┘
           ▼
┌─────────────────────────────┐
│  Es10Dispatcher              │  TLV tag → ASN.1 decode → ES10 handler
│                               │  → ASN.1 encode response → APDU TLV
└──────────┬──────────────────┘
     ┌─────┼─────┬──────────┐
     ▼     ▼     ▼          ▼
  ES10a  ES10b  ES10c   ES10b-IoT
  Config  Auth  LPM     eIM/PSMO
     │     │     │          │
     └─────┴─────┴──────────┘
           ▼
┌─────────────────────────────┐
│  EuiccState (per-EID)       │
│  profiles[], sessions,       │
│  certs, eim_associations    │
└─────────────────────────────┘
```

### Interfaces

| Interface | Protocol | Use case |
|-----------|----------|----------|
| **TCP raw APDU** | ISO 7816-4 binary, port 9000+ | Primary — IPAd `pal_scard_transmit()` replacement |
| **HTTP hex APDU** | POST `/api/apdu/{eid}` with `{"apdu":"hex..."}` | Debug / single-step testing |
| **HTTP REST** | GET `/api/es10/{eid}/*`, `/api/euiccs` | Management / direct function access |
| **OpenAPI docs** | GET `/api/docs` | Interactive API explorer |

---

## Directory Structure

```
euicc-simulator/
├── app/
│   ├── main.py                  # FastAPI lifespan: co-launches TCP + HTTP
│   ├── config.py                # Pydantic settings (YAML + env)
│   ├── transport/               # Raw APDU transport layer
│   │   ├── apdu_codec.py        #   ISO 7816-4 encode/decode (Cases 1-4)
│   │   ├── tcp_protocol.py      #   TCP stream → APDU frame parser
│   │   └── tcp_server.py        #   asyncio TCP server, per-port EID
│   ├── services/                # Business logic
│   │   ├── apdu_handler.py      #   ApduProcessor + ES10_TAGS (28 tags)
│   │   ├── apdu_dispatcher.py   #   TLV → ES10 handler bridge
│   │   ├── asn1_codec.py        #   DER encode/decode (asn1tools)
│   │   ├── euicc_manager.py     #   Multi-EID lifecycle
│   │   └── laravel_seeder.py    #   Seed data from external backend
│   ├── es10/                    # SGP.22/SGP.32 interface handlers
│   │   ├── es10a.py             #   Configuration (addresses)
│   │   ├── es10b.py             #   Profile download + authentication (8-step)
│   │   ├── es10c.py             #   Local profile management
│   │   └── es10b_iot.py         #   SGP.32 IoT (eIM config, PSMO/eCO)
│   ├── crypto/                  # ECDSA P-256, SCP03t, PKI
│   │   ├── ecdsa_engine.py      #   Signature (raw r||s), OTPK, ECDH
│   │   ├── certificates.py      #   CI → EUM → eUICC cert chain
│   │   ├── cert_validator.py    #   X.509 chain validation
│   │   └── scp03t.py            #   BPP decryption (AES-CBC/CMAC)
│   └── models/                  # State & persistence
│       ├── euicc.py             #   EuiccState, ProfileSlot, DownloadSession
│       └── database.py          #   SQLAlchemy + aiosqlite
├── asn1_schemas/                # ASN.1 DER schema (821 lines, 96 types)
│   └── rsp_definitions.asn
├── certs/                       # SGP.26 NIST test certificates
│   ├── sgp26_nist/
│   └── _trusted_cis/
├── config.yaml                  # Port-EID mapping, server config
├── pyproject.toml               # Build deps, pytest config
└── tests/                       # 8 test files, 86 tests
    ├── test_apdu_codec.py       #   ISO 7816-4 encode/decode
    ├── test_tcp_protocol.py     #   Frame parsing, segment reassembly
    ├── test_apdu_dispatcher.py  #   ES10 dispatch (one per tag)
    ├── test_tcp_full_flow.py    #   TCP end-to-end round-trip
    ├── test_es10b.py            #   Profile download flow
    ├── test_crypto.py           #   ECDSA, SCP03t, cert chain
    ├── test_asn1.py             #   ASN.1 encode/decode round-trips
    └── conftest.py              #   Fixtures
```

---

## ES10 Command Tag Coverage

28 tags covering **SGP.22 v3.1** + **SGP.32 v1.2**.

### ES10a — Configuration

| Tag | Command | Description |
|-----|---------|-------------|
| 0xBF3C | GetEuiccConfiguredAddresses | Return default SM-DP+ and SM-DS addresses |
| 0xBF3F | SetDefaultDpAddress | Update default SM-DP+ address |

### ES10b — Profile Download & Authentication

| Tag | Command | Description |
|-----|---------|-------------|
| 0xBF20 | GetEuiccInfo1 | SVN + CI PKI IDs (pre-auth) |
| 0xBF22 | GetEuiccInfo2 | Full eUICC capabilities (post-auth) |
| 0xBF2E | GetEuiccChallenge | 16-byte nonce for mutual authentication |
| 0xBF38 | AuthenticateServer | Verify SM-DP+ + sign eUICC proof (ECDSA P-256) |
| 0xBF21 | PrepareDownload | Generate OTPK + derive SCP03t session keys (ECDH) |
| 0xBF36 | LoadBoundProfilePackage | Decrypt BPP (AES-CBC/CMAC) + install profile |
| 0xBF41 | CancelSession | Abort active download session |
| 0xBF28 | ListNotification | List pending notifications |
| 0xBF2F | RemoveNotificationFromList | Acknowledge a notification |
| 0xBF43 | GetEUICCInformation | Platform info (SGP.22 v3.0+) |

### ES10c — Local Profile Management

| Tag | Command | Description |
|-----|---------|-------------|
| 0xBF3E | GetEID | Return 32-digit EID |
| 0xBF2D | GetProfilesInfo | List installed profiles |
| 0xBF31 | EnableProfile | Activate a profile |
| 0xBF32 | DisableProfile | Deactivate a profile |
| 0xBF33 | DeleteProfile | Remove a profile |
| 0xBF34 | eUICCMemoryReset | Factory reset + SGP.32 eIM/auto-enable options |
| 0xBF29 | SetNickname | Set profile nickname |

### SGP.32 IoT Extensions

| Tag | Command | Section | Description |
|-----|---------|---------|-------------|
| 0xBF2B | RetrieveNotificationsList | §5.9.11 | Enhanced notification list with ePR |
| 0xBF50 | LoadEuiccPackage | — | ESep relay: PSMO + eCO execution |
| 0xBF52 | GetEimConfigurationData | — | List eIM associations (simple format) |
| 0xBF55 | GetEimConfigurationDataSGP32 | §5.9.18 | Enhanced eIM config (SGP.32 format) |
| 0xBF56 | GetCertsSGP32 | §5.9.10 | EUM + eUICC certificate chain |
| 0xBF57 | AddInitialEim | §5.9.4 | Batch register eIM associations |
| 0xBF58 | ProfileRollback | §5.9.16 | Revert last profile operation |
| 0xBF59 | ConfigureAutoProfileEnabling | §5.9.17 | Auto-enable profile configuration |
| 0xBF5A | EnableUsingDD | §5.9.15 | Enable profile via Device Discovery |

---

## Build & Install

```bash
# Clone
git clone git@github.com:xixijay1988/euicc_simulator.git
cd euicc_simulator

# Create virtualenv and install
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Run tests
.venv/bin/pytest tests/ -v

# Start server (TCP ports 9000-9002 + HTTP 8100)
.venv/bin/uvicorn app.main:app --port 8100
```

Requirements: Python >= 3.11, `cryptography`, `asn1tools`, `fastapi`, `uvicorn`,
`sqlalchemy`, `aiosqlite`, `structlog`, `pyyaml`.

---

## Usage

### TCP Raw APDU (primary interface)

Connect to a TCP port mapped to an eUICC. Each port maps to one EID
(configured in `config.yaml`).

```python
import asyncio

ISDR_AID = bytes.fromhex("A0000005591010FFFFFFFF8900001000")

async def test():
    r, w = await asyncio.open_connection("localhost", 9000)

    # 1. SELECT ISD-R
    select = bytes.fromhex("80A4040010") + ISDR_AID
    w.write(select); await w.drain()
    resp = await r.read(256)  # → 90 00 (SW_OK)

    # 2. GetEID (tag BF3E)
    store = bytes.fromhex("80E2910004BF3E0000")
    w.write(store); await w.drain()
    resp = await r.read(256)  # → BF3Exx...eid...9000

    # 3. GetEuiccInfo1 (tag BF20)
    store = bytes.fromhex("80E2910004BF200000")
    w.write(store); await w.drain()
    resp = await r.read(256)  # → BF20xx...svn...ciPkids...9000

    w.close()
```

### APDU protocol details

APDUs follow ISO 7816-4:

| Case | Format | Example |
|------|--------|---------|
| Case 1 | CLA INS P1 P2 | `80E29100` |
| Case 3 | CLA INS P1 P2 Lc Data | `80E2910004BF3E0000` (STORE DATA, last block, Lc=4) |

Multi-segment STORE DATA uses P1 bit 7 as "last block" flag:
- P1=0x91 → last block (bit 7 set)
- P1=0x11 → more blocks follow

### HTTP Debug (secondary interface)

```bash
# GetEID via hex-encoded APDU
curl -X POST http://localhost:8100/api/apdu/89049032123451234512345678901235 \
  -H "Content-Type: application/json" \
  -d '{"apdu":"80E2910004BF3E0000"}'

# List all eUICCs
curl http://localhost:8100/api/euiccs

# Get eUICC info (REST API)
curl http://localhost:8100/api/es10/89049032123451234512345678901235/eid

# OpenAPI docs
open http://localhost:8100/api/docs
```

---

## Configuration

`config.yaml`:

```yaml
server:
  tcp_start_port: 9000     # First TCP port (sequential for multi-EID)
  http_port: 8100
  host: "0.0.0.0"

euicc:
  svn: "3.1.0"             # SGP.22 version
  profile_version: "2.3.1"
  iot_version: "1.2.0"     # SGP.32 version

database_url: "sqlite:///./esim_simulator.db"
certs_dir: "./certs"

# Per-port EID mapping
eids:
  9000: "89049032123451234512345678901235"   # 2 preloaded profiles
  9001: "89049032123451234512345678901236"   # empty, ready
  9002: "89049032123451234512345678901237"   # bootstrap (no eIM)
```

Three test eUICCs are pre-created on startup with sample profiles and eIM
associations for immediate testing.

---

## Crypto Infrastructure

- **Certificate chain**: CI (self-signed root) → EUM (intermediate CA) → eUICC (end-entity)
- **Curve**: ECDSA P-256 (secp256r1) with SHA-256
- **Signature format**: raw `r||s` (64 bytes), per GSMA convention
- **Key agreement**: ECDH with X9.63 KDF → 4× AES-128 session keys
- **BPP decryption**: SCP03t (AES-CBC + AES-CMAC)
- **SGP.26 support**: Loads public GSMA NIST test CI + EUM certs for EIDs
  starting with `89049032`, making the simulator interoperable with
  lab/test SM-DP+ deployments

---

## Profile Download Flow (8-step)

The simulator implements the complete SGP.22 §5.7 profile download:

```
Step 1:  ES10b.GetEuiccChallenge      → 16-byte nonce
Step 2:  ES10b.GetEuiccInfo1          → SVN + CI PKI IDs
Step 3:  ES9+.InitiateAuthentication   → SM-DP+ ServerSigned1 + cert
Step 4:  ES10b.AuthenticateServer      → Verify SM-DP+ + sign EuiccSigned1
Step 5:  ES9+.AuthenticateClient       → SM-DP+ SmdpSigned2 + cert
Step 6:  ES10b.PrepareDownload         → Generate OTPK + derive session keys
Step 7:  ES9+.GetBoundProfilePackage   → BoundProfilePackage (encrypted)
Step 8:  ES10b.LoadBoundProfilePackage → Decrypt (SCP03t) + install ISD-P
```

Steps 3, 5, 7 are handled by the IPA/IPAd (not this simulator).
This simulator handles steps 1, 2, 4, 6, 8 (the eUICC side of ES10b).

---

## Testing

```bash
# All tests
.venv/bin/pytest tests/ -v

# Targeted
.venv/bin/pytest tests/test_apdu_codec.py -v          # APDU encode/decode
.venv/bin/pytest tests/test_tcp_protocol.py -v         # Frame parsing
.venv/bin/pytest tests/test_apdu_dispatcher.py -v      # ES10 dispatch (16 test cases)
.venv/bin/pytest tests/test_tcp_full_flow.py -v        # TCP end-to-end
.venv/bin/pytest tests/test_es10b.py -v                # Profile download flow
.venv/bin/pytest tests/test_crypto.py -v               # ECDSA, SCP03t, certs
```

Test counts: 86 total (81 pass, 5 pre-existing ASN.1 compatibility failures
from upstream ConnectX tests due to Python 3.14/asn1tools version differences).

---

## Key Design Decisions

1. **Raw binary APDU over TCP** — no wrapping protocol. ISO 7816-4's own
   structure (CLA byte + Lc-based length) provides frame boundaries.
2. **Per-port EID mapping** — each TCP port maps to one eUICC instance.
   Simple, deterministic, no per-connection EID negotiation needed.
3. **Heavy reuse of ConnectX eUICC** — all ES10 handlers, crypto, ASN.1
   codec, state models, and certificate infrastructure were reused from
   the ConnectX IoT eUICC simulator. Only the TCP transport layer and
   APDU-ES10 dispatcher bridge were built new.
4. **CHOICE types as tuples** — asn1tools represents ASN.1 CHOICE as
   `(alternative_name, value)` tuples. All dispatcher encode calls use
   this convention.
5. **SGP.32 compact format types** — defined in the ASN.1 schema but
   not used in default responses (compact format is an IP-layer
   optimization; the non-compact variants are always valid).
