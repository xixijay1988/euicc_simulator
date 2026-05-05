# CLAUDE.md — euicc-simulator

Virtual eUICC simulator implementing GSMA SGP.22 v3.1 + SGP.32 v1.2.
Communicates via raw binary APDU over TCP (primary) + hex HTTP (debug).

## Build & Run

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/uvicorn app.main:app --port 8100          # TCP 9000-9002 + HTTP 8100
.venv/bin/pytest tests/ -v                           # 81 pass, 5 pre-existing fails
```

## Architecture

```
TCP raw APDU (port 9000+N) → ApduFrameParser → ApduProcessor → Es10Dispatcher
  → ES10a/b/c/IoT handler → ASN.1 encode → TCP response

HTTP hex APDU (POST /api/apdu/{eid}) → ApduProcessor → Es10Dispatcher
```

Each TCP port maps to one EID (config.yaml `eids:`). Multi-segment STORE DATA
uses P1 bit 7 for "last block" — ApduSegmentBuffer reassembles across blocks.

## Key Files

| File | Role |
|------|------|
| `app/main.py` | FastAPI lifespan co-launches TCP + HTTP servers |
| `app/transport/tcp_server.py` | asyncio TCP, per-connection ApduConnectionHandler |
| `app/transport/tcp_protocol.py` | ApduFrameParser (stream→frames), ApduSegmentBuffer |
| `app/transport/apdu_codec.py` | ISO 7816-4 Case 1/2/3/4 decode, SW constants |
| `app/services/apdu_handler.py` | ApduProcessor (SELECT/STORE DATA dispatch), ES10_TAGS (28 tags) |
| `app/services/apdu_dispatcher.py` | Core bridge: TLV tag → ASN.1 decode → handler → ASN.1 encode |
| `app/services/asn1_codec.py` | asn1tools wrapper, schema at `asn1_schemas/rsp_definitions.asn` (96 types) |
| `app/services/euicc_manager.py` | EuiccManager (multi-EID), EuiccInstance (bundles handlers+PKI) |
| `app/es10/es10b.py` | 8-step profile download: challenge→auth→prepare→load BPP (SCP03t) |
| `app/es10/es10c.py` | Profile enable/disable/delete, EID, memory reset, SGP.32 rollback |
| `app/es10/es10b_iot.py` | eIM config, PSMO/eCO, LoadEuiccPackage, AddInitialEim |
| `app/crypto/ecdsa_engine.py` | ECDSA P-256 raw `r||s` (64 bytes), ECDH, SCP03t session keys |
| `app/crypto/certificates.py` | CI→EUM→eUICC chain; SGP.26 NIST certs for `89049032*` EIDs |
| `app/models/euicc.py` | EuiccState, ProfileSlot, DownloadSession, EimAssociation |
| `app/config.py` | Pydantic SimConfig loaded from `config.yaml` |

## ES10 Tag Coverage (28 tags)

ES10a: BF3C BF3F
ES10b: BF20 BF22 BF2E BF38 BF21 BF36 BF41 BF28 BF2F BF43
ES10c: BF3E BF2D BF31 BF32 BF33 BF34 BF29
SGP.32 IoT: BF2B BF50 BF52 BF55 BF56 BF57 BF58 BF59 BF5A

To add a new tag: (1) add ASN.1 types to `rsp_definitions.asn`,
(2) add handler in `app/es10/`, (3) add to `ES10_TAGS` in `apdu_handler.py`,
(4) add dispatch branch in `apdu_dispatcher.py`, (5) add test.

## Testing Patterns

- Unit tests use `EuiccState` + `CertificateInfrastructure` with `tempfile.mkdtemp()`
- Dispatcher tests: build TLV manually (tag_bytes + DER request) → `dispatcher.dispatch(eid, data)` → check `resp.endswith(9000)`
- TCP tests: `ApduTcpServer` on `127.0.0.1` + `asyncio.open_connection` → raw APDU → read response
- `conftest.py` configures structlog to WARNING to suppress noise

## ASN.1 Conventions

- CHOICE types: `asn1tools` expects `(alternative_name, value)` tuples — NOT dicts
- BIT STRING: `(bytes, unused_bits)` tuple
- Context tags use `[N]` prefix on SEQUENCE/CHOICE definitions
- `AUTOMATIC TAGS` is on — tag numbers within SEQUENCEs are auto-assigned

## Known Quirks

1. 5 pre-existing test failures in `test_asn1.py` + `test_es10b.py` from upstream
   ConnectX — Python 3.14 / asn1tools 0.167 compatibility, not functional bugs.
2. `Asn1Codec` compiles schema once via `@lru_cache(maxsize=1)`. If you edit
   `rsp_definitions.asn`, restart the server.
3. SGP.32 compact format types (compactPrepareDownloadResponseOk etc.) are defined
   in the schema but handlers always return non-compact. This is valid per spec.
4. TCP frame parser identifies frame boundaries using Lc byte at offset 4.
   CLA bytes (0x80, 0x84, 0x00, 0x0C, 0x04) after data are treated as next
   APDU, not Le. See `ApduCodec.frame_size()`.
5. EID port mapping is 1:1. Each TCP port = one eUICC instance. No multi-EID
   on a single port.
