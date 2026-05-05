"""
GSMA RSP Certificate Infrastructure for eUICC Simulator.

Generates the full certificate chain per SGP.22 §2.6.3:
  CI (Certificate Issuer) -> EUM (eUICC Manufacturer) -> eUICC

All using ECDSA with P-256 (secp256r1) and SHA-256.
"""

import datetime
import os
from pathlib import Path
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    SECP256R1,
)

# GSMA SGP.26 v1.5 NIST P-256 test cert package — public CI/EUM with
# published private keys, designed so any test eUICC manufacturer can
# sign chains under it. Lab/test SM-DP+ deployments (osmo-smdpp,
# sysmocom test, vendor labs) accept eUICCs rooted in this chain.
SGP26_DIR = Path(__file__).parent.parent.parent / "certs" / "sgp26_nist"
# EUM cert's name constraint (`Permitted: O=RSP Test EUM, serialNumber=89049032`)
# requires the eUICC subject's serialNumber attribute to start with this
# IIN. EIDs not under this prefix can't legally be issued under the
# SGP.26 EUM, so we fall back to the locally-generated chain for them.
SGP26_EID_PREFIX = "89049032"


@dataclass
class KeyPairBundle:
    """Holds a private key and its X.509 certificate."""
    private_key: EllipticCurvePrivateKey
    certificate: x509.Certificate
    ski: bytes = field(default_factory=bytes)  # Subject Key Identifier


class CertificateInfrastructure:
    """
    Manages the GSMA RSP PKI hierarchy for the eUICC simulator.

    Chain: CI Root (self-signed) -> EUM Intermediate -> eUICC End-entity

    The CI represents GSMA's Certificate Issuer (e.g., GSMATestCI).
    The EUM represents the eUICC Manufacturer (e.g., ConnectX-EUM).
    The eUICC cert is the end-entity cert embedded in each simulated eUICC.
    """

    def __init__(self, certs_dir: str | Path):
        self.certs_dir = Path(certs_dir)
        self.certs_dir.mkdir(parents=True, exist_ok=True)

        self.ci: KeyPairBundle | None = None
        self.eum: KeyPairBundle | None = None
        self.euicc: KeyPairBundle | None = None

    def initialize(self, eid: str, force_regenerate: bool = False) -> None:
        """Generate or load the full certificate chain.

        Two modes:
        - SGP.26 mode (preferred when the EID falls under the SGP.26 EUM's
          name-constraint prefix and the SGP.26 cert package is available):
          load the public SGP.26 NIST CI + EUM, issue the eUICC end-entity
          cert under them. This makes the chain accepted by any lab/test
          SM-DP+ that trusts SGP.26 NIST TestCI.
        - Legacy mode: locally-generate a synthetic CI/EUM/eUICC chain
          rooted in `ConnectX-GSMA-CI-Test`. Only our own SM-DP+ trusts it.
        """
        sgp26 = (
            self._load_sgp26_chain()
            if eid.upper().startswith(SGP26_EID_PREFIX)
            else None
        )
        ci_key_path = self.certs_dir / "ci_private.pem"
        euicc_key_path = self.certs_dir / "euicc_private.pem"

        if sgp26 is not None:
            # SGP.26 chain — CI/EUM live in the shared package, only the
            # eUICC end-entity is per-EID.
            self.ci, self.eum = sgp26
            reuse_euicc = (
                euicc_key_path.exists()
                and not force_regenerate
                and self._euicc_cert_chains_to(self.eum)
            )
            if reuse_euicc:
                self.euicc = self._load_key_pair("euicc")
            else:
                # Mode-switched (legacy → SGP.26) or first run; reissue.
                self.euicc = self._generate_euicc_cert(self.eum, eid)
                self._save_key_pair("euicc", self.euicc)
        elif ci_key_path.exists() and not force_regenerate:
            self._load_existing(eid)
        else:
            self._generate_full_chain(eid)

    def _euicc_cert_chains_to(self, eum: "KeyPairBundle") -> bool:
        """Whether the on-disk eUICC cert was issued by the given EUM (by SKI).
        Used to detect chain-mode switches that require reissuing the eUICC
        end-entity cert."""
        cert_path = self.certs_dir / "euicc_cert.pem"
        if not cert_path.exists():
            return False
        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
            return aki.value.key_identifier == eum.ski
        except Exception:
            return False

    @staticmethod
    def _load_sgp26_chain() -> tuple["KeyPairBundle", "KeyPairBundle"] | None:
        """Load the SGP.26 NIST CI + EUM bundle from `certs/sgp26_nist/`,
        or return None if any of the four expected files is missing."""
        ci_cert_p = SGP26_DIR / "CERT_CI_ECDSA_NIST.pem"
        ci_key_p = SGP26_DIR / "SK_CI_ECDSA_NIST.pem"
        eum_cert_p = SGP26_DIR / "CERT_EUM_ECDSA_NIST.der"
        eum_key_p = SGP26_DIR / "SK_EUM_ECDSA_NIST.pem"
        if not all(p.exists() for p in (ci_cert_p, ci_key_p, eum_cert_p, eum_key_p)):
            return None

        ci_cert = x509.load_pem_x509_certificate(ci_cert_p.read_bytes())
        ci_key = serialization.load_pem_private_key(ci_key_p.read_bytes(), password=None)
        eum_cert = x509.load_der_x509_certificate(eum_cert_p.read_bytes())
        eum_key = serialization.load_pem_private_key(eum_key_p.read_bytes(), password=None)

        ci_ski = ci_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.digest
        eum_ski = eum_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.digest

        return (
            KeyPairBundle(private_key=ci_key, certificate=ci_cert, ski=ci_ski),
            KeyPairBundle(private_key=eum_key, certificate=eum_cert, ski=eum_ski),
        )

    def _generate_full_chain(self, eid: str) -> None:
        """Generate CI -> EUM -> eUICC certificate chain from scratch."""
        # 1. CI Root (self-signed)
        self.ci = self._generate_ci_root()
        self._save_key_pair("ci", self.ci)

        # 2. EUM Intermediate (signed by CI)
        self.eum = self._generate_eum_cert(self.ci)
        self._save_key_pair("eum", self.eum)

        # 3. eUICC End-entity (signed by EUM)
        self.euicc = self._generate_euicc_cert(self.eum, eid)
        self._save_key_pair("euicc", self.euicc)

    def _load_existing(self, eid: str) -> None:
        """Load existing certificates and keys from disk."""
        self.ci = self._load_key_pair("ci")
        self.eum = self._load_key_pair("eum")

        euicc_key_path = self.certs_dir / "euicc_private.pem"
        if euicc_key_path.exists():
            self.euicc = self._load_key_pair("euicc")
        else:
            # Generate new eUICC cert for this EID using existing EUM
            self.euicc = self._generate_euicc_cert(self.eum, eid)
            self._save_key_pair("euicc", self.euicc)

    def _generate_ci_root(self) -> KeyPairBundle:
        """Generate GSMA CI Root Certificate (self-signed)."""
        private_key = ec.generate_private_key(SECP256R1())

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "ConnectX-GSMA-CI-Test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ConnectX IoT"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "GSMA CI Simulator"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AE"),
        ])

        ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
            )
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(ski, critical=False)
            .sign(private_key, hashes.SHA256())
        )

        return KeyPairBundle(
            private_key=private_key,
            certificate=cert,
            ski=ski.digest,
        )

    def _generate_eum_cert(self, ci: KeyPairBundle) -> KeyPairBundle:
        """Generate EUM (eUICC Manufacturer) certificate signed by CI."""
        private_key = ec.generate_private_key(SECP256R1())

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "ConnectX-EUM-Test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ConnectX IoT"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "eUICC Manufacturing"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AE"),
        ])

        ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ci.certificate.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ci.certificate.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1825)
            )
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(ski, critical=False)
            .add_extension(aki, critical=False)
            .sign(ci.private_key, hashes.SHA256())
        )

        return KeyPairBundle(
            private_key=private_key,
            certificate=cert,
            ski=ski.digest,
        )

    def _generate_euicc_cert(self, eum: KeyPairBundle, eid: str) -> KeyPairBundle:
        """
        Generate eUICC end-entity certificate signed by EUM.

        Per SGP.22 §2.6.3, the eUICC certificate contains:
        - Subject with EID in serialNumber field
        - Key usage: digitalSignature + keyAgreement
        - No basicConstraints (end-entity)

        When the EUM is the SGP.26 test EUM, the subject DN must extend
        its `Permitted: O=RSP Test EUM, serialNumber=89049032` name
        constraint, so we mirror the canonical SGP.26 sample eUICC cert
        subject (`C=ES, O=RSP Test EUM, serialNumber=<eid>, CN=Test eUICC`).
        """
        private_key = ec.generate_private_key(SECP256R1())

        eum_subject = eum.certificate.subject
        is_sgp26 = any(
            a.oid == NameOID.ORGANIZATION_NAME and a.value == "RSP Test EUM"
            for a in eum_subject
        )
        if is_sgp26:
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RSP Test EUM"),
                x509.NameAttribute(NameOID.SERIAL_NUMBER, eid),
                x509.NameAttribute(NameOID.COMMON_NAME, f"eUICC-{eid[-8:]}"),
            ])
        else:
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"eUICC-{eid[-8:]}"),
                x509.NameAttribute(NameOID.SERIAL_NUMBER, eid),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ConnectX IoT"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "eUICC Simulator"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "AE"),
            ])

        ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            eum.certificate.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(eum.certificate.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=730)
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(ski, critical=False)
            .add_extension(aki, critical=False)
            .sign(eum.private_key, hashes.SHA256())
        )

        return KeyPairBundle(
            private_key=private_key,
            certificate=cert,
            ski=ski.digest,
        )

    def _save_key_pair(self, name: str, bundle: KeyPairBundle) -> None:
        """Save private key (PEM) and certificate (PEM + DER) to disk."""
        key_path = self.certs_dir / f"{name}_private.pem"
        cert_pem_path = self.certs_dir / f"{name}_cert.pem"
        cert_der_path = self.certs_dir / f"{name}_cert.der"

        key_path.write_bytes(
            bundle.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cert_pem_path.write_bytes(
            bundle.certificate.public_bytes(serialization.Encoding.PEM)
        )
        cert_der_path.write_bytes(
            bundle.certificate.public_bytes(serialization.Encoding.DER)
        )

    def _load_key_pair(self, name: str) -> KeyPairBundle:
        """Load private key and certificate from disk."""
        key_path = self.certs_dir / f"{name}_private.pem"
        cert_pem_path = self.certs_dir / f"{name}_cert.pem"

        private_key = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None
        )
        certificate = x509.load_pem_x509_certificate(cert_pem_path.read_bytes())

        ski_ext = certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )

        return KeyPairBundle(
            private_key=private_key,
            certificate=certificate,
            ski=ski_ext.value.digest,
        )

    def get_ci_pki_id(self) -> bytes:
        """Get CI Public Key Identifier (SubjectKeyIdentifier from CI cert)."""
        return self.ci.ski

    def get_trusted_ci_certs(self) -> list[x509.Certificate]:
        """Return all CI certs the eUICC trusts: its own (for signing) plus
        any extra trust anchors loaded from `certs/_trusted_cis/*.crt`. The
        extras let the sim accept SM-DP+/eIM chains rooted in the public
        GSMA SGP.26 TestCI without needing the corresponding private key.
        """
        out: list[x509.Certificate] = [self.ci.certificate]
        trusted_dir = Path(__file__).parent.parent.parent / "certs" / "_trusted_cis"
        if trusted_dir.is_dir():
            for p in sorted(trusted_dir.iterdir()):
                if p.suffix.lower() not in (".crt", ".pem", ".der"):
                    continue
                try:
                    raw = p.read_bytes()
                    cert = (
                        x509.load_pem_x509_certificate(raw)
                        if b"-----BEGIN CERTIFICATE-----" in raw
                        else x509.load_der_x509_certificate(raw)
                    )
                    out.append(cert)
                except Exception:
                    continue
        return out

    def get_trusted_ci_pkids(self) -> list[bytes]:
        """Return SubjectKeyIdentifier of every trusted CI cert."""
        ids: list[bytes] = []
        for cert in self.get_trusted_ci_certs():
            try:
                ski = cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value.digest
                if ski and ski not in ids:
                    ids.append(ski)
            except Exception:
                continue
        return ids

    def get_euicc_cert_der(self) -> bytes:
        """Get eUICC certificate in DER encoding."""
        return self.euicc.certificate.public_bytes(serialization.Encoding.DER)

    def get_eum_cert_der(self) -> bytes:
        """Get EUM certificate in DER encoding."""
        return self.eum.certificate.public_bytes(serialization.Encoding.DER)

    def get_ci_cert_der(self) -> bytes:
        """Get CI certificate in DER encoding."""
        return self.ci.certificate.public_bytes(serialization.Encoding.DER)
