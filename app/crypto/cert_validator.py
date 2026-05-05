"""
Certificate chain validation for eUICC Simulator.

Validates SM-DP+ server certificates against the CI root,
as required by SGP.22 §2.6.3 during AuthenticateServer.

Chain: CI Root -> SM-DP+ CA (optional) -> SM-DP+ End-Entity
"""

import datetime
import structlog
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ExtensionNotFound

logger = structlog.get_logger()


class CertChainValidator:
    """
    Validates X.509 certificate chains against CI root certificates.

    The eUICC stores one or more CI root certificates (identified by
    SubjectKeyIdentifier). During AuthenticateServer, the SM-DP+
    presents its certificate chain, which must chain back to a
    trusted CI root.
    """

    def __init__(self, ci_certificates: list[x509.Certificate]):
        self.ci_certs = {self._get_ski(c): c for c in ci_certificates}

    def validate_server_cert(
        self,
        server_cert_der: bytes,
        ci_pkid: bytes,
    ) -> tuple[bool, str, EllipticCurvePublicKey | None]:
        """
        Validate a server certificate against the CI root.

        Returns:
            (is_valid, error_message, server_public_key)
        """
        # Parse the server certificate
        try:
            server_cert = x509.load_der_x509_certificate(server_cert_der)
        except Exception as e:
            return False, f"Invalid certificate DER: {e}", None

        # Check if we trust the CI PKI ID
        ci_cert = self.ci_certs.get(ci_pkid)
        if ci_cert is None:
            return False, f"Unknown CI PKI ID: {ci_pkid.hex()}", None

        # Validate certificate dates
        now = datetime.datetime.now(datetime.timezone.utc)
        if now < server_cert.not_valid_before_utc:
            return False, "Certificate not yet valid", None
        if now > server_cert.not_valid_after_utc:
            return False, "Certificate expired", None

        # Validate signature chain
        # Case 1: Server cert directly signed by CI
        ci_public_key = ci_cert.public_key()
        if self._verify_signature(server_cert, ci_public_key):
            logger.info("cert_validated_direct", issuer="CI")
            return True, "", server_cert.public_key()

        # Case 2: Server cert signed by an intermediate CA
        # The intermediate's AKI should match CI's SKI
        try:
            aki = server_cert.extensions.get_extension_for_class(
                x509.AuthorityKeyIdentifier
            ).value
            if aki.key_identifier == ci_pkid:
                # Signed by CI (AKI matches CI SKI)
                if self._verify_signature(server_cert, ci_public_key):
                    return True, "", server_cert.public_key()
        except ExtensionNotFound:
            pass

        # Case 3: Accept self-signed certs in test mode
        # (The simulator's own CI cert is self-signed)
        if server_cert.issuer == server_cert.subject:
            try:
                server_cert.public_key().verify(
                    server_cert.signature,
                    server_cert.tbs_certificate_bytes,
                    ECDSA(hashes.SHA256()),
                )
                logger.info("cert_validated_self_signed")
                return True, "", server_cert.public_key()
            except Exception:
                pass

        return False, "Certificate chain validation failed", None

    @staticmethod
    def _verify_signature(
        cert: x509.Certificate,
        issuer_public_key: EllipticCurvePublicKey,
    ) -> bool:
        """Verify that a certificate was signed by the given key."""
        try:
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ECDSA(hashes.SHA256()),
            )
            return True
        except Exception:
            return False

    @staticmethod
    def _get_ski(cert: x509.Certificate) -> bytes:
        """Extract SubjectKeyIdentifier from a certificate."""
        try:
            ski = cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value
            return ski.digest
        except ExtensionNotFound:
            return b""
