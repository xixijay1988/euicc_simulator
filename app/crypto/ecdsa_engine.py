"""
ECDSA P-256 signing/verification engine for eUICC Simulator.

Implements the cryptographic operations required by SGP.22 ES10b:
- Challenge generation (16-byte random nonce)
- ECDSA signature creation (raw r||s format, 64 bytes)
- ECDSA signature verification
- One-time key pair generation (OTPK for profile download)
- Session key derivation via ECDH (for SCP03t/BSP)
"""

import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    ECDH,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    SECP256R1,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC


@dataclass
class SessionKeys:
    """SCP03t session keys derived from ECDH shared secret."""
    s_enc: bytes  # Session encryption key (AES-128)
    s_mac: bytes  # Session MAC key (AES-128)
    s_rmac: bytes  # Response MAC key (AES-128)
    receipt_key: bytes  # Receipt generation key


class EcdsaEngine:
    """
    Core ECDSA operations for eUICC mutual authentication per SGP.22.

    All signatures use ECDSA with SHA-256 over P-256 (secp256r1).
    Signature format is raw r||s (32 bytes each = 64 bytes total),
    NOT DER-encoded, as specified by GSMA.
    """

    @staticmethod
    def generate_challenge() -> bytes:
        """Generate a 16-byte cryptographic random challenge (nonce)."""
        return os.urandom(16)

    @staticmethod
    def generate_transaction_id() -> bytes:
        """Generate a 16-byte transaction identifier."""
        return os.urandom(16)

    @staticmethod
    def generate_otpk() -> tuple[EllipticCurvePrivateKey, bytes]:
        """
        Generate a one-time key pair (OTPK) for profile download.

        Returns:
            (private_key, public_key_bytes) where public_key_bytes is the
            uncompressed point encoding (65 bytes: 04 || x || y).
        """
        private_key = ec.generate_private_key(SECP256R1())
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        return private_key, public_bytes

    @staticmethod
    def sign(private_key: EllipticCurvePrivateKey, data: bytes) -> bytes:
        """
        Create ECDSA-SHA256 signature in raw r||s format (64 bytes).

        Per SGP.22, signatures are NOT DER-encoded but raw concatenation
        of r and s values, each zero-padded to 32 bytes.
        """
        der_signature = private_key.sign(data, ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_signature)

        # Convert to raw r||s format, each 32 bytes (P-256 order is 32 bytes)
        r_bytes = r.to_bytes(32, byteorder="big")
        s_bytes = s.to_bytes(32, byteorder="big")
        return r_bytes + s_bytes

    @staticmethod
    def verify(
        public_key: EllipticCurvePublicKey,
        signature: bytes,
        data: bytes,
    ) -> bool:
        """
        Verify ECDSA-SHA256 signature in raw r||s format.

        Returns True if valid, False otherwise.
        """
        if len(signature) != 64:
            return False

        r = int.from_bytes(signature[:32], byteorder="big")
        s = int.from_bytes(signature[32:], byteorder="big")
        der_signature = encode_dss_signature(r, s)

        try:
            public_key.verify(der_signature, data, ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    @staticmethod
    def verify_certificate_signature(
        cert_der: bytes,
        issuer_public_key: EllipticCurvePublicKey,
    ) -> bool:
        """Verify that a certificate was signed by the given issuer key."""
        from cryptography import x509

        cert = x509.load_der_x509_certificate(cert_der)
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
    def derive_session_keys(
        euicc_otpk_private: EllipticCurvePrivateKey,
        smdp_otpk_public_bytes: bytes,
        transaction_id: bytes,
    ) -> SessionKeys:
        """
        Derive SCP03t session keys via ECDH + X9.63 KDF.

        Per SGP.22 §5.7.2 and GlobalPlatform Amendment F:
        1. Perform ECDH with eUICC OTPK and SM-DP+ OTPK
        2. Use X9.63 KDF with SHA-256 to derive key material
        3. Split into S-ENC, S-MAC, S-RMAC, and receipt key

        Args:
            euicc_otpk_private: eUICC's one-time private key
            smdp_otpk_public_bytes: SM-DP+ OTPK (uncompressed point, 65 bytes)
            transaction_id: 16-byte transaction ID used as shared info
        """
        # Load SM-DP+ public key from uncompressed point
        smdp_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            SECP256R1(), smdp_otpk_public_bytes
        )

        # ECDH shared secret
        shared_secret = euicc_otpk_private.exchange(ECDH(), smdp_public_key)

        # X9.63 KDF: derive 4 * 16 = 64 bytes of key material
        # SharedInfo = transactionId (used as context/label)
        kdf = X963KDF(
            algorithm=hashes.SHA256(),
            length=64,
            sharedinfo=transaction_id,
        )
        key_material = kdf.derive(shared_secret)

        return SessionKeys(
            s_enc=key_material[0:16],
            s_mac=key_material[16:32],
            s_rmac=key_material[32:48],
            receipt_key=key_material[48:64],
        )

    @staticmethod
    def compute_receipt(receipt_key: bytes, data: bytes) -> bytes:
        """
        Compute a receipt (AES-CMAC) for confirming key agreement.

        Used in the profile download flow to confirm both sides
        derived the same session keys.
        """
        c = CMAC(algorithms.AES128(receipt_key))
        c.update(data)
        return c.finalize()

    @staticmethod
    def get_public_key_bytes(private_key: EllipticCurvePrivateKey) -> bytes:
        """Get the uncompressed public key point (65 bytes: 04 || x || y)."""
        return private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    @staticmethod
    def load_public_key_from_bytes(public_bytes: bytes) -> EllipticCurvePublicKey:
        """Load a public key from uncompressed point bytes."""
        return ec.EllipticCurvePublicKey.from_encoded_point(
            SECP256R1(), public_bytes
        )
