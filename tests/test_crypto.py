"""Tests for the eUICC cryptographic layer."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.crypto.certificates import CertificateInfrastructure
from app.crypto.ecdsa_engine import EcdsaEngine
from app.crypto.scp03t import Scp03tProcessor


@pytest.fixture
def pki(tmp_path):
    pki = CertificateInfrastructure(tmp_path / "certs")
    pki.initialize("89049032123451234512345678901235")
    return pki


@pytest.fixture
def ecdsa():
    return EcdsaEngine()


class TestCertificateChain:
    def test_chain_generates_three_certs(self, pki):
        assert pki.ci is not None
        assert pki.eum is not None
        assert pki.euicc is not None

    def test_ci_is_self_signed(self, pki):
        ci_cert = pki.ci.certificate
        assert ci_cert.issuer == ci_cert.subject

    def test_eum_signed_by_ci(self, pki):
        ok = EcdsaEngine.verify_certificate_signature(
            pki.get_eum_cert_der(), pki.ci.private_key.public_key()
        )
        assert ok

    def test_euicc_signed_by_eum(self, pki):
        ok = EcdsaEngine.verify_certificate_signature(
            pki.get_euicc_cert_der(), pki.eum.private_key.public_key()
        )
        assert ok

    def test_ci_pki_id_is_20_bytes(self, pki):
        ski = pki.get_ci_pki_id()
        assert len(ski) == 20

    def test_certs_persist_and_reload(self, pki, tmp_path):
        old_ski = pki.get_ci_pki_id()
        pki2 = CertificateInfrastructure(tmp_path / "certs")
        pki2.initialize("89049032123451234512345678901235")
        assert pki2.get_ci_pki_id() == old_ski

    def test_der_encoding(self, pki):
        der = pki.get_euicc_cert_der()
        assert der[:2] == b"\x30\x82" or der[0] == 0x30  # SEQUENCE


class TestEcdsaEngine:
    def test_sign_and_verify(self, pki, ecdsa):
        data = b"test data to sign"
        sig = ecdsa.sign(pki.euicc.private_key, data)
        assert len(sig) == 64
        assert ecdsa.verify(pki.euicc.private_key.public_key(), sig, data)

    def test_verify_wrong_data_fails(self, pki, ecdsa):
        sig = ecdsa.sign(pki.euicc.private_key, b"correct data")
        assert not ecdsa.verify(pki.euicc.private_key.public_key(), sig, b"wrong data")

    def test_challenge_is_16_bytes(self, ecdsa):
        c = ecdsa.generate_challenge()
        assert len(c) == 16

    def test_transaction_id_is_16_bytes(self, ecdsa):
        t = ecdsa.generate_transaction_id()
        assert len(t) == 16

    def test_otpk_generation(self, ecdsa):
        private, public = ecdsa.generate_otpk()
        assert len(public) == 65  # Uncompressed point
        assert public[0] == 0x04

    def test_ecdh_session_key_derivation(self, ecdsa):
        priv1, pub1 = ecdsa.generate_otpk()
        priv2, pub2 = ecdsa.generate_otpk()
        txn_id = os.urandom(16)

        keys1 = ecdsa.derive_session_keys(priv1, pub2, txn_id)
        keys2 = ecdsa.derive_session_keys(priv2, pub1, txn_id)

        # Both sides should derive the same keys
        assert keys1.s_enc == keys2.s_enc
        assert keys1.s_mac == keys2.s_mac
        assert keys1.s_rmac == keys2.s_rmac
        assert keys1.receipt_key == keys2.receipt_key
        assert len(keys1.s_enc) == 16

    def test_receipt_computation(self, ecdsa):
        key = os.urandom(16)
        receipt = ecdsa.compute_receipt(key, b"some data")
        assert len(receipt) == 16  # AES block size


class TestScp03t:
    def test_mac_chaining(self):
        from app.crypto.ecdsa_engine import SessionKeys
        keys = SessionKeys(
            s_enc=os.urandom(16),
            s_mac=os.urandom(16),
            s_rmac=os.urandom(16),
            receipt_key=os.urandom(16),
        )
        scp = Scp03tProcessor(keys)

        # Two successive MACs should differ (chaining)
        mac1 = scp._compute_mac(b"block1")
        mac2 = scp._compute_mac(b"block2")
        assert mac1 != mac2

    def test_padding_removal(self):
        # ISO 9797-1 Method 2: data || 80 || 00...
        padded = b"hello\x80\x00\x00"
        result = Scp03tProcessor._remove_padding(padded)
        assert result == b"hello"

    def test_padding_removal_no_padding(self):
        data = b"no padding here"
        result = Scp03tProcessor._remove_padding(data)
        assert result == data
