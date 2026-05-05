"""Tests for ES10b handler — the profile download authentication flow."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models.euicc import EuiccState, ProfileSlot, ProfileState, ProfileClass
from app.crypto.certificates import CertificateInfrastructure
from app.crypto.ecdsa_engine import EcdsaEngine
from app.es10.es10b import Es10bHandler
from app.es10.es10c import Es10cHandler
from app.services.asn1_codec import Asn1Codec


@pytest.fixture
def euicc_setup(tmp_path):
    """Create a fully initialized eUICC with PKI."""
    eid = "89049032123451234512345678901235"
    euicc = EuiccState(eid=eid, default_smdp_address="smdp.test.com")
    pki = CertificateInfrastructure(tmp_path / "certs")
    pki.initialize(eid)
    return euicc, pki


@pytest.fixture
def es10b(euicc_setup):
    euicc, pki = euicc_setup
    return Es10bHandler(euicc, pki)


@pytest.fixture
def es10c(euicc_setup):
    euicc, pki = euicc_setup
    return Es10cHandler(euicc, pki)


@pytest.fixture
def ecdsa():
    return EcdsaEngine()


@pytest.fixture
def codec():
    return Asn1Codec()


class TestGetEuiccInfo:
    def test_info1_has_ci_pkid(self, es10b):
        info1 = es10b.get_euicc_info1()
        assert "svn" in info1
        assert len(info1["euiccCiPKIdListForVerification"]) == 1
        assert len(info1["euiccCiPKIdListForSigning"]) == 1

    def test_info2_has_iot_extensions(self, es10b):
        info2 = es10b.get_euicc_info2()
        assert info2["ipaMode"] == 0
        assert "iotSpecificInfo" in info2
        assert "certificationDataObject" in info2


class TestGetEuiccChallenge:
    def test_challenge_is_16_bytes(self, es10b):
        result = es10b.get_euicc_challenge()
        challenge = result["euiccChallenge"]
        assert len(challenge) == 16

    def test_creates_active_session(self, es10b):
        es10b.get_euicc_challenge()
        assert es10b.euicc.active_session is not None


class TestAuthenticateServer:
    def test_full_auth_flow(self, es10b, euicc_setup, ecdsa, codec):
        """Simulate a complete server authentication using the eUICC's own PKI."""
        euicc, pki = euicc_setup

        # Step 1: Get challenge
        challenge_result = es10b.get_euicc_challenge()
        challenge = challenge_result["euiccChallenge"]

        # Step 2: Build server_signed1 (simulating SM-DP+)
        # Use the CI's key as the "server" key for self-test
        server_signed1 = {
            "transactionId": os.urandom(16),
            "euiccChallenge": challenge,
            "serverAddress": "smdp.test.com",
            "serverChallenge": os.urandom(16),
        }

        # Sign with CI key (acting as SM-DP+ for test)
        tbs = codec.encode_server_signed1(server_signed1)
        server_sig = ecdsa.sign(pki.ci.private_key, tbs)

        # Step 3: Call AuthenticateServer
        result = es10b.authenticate_server(
            server_signed1=server_signed1,
            server_signature1=server_sig,
            euicc_ci_pkid=pki.get_ci_pki_id(),
            server_certificate_der=pki.get_ci_cert_der(),
        )

        # Should succeed
        assert "authenticateResponseOk" in result
        ok = result["authenticateResponseOk"]
        assert "euiccSigned1" in ok
        assert "euiccSignature1" in ok
        assert len(ok["euiccSignature1"]) == 64
        assert "euiccCertificate" in ok

    def test_wrong_ci_pkid_fails(self, es10b):
        es10b.get_euicc_challenge()
        result = es10b.authenticate_server(
            server_signed1={"transactionId": os.urandom(16)},
            server_signature1=os.urandom(64),
            euicc_ci_pkid=b"\xff" * 20,  # Wrong PKI ID
            server_certificate_der=b"",
        )
        assert "authenticateResponseError" in result
        assert result["authenticateResponseError"]["authenticateErrorCode"] == 3

    def test_no_session_fails(self, es10b):
        # Don't call get_euicc_challenge first
        result = es10b.authenticate_server(
            server_signed1={},
            server_signature1=b"",
            euicc_ci_pkid=b"",
            server_certificate_der=b"",
        )
        assert "authenticateResponseError" in result


class TestCancelSession:
    def test_cancel_active_session(self, es10b, euicc_setup, ecdsa, codec):
        euicc, pki = euicc_setup

        # Create a session
        es10b.get_euicc_challenge()
        challenge = es10b.euicc.active_session.euicc_challenge

        # Authenticate to get a transaction ID
        server_signed1 = {
            "transactionId": os.urandom(16),
            "euiccChallenge": challenge,
            "serverAddress": "smdp.test.com",
            "serverChallenge": os.urandom(16),
        }
        tbs = codec.encode_server_signed1(server_signed1)
        server_sig = ecdsa.sign(pki.ci.private_key, tbs)

        es10b.authenticate_server(
            server_signed1=server_signed1,
            server_signature1=server_sig,
            euicc_ci_pkid=pki.get_ci_pki_id(),
            server_certificate_der=pki.get_ci_cert_der(),
        )

        txn_id = es10b.euicc.active_session.transaction_id

        # Cancel
        result = es10b.cancel_session(txn_id, reason=2)
        assert "cancelSessionResponseOk" in result
        assert es10b.euicc.active_session is None

    def test_cancel_no_session_fails(self, es10b):
        result = es10b.cancel_session(os.urandom(16), 0)
        assert "cancelSessionResponseError" in result


class TestES10cProfileManagement:
    def test_get_eid(self, es10c, euicc_setup):
        euicc, _ = euicc_setup
        result = es10c.get_eid()
        assert "eid" in result
        assert result["eid"] == bytes.fromhex(euicc.eid)

    def test_empty_profiles(self, es10c):
        result = es10c.get_profiles_info()
        assert result["profileInfoListOk"] == []

    def test_enable_disable_profile(self, es10c, euicc_setup):
        euicc, _ = euicc_setup
        # Add a profile manually
        iccid = os.urandom(10)
        euicc.profiles.append(ProfileSlot(
            iccid=iccid,
            isdp_aid=euicc.allocate_isdp_aid(),
            state=ProfileState.DISABLED,
            profile_name="Test",
        ))

        # Enable
        result = es10c.enable_profile(iccid=iccid)
        assert result["enableResult"] == 0
        assert euicc.profiles[0].state == ProfileState.ENABLED

        # Disable
        result = es10c.disable_profile(iccid=iccid)
        assert result["disableResult"] == 0
        assert euicc.profiles[0].state == ProfileState.DISABLED

    def test_delete_profile(self, es10c, euicc_setup):
        euicc, _ = euicc_setup
        iccid = os.urandom(10)
        euicc.profiles.append(ProfileSlot(
            iccid=iccid,
            isdp_aid=euicc.allocate_isdp_aid(),
            state=ProfileState.DISABLED,
        ))

        result = es10c.delete_profile(iccid=iccid)
        assert result["deleteResult"] == 0
        assert len(euicc.profiles) == 0

    def test_cannot_delete_enabled_profile(self, es10c, euicc_setup):
        euicc, _ = euicc_setup
        iccid = os.urandom(10)
        euicc.profiles.append(ProfileSlot(
            iccid=iccid,
            isdp_aid=euicc.allocate_isdp_aid(),
            state=ProfileState.ENABLED,
        ))
        result = es10c.delete_profile(iccid=iccid)
        assert result["deleteResult"] == 2  # profileNotInDisabledState

    def test_set_nickname(self, es10c, euicc_setup):
        euicc, _ = euicc_setup
        iccid = os.urandom(10)
        euicc.profiles.append(ProfileSlot(
            iccid=iccid,
            isdp_aid=euicc.allocate_isdp_aid(),
        ))
        result = es10c.set_nickname(iccid, "My Profile")
        assert result["setNicknameResult"] == 0
        assert euicc.profiles[0].profile_nickname == "My Profile"

    def test_memory_reset(self, es10c, euicc_setup):
        euicc, _ = euicc_setup
        euicc.profiles.append(ProfileSlot(
            iccid=os.urandom(10),
            isdp_aid=euicc.allocate_isdp_aid(),
            state=ProfileState.DISABLED,
        ))
        euicc.default_smdp_address = "smdp.test.com"

        result = es10c.euicc_memory_reset()
        assert result["resetResult"] == 0
        assert len(euicc.profiles) == 0
        assert euicc.default_smdp_address == ""
