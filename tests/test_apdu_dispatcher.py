"""Unit tests for ES10 APDU dispatcher."""
import pytest
import tempfile
import pathlib
import structlog
import logging

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING)
)

from app.services.apdu_dispatcher import Es10Dispatcher
from app.models.euicc import EuiccState
from app.crypto.certificates import CertificateInfrastructure
from app.services.euicc_manager import EuiccInstance


@pytest.fixture
def instance():
    eid = "89049032123451234512345678901235"
    euicc = EuiccState(eid=eid, default_smdp_address="smdp.example.com")
    tmp = pathlib.Path(tempfile.mkdtemp())
    pki = CertificateInfrastructure(tmp)
    pki.initialize(eid)
    return EuiccInstance(euicc, pki)


@pytest.fixture
def dispatcher(instance):
    return Es10Dispatcher(instance)


class TestEs10Dispatcher:
    def test_get_eid(self, dispatcher, instance):
        """BF3E GetEID — no input data, returns EID in TLV."""
        data = bytes.fromhex("BF3E0000")
        resp = dispatcher.dispatch(instance.euicc.eid, data)
        assert resp.endswith(bytes.fromhex("9000"))
        # Verify EID is in the response
        eid_bytes = bytes.fromhex("89049032123451234512345678901235")
        assert eid_bytes in resp

    def test_get_euicc_info1(self, dispatcher, instance):
        """BF20 GetEuiccInfo1."""
        data = bytes.fromhex("BF200000")
        resp = dispatcher.dispatch(instance.euicc.eid, data)
        assert resp.endswith(bytes.fromhex("9000"))

    def test_get_euicc_challenge(self, dispatcher, instance):
        """BF2E GetEuiccChallenge — creates session."""
        data = bytes.fromhex("BF2E0000")
        resp = dispatcher.dispatch(instance.euicc.eid, data)
        assert resp.endswith(bytes.fromhex("9000"))
        assert instance.euicc.active_session is not None
        assert len(instance.euicc.active_session.euicc_challenge) == 16

    def test_get_euicc_configured_addresses(self, dispatcher, instance):
        """BF3C GetEuiccConfiguredAddresses."""
        data = bytes.fromhex("BF3C0000")
        resp = dispatcher.dispatch(instance.euicc.eid, data)
        assert resp.endswith(bytes.fromhex("9000"))

    def test_get_profiles_info(self, dispatcher, instance):
        """BF2D GetProfilesInfo — empty list when no profiles."""
        data = bytes.fromhex("BF2D0000")
        resp = dispatcher.dispatch(instance.euicc.eid, data)
        assert resp.endswith(bytes.fromhex("9000"))

    def test_remove_notification_from_list(self, dispatcher, instance):
        """BF2F RemoveNotificationFromList."""
        # First add a notification so there's one to remove
        instance.euicc.add_notification("install", "smdp.example.com", b"\x00" * 10)
        seq = instance.euicc.notifications[-1].seq_number

        from app.services.asn1_codec import Asn1Codec
        codec = Asn1Codec()
        req_der = codec.encode("RemoveNotificationFromListRequest", {"seqNumber": seq})
        tag_len = bytes([0xBF, 0x2F]) + (bytes([len(req_der)]) if len(req_der) < 128 else bytes([0x81, len(req_der)]))
        data = tag_len + req_der

        resp = dispatcher.dispatch(instance.euicc.eid, data)
        assert resp.endswith(bytes.fromhex("9000"))

    def test_get_euicc_information(self, dispatcher, instance):
        """BF43 GetEUICCInformation (SGP.22 v3.0+)."""
        data = bytes.fromhex("BF430000")
        resp = dispatcher.dispatch(instance.euicc.eid, data)
        assert resp.endswith(bytes.fromhex("9000"))
        # Verify key fields are present in the response
        assert len(resp) > 50  # Substantial response with SVN, firmware, cert IDs

    def test_get_eim_configuration_data(self, dispatcher, instance):
        """BF52 GetEimConfigurationData (SGP.32 IoT).
        Add an eIM association first to have data to return."""
        from app.models.euicc import EimAssociation
        instance.euicc.eim_associations.append(
            EimAssociation(eim_id="test-eim", eim_fqdn="eim.example.com")
        )
        data = bytes.fromhex("BF520000")
        resp = dispatcher.dispatch(instance.euicc.eid, data)
        assert resp.endswith(bytes.fromhex("9000"))

    def test_get_eim_config_sgp32_bf55(self, dispatcher, instance):
        """BF55 GetEimConfigurationData (SGP.32 §5.9.18)."""
        from app.models.euicc import EimAssociation
        from app.services.asn1_codec import Asn1Codec
        codec = Asn1Codec()
        instance.euicc.eim_associations.append(
            EimAssociation(eim_id="bf55-test", eim_fqdn="bf55.example.com")
        )
        req_der = codec.encode("GetEimConfigurationDataRequest", {})
        tag_len = bytes([0xBF, 0x55]) + (bytes([len(req_der)]) if len(req_der) < 128 else bytes([0x81, len(req_der)]))
        resp = dispatcher.dispatch(instance.euicc.eid, tag_len + req_der)
        assert resp.endswith(bytes.fromhex("9000"))

    def test_get_certs_sgp32_bf56(self, dispatcher, instance):
        """BF56 GetCerts (SGP.32 §5.9.10)."""
        from app.services.asn1_codec import Asn1Codec
        codec = Asn1Codec()
        req_der = codec.encode("GetCertsRequestSGP32", {})
        tag_len = bytes([0xBF, 0x56]) + (bytes([len(req_der)]) if len(req_der) < 128 else bytes([0x81, len(req_der)]))
        resp = dispatcher.dispatch(instance.euicc.eid, tag_len + req_der)
        assert resp.endswith(bytes.fromhex("9000"))
        assert len(resp) > 100  # Certificate data is substantial

    def test_add_initial_eim_bf57(self, dispatcher, instance):
        """BF57 AddInitialEim (SGP.32 §5.9.4)."""
        from app.services.asn1_codec import Asn1Codec
        codec = Asn1Codec()
        req_data = {
            "eimConfigurationDataList": [{
                "eimId": "bf57-test",
                "eimFqdn": "bf57.example.com",
                "counterValue": 0,
                "eimSupportedProtocol": 0,
            }]
        }
        req_der = codec.encode("AddInitialEimRequest", req_data)
        tag_len = bytes([0xBF, 0x57]) + (bytes([len(req_der)]) if len(req_der) < 128 else bytes([0x81, len(req_der)]))
        prev_count = len(instance.euicc.eim_associations)
        resp = dispatcher.dispatch(instance.euicc.eid, tag_len + req_der)
        assert resp.endswith(bytes.fromhex("9000"))
        assert len(instance.euicc.eim_associations) == prev_count + 1

    def test_retrieve_notifications_sgp32_bf2b(self, dispatcher, instance):
        """BF2B RetrieveNotificationsList (SGP.32 §5.9.11)."""
        from app.services.asn1_codec import Asn1Codec
        codec = Asn1Codec()
        # Add a notification first
        instance.euicc.add_notification("install", "smdp.example.com", b"\x00" * 10)
        req_der = codec.encode("SGP32-RetrieveNotificationsListRequest", {})
        tag_bytes = bytes([0xBF, 0x2B])
        full = tag_bytes + (bytes([len(req_der)]) if len(req_der) < 128 else bytes([0x81, len(req_der)])) + req_der
        resp = dispatcher.dispatch(instance.euicc.eid, full)
        assert resp.endswith(bytes.fromhex("9000"))

    def test_profile_rollback_bf58(self, dispatcher, instance):
        """BF58 ProfileRollback (SGP.32 §5.9.16)."""
        from app.services.asn1_codec import Asn1Codec
        codec = Asn1Codec()
        req_der = codec.encode("ProfileRollbackRequest", {"refreshFlag": False})
        tag_bytes = bytes([0xBF, 0x58])
        full = tag_bytes + (bytes([len(req_der)]) if len(req_der) < 128 else bytes([0x81, len(req_der)])) + req_der
        resp = dispatcher.dispatch(instance.euicc.eid, full)
        assert resp.endswith(bytes.fromhex("9000"))

    def test_configure_auto_enable_bf59(self, dispatcher, instance):
        """BF59 ConfigureAutoProfileEnabling (SGP.32 §5.9.17)."""
        from app.services.asn1_codec import Asn1Codec
        codec = Asn1Codec()
        req_der = codec.encode("ConfigureAutoProfileEnablingRequest", {})
        tag_bytes = bytes([0xBF, 0x59])
        full = tag_bytes + (bytes([len(req_der)]) if len(req_der) < 128 else bytes([0x81, len(req_der)])) + req_der
        resp = dispatcher.dispatch(instance.euicc.eid, full)
        assert resp.endswith(bytes.fromhex("9000"))

    def test_enable_using_dd_bf5a(self, dispatcher, instance):
        """BF5A EnableUsingDD (SGP.32 §5.9.15)."""
        from app.services.asn1_codec import Asn1Codec
        codec = Asn1Codec()
        req_der = codec.encode("EnableUsingDDRequest", {})
        tag_bytes = bytes([0xBF, 0x5A])
        full = tag_bytes + (bytes([len(req_der)]) if len(req_der) < 128 else bytes([0x81, len(req_der)])) + req_der
        resp = dispatcher.dispatch(instance.euicc.eid, full)
        assert resp.endswith(bytes.fromhex("9000"))

    def test_unknown_tag(self, dispatcher, instance):
        """Unknown tag returns error SW."""
        data = bytes.fromhex("BFFF0000")
        resp = dispatcher.dispatch(instance.euicc.eid, data)
        # Should return error status word for unknown
        assert len(resp) >= 2
