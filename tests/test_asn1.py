"""Tests for ASN.1 DER encoding/decoding."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.asn1_codec import Asn1Codec


@pytest.fixture
def codec():
    return Asn1Codec()


class TestAsn1Codec:
    def test_schema_compiles(self, codec):
        assert len(codec.schema.types) == 68

    def test_server_signed1_roundtrip(self, codec):
        data = {
            "transactionId": os.urandom(16),
            "euiccChallenge": os.urandom(16),
            "serverAddress": "smdpplus.connectxiot.com",
            "serverChallenge": os.urandom(16),
        }
        der = codec.encode_server_signed1(data)
        decoded = codec.decode("ServerSigned1", der)
        assert decoded["transactionId"] == data["transactionId"]
        assert decoded["serverAddress"] == data["serverAddress"]

    def test_euicc_signed1_roundtrip(self, codec):
        data = {
            "transactionId": os.urandom(16),
            "serverAddress": "test.example.com",
            "serverChallenge": os.urandom(16),
        }
        der = codec.encode_euicc_signed1(data)
        decoded = codec.decode("EuiccSigned1", der)
        assert decoded["serverAddress"] == "test.example.com"

    def test_euicc_signed2_roundtrip(self, codec):
        data = {
            "transactionId": os.urandom(16),
            "euiccOtpk": os.urandom(65),
        }
        der = codec.encode_euicc_signed2(data)
        decoded = codec.decode("EuiccSigned2", der)
        assert decoded["euiccOtpk"] == data["euiccOtpk"]

    def test_euicc_info1_has_bf20_tag(self, codec):
        data = {
            "svn": b"\x03\x01\x00",
            "euiccCiPKIdListForVerification": [os.urandom(20)],
            "euiccCiPKIdListForSigning": [os.urandom(20)],
        }
        der = codec.encode_euicc_info1(data)
        assert der[0:2] == b"\xbf\x20"  # Tag BF20

    def test_euicc_info2_encoding(self, codec):
        data = {
            "profileVersion": b"\x02\x03\x01",
            "svn": b"\x03\x01\x00",
            "euiccFirmwareVer": b"\x01\x00\x00",
            "extCardResource": b"\x82\x03\x07\x80\x00\x83\x03\x01\xc0\x00",
            "uiccCapability": b"\x07\x73",
            "rspCapability": b"\x04\x90",
            "euiccCiPKIdListForVerification": [os.urandom(20)],
            "euiccCiPKIdListForSigning": [os.urandom(20)],
            "certificationDataObject": {
                "platformLabel": "ConnectX-Simulator",
            },
            "ipaMode": 0,
            "iotSpecificInfo": {"iotVersion": b"\x01\x02\x00"},
        }
        der = codec.encode_euicc_info2(data)
        assert der[0:2] == b"\xbf\x22"  # Tag BF22
        decoded = codec.decode("EuiccInfo2", der)
        assert decoded["ipaMode"] == 0

    def test_profile_info_list_response(self, codec):
        data = ("profileInfoListOk", [
            {
                "iccid": os.urandom(10),
                "profileState": 1,
                "profileName": "Test Profile",
                "profileClass": 2,
            }
        ])
        der = codec.encode_profile_info_list_response(data)
        assert der[0:2] == b"\xbf\x2d"  # Tag BF2D

    def test_authenticate_server_response_ok(self, codec):
        data = ("authenticateResponseOk", {
            "euiccSigned1": {
                "transactionId": os.urandom(16),
                "serverAddress": "test.example.com",
                "serverChallenge": os.urandom(16),
            },
            "euiccSignature1": os.urandom(64),
            "euiccCertificate": os.urandom(32),
        })
        der = codec.encode_authenticate_server_response(data)
        assert der[0:2] == b"\xbf\x38"  # Tag BF38

    def test_authenticate_server_response_error(self, codec):
        data = ("authenticateResponseError", {
            "transactionId": os.urandom(16),
            "authenticateErrorCode": 2,  # invalidServerSignature
        })
        der = codec.encode_authenticate_server_response(data)
        assert der[0:2] == b"\xbf\x38"

    def test_prepare_download_response(self, codec):
        data = ("downloadResponseOk", {
            "euiccSigned2": {
                "transactionId": os.urandom(16),
                "euiccOtpk": os.urandom(65),
            },
            "euiccSignature2": os.urandom(64),
        })
        der = codec.encode_prepare_download_response(data)
        assert der[0:2] == b"\xbf\x21"  # Tag BF21

    def test_cancel_session_response(self, codec):
        data = ("cancelSessionResponseOk", {
            "euiccCancelSessionSigned": {
                "transactionId": os.urandom(16),
                "reason": 2,
            },
            "euiccCancelSessionSignature": os.urandom(64),
        })
        der = codec.encode_cancel_session_response(data)
        assert der[0:2] == b"\xbf\x41"  # Tag BF41

    def test_provide_eim_package_result(self, codec):
        data = ("ipaEuiccDataResponse", {
            "eid": os.urandom(16),
            "eimConfigList": [{"eimId": "test-eim", "counterValue": 5}],
        })
        der = codec.encode("ProvideEimPackageResult", data)
        decoded = codec.decode("ProvideEimPackageResult", der)
        assert decoded[0] == "ipaEuiccDataResponse"

    def test_notification_metadata(self, codec):
        data = {
            "seqNumber": 42,
            "profileManagementOperation": (b"\x80", 8),
            "notificationAddress": "smdp.example.com",
            "iccid": os.urandom(10),
        }
        der = codec.encode_notification_metadata(data)
        decoded = codec.decode("NotificationMetadata", der)
        assert decoded["seqNumber"] == 42

    def test_installation_result_data_for_signing(self, codec):
        data = {
            "transactionId": os.urandom(16),
            "notificationMetadata": {
                "seqNumber": 1,
                "profileManagementOperation": (b"\x80", 8),
                "notificationAddress": "smdp.example.com",
                "iccid": os.urandom(10),
            },
            "finalResult": ("successResult", {"aid": os.urandom(16)}),
        }
        der = codec.encode_profile_installation_result_data(data)
        assert len(der) > 0
        # Should be deterministic
        der2 = codec.encode_profile_installation_result_data(data)
        assert der == der2
