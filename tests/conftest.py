"""Test fixtures and configuration for esim-simulator tests."""
import pytest
import tempfile
import pathlib
import structlog
import logging

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING)
)

from app.models.euicc import EuiccState
from app.crypto.certificates import CertificateInfrastructure
from app.services.euicc_manager import EuiccInstance


@pytest.fixture
def test_eid():
    return "89049032123451234512345678901235"


@pytest.fixture
def euicc_state(test_eid):
    return EuiccState(eid=test_eid, default_smdp_address="smdp.example.com")


@pytest.fixture
def tmp_certs_dir():
    return pathlib.Path(tempfile.mkdtemp())
