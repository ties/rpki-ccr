from pathlib import Path

import pytest

import rpki_ccr

DATA_DIR = Path(__file__).resolve().parents[2] / "rpki-ccr" / "tests" / "data"


@pytest.fixture(scope="session")
def example_der() -> bytes:
    return (DATA_DIR / "example.ccr").read_bytes()


@pytest.fixture(scope="session")
def multi_location_der() -> bytes:
    return (DATA_DIR / "multi-location.ccr").read_bytes()


@pytest.fixture
def example(example_der: bytes) -> rpki_ccr.Ccr:
    return rpki_ccr.Ccr.decode(example_der)
