from pathlib import Path

import pytest

from watermargin.c2pa_layer import Signer
from watermargin.certs import generate_dev_cert

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_image() -> Path:
    return FIXTURES_DIR / "sample.jpg"


@pytest.fixture
def dev_signer() -> Signer:
    dc = generate_dev_cert()
    return Signer(cert_pem=dc.cert_pem, key_pem=dc.key_pem)


@pytest.fixture
def tmp_output(tmp_path: Path) -> Path:
    return tmp_path / "output.jpg"
