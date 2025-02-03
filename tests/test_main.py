# pylint: disable=W0212:protected-access

import rich
from cryptography.x509 import Certificate

from pyChainTool import main


def test__get_trusted_certs_from_certifi():
    """Validate that _get_trusted_certs_from_certifi loads certificates correctly."""

    certs = main._get_trusted_certs_from_certifi()
    assert len(certs)
    assert isinstance(certs[0], Certificate)


def test__verify_google_all_certifi():
    verifier = main.CertVerifier("google.com", trust="certifi")
    result = verifier.verify()
    rich.print(result)
    assert result
