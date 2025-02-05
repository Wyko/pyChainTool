"""Tests for the main.py file."""

# pylint: disable=W0212:protected-access
# pylint: disable=C0116:missing-function-docstring

import rich
from cryptography.x509 import Certificate

import pyChainTool.ops
from pyChainTool import checks, main


def test__get_trusted_certs_from_certifi():
    """Validate that _get_trusted_certs_from_certifi loads certificates correctly."""

    certs = pyChainTool.ops.get_trusted_certs_from_certifi()
    assert len(certs)
    assert isinstance(certs[0], Certificate)


def test__verify_google_all_certifi():
    verifier = main.CertVerifier("google.com", trust="certifi")
    result = verifier.verify()
    rich.print(result)
    assert result
    assert len(result.results) == len(checks.get_verifiers())


def test_updting_trust_updates_cache():
    verifier = main.CertVerifier("google.com", trust=None)
    assert verifier._trust_store is None

    # The first time this is called, it should use the original value (None) to populate the store
    verifier.get_trusted_certs()
    assert verifier._trust_store == []

    # Assigning a new trust should clear the store
    verifier.trust = "certifi"
    assert verifier._trust_store is None

    # Calling get_trusted_certs again should set a new value in the store
    verifier.get_trusted_certs()
    assert len(verifier._trust_store) > 10
    assert isinstance(verifier._trust_store[0], Certificate)
