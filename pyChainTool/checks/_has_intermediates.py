"""Verify that the chain presents at least two certificates, not counting the root (if it is available). One
certificate must be the leaf, and the rest must be intermediate (non-self-signed) certificates. All but one
certificate must be signed by another available certificate (the last certificate is assumed to be signed by
the root)."""

from cryptography.x509 import Certificate

from pyChainTool.logs import get_logger
from pyChainTool.models import SingleVerification

logger = get_logger(__name__)

__all__ = ["has_intermediates"]


def has_intermediates(chain_certs: list[Certificate], trusted_certs: list[Certificate], **_) -> SingleVerification:
    """Verify that the chain presents at least two certificates, not counting the root (if it is available)."""
    logger.debug("Starting verification: has_intermediates")
    result = SingleVerification("has_intermediates")

    result.message = "Not implemented."
    return result
