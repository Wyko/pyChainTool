"""Verify that a given chain, plus the contents of the trust store, can result in finding a valid root.
Without a trust store, this can only pass if the server presents a root certificate in its chain, which
may actually violate some standards."""

from cryptography.x509 import Certificate

from pyChainTool import ops
from pyChainTool.logs import get_logger
from pyChainTool.models import SingleVerification

logger = get_logger(__name__)

__all__ = ["has_root"]


def has_root(chain_certs: list[Certificate], trusted_certs: list[Certificate], **_) -> SingleVerification:
    """Verify that a given chain, plus the contents of the trust store, can result in finding a valid root.

    Without a trust store, this can only pass if the server presents a root certificate in its chain, which
    may actually violate some standards.

    Args:
        chain_certs (list[Certificate]): The chain presented by the server

        trusted_certs (list[Certificate]): A list of trusted certificates to use as root

    Returns:
        SingleVerification: The result of the verification

    """
    logger.debug("Starting verification: has_root")
    result = SingleVerification("has_root")
    root = ops.get_root(chain_certs, trusted_certs)
    if root:
        result.passed = True
        result.message = f"Found root certificate {root.subject.rfc4514_string()}"
        return result

    result.message = (
        "The root certificate could not be identified. "
        "The certificate chain does not contain a root and none of the certificates in the trust store were used "
        "to sign any certificate in the chain."
    )
    return result
