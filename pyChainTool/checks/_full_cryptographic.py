"""Verify the validity of the certificate and chain using Cryptography."""

from cryptography.x509 import Certificate, DNSName
from cryptography.x509.verification import PolicyBuilder, Store

from pyChainTool.logs import get_logger
from pyChainTool.models import SingleVerification

logger = get_logger(__name__)

__all__ = ["full_cryptographic"]


def full_cryptographic(
    host: str, chain_certs: list[Certificate], trusted_certs: list[Certificate], **_
) -> SingleVerification:
    """Verify the validity of the certificate and chain using Cryptography.

    Args:
        host (str): The hostname of the leaf.
        chain_certs (list[Certificate]): The chain retrieved from the server.
        trusted_certs (list[Certificate]): The certificates that make up the trust store.

    Returns:
        SingleVerification: The result of the verification

    """
    logger.debug("Starting full cryptographic verification.")
    result = SingleVerification("full_cryptographic")

    try:
        store = Store(trusted_certs)  # @IgnoreException
        builder = PolicyBuilder()
        builder = builder.store(store)
        builder = builder.max_chain_depth(15)
        verifier = builder.build_server_verifier(DNSName(host))
    except Exception as err:
        result.message = "Problem building certificate verification engine: " + str(err)
        return result

    try:
        verifier.verify(chain_certs[-1], chain_certs[:-1])
    except Exception as err:
        result.message = "Problem validating the certificate: " + str(err)
        return result

    result.passed = True
    logger.debug("Full cryptographic verification passed.")
    return result
