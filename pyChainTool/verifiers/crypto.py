"""A verifier function for use in the top-level CertVerifier class."""

from cryptography.x509 import Certificate, DNSName
from cryptography.x509.verification import PolicyBuilder, Store

from pyChainTool.models import SingleVerification, Verification


def verify_full_cryptographic(
    host: str, chain_certs: list[Certificate], trusted_certs: list[Certificate]
) -> SingleVerification:
    """Verify the validity of the certificate and chain using Cryptography.

    Args:
        host (str): The hostname of the leaf.
        chain_certs (list[Certificate]): The chain retrieved from the server.
        trusted_certs (list[Certificate]): The certificates that make up the trust store.

    Returns:
        SingleVerification: The result of the verification

    """
    result = SingleVerification(verification_type=Verification.FULL_CRYPTOGRAPHIC)

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
    return result
