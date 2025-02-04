import contextlib

from cryptography.x509 import Certificate

from pyChainTool.logs import root_logger
from pyChainTool.models import SingleVerification, Verification

logger = root_logger.getChild(__name__)


def _verify_cert_signed_by_any(
    cert: Certificate, chain_certs: list[Certificate], trusted_certs: list[Certificate]
) -> None | Certificate:
    """Verify that the given certificate is signed by a certificate in the given list of Certificates.

    Args:
        cert (Certificate): The certificate to validate
        chain_certs (list[Certificate]): The list of certificate to check against
        trusted_certs (list[Certificate]): A list of trusted certificates to use as root

    Returns:
        Certificate: The certificate that signed the given certificate
        None: If no signing certificate could be found

    """
    for c in chain_certs:
        with contextlib.suppress(Exception):
            cert.verify_directly_issued_by(c)  # @IgnoreException
            logger.debug(f"Validated {cert.subject.rfc4514_string()} was signed by {c.subject.rfc4514_string()}")
            return c

        for trust in trusted_certs:
            with contextlib.suppress(Exception):
                cert.verify_directly_issued_by(trust)  # @IgnoreException
                logger.debug(
                    f"Validated {cert.subject.rfc4514_string()} was signed by root {cert.subject.rfc4514_string()}"
                )
                return trust

    return None


def verify_cert_chain_all_signed_by_any(
    chain_certs: list[Certificate], trusted_certs: list[Certificate]
) -> SingleVerification:
    """Verify that all of the certificates are signed by a certificate in the given list of Certificates.

    The root certificate would be self-signed, and therefore pass this check.

    Args:
        chain_certs (list[Certificate]): The list of certificate to check against

        trusted_certs (list[Certificate]): A list of trusted certificates to use as root

    Returns:
        SingleVerification: The result of the verification

    """
    logger.debug("Verifying that all certificates in the chain are signed by a known certificate.")
    result = SingleVerification(Verification.ALL_SIGNED_BY_ANY)
    for cert in chain_certs:
        signing_cert = _verify_cert_signed_by_any(cert, chain_certs, trusted_certs)
        if not signing_cert:
            result.message = f"Certificate {cert.subject} was not signed by any presented or known certificate."
            return result

    logger.debug("The certificate chain passes basic verification; All certs are signed by a presented cert.")
    result.passed = True
    return result
