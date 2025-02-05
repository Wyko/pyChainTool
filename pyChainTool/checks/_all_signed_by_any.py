"""Verify that the given certificate is signed by any certificate in the trust store or list of certificates."""

import contextlib

from cryptography.x509 import Certificate

from pyChainTool.logs import get_logger
from pyChainTool.models import SingleVerification

logger = get_logger(__name__)

__all__ = ["all_signed_by_any"]


def all_signed_by_any(chain_certs: list[Certificate], trusted_certs: list[Certificate], **_) -> SingleVerification:
    """Verify that all of the certificates are signed by a certificate in the given list of Certificates.

    The root certificate would be self-signed, and therefore pass this check.

    Args:
        chain_certs (list[Certificate]): The list of certificate to check against

        trusted_certs (list[Certificate]): A list of trusted certificates to use as root

    Returns:
        SingleVerification: The result of the verification

    """
    logger.debug("Verifying that all certificates in the chain are signed by a known certificate.")
    result = SingleVerification("all_signed_by_any")
    for cert in chain_certs:
        signing_cert = _verify_cert_signed_by_any(cert, chain_certs, trusted_certs)
        if not signing_cert:
            result.message = f"Certificate {cert.subject} was not signed by any presented or known certificate."
            return result

    logger.debug("The certificate chain passes basic verification; All certs are signed by a presented cert.")
    result.passed = True
    return result


def _verify_cert_signed_by_any(
    cert: Certificate, chain_certs: list[Certificate], trusted_certs: list[Certificate]
) -> None | Certificate:
    """Verify that the given certificate is signed by any certificate in the trust store or list of certificates.

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
