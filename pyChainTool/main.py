"""The main entry point to the verification system.

Users should import the `CertVerifier` class and create a new instance, supplying (at least) a valid host (a remote
url) to pull a certificate chain from. Then call the instance's `.verify()` method to perform the checks.
"""

from pathlib import Path

import rich
from cryptography.x509 import Certificate

from pyChainTool import checks, guard, ops
from pyChainTool.logs import get_logger
from pyChainTool.models import VerificationResult

logger = get_logger(__name__)


class CertVerifier:
    """Verify certificates and their associated chain from a remote host.

    This module allows for much more basic certificate validation than Cryptography's (although full validation
    is an option here). The original use case for this tool was to validate that a remote host was
    presenting intermediates, even if I didn't posses the root certificate in my own trust store.

    It also was designed to validate the validity of a certificate against a custom trust store, totally ignoring
    the system trust store.

    Usage:
    -----

    >>> r = CertVerifier("google.com", trust="certifi").verify()
    >>> rich.print(r)
    VerificationResult(
        host='google.com',
        results=[
            SingleVerification(
                'Has_root',
                Passed=True,
                Message='Found root certificate CN=GTS Root R1,O=Google Trust Services LLC,C=US'
            ),
            SingleVerification('All_signed_by_any', Passed=True),
            SingleVerification(
                'Full_cryptographic',
                Passed=False,
                Message=(
                    'Problem validating the certificate: validation failed: '
                    'Other("EE keyUsage must not assert keyCertSign")'
                )
            )
        ]
    )

    """

    def __init__(
        self,
        host: str,
        port: int = 443,
        trust: str | list[Certificate] | Path | None = None,
        proxy_host: str = None,
        proxy_port: int = 8080,
        fallback: bool = False,
    ):
        """Create a new instance of the CertVerifier.

        Args:
            host (str): The web address for the host.

            port (int, optional): The port to conenct to the host on. Defaults to 443.

            trust (str | list[Certificate] | Path | None, optional): The trusted certificates to use to validate the
            certificate. Defaults to None. The options are:

            - `str`: If `"certifi"`, then the `certifi` package is used to establish a trust store using a set of
                default certificates from Mozilla. No other string is accepted.

            - `Path`: Load all of the certificates loaded in the given folder and use them as a trust store.
                The certificates should be PEM-formatted.

            - `list[Certificate]`: Use the given certificates as the trust.

            - `None`: no trust store will be used. The server must supply a root certificate itself to validate chain
                signing, and the connection will probably fail any strict validation since no certificate is
                trusted.

            proxy_host (str, optional): An optional proxy host to use.

            proxy_port (int, optional): The port to use to connect to the proxy. Ignored if proxy_host is not specified.
            Defaults to None.

            fallback (bool, optional): Whether to try connecting directly to the host if the proxy is supplied but
            doesn't work. Defaults to False.

            timeout (int, optional): The timeout for the connection, in seconds.

        """
        self.host: str = host
        self.port: str = port
        self.proxy_host: str = proxy_host
        self.proxy_port: str = proxy_port
        self.fallback: bool = fallback
        self.trust: str | list[Certificate] | Path | None = trust
        self.timeout: int = 10

        self._trust_store: list[Certificate] | None = None

    def verify(self, verifications: list[str] | None = None) -> VerificationResult:
        """Validate that a given domain presents a complete chain of certificates, and optionally verify the chain.

        Args:
            verifications (list[str], optional): The verifications to perform. If None, all possible
            verifications are performed.

        Raises:
            LookupError: If the certificate chain could not be retireved from the source.

        Returns:
            VerificationResult: The result of the operation

        """
        result = VerificationResult(host=self.host)

        if verifications is None:
            verifications = checks.__all__

        guard.all_values_are_valid_verifications(verifications)

        trusted_certs = self.get_trusted_certs()
        chain_certs = self.get_chain()

        for check in verifications:
            func = getattr(checks, check)
            result.results.append(func(host=self.host, chain_certs=chain_certs, trusted_certs=trusted_certs))

        return result

    def get_trusted_certs(self) -> list[Certificate]:
        """Return a list of trusted certificates.

        Returns:
            list[Certificate]: The trusted certificates.

        """
        if self._trust_store is not None:
            logger.debug("Returning cached trusted certs")
            return self._trust_store

        logger.debug("Loading trusted certs")

        if self.trust is None:
            logger.warning("Trust store set to an empty list since no trust was supplied")
            self._trust_store = []

        elif self.trust == "certifi":
            self._trust_store = ops.get_trusted_certs_from_certifi()

        elif isinstance(self.trust, list):
            if not all((isinstance(x, Certificate) for x in self.trust)):
                raise ValueError("Trust entries given as a list must all be x509.Certificate objects")
            self._trust_store = self.trust

        elif isinstance(self.trust, (Path, str)):
            self._trust_store = ops.get_trusted_certs_from_path(self.trust)

        elif self._trust_store is None:
            raise ValueError(f"Unknown trust type: {self.trust}")

        return self._trust_store

    def get_chain(self) -> list[Certificate]:
        """Get the certificate chain from a host.

        Raises:
            LookupError: If the certificate and chain could not be retrieved.
            ConnectionError: If the connection could not be established.

        Returns:
            list[Certificate]: A list of Certificate objects that make up the leaf and intermediates in the chain.

        """
        try:
            return ops.get_chain(
                host=self.host,
                port=self.port,
                proxy_host=self.proxy_host,
                proxy_port=self.proxy_port,
                fallback=self.fallback,
                timeout=self.timeout,
            )
        except Exception as err:
            raise LookupError(f"Problem getting the certificate chain from {self.host}.") from err

    def get_root(self, chain_certs: list[Certificate]) -> Certificate | None:
        """Get the root certificate from a list of certs.

        Args:
            chain_certs (list[Certificate]]): A list of certificates to get the root certificate from.

        Returns:
            Certificate | None: The root certificate, or None if not found.

        """

        trusted_certs = self.get_trusted_certs()
        return ops.get_root(certs=chain_certs, trusted_certs=trusted_certs)

    def __setattr__(self, name, value):
        """Intercept calls to update the trust since we cache the trust and otherwise the new value wouldn't be used."""
        if name == "trust":
            logger.debug("Clearing cached trust store")
            self._trust_store = None
        super(CertVerifier, self).__setattr__(name, value)


if __name__ == "__main__":
    # verifier = CertVerifier("incomplete-chain.badssl.com")  # noqa: ERA001
    # r = verifier.verify(verifications=[Verification.ALL_SIGNED_BY_ANY])  # noqa: ERA001
    verifier = CertVerifier("google.com", trust="certifi")
    r = verifier.verify()
    rich.print(r)
