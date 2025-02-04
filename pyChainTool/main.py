"""The main entry point to the verification system.

Users should import the `CertVerifier` class and create a new instance, supplying (at least) a valid host (a remote
url) to pull a certificate chain from. Then call the instance's `.verify()` method to perform the checks.
"""

import contextlib
import socket
from pathlib import Path

import certifi
import rich
from cryptography.x509 import Certificate, load_pem_x509_certificate, load_pem_x509_certificates
from OpenSSL import SSL

from pyChainTool.logs import root_logger
from pyChainTool.models import SingleVerification, Verification, VerificationResult
from pyChainTool.verifiers.crypto import verify_full_cryptographic
from pyChainTool.verifiers.validate_cert_chain import verify_cert_chain_all_signed_by_any

logger = root_logger.getChild(__name__)


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

            - `None`: Do not use a trust store. The server must supply a root certificate itself to validate chain
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

    def verify(self, verifications: list[Verification] = None) -> VerificationResult:
        """Validate that a given domain presents a complete chain of certificates, and optionally verify the chain.

        Args:
            verifications (list[VerificationType], optional): The verifications to perform. If None, all possible
            verifications are performed.

        Raises:
            LookupError: If the certificate chain could not be retireved from the source.

        Returns:
            VerificationResult: The result of the operation

        """
        do_all = verifications is None
        result = VerificationResult(host=self.host)

        try:
            chain_certs = self.get_chain()
        except Exception as err:
            raise LookupError(f"Problem getting the certificate chain from {self.host}.") from err

        if do_all or Verification.HAS_ROOT in verifications:
            result.results.append(self._verify_chain_has_root(chain_certs))

        if do_all or Verification.ALL_SIGNED_BY_ANY in verifications:
            result.results.append(verify_cert_chain_all_signed_by_any(chain_certs, self.get_trusted_certs()))

        if do_all or Verification.FULL_CRYPTOGRAPHIC in verifications:
            result.results.append(verify_full_cryptographic(self.host, chain_certs, self.get_trusted_certs()))

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
            self._trust_store = _get_trusted_certs_from_certifi()

        elif isinstance(self.trust, list):
            if not all((isinstance(x, Certificate) for x in self.trust)):
                raise ValueError("Trust entries given as a list must all be x509.Certificate objects")

            self._trust_store = self.trust

        elif isinstance(self.trust, Path):
            self._trust_store = _get_trusted_certs_from_path(self.trust)

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
        return _get_chain(
            host=self.host,
            port=self.port,
            proxy_host=self.proxy_host,
            proxy_port=self.proxy_port,
            fallback=self.fallback,
            timeout=self.timeout,
        )

    def get_root(self, chain_certs: list[Certificate]) -> Certificate | None:
        """Get the root certificate from a list of certs.

        Args:
            chain_certs (list[Certificate]]): A list of certificates to get the root certificate from.

        Returns:
            Certificate | None: The root certificate, or None if not found.

        """

        trusted_certs = self.get_trusted_certs()
        return _get_root(certs=chain_certs, trusted_certs=trusted_certs)

    def _verify_chain_has_root(self, chain_certs: list[Certificate]) -> SingleVerification:
        """Verify that a given chain, plus the contents of the trust store, can result in finding a valid root.

        Without a trust store, this can only pass if the server presents a root certificate in its chain, which
        may actually violate some standards.

        Args:
            chain_certs (list[Certificate]): The chain presented by the server

        Returns:
            SingleVerification: The result of the verification

        """
        result = SingleVerification(Verification.HAS_ROOT)
        root = self.get_root(chain_certs)
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

    def __setattr__(self, name, value):
        """Intercept calls to update the trust since we cache the trust and otherwise the new value wouldn't be used."""
        if name == "trust":
            logger.debug("Clearing cached trust store")
            self._trust_store = None
        super(CertVerifier, self).__setattr__(name, value)


def _get_root(certs: list[Certificate], trusted_certs: list[Certificate] = None) -> Certificate | None:
    """Get the root certificate from a list of certs.

    Args:
        certs (list[Certificate]]): A list of certificates to get the root certificate from.

        trusted_certs (list[Certificate], optional): A list of trusted certificates.

    Returns:
        Certificate | None: The root certificate, or None if not found.

    """

    for cert in certs:
        with contextlib.suppress(Exception):
            cert.verify_directly_issued_by(cert)  # @IgnoreException
            logger.debug(f"Found root certificate embedded in chain: {cert.subject.rfc4514_string()}")
            return cert

    if trusted_certs:
        for cert in certs:
            for trust in trusted_certs:
                with contextlib.suppress(Exception):
                    cert.verify_directly_issued_by(trust)  # @IgnoreException
                    logger.debug(f"Found root in trust store (not embedded): {cert.subject.rfc4514_string()}")
                    return trust

    logger.debug("The provided certificate chain does not contain a root certificate.")
    return None


def _get_chain(
    host: str,
    port: int = 443,
    proxy_host: str = None,
    proxy_port: int = 8080,
    fallback: bool = False,
    timeout: int = 10,
) -> list[Certificate]:
    """Get the certificate chain from a host.

    Args:
        host (str): The web address for the host.

        port (int, optional): The port to conenct to the host on. Defaults to 443.

        proxy_host (str, optional): An optional proxy host to use.

        proxy_port (int, optional): The port to use to connect to the proxy. Ignored if proxy_host is not specified.
        Defaults to None.

        fallback (bool, optional): Whether to try connecting directly to the host if the proxy is supplied but
        doesn't work. Defaults to False.

        timeout (int, optional): The timeout for the connection, in seconds.

    Raises:
        LookupError: If the certificate and chain could not be retrieved.
        ConnectionError: If the connection could not be established.

    Returns:
        list[Certificate]: A list of Certificate objects that make up the leaf and intermediates in the chain.

    """
    conn = _create_connection(host, port, proxy_host, proxy_port, fallback, timeout)
    return _get_chain_from_connection(host, conn)


def _create_connection(
    host: str, port: int, proxy_host: str, proxy_port: int, fallback: bool, timeout: int = 10
) -> SSL.Connection:
    "Create a connection to a remote host, optionally using a proxy."
    if proxy_host:
        try:
            return _create_connection_proxy(host, port, proxy_host, proxy_port, timeout=timeout)
        except Exception as err:
            logger.error(f"Problem establishing proxied connection: {err}")

    if fallback or not proxy_host:
        try:
            return _create_connection_direct(host, port, timeout=timeout)
        except Exception as err:
            logger.error(f"Problem establishing direct connection: {err}")

    raise ConnectionError("No connection to the remote host could be established")


def _create_connection_proxy(
    host: str, port: int, proxy_host: str, proxy_port: int, timeout: int = 10
) -> SSL.Connection:
    """Create a SSL connection to a remote host via a HTTPS proxy.

    Args:
        host (str): The remote host to connect to.
        port (int): The port to connect to the remote host on.
        proxy_host (str): The hostname of the proxy.
        proxy_port (int): The port to connect to the proxy on.
        timeout (int, optional): The timeout for the connection, in seconds.

    Returns:
        SSL.Connection: The established connection to the remote host.

    """
    logger.debug(f"Creating proxied connection to {host}:{port} via {proxy_host}:{proxy_port}")
    headers = f"CONNECT {host}:{port} HTTP/1.0\r\nConnection: close\r\n\r\n"

    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    s.settimeout(None)
    s.send(headers.encode("utf-8"))
    response = s.recv(3000)
    logger.debug("Proxy Response: " + str(response))
    return SSL.Connection(SSL.Context(SSL.TLS_METHOD), s)


def _create_connection_direct(host: str, port: int = 443, timeout: int = 10) -> SSL.Connection:
    """Create a direct SSL connection to a remote host."""
    logger.debug(f"Creating direct connection to {host}:{port}")
    dst = (host, port)
    s = socket.create_connection(dst, timeout=timeout)
    s.settimeout(None)
    return SSL.Connection(SSL.Context(SSL.TLS_METHOD), s)


def _get_chain_from_connection(host: str, conn: SSL.Connection) -> list[Certificate]:
    """Connect to a remote host and return the certificate chain that it presents.

    Args:
        host (str): The remote host to connect to.
        conn (SSL.Connection): The established SSL connection object to the remote host.

    Returns:
        list[Certificate]: The list of cryptography Certificate objects presented by the remote host.

    """
    logger.debug(f"Getting chain from established connection to {host}")
    conn.set_connect_state()
    conn.set_tlsext_host_name(host.encode())
    conn.sendall(b"HEAD / HTTP/1.0\n\n")
    conn.recv(16)
    certs = conn.get_peer_cert_chain()

    logger.debug("Got chain from source with %s embedded certificate(s).", len(certs))

    results = []
    for pos, cert in enumerate(certs):
        crypto_cert = cert.to_cryptography()
        results.append(crypto_cert)
        logger.debug("Certificate #" + str(pos))
        for component in cert.get_subject().get_components():
            logger.debug(f"Subject {component[0]}: {component[1]}")
        logger.debug("Issuer: " + str(crypto_cert.issuer))

    conn.shutdown()

    return results


def _get_trusted_certs_from_path(fp: Path) -> list[Certificate]:
    """Load all the certificates in a path.

    Args:
        fp (Path): The Path to load certificates from.

    Returns:
        list[Certificate]: A list of Certificate objects.

    """
    logger.debug("Loading trusted certificates from path %s", str(fp))
    trusted_certs = [load_pem_x509_certificate(file.read_bytes()) for file in fp.glob("*")]
    return trusted_certs


def _get_trusted_certs_from_certifi() -> list[Certificate]:
    """Load all the certificates in the certifi trust store.

    Returns:
        list[Certificate]: A list of Certificate objects.

    """
    logger.debug("Loading trusted certificates from certifi")
    contents = certifi.contents()
    trusted_certs = load_pem_x509_certificates(contents.encode())
    return trusted_certs


if __name__ == "__main__":
    # verifier = CertVerifier("incomplete-chain.badssl.com")  # noqa: ERA001
    # r = verifier.verify(verifications=[Verification.ALL_SIGNED_BY_ANY])  # noqa: ERA001
    verifier = CertVerifier("google.com", trust="certifi")
    r = verifier.verify()
    rich.print(r)
