import contextlib
import socket
from dataclasses import dataclass, field
from enum import StrEnum, auto
from pathlib import Path

import rich
from cryptography.x509 import Certificate, DNSName, load_pem_x509_certificate
from cryptography.x509.verification import PolicyBuilder, Store
from OpenSSL import SSL

from pytooling.logs import root_logger

logger = root_logger.getChild(__name__)


class VerificationType(StrEnum):
    """The types of verification to perform on the certificate."""

    CHAIN_OF_SIGNING = auto()
    "Verify that each certificate is signed by another certificate in the chain."

    FULL_CRYPTOGRAPHIC = auto()
    """Verify the certificate using Cryptography's server verifier module. 
    This should be the most complete verification possible.
    """


@dataclass
class SingleVerification:
    """The result of a single validation operation."""

    verification_type: VerificationType
    passed: bool = False
    message: str | None = None


@dataclass
class VerificationResult:
    """The results of a collection of certificate + chain validation operation."""

    host: str
    results: dict[VerificationType, SingleVerification] = field(default_factory=dict)
    errors: list = field(default_factory=list)

    def validated(self) -> bool:
        """Whether the operation passed all validations.

        There must be at least one validation (an empty result set is False)."""
        if len(self.results) == 0:
            return False

        return all(result.passed for result in self.results.values())

    def add_exception(self, err: Exception, description: str = None) -> None:
        """Add an exception to the list of stored errors.

        Args:
            err (Exception): The exception to add.

            description (str, optional): An optional description. This is prepended to the error message.
            Defaults to None.

        """
        msg = f"{description} - " if description else ""
        msg += f"{type(err).__name__}: {str(err)}"
        self.errors.append(msg)


class CertVerifier:
    def __init__(
        self,
        host: str,
        port: int = 443,
        proxy_host: str = None,
        proxy_port: int = 8080,
        fallback: bool = False,
        trust: str | list[Certificate] | Path | None = "certifi",
    ):
        """_summary_.

        Args:
            host (str): The web address for the host.

            port (int, optional): The port to conenct to the host on. Defaults to 443.

            proxy_host (str, optional): An optional proxy host to use.

            proxy_port (int, optional): The port to use to connect to the proxy. Ignored if proxy_host is not specified.
            Defaults to None.

            fallback (bool, optional): Whether to try connecting directly to the host if the proxy is supplied but
            doesn't work. Defaults to False.

            trust (str | list[Certificate] | Path | None, optional): The trusted certificates to use to validate the
            certificate. Defaults to "certifi".
                - If "certifi", the the certifi package is used to establish trust store using the system default
                certificates.
                - Path: Load all of the certificates loaded in the given folder and use them as a trust store.
                The certificates should be PEM-formatted.
                - list[Certificate]: Use the given certificates as the trust.
                - None: Do not use a trust store. The server must supply a root certificate itself to validate chain
                signing, and the connection will probably fail any strict validation since no certificate is trusted.

        """
        self.host: str = host
        self.port: str = port
        self.proxy_host: str = proxy_host
        self.proxy_port: str = proxy_port
        self.fallback: bool = fallback
        self.trust: str | list[Certificate] | Path | None = trust

    def verify(self, verifications: list[VerificationType] = None) -> VerificationResult:
        """Validate that a given domain presents a complete chain of certificates, and optionally verify the chain.

        Args:
            verifications (list[VerificationType], optional): The verifications to perform. If None, all possible
            verifications are performed.

        Returns:
            VerificationResult: The result of the operation

        """
        result = VerificationResult(host=self.host)

        try:
            chain_certs = self.get_chain()
        except Exception as err:
            result.add_exception(err, "Problem getting the certificate chain from the source.")
            return result

        try:
            get_root(chain_certs)
            validate_cert_chain(chain_certs)
        except Exception as err:
            result.add_exception(err)
            return result

        if verifications:
            verify_chain_validity(self.host, chain_certs, result)

        if not result.errors:
            result.validated = True

        return result

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
        )


def _get_chain(
    host: str, port: int = 443, proxy_host: str = None, proxy_port: int = 8080, fallback: bool = False
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

    Raises:
        LookupError: If the certificate and chain could not be retrieved.
        ConnectionError: If the connection could not be established.

    Returns:
        list[Certificate]: A list of Certificate objects that make up the leaf and intermediates in the chain.

    """
    conn = _create_connection(host, port, proxy_host, proxy_port, fallback)
    return _get_chain_from_connection(host, conn)


def _create_connection(host: str, port: int, proxy_host: str, proxy_port: int, fallback: bool) -> SSL.Connection:
    "Create a connection to a remote host, optionally using a proxy."
    if proxy_host:
        try:
            return _create_connection_proxy(host, port, proxy_host, proxy_port)
        except Exception as err:
            logger.error(f"Problem establishing proxied connection: {err}")

    if fallback or not proxy_host:
        try:
            return _create_connection_direct(host, port)
        except Exception as err:
            logger.error(f"Problem establishing direct connection: {err}")

    raise ConnectionError("No connection to the remote host could be established")


def _create_connection_proxy(host: str, port: int, proxy_host: str, proxy_port: int) -> SSL.Connection:
    """Create a SSL connection to a remote host via a HTTPS proxy.

    Args:
        host (str): The remote host to connect to.
        port (int): The port to connect to the remote host on.
        proxy_host (str): The hostname of the proxy.
        proxy_port (int): The port to connect to the proxy on.

    Returns:
        SSL.Connection: The established connection to the remote host.

    """
    logger.debug(f"Creating proxied connection to {host}:{port} via {proxy_host}:{proxy_port}")
    headers = f"CONNECT {host}:{port} HTTP/1.0\r\nConnection: close\r\n\r\n"

    s = socket.create_connection((proxy_host, proxy_port), timeout=10)
    s.settimeout(None)
    s.send(headers.encode("utf-8"))
    response = s.recv(3000)
    print("Proxy Response: " + str(response))
    conn = SSL.Connection(SSL.Context(SSL.TLS_METHOD), s)

    return conn


def _create_connection_direct(host: str, port: int = 443) -> SSL.Connection:
    """Create a direct SSL connection to a remote host."""
    logger.debug(f"Creating direct connection to {host}:{port}")
    dst = (host, port)
    conn = socket.create_connection(dst, timeout=5)
    return _get_chain_from_connection(host, conn)


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
    trusted_certs = [load_pem_x509_certificate(file.read_bytes()) for file in fp.glob("*")]
    return trusted_certs


def verify_chain_validity(subject: str, chain_certs: list[Certificate], result: VerificationResult) -> None:
    try:
        store = Store(_get_trusted_certs())
        builder = PolicyBuilder()
        builder = builder.store(store)
        builder = builder.max_chain_depth(15)
        verifier = builder.build_server_verifier(DNSName(subject))
    except Exception as err:
        result.add_exception(err, "Problem building certificate verification engine.")
        return None
    try:
        verifier.verify(chain_certs[-1], chain_certs[:-1])
    except Exception as err:
        result.add_exception(err, "Problem validating the certificate.")


def validate_cert_chain(chain_certs: list[Certificate]) -> None:
    """Verify that all of the certificates are signed by a certificate in the given list of Certificates.

    The root certificate would be self-signed, and therefore pass this check.

    Args:
        chain_certs (list[Certificate]): The list of certificate to check against

    Raises:
        LookupError: If any certificate is not signed by any of the provided certificates

    """
    for cert in chain_certs:
        verify_cert_signed_by_any(cert, chain_certs)

    logger.info("The certificate chain passes basic verification; All certs are signed by a presented cert.")


def verify_cert_signed_by_any(cert: Certificate, chain_certs: list[Certificate]) -> None:
    """Verify that the given certificate is signed by a certificate in the given list of Certificates.

    Args:
        cert (Certificate): The certificate to validate
        chain_certs (list[Certificate]): The list of certificate to check against

    Raises:
        LookupError: If the certificate is not signed by any of the provided certificates

    """
    for c in chain_certs:
        with contextlib.suppress(Exception):
            cert.verify_directly_issued_by(c)
            logger.debug(f"Validated {cert.subject.rfc4514_string()} was signed by {c.subject.rfc4514_string()}")
            return

    raise LookupError(f"Certificate {cert.subject} was not signed by any presented certificate.")


def get_intermediate_certs(chain_certs: list[Certificate]) -> list[Certificate]:
    intermediates = chain_certs.copy()
    intermediates.remove(get_root(intermediates))

    if len(intermediates) == 0:
        raise LookupError("Only the root cert is present in the chain.")

    logger.debug(f"Got {len(intermediates)} intermediate certificates.")
    return intermediates


def get_root(certs: list[Certificate], raise_err: bool = True) -> Certificate | None:
    """Get the root certificate from a list of certs.

    Args:
        certs (list[Certificate]]): A list of certificates to get the root certificate from.

        raise_err(bool): If True, raise a LookupError if the root certificate is missing.

    Returns:
        Certificate | None: The root certificate, or None if not found.

    """

    trusted_certs = _get_trusted_certs()

    for cert in certs:
        with contextlib.suppress(Exception):
            cert.verify_directly_issued_by(cert)
            logger.debug(f"Found root certificate embedded in chain: {cert.subject.rfc4514_string()}")
            return cert

    for cert in certs:
        for trust in trusted_certs:
            with contextlib.suppress(Exception):
                cert.verify_directly_issued_by(trust)
                logger.debug(f"Found root certificate in trust store (not embedded): {cert.subject.rfc4514_string()}")
                return trust

    if raise_err:
        raise LookupError(
            "The root certificate could not be identified. "
            "The certificate chain does not contain a root and none of the certificates in the trust store were used "
            "to sign any certificate in the chain."
        )

    logger.debug("The provided certificate chain does not contain a root certificate.")
    return None


if __name__ == "__main__":
    r = verify_chain("incomplete-chain.badssl.com")

    rich.print(r)

    pass
