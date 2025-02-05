"""Operations carried out by the main interfaces in the package."""

import contextlib
import socket
from pathlib import Path

import certifi
from cryptography.x509 import Certificate, load_pem_x509_certificate, load_pem_x509_certificates
from OpenSSL import SSL

from pyChainTool.logs import get_logger

logger = get_logger(__name__)


def get_root(certs: list[Certificate], trusted_certs: list[Certificate] = None) -> Certificate | None:
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


def get_chain(
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


def get_trusted_certs_from_path(fp: Path | str) -> list[Certificate]:
    """Load all the certificates in a path.

    Args:
        fp (Path): The Path to load certificates from.

    Returns:
        list[Certificate]: A list of Certificate objects.

    """
    logger.debug("Loading trusted certificates from path %s", str(fp))
    if isinstance(fp, str):
        fp = Path(fp)

    trusted_certs = [load_pem_x509_certificate(file.read_bytes()) for file in fp.glob("*")]
    return trusted_certs


def get_trusted_certs_from_certifi() -> list[Certificate]:
    """Load all the certificates in the certifi trust store.

    Returns:
        list[Certificate]: A list of Certificate objects.

    """
    logger.debug("Loading trusted certificates from certifi")
    contents = certifi.contents()
    trusted_certs = load_pem_x509_certificates(contents.encode())
    return trusted_certs
