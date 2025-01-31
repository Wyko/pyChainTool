import contextlib
import socket
from dataclasses import dataclass, field

import rich
from cryptography.x509 import Certificate, DNSName, load_pem_x509_certificate
from cryptography.x509.verification import PolicyBuilder, Store
from OpenSSL import SSL

from pytooling.logs import root_logger

logger = root_logger.getChild(__name__)


@dataclass
class VerificationResult:
    """The results of a certificate + chain validation operation."""

    domain: str
    validated: bool = False
    errors: list = field(default_factory=list)

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


def get_chain(host: str, port: int = 443, proxy_host: str = None, proxy_port: int = 8080, fallback: bool = False) -> list[Certificate]:
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

    Returns:
        list[Certificate]: A list of Certificate objects that make up the leaf and intermediates in the chain.

    """

    if proxy_host:
        
    errors = []
    for method in [
        _get_chain_proxy,
        _get_chain_direct,
    ]:
        try:
            chain = method(host, port)
            logger.debug(f"Got chain from source with {len(chain)} embedded certificate(s).")
            return chain
        except Exception as err:
            errors.append(err)

    for err in errors:
        logger.error("Failed to get certificate chain for %s: %s", host, str(err))

    raise LookupError("Failed to get certificate chain by any means.")


def _get_chain_proxy(subject: str, port: int = 443) -> list[Certificate]:
    headers = f"CONNECT {subject}:{port} HTTP/1.0\r\nConnection: close\r\n\r\n"

    proxy_host = "giba-proxy.wps.ing.net"  # proxy server IP
    port = 8080  # proxy server port

    try:
        s = socket.create_connection((proxy_host, port), timeout=10)
        s.settimeout(None)
        s.send(headers.encode("utf-8"))
        response = s.recv(3000)
        print("Proxy Response: " + str(response))
        conn = SSL.Connection(SSL.Context(SSL.TLS_METHOD), s)

        return _get_chain_from_connection(subject, conn)
    except Exception as err:
        logger.error(str(err))
        with contextlib.suppress(Exception):
            s.close()
        raise


def _get_chain_from_connection(subject: str, conn: SSL.Connection):
    conn.set_connect_state()
    conn.set_tlsext_host_name(subject.encode())
    conn.sendall(b"HEAD / HTTP/1.0\n\n")
    conn.recv(16)
    certs = conn.get_peer_cert_chain()
    results = []
    for pos, cert in enumerate(certs):
        crypto_cert = cert.to_cryptography()
        results.append(crypto_cert)
        print("Certificate #" + str(pos))
        for component in cert.get_subject().get_components():
            print(f"Subject {component[0]}: {component[1]}")
        print("Issuer: " + str(crypto_cert.issuer))

    conn.shutdown()
    return results


def _get_chain_direct(subject: str, port: int = 443) -> list[Certificate]:
    dst = (subject, port)
    conn = socket.create_connection(dst, timeout=5)
    return _get_chain_from_connection(subject, conn)


def get_trusted_certs() -> list[Certificate]:
    trusted_certs = [load_pem_x509_certificate(file.read_bytes()) for file in config.ING_ROOT_CERTS.glob("*")]
    return trusted_certs


def verify_chain(subject: str, verify_cert: bool = False) -> VerificationResult:
    """Validate that a given domain presents a complete chain of certificates, and optionally verify the chain.

    Args:
        subject (str): The domain to retrieve the certificates from.
        verify_cert (bool): Whether to cryptographically validate the certificate chain.

    Returns:
        VerificationResult: The result of the operation

    """
    result = VerificationResult(domain=subject)

    try:
        chain_certs = get_chain(subject)
    except Exception as err:
        result.add_exception(err, "Problem getting the certificate chain from the source.")
        return result

    try:
        get_root(chain_certs)
        validate_cert_chain(chain_certs)
    except Exception as err:
        result.add_exception(err)
        return result

    if verify_cert:
        verify_chain_validity(subject, chain_certs, result)

    if not result.errors:
        result.validated = True

    return result


def verify_chain_validity(subject: str, chain_certs: list[Certificate], result: VerificationResult) -> None:
    try:
        store = Store(get_trusted_certs())
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

    trusted_certs = get_trusted_certs()

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
