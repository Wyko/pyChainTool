"""The command line interface to the package."""

import logging
from typing import Annotated

import rich
import typer
from typer import Typer

from pyChainTool import logs
from pyChainTool.main import CertVerifier, Verification

app = Typer()


@app.command()
def verify(
    host: Annotated[
        str, typer.Argument(help="The hostname/URL of the remote host to download the certificate and chain from.")
    ],
    checks: Annotated[
        list[Verification],
        typer.Option(
            "--check",
            "-c",
            help="""
            The verifications to perform against the downloaded certificate. 

            You may specify this one or more times with the names of the checks you want to perform, or omit this to
            run all possible checks.
            """,
        ),
    ] = None,
    port: Annotated[
        int, typer.Option("--port", "-p", help="The port to connect to the remote host on.", show_default=True)
    ] = 443,
    trust: Annotated[
        str,
        typer.Option(
            "--trust",
            "-t",
            show_default=True,
            help="""The trusted certificates to use to validate the chain loaded from the remote host. 

            If you specify "certifi"`, then the `certifi` package is used to establish a trust store using a set of
            default certificates from Mozilla. Any other string is interpreted as a filepath. This filepath should
            point to a folder containing certificates in PEM format. 

            If this option is not specified, no trust store will be used. The server must supply a root certificate 
                itself to validate chain signing, and the connection will probably fail any strict validation since 
                no certificate is trusted. This can still be useful to pass some basic verifications.
            """,
        ),
    ] = None,
    proxy_host: Annotated[
        str,
        typer.Option(
            "--proxy", help="If specified, use the specified proxy server to create a connection to the remote host."
        ),
    ] = None,
    proxy_port: Annotated[int, typer.Option(help="The port for the proxy, if specified.")] = 8080,
    fallback: Annotated[
        bool,
        typer.Option(
            "--fallback",
            "-f",
            help=(
                "Whether to try connecting directly to the host if the proxy is supplied but"
                "doesn't work. Defaults to False."
            ),
        ),
    ] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", count=True)] = 0,
):
    """Download the certificate chain from a remote host and then run one or more verification checks against it."""

    if verbose > 0:
        logs.set_logger_level(logging.DEBUG)
    else:
        logs.set_logger_level(logging.WARNING)

    verifier = CertVerifier(
        host=host,
        port=port,
        fallback=fallback,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        trust=trust,
    )

    r = verifier.verify(verifications=checks)

    rich.print(r.results)


if __name__ == "__main__":
    app()
