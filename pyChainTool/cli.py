"""The command line interface to the package."""

import logging
from typing import Annotated

import rich
import rich.padding
import typer
from rich.padding import Padding
from typer import Typer

from pyChainTool import checks, logs
from pyChainTool.main import CertVerifier

app = Typer()


@app.command()
def verify(
    host: Annotated[
        str, typer.Argument(help="The hostname/URL of the remote host to download the certificate and chain from.")
    ],
    verifications: Annotated[
        list[str],
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
            help="""The trusted certificates to use to validate the chain loaded from the remote host. This should be
            a file path pointing to a folder containing certificates in PEM format. If this option is not 
            specified, the default is to use the certificates supplied by the certifi package, which uses the Mozilla
            default certificates.
            """,
        ),
    ] = "certifi",
    no_trust: Annotated[
        bool,
        typer.Option(
            "--no-trust",
            "-n",
            help=(
                """If this option is specified, no trust store will be used. The server must supply a root certificate 
                itself to validate chain signing, and the connection will probably fail any strict validation since 
                no certificate is trusted. This can still be useful to pass some basic verifications.
                This option overrides the trust option if it is supplied.
                """
            ),
        ),
    ] = False,
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
        trust=trust if no_trust is False else None,
    )

    try:
        r = verifier.verify(verifications=verifications)
    except Exception as err:
        rich.print("[bold red]Errors during checks")
        rich.print(f"[i]The log file may have more info, found in {logs.OUTPUT_DIR}")
        exceptions = []
        while err:
            exceptions.append(err)
            err = err.__cause__
        for ex in reversed(exceptions):
            rich.print(rich.padding.Padding(f"[bold]- {type(ex).__name__}[/bold]: {ex}", (0, 0, 0, 2)))

        return

    rich.print(r.results)


@app.command(name="list")
def list_verifiers():
    """List the available verification checks."""
    verifiers = checks.get_verifiers()
    rich.print("[bold]Available Verifiers")
    rich.print("[i]Use these as values passed to [bold]--check[/bold].")
    for k, v in verifiers.items():
        rich.print(Padding(f"- [bold]{k}[/bold]: {v}", pad=(0, 0, 0, 2)))


if __name__ == "__main__":
    app()
