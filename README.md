# pyChainTool

## Introduction

Verify certificates and their associated chains from a remote host.

This module allows for much more basic certificate validation than `cryptography`'s (although full validation
is also an option here). The original use case for this tool was to validate that a remote host was
presenting intermediates, even if we didn't posses the root certificate in our own trust stores (i.e. for
basic device configuration verification when a client supplies their own self-signed certificates).

It also was designed to verify the validity of a certificate against a custom trust store, totally ignoring
the system trust store.

This tool presents a few different verification options, of which you can select one or more to run sequentially.
It will return an object containing the results of the verifications. 

## Usage: Python

```python
>>> from pyChainTool import CertVerifier
>>> r = CertVerifier("google.com", trust="certifi").verify()
>>> rich.print(r)

VerificationResult(
    host='google.com',
    results=[
        SingleVerification('Has_root', Passed=True, Message='Found root certificate CN=GTS Root R1,O=Google Trust Services LLC,C=US'),
        SingleVerification('All_signed_by_any', Passed=True),
        SingleVerification('Full_cryptographic', Passed=False, Message='Problem validating the certificate: validation failed: Other("EE keyUsage must not assert keyCertSign")')  
    ]
)
```

## Usage: CLI


**Commands**:

* `verify`: Download the certificate chain from a...
* `list`: List the available verification checks.

## `verify`

Download the certificate chain from a remote host and then run one or more verification checks against it.

**Usage**:

```console
$ verify [OPTIONS] HOST
```

**Arguments**:

* `HOST`: The hostname/URL of the remote host to download the certificate and chain from.  [required]

**Options**:

* `-c, --check TEXT`: The verifications to perform against the downloaded certificate. 

You may specify this one or more times with the names of the checks you want to perform, or omit this to
run all possible checks.
* `-p, --port INTEGER`: The port to connect to the remote host on.  [default: 443]
* `-t, --trust TEXT`: The trusted certificates to use to validate the chain loaded from the remote host. This should be
a file path pointing to a folder containing certificates in PEM format. If this option is not 
specified, the default is to use the certificates supplied by the certifi package, which uses the Mozilla
default certificates.  [default: certifi]
* `-n, --no-trust`: If this option is specified, no trust store will be used. The server must supply a root certificate 
itself to validate chain signing, and the connection will probably fail any strict validation since 
no certificate is trusted. This can still be useful to pass some basic verifications.
This option overrides the trust option if it is supplied.
* `--proxy TEXT`: If specified, use the specified proxy server to create a connection to the remote host.
* `--proxy-port INTEGER`: The port for the proxy, if specified.  [default: 8080]
* `-f, --fallback`: Whether to try connecting directly to the host if the proxy is supplied butdoesn&#x27;t work. Defaults to False.
* `-v, --verbose`: [default: 0]
* `--help`: Show this message and exit.

## `list`

List the available verification checks.

**Usage**:

```console
$ list [OPTIONS]
```

**Options**:

* `--help`: Show this message and exit.

