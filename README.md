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

## Usage

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

## CLI Documentation

This tool can be run directly from a terminal after installation via `pip`. 


**Usage**:

```console
$ chaintool [OPTIONS] HOST
```

**Arguments**:

* `HOST`: The hostname/URL of the remote host to download the certificate and chain from.  [required]

**Options**:

* `-c, --check [has_root|all_signed_by_any|full_cryptographic]`: The verifications to perform against the downloaded certificate. 

    You may specify this one or more times with the names of the checks you want to perform, or omit this to
    run all possible checks.
* `-p, --port INTEGER`: The port to connect to the remote host on.  [default: 443]
* `-t, --trust TEXT`: The trusted certificates to use to validate the chain loaded from the remote host. 

    If you specify `"certifi"`, then the `certifi` package is used to establish a trust store using a set of
    default certificates from Mozilla. Any other string is interpreted as a filepath. This filepath should
    point to a folder containing certificates in PEM format. 

    If this option is not specified, **no trust store will be used**. The server must supply a root certificate 
    itself to validate chain signing, and the connection will probably fail most checks since 
    no certificate is trusted. This can still be useful to pass some basic verifications.
* `--proxy TEXT`: If specified, use the specified proxy server to create a connection to the remote host.
* `--proxy-port INTEGER`: The port for the proxy, if specified.  [default: 8080]
* `-f, --fallback`: Whether to try connecting directly to the host if the proxy is supplied but doesn&#x27;t work. Defaults to False.
* `-v, --verbose`: Enable debug logging.
* `--help`: Show this message and exit.



## Verifications
These are the currently available verification options. 

The enum for these options (the `Verification` class, used in 
the `verify()` function parameters to select which checks to run) can be found in `pyChainTool.models`.


- **HAS_ROOT**: Verify that we can find a root certificate for the presented chain.

- **ALL_SIGNED_BY_ANY**: Verify that each certificate is signed by another certificate in the chain, including a known root.

- **FULL_CRYPTOGRAPHIC**: Verify the certificate using Cryptography's server verifier module. This should be the most complete verification possible.


