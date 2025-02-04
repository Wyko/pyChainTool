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
>> r = CertVerifier("google.com", trust="certifi").verify()
>> rich.print(r)

VerificationResult(
    host='google.com',
    results=[
        SingleVerification('Has_root', Passed=True, Message='Found root certificate CN=GTS Root R1,O=Google Trust Services LLC,C=US'),
        SingleVerification('All_signed_by_any', Passed=True),
        SingleVerification('Full_cryptographic', Passed=False, Message='Problem validating the certificate: validation failed: Other("EE keyUsage must not assert keyCertSign")')  
    ]
)
```

## Verifications
These are the currently available verification options. 

The enum for these options (the `Verification` class, used in 
the `verify()` function parameters to select which checks to run) can be found in `pyChainTool.models`.


- **HAS_ROOT**: Verify that we can find a root certificate for the presented chain.

- **ALL_SIGNED_BY_ANY**: Verify that each certificate is signed by another certificate in the chain, including a known root.

- **FULL_CRYPTOGRAPHIC**: Verify the certificate using Cryptography's server verifier module. This should be the most complete verification possible.


