"""All of the verifiers available."""

import inspect

from pyChainTool.checks._all_signed_by_any import all_signed_by_any
from pyChainTool.checks._full_cryptographic import full_cryptographic
from pyChainTool.checks._has_root import has_root

__all__ = [
    "full_cryptographic",
    "all_signed_by_any",
    "has_root",
]


def get_verifiers() -> dict:
    """Return the available verifiers and their descriptions.

    Returns:
        dict: The verifiers, formatted as {verifier_name: description}

    """

    verifiers = {}
    for verifier in __all__:
        func = globals()[verifier]
        # Get the docstring for the module.
        verifiers[verifier] = inspect.getmodule(func).__doc__
    return verifiers


get_verifiers()
