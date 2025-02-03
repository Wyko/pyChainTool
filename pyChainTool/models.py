"""Models used by the tools."""

from dataclasses import dataclass, field
from enum import StrEnum, auto


class Verification(StrEnum):
    """The types of verification to perform on the certificate."""

    HAS_ROOT = auto()
    "Verify that we can find a root certificate for the presented chain."

    ALL_SIGNED_BY_ANY = auto()
    "Verify that each certificate is signed by another certificate in the chain."

    FULL_CRYPTOGRAPHIC = auto()
    """Verify the certificate using Cryptography's server verifier module. 
    This should be the most complete verification possible.
    """


@dataclass
class SingleVerification:
    """The result of a single validation operation."""

    verification_type: Verification
    passed: bool = False
    message: str | None = None

    def __rich_repr__(self):  # noqa: PLW3201
        yield self.verification_type.capitalize()
        yield "Passed", self.passed
        yield "Message", self.message, None


@dataclass
class VerificationResult:
    """The results of a collection of certificate + chain validation operation."""

    host: str
    results: list[SingleVerification] = field(default_factory=list)

    def verified(self) -> bool:
        """Whether the operation passed all verifications.

        There must be at least one result (an empty result set is False)."""
        if len(self.results) == 0:
            return False

        return all(result.passed for result in self.results)
