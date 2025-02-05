"""Models used by the tools."""

from dataclasses import dataclass, field


@dataclass
class SingleVerification:
    """The result of a single validation operation."""

    verification_name: str
    passed: bool = False
    message: str | None = None

    def __rich_repr__(self):  # noqa: PLW3201
        yield self.verification_name.capitalize()
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
