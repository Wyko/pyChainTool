"""Guard conditions."""

from pyChainTool import checks


def all_values_are_valid_verifications(values: list[str]) -> None:
    """Raise a ValueError if any value in the list does not match with a known check.

    Args:
        values (list[str]): A list of checks.

    """
    for v in values:
        if v.lower() not in checks.__all__:
            raise ValueError(f"{v} is not a known verification check.")
