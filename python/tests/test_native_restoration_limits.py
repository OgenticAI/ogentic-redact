"""Exercise resource budgets through the public compiled Python binding."""

import pytest

from ogentic_redact import unredact


@pytest.mark.parametrize("name", ["max_output_bytes", "max_replacements"])
@pytest.mark.parametrize("value", [True, False, 1.5, None, -1, 1 << 100, "100"])
def test_native_rejects_invalid_budgets(name, value) -> None:
    with pytest.raises((ValueError, TypeError), match="nonnegative"):
        unredact("", {}, **{name: value})


def test_native_zero_budgets_and_empty_output() -> None:
    assert unredact("", {}, max_output_bytes=0, max_replacements=0) == ""
    assert unredact("[Name_deadbeef]", {"[Name_deadbeef]": ""}, max_output_bytes=0) == ""
    with pytest.raises(ValueError, match="limit exceeded"):
        unredact("[Name_deadbeef]", {"[Name_deadbeef]": ""}, max_replacements=0)


def test_native_utf8_output_budget_is_exact_and_allows_shorter_output() -> None:
    mapping = {"[Name_deadbeef]": "😀"}
    assert unredact("é[Name_deadbeef]", mapping, max_output_bytes=6) == "é😀"
    with pytest.raises(ValueError, match="limit exceeded"):
        unredact("é[Name_deadbeef]", mapping, max_output_bytes=5)
    assert unredact("[Name_deadbeef]", mapping, max_output_bytes=4) == "😀"


def test_native_default_budget_rejects_amplified_output() -> None:
    with pytest.raises(ValueError, match="limit exceeded"):
        unredact("[Name_deadbeef]" * 1024, {"[Name_deadbeef]": "a" * 65536})


def test_native_replacement_budget_counts_repetitions_only_in_input() -> None:
    mapping = {"[Name_deadbeef]": "[Name_aaaaaaaa]", "[Name_aaaaaaaa]": "secret"}
    assert unredact("[Name_deadbeef]" * 2, mapping, max_replacements=2) == "[Name_aaaaaaaa]" * 2
    with pytest.raises(ValueError, match="limit exceeded"):
        unredact("[Name_deadbeef]" * 2, mapping, max_replacements=1)
