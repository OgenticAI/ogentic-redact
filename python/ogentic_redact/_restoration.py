"""Bounded, single-pass restoration shared by Python entry points."""

from __future__ import annotations

import re

DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_REPLACEMENTS = 100_000


def validate_restoration_input(text: str, max_output_bytes: int, max_replacements: int) -> None:
    """Reject invalid input before any potentially destructive vault operation."""
    if not isinstance(text, str):
        raise TypeError("redacted_text must be str")
    for name, limit in (("max_output_bytes", max_output_bytes), ("max_replacements", max_replacements)):
        if type(limit) is not int or limit < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("response text must be valid UTF-8") from None


def restore_mapping(
    text: str,
    mapping: dict[str, str],
    *,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    max_replacements: int = DEFAULT_MAX_REPLACEMENTS,
) -> str:
    """Preflight UTF-8 size and mapped replacements, then construct the output."""
    validate_restoration_input(text, max_output_bytes, max_replacements)
    if any(not isinstance(k, str) or not k or not isinstance(v, str) for k, v in mapping.items()):
        raise ValueError("invalid restoration mapping")

    def size(value: str) -> int:
        if len(value) > max_output_bytes:
            raise ValueError("restoration exceeds configured limits")
        try:
            return len(value.encode("utf-8"))
        except UnicodeEncodeError:
            raise ValueError("restoration mapping must contain valid UTF-8") from None

    if not mapping:
        if size(text) > max_output_bytes:
            raise ValueError("restoration exceeds configured limits")
        return text
    # Longest first preserves support for legacy/custom mappings. Inserted
    # originals are never scanned again, including token-shaped originals.
    pattern = re.compile("|".join(re.escape(t) for t in sorted(mapping, key=len, reverse=True)))
    total, replacements, cursor = 0, 0, 0
    value_sizes: dict[str, int] = {}
    for match in pattern.finditer(text):
        replacements += 1
        if replacements > max_replacements:
            raise ValueError("restoration exceeds configured limits")
        key = match.group(0)
        if key not in value_sizes:
            value_sizes[key] = size(mapping[key])
        total += size(text[cursor:match.start()]) + value_sizes[key]
        if total > max_output_bytes:
            raise ValueError("restoration exceeds configured limits")
        cursor = match.end()
    if total + size(text[cursor:]) > max_output_bytes:
        raise ValueError("restoration exceeds configured limits")
    return pattern.sub(lambda match: mapping[match.group(0)], text)
