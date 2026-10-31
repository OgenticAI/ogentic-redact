"""Span — a detected entity region within a text."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Span:
    """A half-open ``[start, end)`` character range with an entity type and group.

    Args:
        start: Inclusive start index into the source text.
        end: Exclusive end index into the source text.
        entity_type: Label for the detected entity (e.g. ``"EMAIL"``).
        group: Precedence tier. Lower values have higher precedence; the
            overlap resolver uses the lowest group's label while protecting
            the complete union of overlapping sensitive ranges.
    """

    start: int
    end: int
    entity_type: str
    group: int = 0
