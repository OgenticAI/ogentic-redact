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
            overlap resolver keeps the span with the lowest group when two
            spans overlap.
    """

    start: int
    end: int
    entity_type: str
    group: int = 0
