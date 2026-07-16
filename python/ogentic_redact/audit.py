"""Audit types emitted by the streaming redactor."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["DetectionEvent"]


@dataclass(frozen=True, slots=True)
class DetectionEvent:
    """A single detected-entity event emitted per chunk.

    Attributes:
        entity_type: Presidio entity type (e.g. ``"PERSON"``, ``"EMAIL_ADDRESS"``).
        chunk_index: Zero-based index of the chunk this event belongs to.
        start: Character offset (inclusive) within the *original* chunk string.
        end: Character offset (exclusive) within the *original* chunk string.
        score: Presidio recognition confidence score (0.0-1.0).
    """

    entity_type: str
    chunk_index: int
    start: int
    end: int
    score: float
