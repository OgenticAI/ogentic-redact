"""Audit types emitted by the streaming redactor."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

__all__ = ["AuditDetectionEvent", "AuditEmitter", "DetectionEvent"]


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


@dataclass(frozen=True, slots=True)
class AuditDetectionEvent:
    """A redaction detection event sent to ogentic-audit.

    Never includes raw sensitive values. Contains only metadata about the
    redaction decision: category, mode, profile, count, and (if reversible)
    the mapping_id token.

    Attributes:
        entity_type: Presidio entity type (e.g. ``"PERSON"``, ``"EMAIL_ADDRESS"``).
        mode: Redaction mode: ``"one-way"`` or ``"reversible"``.
        profile: Profile name (e.g., ``"shield-legal"``, ``"default"``).
        count: Number of entities of this type detected in this operation.
        mapping_id: Token reference (e.g., ``"RTKN_3a7f9c12ab01"``) if mode is
            reversible, else ``None``.
        tenant_id: Tenant identifier from the caller context.
        request_id: Request identifier from the caller context.
    """

    entity_type: str
    mode: str
    profile: str
    count: int
    mapping_id: str | None
    tenant_id: str
    request_id: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary suitable for JSON encoding.

        Returns:
            A dict with all fields, omitting ``None`` values.
        """
        data: dict[str, Any] = {
            "entity_type": self.entity_type,
            "mode": self.mode,
            "profile": self.profile,
            "count": self.count,
            "tenant_id": self.tenant_id,
            "request_id": self.request_id,
        }
        if self.mapping_id is not None:
            data["mapping_id"] = self.mapping_id
        return data


class AuditEmitter(ABC):
    """Abstract interface for emitting audit detection events."""

    @abstractmethod
    def emit(self, event: AuditDetectionEvent) -> None:
        """Emit an audit detection event.

        Args:
            event: The detection event to record.

        Raises:
            AuditError: If the event cannot be recorded.
        """
        raise NotImplementedError
