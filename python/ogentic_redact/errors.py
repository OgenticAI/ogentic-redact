"""Domain exceptions for ogentic-redact."""

from __future__ import annotations

__all__ = [
    "AuditError",
    "LocalhostOnlyError",
    "MappingNotFound",
    "MappingStoreError",
    "RedactError",
]


class RedactError(Exception):
    """Base exception for redaction errors."""


class MappingStoreError(RedactError):
    """Base exception for vault operations."""


class MappingNotFound(MappingStoreError):
    """Mapping not found under the given matter_id."""


class AuditError(RedactError):
    """Raised when an audit event cannot be recorded.

    Redaction fails closed: an audit event must be successfully recorded, or the
    redaction operation raises this exception rather than silently succeeding
    without audit.
    """


class LocalhostOnlyError(Exception):
    """Raised when a cloud recogniser is requested without explicit opt-in.

    The default redaction path enforces on-device-only execution.
    Cloud-assisted recognisers require explicit `cloud=True` opt-in.
    """

    def __init__(self) -> None:
        super().__init__(
            "Cloud recognisers require explicit opt-in (cloud=True). "
            "The default redaction path is on-device only."
        )
