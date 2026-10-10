"""Domain exceptions for ogentic-redact."""

from __future__ import annotations

__all__ = [
    "AuditError",
    "ClassifierError",
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


class ClassifierError(RedactError):
    """Raised when a classifier (e.g. the Shield adapter) fails to return spans.

    Wraps transport/parse failures behind a sanitised message so raw adapter
    errors (URLs, upstream response bodies) are never surfaced to the caller
    (CLAUDE.md §4). External exception payloads are suppressed at this boundary.
    """


class AuditError(RedactError):
    """Raised when an audit event cannot be recorded.

    Redaction fails closed: an audit event must be successfully recorded, or the
    redaction operation raises this exception rather than silently succeeding
    without audit.
    """


class LocalhostOnlyError(Exception):
    """Legacy exception available for caller-enforced classifier policy.

    The default span path is local, but Redactor does not sandbox injected
    classifiers or raise this exception automatically.
    """

    def __init__(self) -> None:
        super().__init__(
            "Cloud recognisers require explicit opt-in (cloud=True). "
            "The default redaction path is on-device only."
        )
