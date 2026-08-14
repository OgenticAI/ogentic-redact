"""ogentic-redact — real-time, on-device sensitive-content redaction."""

from ogentic_redact._native import __version__
from ogentic_redact.audit import AuditDetectionEvent, AuditEmitter, DetectionEvent
from ogentic_redact.categories import CATEGORY_GROUP_PRECEDENCE
from ogentic_redact.errors import (
    AuditError,
    LocalhostOnlyError,
    MappingNotFound,
    MappingStoreError,
    RedactError,
)
from ogentic_redact.profile import DEFAULT_ENTITY_TYPES, KNOWN_PROFILES, Profile
from ogentic_redact.redactor import Redactor, RedactResult
from ogentic_redact.span import Span
from ogentic_redact.stores import InProcessMappingStore, SQLiteMappingStore
from ogentic_redact.stream import redact_stream

__all__ = [
    "CATEGORY_GROUP_PRECEDENCE",
    "DEFAULT_ENTITY_TYPES",
    "KNOWN_PROFILES",
    "AuditDetectionEvent",
    "AuditEmitter",
    "AuditError",
    "DetectionEvent",
    "InProcessMappingStore",
    "LocalhostOnlyError",
    "MappingNotFound",
    "MappingStoreError",
    "Profile",
    "RedactError",
    "RedactResult",
    "Redactor",
    "SQLiteMappingStore",
    "Span",
    "__version__",
    "redact_stream",
]
