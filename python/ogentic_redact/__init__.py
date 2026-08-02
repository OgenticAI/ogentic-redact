"""ogentic-redact — real-time, on-device sensitive-content redaction."""

from ogentic_redact._native import __version__
from ogentic_redact.audit import AuditDetectionEvent, AuditEmitter, DetectionEvent
from ogentic_redact.errors import AuditError
from ogentic_redact.profile import DEFAULT_ENTITY_TYPES, KNOWN_PROFILES, Profile
from ogentic_redact.redactor import Redactor, RedactResult
from ogentic_redact.span import Span
from ogentic_redact.stream import redact_stream

__all__ = [
    "DEFAULT_ENTITY_TYPES",
    "KNOWN_PROFILES",
    "AuditDetectionEvent",
    "AuditEmitter",
    "AuditError",
    "DetectionEvent",
    "Profile",
    "RedactResult",
    "Redactor",
    "Span",
    "__version__",
    "redact_stream",
]
