"""Domain exceptions for ogentic-redact."""

__all__ = ["AuditError"]


class AuditError(Exception):
    """Raised when an audit event cannot be recorded.

    Redaction fails closed: an audit event must be successfully recorded,
    or the redaction operation raises this exception rather than silently
    succeeding without audit.
    """

    pass
