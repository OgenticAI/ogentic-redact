"""Exceptions for ogentic-redact."""


class RedactError(Exception):
    """Base exception for redaction errors."""

    pass


class VaultError(RedactError):
    """Base exception for vault operations."""

    pass


class VaultNotFound(VaultError):
    """Mapping not found under the given matter_id."""

    pass
