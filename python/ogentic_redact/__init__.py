"""ogentic-redact — real-time, on-device sensitive-content redaction."""

from ogentic_redact._native import __version__
from ogentic_redact.errors import RedactError, VaultError, VaultNotFound
from ogentic_redact.redactor import Redactor, RedactResult
from ogentic_redact.span import Span
from ogentic_redact.vault import InProcessVault, SQLiteVault, Vault

__all__ = [
    "__version__",
    "Redactor",
    "RedactResult",
    "Span",
    "Vault",
    "InProcessVault",
    "SQLiteVault",
    "RedactError",
    "VaultError",
    "VaultNotFound",
]
