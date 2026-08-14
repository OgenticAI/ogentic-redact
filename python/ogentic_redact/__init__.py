"""ogentic-redact — real-time, on-device sensitive-content redaction."""

from ogentic_redact._native import __version__
from ogentic_redact.categories import CATEGORY_GROUP_PRECEDENCE
from ogentic_redact.errors import (
    LocalhostOnlyError,
    RedactError,
    VaultError,
    VaultNotFound,
)
from ogentic_redact.redactor import Redactor, RedactResult
from ogentic_redact.span import Span
from ogentic_redact.vault import InProcessVault, SQLiteVault

__all__ = [
    "CATEGORY_GROUP_PRECEDENCE",
    "InProcessVault",
    "LocalhostOnlyError",
    "RedactError",
    "RedactResult",
    "Redactor",
    "SQLiteVault",
    "Span",
    "VaultError",
    "VaultNotFound",
    "__version__",
]
