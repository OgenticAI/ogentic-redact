"""ogentic-redact — real-time, on-device sensitive-content redaction."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ogentic_redact._native import __version__
from ogentic_redact.errors import RedactError, VaultError, VaultNotFound
from ogentic_redact.redactor import Redactor, RedactResult
from ogentic_redact.span import Span
from ogentic_redact.vault import InProcessVault, SQLiteVault

if TYPE_CHECKING:
    from ogentic_redact.vault import Vault

__all__ = [
    "__version__",
    "Redactor",
    "RedactResult",
    "Span",
    "InProcessVault",
    "SQLiteVault",
    "RedactError",
    "VaultError",
    "VaultNotFound",
]
