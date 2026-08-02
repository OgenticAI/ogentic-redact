"""ogentic-redact — real-time, on-device sensitive-content redaction."""

from ogentic_redact._native import __version__
from ogentic_redact.errors import LocalhostOnlyError

__all__ = ["LocalhostOnlyError", "__version__"]
