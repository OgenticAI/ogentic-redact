"""ogentic-redact — real-time, on-device sensitive-content redaction."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    __version__: str = _pkg_version("ogentic-redact")
except PackageNotFoundError:
    # Package not installed (dev mode without maturin build).
    __version__ = "0.0.0+dev"

from ogentic_redact.audit import DetectionEvent
from ogentic_redact.profile import DEFAULT_ENTITY_TYPES, Profile
from ogentic_redact.stream import redact_stream

__all__ = [
    "DEFAULT_ENTITY_TYPES",
    "DetectionEvent",
    "Profile",
    "__version__",
    "redact_stream",
]
