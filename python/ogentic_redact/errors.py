"""Domain exceptions for ogentic-redact."""

from __future__ import annotations

__all__ = ["LocalhostOnlyError"]


class LocalhostOnlyError(Exception):
    """Raised when a cloud recogniser is requested without explicit opt-in.

    The default redaction path enforces on-device-only execution.
    Cloud-assisted recognisers require explicit `cloud=True` opt-in.
    """

    def __init__(self) -> None:
        super().__init__(
            "Cloud recognisers require explicit opt-in (cloud=True). "
            "The default redaction path is on-device only."
        )
