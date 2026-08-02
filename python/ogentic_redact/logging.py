"""Structured logging for ogentic-redact."""

from __future__ import annotations

import json
import logging
from typing import Any

__all__ = ["log_structured"]


def log_structured(
    level: int,
    message: str,
    tenant_id: str = "",
    request_id: str = "",
    op: str = "",
    **kwargs: Any,
) -> None:
    """Emit a structured JSON log with mandatory audit fields.

    Per CLAUDE.md §6, all logs must include:
    - tenant_id: Tenant identifier
    - request_id: Request identifier
    - service: Always "ogentic-redact"
    - op: Operation name (e.g., "redact", "redact_stream")

    Additional fields may be passed via kwargs.

    Args:
        level: Python logging level (logging.INFO, logging.ERROR, etc.)
        message: Log message.
        tenant_id: Tenant identifier.
        request_id: Request identifier.
        op: Operation name.
        **kwargs: Additional fields to include in the JSON log.
    """
    log_data: dict[str, Any] = {
        "message": message,
        "tenant_id": tenant_id,
        "request_id": request_id,
        "service": "ogentic-redact",
        "op": op,
    }
    log_data.update(kwargs)

    logger = logging.getLogger("ogentic_redact")
    logger.log(level, json.dumps(log_data))
