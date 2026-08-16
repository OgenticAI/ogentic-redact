"""Optional MCP server for ogentic-redact (``pip install 'ogentic-redact[mcp]'``).

See :mod:`ogentic_redact.mcp.server` for the tool surface. Run with
``python -m ogentic_redact.mcp``.
"""

from ogentic_redact.mcp.server import (
    TOOL_OUTBOUND,
    TOOL_UNREDACT,
    build_server,
    redact_outbound,
    run,
    unredact_response,
)

__all__ = [
    "TOOL_OUTBOUND",
    "TOOL_UNREDACT",
    "build_server",
    "redact_outbound",
    "run",
    "unredact_response",
]
