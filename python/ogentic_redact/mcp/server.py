"""MCP server surface for ogentic-redact (OGE-1270).

Exposes Redact as an optional MCP server (``pip install 'ogentic-redact[mcp]'``)
with two tools, mirroring the FastMCP pattern in ``ogentic-shield``:

    redact.outbound(text, profile)          -> {"redacted": str, "mapping_id": str}
    redact.unredact_response(text, id)      -> str

Redact's differentiator over Shield (demo-design §1): the token→original mapping
is **never returned inline**. ``redact.outbound`` stores it in a per-tenant
:class:`~ogentic_redact.stores.MappingStore` and returns only the opaque
``mapping_id``; ``redact.unredact_response`` resolves it back.

Detection is the core on-device byte-scanner (EMAIL / PHONE / US_SSN) via the
``_native`` extension — a documented development convenience. Production spans
come from ``ogentic-shield`` (ADR-0002 / OGE-1230); the ``profile`` argument is
validated against the allow-list (hostile-profile guard) but does not yet steer
detection.

Tenant isolation (demo-design §6): the tenant/matter scope is bound to the server
at session construction — derived from the authenticated principal at the session
boundary, never from a tool argument. The tool signatures deliberately omit any
tenant parameter, so a caller cannot spoof one via the request body. A
``mapping_id`` issued for one tenant surfaces as "unknown" (never the wrong vault)
when presented under another.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import ogentic_redact._native as _native
from ogentic_redact.errors import MappingNotFound, MappingStoreError
from ogentic_redact.profile import KNOWN_PROFILES
from ogentic_redact.stores import InProcessMappingStore

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from ogentic_redact.stores import MappingStore

logger = logging.getLogger("ogentic_redact.mcp")

# Tool names (demo-design §3). Exported so tests and docs share one source.
TOOL_OUTBOUND = "redact.outbound"
TOOL_UNREDACT = "redact.unredact_response"

# Default profile when a caller omits one — a known Redact workflow profile.
DEFAULT_PROFILE = "shield-legal"

# Tenant for a single-principal local session (stdio). Multi-tenant deployments
# MUST override via ``OGENTIC_REDACT_TENANT`` / the transport auth layer.
DEFAULT_TENANT = "local"


def _resolve_profile(requested: str) -> str:
    """Validate *requested* against the allow-list before any processing.

    Mirrors shield's hostile-profile injection defence: an unknown profile name
    is rejected up front, so a caller cannot coax the server into an unintended
    redaction policy.
    """
    if requested not in KNOWN_PROFILES:
        raise ValueError(
            f"Unknown profile {requested!r}. Known profiles: {sorted(KNOWN_PROFILES)}"
        )
    return requested


def redact_outbound(
    text: str,
    profile: str,
    *,
    mapping_store: MappingStore,
    tenant_id: str,
) -> dict[str, str]:
    """Redact *text*; return ``{"redacted", "mapping_id"}`` — mapping never inline.

    The token→original mapping is stored in *mapping_store* under *tenant_id* and
    only the opaque ``mapping_id`` is returned. See the module docstring for the
    detection and tenant-scope caveats.
    """
    if not text:
        raise ValueError("`text` must be a non-empty string")
    _resolve_profile(profile)

    raw = _native.redact(text)
    redacted: str = raw["text"]
    tokens: dict[str, str] = raw["tokens"]
    mapping_id = mapping_store.store(tokens, tenant_id)
    return {"redacted": redacted, "mapping_id": mapping_id}


def unredact_response(
    text: str,
    mapping_id: str,
    *,
    mapping_store: MappingStore,
    tenant_id: str,
) -> str:
    """Restore *text* using the mapping stored under (*tenant_id*, *mapping_id*).

    Raises :class:`ValueError` if *mapping_id* is unknown/expired or was issued
    for a different tenant — the lookup is tenant-scoped, so a cross-tenant
    ``mapping_id`` surfaces as "unknown", never the wrong vault (demo-design §6).
    """
    try:
        tokens = mapping_store.fetch(mapping_id, tenant_id)
    except MappingNotFound:
        # Sanitised: never echo tenant/matter internals to the client.
        raise ValueError("unknown or expired mapping_id") from None
    except MappingStoreError as e:
        logger.error("mapping store fetch failed: %s", e)
        raise ValueError("mapping store unavailable") from None

    restored: str = _native.unredact(text, tokens)
    return restored


def build_server(
    *,
    tenant_id: str | None = None,
    mapping_store: MappingStore | None = None,
    name: str = "ogentic-redact",
) -> FastMCP:
    """Construct (but don't run) the FastMCP server.

    The ``mcp`` SDK is imported lazily so the rest of the package keeps working
    when it isn't installed (it's an optional dependency —
    ``pip install 'ogentic-redact[mcp]'``).

    Args:
        tenant_id: Session tenant/matter scope. Defaults to
            ``OGENTIC_REDACT_TENANT`` then :data:`DEFAULT_TENANT`. Bound here at
            the session boundary; tool calls cannot override it.
        mapping_store: Store for reversible mappings. Defaults to a fresh
            in-process store (demo-design §5 option a).
        name: MCP server name.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "ogentic-redact MCP server requires the `mcp` package. "
            "Install with: pip install 'ogentic-redact[mcp]'"
        ) from e

    resolved_tenant = tenant_id or os.environ.get("OGENTIC_REDACT_TENANT") or DEFAULT_TENANT
    store: MappingStore = mapping_store or InProcessMappingStore()

    server = FastMCP(name=name)

    @server.tool(name=TOOL_OUTBOUND)
    def _outbound(text: str, profile: str = DEFAULT_PROFILE) -> dict[str, str]:
        """Redact *text* and return ``{redacted, mapping_id}`` (mapping never inline).

        The token→original mapping is stored server-side under the session tenant;
        pair the returned ``mapping_id`` with ``redact.unredact_response`` to
        restore. ``profile`` is validated against the allow-list.
        """
        return redact_outbound(
            text, profile, mapping_store=store, tenant_id=resolved_tenant
        )

    @server.tool(name=TOOL_UNREDACT)
    def _unredact(text: str, mapping_id: str) -> str:
        """Restore the original tokens in *text* using *mapping_id*.

        Errors if ``mapping_id`` is unknown/expired or was issued for a different
        tenant. Tokens absent from *text* are skipped, so a model that drops or
        rewords part of the input still round-trips safely.
        """
        return unredact_response(
            text, mapping_id, mapping_store=store, tenant_id=resolved_tenant
        )

    logger.info(
        "ogentic-redact MCP server built: tenant=%s tools=%s",
        resolved_tenant,
        [TOOL_OUTBOUND, TOOL_UNREDACT],
    )
    return server


def run(
    transport: str = "stdio",
    *,
    tenant_id: str | None = None,
    host: str = "127.0.0.1",
    port: int = 8766,
) -> None:
    """Build and run the MCP server.

    Args:
        transport: ``"stdio"`` (default — Claude Desktop, Goose, etc.) or
            ``"sse"`` (network clients).
        tenant_id: Session tenant/matter scope (see :func:`build_server`).
        host / port: Bind address for SSE. Loopback by default; do not expose
            this server on a public interface without an auth proxy in front.
    """
    server = build_server(tenant_id=tenant_id)

    if transport == "stdio":
        server.run(transport="stdio")
    elif transport == "sse":
        server.settings.host = host
        server.settings.port = port
        server.run(transport="sse")
    else:
        raise ValueError(f"Unknown transport {transport!r}. Use 'stdio' or 'sse'.")


def main() -> None:
    """CLI entry point — ``python -m ogentic_redact.mcp``."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m ogentic_redact.mcp",
        description="ogentic-redact MCP server — exposes Redact as MCP tools.",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse"),
        default="stdio",
        help="MCP transport (default: stdio)",
    )
    parser.add_argument(
        "--tenant",
        dest="tenant_id",
        default=None,
        help="Session tenant/matter scope (default: $OGENTIC_REDACT_TENANT or 'local').",
    )
    parser.add_argument("--host", default="127.0.0.1", help="SSE bind host")
    parser.add_argument("--port", type=int, default=8766, help="SSE bind port")
    args = parser.parse_args()

    run(
        transport=args.transport,
        tenant_id=args.tenant_id,
        host=args.host,
        port=args.port,
    )


if __name__ == "__main__":
    main()
