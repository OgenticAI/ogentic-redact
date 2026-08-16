"""Acceptance tests for the optional MCP server (OGE-1270).

The substantive tool logic lives in the pure functions ``redact_outbound`` /
``unredact_response`` and is tested directly — these need only the ``_native``
extension, not the optional ``mcp`` package. A separate block uses
``importorskip`` to exercise the FastMCP wiring when the ``[mcp]`` extra is present.
"""

from __future__ import annotations

import pytest

from ogentic_redact.mcp.server import (
    DEFAULT_TENANT,
    TOOL_OUTBOUND,
    TOOL_UNREDACT,
    redact_outbound,
    unredact_response,
)
from ogentic_redact.stores import InProcessMappingStore, SQLiteMappingStore

SAMPLE = "Contact alice@example.com or call 415-555-0132. SSN 123-45-6789."
TENANT = "tenant-A"


class TestRedactOutbound:
    """AC1: redact.outbound returns {redacted, mapping_id}; mapping never inline."""

    def test_returns_redacted_and_mapping_id(self) -> None:
        store = InProcessMappingStore()
        out = redact_outbound(SAMPLE, "shield-legal", mapping_store=store, tenant_id=TENANT)

        assert set(out) == {"redacted", "mapping_id"}
        assert out["mapping_id"]
        # Originals are gone from the redacted text...
        for secret in ["alice@example.com", "415-555-0132", "123-45-6789"]:
            assert secret not in out["redacted"]
        # ...and the mapping is NOT inlined in the response.
        assert "tokens" not in out
        assert "alice@example.com" not in str(out)
        # The vault holds the originals, retrievable only via the store.
        mapping = store.fetch(out["mapping_id"], TENANT)
        assert "alice@example.com" in mapping.values()

    def test_empty_text_rejected(self) -> None:
        store = InProcessMappingStore()
        with pytest.raises(ValueError, match="non-empty"):
            redact_outbound("", "shield-legal", mapping_store=store, tenant_id=TENANT)


class TestUnredactResponse:
    """AC2 + AC4: round-trip restore; unknown/cross-tenant mapping_id errors."""

    def test_round_trip_restores_original(self) -> None:
        store = InProcessMappingStore()
        out = redact_outbound(SAMPLE, "shield-legal", mapping_store=store, tenant_id=TENANT)
        restored = unredact_response(
            out["redacted"], out["mapping_id"], mapping_store=store, tenant_id=TENANT
        )
        assert restored == SAMPLE

    def test_round_trip_via_sqlite_store(self) -> None:
        store = SQLiteMappingStore()
        out = redact_outbound(SAMPLE, "shield-finance", mapping_store=store, tenant_id=TENANT)
        restored = unredact_response(
            out["redacted"], out["mapping_id"], mapping_store=store, tenant_id=TENANT
        )
        assert restored == SAMPLE
        store.close()

    def test_unknown_mapping_id_errors(self) -> None:
        store = InProcessMappingStore()
        with pytest.raises(ValueError, match="unknown or expired mapping_id"):
            unredact_response(
                "anything", "does-not-exist", mapping_store=store, tenant_id=TENANT
            )

    def test_cross_tenant_mapping_id_errors(self) -> None:
        # A mapping_id issued for tenant A must not resolve under tenant B —
        # it surfaces as "unknown", never the wrong vault (demo-design §6).
        store = InProcessMappingStore()
        out = redact_outbound(SAMPLE, "shield-legal", mapping_store=store, tenant_id="tenant-A")
        with pytest.raises(ValueError, match="unknown or expired mapping_id"):
            unredact_response(
                out["redacted"], out["mapping_id"], mapping_store=store, tenant_id="tenant-B"
            )


class TestProfileGuard:
    """AC3: unknown profile rejected before any processing."""

    def test_unknown_profile_rejected(self) -> None:
        store = InProcessMappingStore()
        with pytest.raises(ValueError, match="Unknown profile"):
            redact_outbound(SAMPLE, "attacker-controlled", mapping_store=store, tenant_id=TENANT)

    def test_unknown_profile_does_not_store_anything(self) -> None:
        # Guard fires before redaction, so no mapping is written on rejection.
        store = InProcessMappingStore()
        with pytest.raises(ValueError):
            redact_outbound(SAMPLE, "nope", mapping_store=store, tenant_id=TENANT)
        # Nothing was stored under the tenant.
        assert store._store == {}


class TestServerWiring:
    """AC5: server is an optional [mcp] extra; FastMCP registers both tools."""

    def test_build_server_registers_both_tools(self) -> None:
        pytest.importorskip("mcp")
        from ogentic_redact.mcp.server import build_server

        server = build_server(tenant_id=TENANT)
        # FastMCP exposes registered tools via list_tools() (async).
        import anyio

        tools = anyio.run(server.list_tools)
        names = {t.name for t in tools}
        assert names == {TOOL_OUTBOUND, TOOL_UNREDACT}

    def test_default_tenant_constant(self) -> None:
        assert DEFAULT_TENANT == "local"
