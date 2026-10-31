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


def test_mcp_consume_is_scoped_and_single_use() -> None:
    store = InProcessMappingStore()
    result = redact_outbound(SAMPLE, "shield-legal", mapping_store=store, tenant_id=TENANT)
    with pytest.raises(ValueError, match="unknown or expired"):
        unredact_response(result["redacted"], result["mapping_id"], mapping_store=store, tenant_id="other", consume=True)
    assert unredact_response(result["redacted"], result["mapping_id"], mapping_store=store, tenant_id=TENANT, consume=True) == SAMPLE
    with pytest.raises(ValueError, match="unknown or expired"):
        unredact_response(result["redacted"], result["mapping_id"], mapping_store=store, tenant_id=TENANT)


def test_mcp_store_failures_hide_sensitive_error_payloads(caplog) -> None:
    class BrokenStore(InProcessMappingStore):
        def store(self, mapping, matter_id):
            raise RuntimeError("secret-alice@example.com")
        def fetch(self, mapping_id, matter_id):
            raise RuntimeError("secret-alice@example.com")
    store = BrokenStore()
    with pytest.raises(ValueError, match="outbound redaction unavailable"):
        redact_outbound(SAMPLE, "shield-legal", mapping_store=store, tenant_id=TENANT)
    with pytest.raises(ValueError, match="mapping store unavailable"):
        unredact_response("text", "id", mapping_store=store, tenant_id=TENANT)
    assert "secret-alice@example.com" not in caplog.text


def test_mcp_invalid_unicode_does_not_consume_vault_through_tool() -> None:
    pytest.importorskip("mcp")
    import anyio
    from mcp.server.fastmcp.exceptions import ToolError
    from ogentic_redact.mcp.server import build_server

    store = InProcessMappingStore()
    result = redact_outbound(SAMPLE, "shield-legal", mapping_store=store, tenant_id=TENANT)
    original_mapping = store.fetch(result["mapping_id"], TENANT)
    server = build_server(tenant_id=TENANT, mapping_store=store)

    async def invoke():
        await server.call_tool(TOOL_UNREDACT, {
            "text": "\ud800", "mapping_id": result["mapping_id"], "consume": True,
        })

    with pytest.raises(ToolError, match="valid UTF-8"):
        anyio.run(invoke)
    assert store.fetch(result["mapping_id"], TENANT) == original_mapping


def test_mcp_over_budget_response_keeps_mapping_for_valid_retry() -> None:
    store = InProcessMappingStore()
    result = redact_outbound(SAMPLE, "shield-legal", mapping_store=store, tenant_id=TENANT)
    original_mapping = store.fetch(result["mapping_id"], TENANT)
    with pytest.raises(ValueError, match="response restoration unavailable"):
        unredact_response(
            result["redacted"], result["mapping_id"], mapping_store=store,
            tenant_id=TENANT, consume=True, max_output_bytes=4,
        )
    assert store.fetch(result["mapping_id"], TENANT) == original_mapping
    assert unredact_response(
        result["redacted"], result["mapping_id"], mapping_store=store,
        tenant_id=TENANT, consume=True,
    ) == SAMPLE


def test_mcp_unexpected_restore_failure_keeps_mapping(monkeypatch) -> None:
    import ogentic_redact.mcp.server as module
    store = InProcessMappingStore()
    result = redact_outbound(SAMPLE, "shield-legal", mapping_store=store, tenant_id=TENANT)
    original_mapping = store.fetch(result["mapping_id"], TENANT)

    def fail(*args, **kwargs):
        raise RuntimeError("sensitive-payload")

    monkeypatch.setattr(module._native, "unredact", fail)
    with pytest.raises(ValueError, match="^response restoration unavailable$"):
        unredact_response(
            result["redacted"], result["mapping_id"], mapping_store=store,
            tenant_id=TENANT, consume=True,
        )
    assert store.fetch(result["mapping_id"], TENANT) == original_mapping
