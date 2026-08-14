"""Tests for Redactor integration with MappingStore (OGE-1234 acceptance criteria)."""

from __future__ import annotations

import pytest

from ogentic_redact import Redactor, RedactResult, Span, InProcessMappingStore, SQLiteMappingStore
from ogentic_redact.errors import MappingNotFound


class TestAC1StoreStorage:
    """AC1: Reversible redact() stores mapping in MappingStore and returns mapping_id."""

    def test_redact_reversible_returns_mapping_id(self) -> None:
        redactor = Redactor(reversible=True)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]

        result = redactor.redact("admin@example.com is the email", spans, matter_id="test")

        assert isinstance(result, RedactResult)
        assert result.mapping_id is not None
        assert isinstance(result.mapping_id, str)
        assert len(result.mapping_id) > 0

    def test_mapping_not_inline_in_vault(self) -> None:
        redactor = Redactor(reversible=True)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]

        result = redactor.redact("admin@example.com is the email", spans, matter_id="test")

        assert result.vault == {}

    def test_mapping_stored_in_vault(self) -> None:
        vault = InProcessMappingStore()
        redactor = Redactor(reversible=True, vault=vault)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]

        result = redactor.redact("admin@example.com is the email", spans, matter_id="test")

        stored_mapping = vault.fetch(result.mapping_id, "test")
        assert len(stored_mapping) > 0
        assert all(token.startswith("[RTKN_") for token in stored_mapping.keys())

    def test_one_way_mode_no_mapping_id(self) -> None:
        redactor = Redactor(reversible=False)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]

        result = redactor.redact("admin@example.com is the email", spans)

        assert result.mapping_id is None
        assert result.vault == {}


class TestAC2StoreFetch:
    """AC2: unredact() fetches mapping from MappingStore by mapping_id."""

    def test_unredact_by_mapping_id(self) -> None:
        redactor = Redactor(reversible=True)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]
        original_text = "admin@example.com is the email"

        result = redactor.redact(original_text, spans, matter_id="test")

        restored = redactor.unredact(result.text, result.mapping_id, matter_id="test")
        assert restored == original_text

    def test_unredact_requires_mapping_id_parameter(self) -> None:
        redactor = Redactor(reversible=True)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]

        result = redactor.redact("admin@example.com", spans, matter_id="test")

        restored = redactor.unredact(result.text, result.mapping_id, matter_id="test")
        assert "admin" in restored

    def test_unredact_without_reversible_raises(self) -> None:
        redactor = Redactor(reversible=False)

        with pytest.raises(ValueError, match="unredact.*reversible=True"):
            redactor.unredact("[EMAIL]", "fake_id", matter_id="test")


class TestAC3MatterScoping:
    """AC3: Mappings scoped per matter; mapping_id not resolvable across matters."""

    def test_mapping_id_from_matter_a_not_resolvable_in_matter_b(self) -> None:
        redactor = Redactor(reversible=True)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]

        result_a = redactor.redact("admin@example.com", spans, matter_id="matter_a")

        with pytest.raises(ValueError):
            redactor.unredact(result_a.text, result_a.mapping_id, matter_id="matter_b")

    def test_different_matters_different_mappings(self) -> None:
        vault = InProcessMappingStore()
        redactor = Redactor(reversible=True, vault=vault)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]

        result_a = redactor.redact("admin@example.com", spans, matter_id="matter_a")
        result_b = redactor.redact("admin@example.com", spans, matter_id="matter_b")

        assert result_a.mapping_id != result_b.mapping_id

        mapping_a = vault.fetch(result_a.mapping_id, "matter_a")
        mapping_b = vault.fetch(result_b.mapping_id, "matter_b")

        # Same source value → same recovered original in both matters, but the
        # per-call salt (OGE-1209) makes the token keys differ across calls.
        assert sorted(mapping_a.values()) == sorted(mapping_b.values())
        assert set(mapping_a.keys()).isdisjoint(mapping_b.keys())

        # Matter isolation: a's mapping cannot be fetched under b's matter_id.
        with pytest.raises(MappingNotFound):
            vault.fetch(result_a.mapping_id, "matter_b")

    def test_default_empty_matter_id(self) -> None:
        redactor = Redactor(reversible=True)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]

        result1 = redactor.redact("admin@example.com", spans)
        result2 = redactor.redact("admin@example.com", spans)

        restored1 = redactor.unredact(result1.text, result1.mapping_id)
        restored2 = redactor.unredact(result2.text, result2.mapping_id)

        assert restored1 == restored2 == "admin@example.com"


class TestAC4NoPlaintextRetention:
    """AC4: No plaintext mapping retained after call returns."""

    def test_redactor_no_plaintext_cache(self) -> None:
        redactor = Redactor(reversible=True)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]

        result = redactor.redact("admin@example.com", spans, matter_id="test")

        assert not hasattr(redactor, "_last_vault")
        assert not hasattr(redactor, "_mapping_cache")

    def test_result_vault_field_empty(self) -> None:
        redactor = Redactor(reversible=True)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]

        result = redactor.redact("admin@example.com", spans, matter_id="test")

        assert result.vault == {}

    def test_unredact_does_not_cache(self) -> None:
        redactor = Redactor(reversible=True)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]

        redact_result = redactor.redact("admin@example.com", spans, matter_id="test")
        restored = redactor.unredact(redact_result.text, redact_result.mapping_id, matter_id="test")

        assert not hasattr(redactor, "_restored_mapping")
        assert restored == "admin@example.com"


class TestAC5StoreInterface:
    """AC5: MappingStore interface is store-agnostic; defaults work out-of-box."""

    def test_in_process_vault_default(self) -> None:
        redactor = Redactor(reversible=True)

        assert redactor.vault is not None
        assert isinstance(redactor.vault, InProcessMappingStore)

    def test_custom_vault_integration(self) -> None:
        vault = SQLiteMappingStore()
        redactor = Redactor(reversible=True, vault=vault)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]

        result = redactor.redact("admin@example.com", spans, matter_id="test")

        restored = redactor.unredact(result.text, result.mapping_id, matter_id="test")
        assert restored == "admin@example.com"

    def test_vault_interface_contract(self) -> None:
        redactor = Redactor(reversible=True)

        assert hasattr(redactor.vault, "store")
        assert hasattr(redactor.vault, "fetch")
        assert callable(redactor.vault.store)
        assert callable(redactor.vault.fetch)


class TestBackwardsCompatibility:
    """Existing tests should still work with default vault."""

    def test_reversible_roundtrip_with_default_vault(self) -> None:
        redactor = Redactor(reversible=True)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]
        original = "admin@example.com is here"

        result = redactor.redact(original, spans, matter_id="test")
        assert result.mapping_id is not None

        restored = redactor.unredact(result.text, result.mapping_id, matter_id="test")
        assert restored == original

    def test_one_way_mode_unchanged(self) -> None:
        redactor = Redactor(reversible=False)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]

        result = redactor.redact("admin@example.com is here", spans)

        assert "[EMAIL]" in result.text
        assert result.mapping_id is None
        assert result.vault == {}


class TestErrorHandling:
    """Error paths and edge cases."""

    def test_vault_not_found_raises_valueerror(self) -> None:
        redactor = Redactor(reversible=True)
        fake_mapping_id = "ffffffff-ffff-ffff-ffff-ffffffffffff"

        with pytest.raises(ValueError):
            redactor.unredact("[RTKN_fake]", fake_mapping_id, matter_id="test")

    def test_wrong_matter_id_raises_error(self) -> None:
        redactor = Redactor(reversible=True)
        spans = [Span(start=0, end=5, entity_type="EMAIL")]

        result = redactor.redact("admin@example.com", spans, matter_id="correct_matter")

        with pytest.raises(ValueError):
            redactor.unredact(result.text, result.mapping_id, matter_id="wrong_matter")

    def test_vault_storage_error_raises_valueerror(self) -> None:
        class FailingStore:
            def store(self, mapping: dict[str, str], matter_id: str) -> str:
                raise RuntimeError("Storage failed")

            def fetch(self, mapping_id: str, matter_id: str) -> dict[str, str]:
                return {}

        redactor = Redactor(reversible=True, vault=FailingStore())
        spans = [Span(start=0, end=5, entity_type="EMAIL")]

        with pytest.raises(ValueError, match="MappingStore storage failed"):
            redactor.redact("admin@example.com", spans, matter_id="test")
