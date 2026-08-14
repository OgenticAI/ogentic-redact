"""Tests for MappingStore implementations (InProcessMappingStore, SQLiteMappingStore)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from ogentic_redact.errors import MappingNotFound
from ogentic_redact.stores import InProcessMappingStore, SQLiteMappingStore


class TestInProcessMappingStore:
    """Tests for InProcessMappingStore implementation."""

    def test_store_and_fetch_basic(self) -> None:
        store = InProcessMappingStore()
        mapping = {"[RTKN_abc123]": "secret_value"}

        mapping_id = store.store(mapping, "matter_1")
        assert isinstance(mapping_id, str)
        assert len(mapping_id) > 0

        retrieved = store.fetch(mapping_id, "matter_1")
        assert retrieved == mapping

    def test_store_creates_copy(self) -> None:
        store = InProcessMappingStore()
        original_mapping = {"[RTKN_abc]": "secret"}

        store.store(original_mapping, "matter_1")
        original_mapping["[RTKN_abc]"] = "modified"

        mapping_id = list(store._store["matter_1"].keys())[0]
        retrieved = store.fetch(mapping_id, "matter_1")
        assert retrieved["[RTKN_abc]"] == "secret"

    def test_fetch_returns_copy(self) -> None:
        store = InProcessMappingStore()
        original_mapping = {"[RTKN_abc]": "secret"}
        mapping_id = store.store(original_mapping, "matter_1")

        retrieved = store.fetch(mapping_id, "matter_1")
        retrieved["[RTKN_abc]"] = "modified"

        retrieved_again = store.fetch(mapping_id, "matter_1")
        assert retrieved_again["[RTKN_abc]"] == "secret"

    def test_fetch_nonexistent_mapping_raises(self) -> None:
        store = InProcessMappingStore()

        with pytest.raises(MappingNotFound):
            store.fetch("nonexistent_id", "matter_1")

    def test_per_matter_isolation(self) -> None:
        store = InProcessMappingStore()
        mapping_a = {"[RTKN_a]": "secret_a"}
        mapping_b = {"[RTKN_b]": "secret_b"}

        mapping_id_a = store.store(mapping_a, "matter_a")
        mapping_id_b = store.store(mapping_b, "matter_b")

        retrieved_a = store.fetch(mapping_id_a, "matter_a")
        assert retrieved_a == mapping_a

        retrieved_b = store.fetch(mapping_id_b, "matter_b")
        assert retrieved_b == mapping_b

        with pytest.raises(MappingNotFound):
            store.fetch(mapping_id_a, "matter_b")

        with pytest.raises(MappingNotFound):
            store.fetch(mapping_id_b, "matter_a")

    def test_multiple_mappings_per_matter(self) -> None:
        store = InProcessMappingStore()
        mapping1 = {"[RTKN_1]": "secret1"}
        mapping2 = {"[RTKN_2]": "secret2"}

        mapping_id_1 = store.store(mapping1, "matter_1")
        mapping_id_2 = store.store(mapping2, "matter_1")

        assert mapping_id_1 != mapping_id_2
        assert store.fetch(mapping_id_1, "matter_1") == mapping1
        assert store.fetch(mapping_id_2, "matter_1") == mapping2


class TestSQLiteMappingStore:
    """Tests for SQLiteMappingStore implementation."""

    def test_store_and_fetch_basic(self) -> None:
        store = SQLiteMappingStore()
        mapping = {"[RTKN_abc123]": "secret_value"}

        mapping_id = store.store(mapping, "matter_1")
        assert isinstance(mapping_id, str)
        assert len(mapping_id) > 0

        retrieved = store.fetch(mapping_id, "matter_1")
        assert retrieved == mapping

    def test_persist_across_instances(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "store.db")

            store1 = SQLiteMappingStore(db_path)
            mapping = {"[RTKN_abc]": "persistent_secret"}
            mapping_id = store1.store(mapping, "matter_1")

            store2 = SQLiteMappingStore(db_path)
            retrieved = store2.fetch(mapping_id, "matter_1")
            assert retrieved == mapping

    def test_fetch_nonexistent_mapping_raises(self) -> None:
        store = SQLiteMappingStore()

        with pytest.raises(MappingNotFound):
            store.fetch("nonexistent_id", "matter_1")

    def test_per_matter_isolation(self) -> None:
        store = SQLiteMappingStore()
        mapping_a = {"[RTKN_a]": "secret_a"}
        mapping_b = {"[RTKN_b]": "secret_b"}

        mapping_id_a = store.store(mapping_a, "matter_a")
        mapping_id_b = store.store(mapping_b, "matter_b")

        retrieved_a = store.fetch(mapping_id_a, "matter_a")
        assert retrieved_a == mapping_a

        retrieved_b = store.fetch(mapping_id_b, "matter_b")
        assert retrieved_b == mapping_b

        with pytest.raises(MappingNotFound):
            store.fetch(mapping_id_a, "matter_b")

        with pytest.raises(MappingNotFound):
            store.fetch(mapping_id_b, "matter_a")

    def test_multiple_mappings_per_matter(self) -> None:
        store = SQLiteMappingStore()
        mapping1 = {"[RTKN_1]": "secret1"}
        mapping2 = {"[RTKN_2]": "secret2"}

        mapping_id_1 = store.store(mapping1, "matter_1")
        mapping_id_2 = store.store(mapping2, "matter_1")

        assert mapping_id_1 != mapping_id_2
        assert store.fetch(mapping_id_1, "matter_1") == mapping1
        assert store.fetch(mapping_id_2, "matter_1") == mapping2

    def test_empty_matter_id(self) -> None:
        store = SQLiteMappingStore()
        mapping = {"[RTKN_test]": "value"}

        mapping_id = store.store(mapping, "")
        retrieved = store.fetch(mapping_id, "")
        assert retrieved == mapping

    def test_special_characters_in_mapping(self) -> None:
        store = SQLiteMappingStore()
        mapping = {
            "[RTKN_1]": "value with\nnewlines",
            "[RTKN_2]": 'value with "quotes"',
            "[RTKN_3]": "value with 'apostrophes'",
        }

        mapping_id = store.store(mapping, "matter_1")
        retrieved = store.fetch(mapping_id, "matter_1")
        assert retrieved == mapping
