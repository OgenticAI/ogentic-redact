"""Tests for Vault implementations (InProcessVault, SQLiteVault)."""

from __future__ import annotations

import pytest
import tempfile
from pathlib import Path

from ogentic_redact.errors import VaultNotFound, VaultError
from ogentic_redact.vault import InProcessVault, SQLiteVault


class TestInProcessVault:
    """Tests for InProcessVault implementation."""

    def test_store_and_fetch_basic(self) -> None:
        vault = InProcessVault()
        mapping = {"[RTKN_abc123]": "secret_value"}

        mapping_id = vault.store(mapping, "matter_1")
        assert isinstance(mapping_id, str)
        assert len(mapping_id) > 0

        retrieved = vault.fetch(mapping_id, "matter_1")
        assert retrieved == mapping

    def test_store_creates_copy(self) -> None:
        vault = InProcessVault()
        original_mapping = {"[RTKN_abc]": "secret"}

        vault.store(original_mapping, "matter_1")
        original_mapping["[RTKN_abc]"] = "modified"

        mapping_id = list(vault._store["matter_1"].keys())[0]
        retrieved = vault.fetch(mapping_id, "matter_1")
        assert retrieved["[RTKN_abc]"] == "secret"

    def test_fetch_returns_copy(self) -> None:
        vault = InProcessVault()
        original_mapping = {"[RTKN_abc]": "secret"}
        mapping_id = vault.store(original_mapping, "matter_1")

        retrieved = vault.fetch(mapping_id, "matter_1")
        retrieved["[RTKN_abc]"] = "modified"

        retrieved_again = vault.fetch(mapping_id, "matter_1")
        assert retrieved_again["[RTKN_abc]"] == "secret"

    def test_fetch_nonexistent_mapping_raises(self) -> None:
        vault = InProcessVault()

        with pytest.raises(VaultNotFound):
            vault.fetch("nonexistent_id", "matter_1")

    def test_per_matter_isolation(self) -> None:
        vault = InProcessVault()
        mapping_a = {"[RTKN_a]": "secret_a"}
        mapping_b = {"[RTKN_b]": "secret_b"}

        mapping_id_a = vault.store(mapping_a, "matter_a")
        mapping_id_b = vault.store(mapping_b, "matter_b")

        retrieved_a = vault.fetch(mapping_id_a, "matter_a")
        assert retrieved_a == mapping_a

        retrieved_b = vault.fetch(mapping_id_b, "matter_b")
        assert retrieved_b == mapping_b

        with pytest.raises(VaultNotFound):
            vault.fetch(mapping_id_a, "matter_b")

        with pytest.raises(VaultNotFound):
            vault.fetch(mapping_id_b, "matter_a")

    def test_multiple_mappings_per_matter(self) -> None:
        vault = InProcessVault()
        mapping1 = {"[RTKN_1]": "secret1"}
        mapping2 = {"[RTKN_2]": "secret2"}

        mapping_id_1 = vault.store(mapping1, "matter_1")
        mapping_id_2 = vault.store(mapping2, "matter_1")

        assert mapping_id_1 != mapping_id_2
        assert vault.fetch(mapping_id_1, "matter_1") == mapping1
        assert vault.fetch(mapping_id_2, "matter_1") == mapping2


class TestSQLiteVault:
    """Tests for SQLiteVault implementation."""

    def test_store_and_fetch_basic(self) -> None:
        vault = SQLiteVault()
        mapping = {"[RTKN_abc123]": "secret_value"}

        mapping_id = vault.store(mapping, "matter_1")
        assert isinstance(mapping_id, str)
        assert len(mapping_id) > 0

        retrieved = vault.fetch(mapping_id, "matter_1")
        assert retrieved == mapping

    def test_persist_across_instances(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "vault.db")

            vault1 = SQLiteVault(db_path)
            mapping = {"[RTKN_abc]": "persistent_secret"}
            mapping_id = vault1.store(mapping, "matter_1")

            vault2 = SQLiteVault(db_path)
            retrieved = vault2.fetch(mapping_id, "matter_1")
            assert retrieved == mapping

    def test_fetch_nonexistent_mapping_raises(self) -> None:
        vault = SQLiteVault()

        with pytest.raises(VaultNotFound):
            vault.fetch("nonexistent_id", "matter_1")

    def test_per_matter_isolation(self) -> None:
        vault = SQLiteVault()
        mapping_a = {"[RTKN_a]": "secret_a"}
        mapping_b = {"[RTKN_b]": "secret_b"}

        mapping_id_a = vault.store(mapping_a, "matter_a")
        mapping_id_b = vault.store(mapping_b, "matter_b")

        retrieved_a = vault.fetch(mapping_id_a, "matter_a")
        assert retrieved_a == mapping_a

        retrieved_b = vault.fetch(mapping_id_b, "matter_b")
        assert retrieved_b == mapping_b

        with pytest.raises(VaultNotFound):
            vault.fetch(mapping_id_a, "matter_b")

        with pytest.raises(VaultNotFound):
            vault.fetch(mapping_id_b, "matter_a")

    def test_multiple_mappings_per_matter(self) -> None:
        vault = SQLiteVault()
        mapping1 = {"[RTKN_1]": "secret1"}
        mapping2 = {"[RTKN_2]": "secret2"}

        mapping_id_1 = vault.store(mapping1, "matter_1")
        mapping_id_2 = vault.store(mapping2, "matter_1")

        assert mapping_id_1 != mapping_id_2
        assert vault.fetch(mapping_id_1, "matter_1") == mapping1
        assert vault.fetch(mapping_id_2, "matter_1") == mapping2

    def test_empty_matter_id(self) -> None:
        vault = SQLiteVault()
        mapping = {"[RTKN_test]": "value"}

        mapping_id = vault.store(mapping, "")
        retrieved = vault.fetch(mapping_id, "")
        assert retrieved == mapping

    def test_special_characters_in_mapping(self) -> None:
        vault = SQLiteVault()
        mapping = {
            "[RTKN_1]": "value with\nnewlines",
            "[RTKN_2]": 'value with "quotes"',
            "[RTKN_3]": "value with 'apostrophes'",
        }

        mapping_id = vault.store(mapping, "matter_1")
        retrieved = vault.fetch(mapping_id, "matter_1")
        assert retrieved == mapping
