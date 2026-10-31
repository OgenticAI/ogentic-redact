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


@pytest.fixture(params=[InProcessMappingStore, SQLiteMappingStore])
def vault_factory(request):
    stores = []
    def create(**kwargs):
        store = request.param(**kwargs)
        stores.append(store)
        return store
    yield create
    for store in stores:
        if isinstance(store, SQLiteMappingStore):
            store.close()


def test_delete_is_scoped_and_final(vault_factory) -> None:
    store = vault_factory()
    mapping_id = store.store({"token": "secret"}, "a")
    with pytest.raises(MappingNotFound):
        store.delete(mapping_id, "b")
    assert store.fetch(mapping_id, "a") == {"token": "secret"}
    store.delete(mapping_id, "a")
    with pytest.raises(MappingNotFound):
        store.fetch(mapping_id, "a")


def test_consume_is_scoped_and_available_once(vault_factory) -> None:
    store = vault_factory()
    mapping_id = store.store({"token": "secret"}, "a")
    with pytest.raises(MappingNotFound):
        store.consume(mapping_id, "b")
    assert store.consume(mapping_id, "a") == {"token": "secret"}
    with pytest.raises(MappingNotFound):
        store.consume(mapping_id, "a")


def test_retention_expiry_releases_capacity(vault_factory, monkeypatch) -> None:
    from ogentic_redact.errors import MappingStoreError
    import ogentic_redact.stores as module
    monkeypatch.setattr(module.time, "time", lambda: 1000.0)
    store = vault_factory(ttl_seconds=10, max_entries=1)
    mapping_id = store.store({"token": "secret"}, "a")
    with pytest.raises(MappingStoreError, match="capacity"):
        store.store({"next": "value"}, "b")
    monkeypatch.setattr(module.time, "time", lambda: 1010.0)
    with pytest.raises(MappingNotFound):
        store.fetch(mapping_id, "a")
    new_id = store.store({"next": "value"}, "b")
    assert store.fetch(new_id, "b") == {"next": "value"}


def test_concurrent_consumers_have_one_winner(vault_factory) -> None:
    from concurrent.futures import ThreadPoolExecutor
    store = vault_factory()
    mapping_id = store.store({"token": "secret"}, "a")
    def consume():
        try:
            return store.consume(mapping_id, "a")
        except MappingNotFound:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: consume(), range(2)))
    assert results.count({"token": "secret"}) == 1
    assert results.count(None) == 1


@pytest.mark.parametrize("kwargs", [
    {"ttl_seconds": 0}, {"ttl_seconds": float("nan")}, {"ttl_seconds": float("inf")},
    {"max_entries": 0}, {"max_entries": 0.5}, {"max_entries": True},
])
def test_invalid_retention_configuration_rejected(vault_factory, kwargs) -> None:
    with pytest.raises(ValueError):
        vault_factory(**kwargs)


def test_sqlite_expiry_survives_reopen(tmp_path, monkeypatch) -> None:
    import ogentic_redact.stores as module
    monkeypatch.setattr(module.time, "time", lambda: 1000.0)
    path = str(tmp_path / "vault.sqlite")
    first = SQLiteMappingStore(path, ttl_seconds=10)
    mapping_id = first.store({"token": "secret"}, "a")
    first.close()
    monkeypatch.setattr(module.time, "time", lambda: 1011.0)
    reopened = SQLiteMappingStore(path)
    try:
        with pytest.raises(MappingNotFound):
            reopened.fetch(mapping_id, "a")
    finally:
        reopened.close()


def test_sqlite_legacy_schema_migration_and_owner_permissions(tmp_path) -> None:
    import os
    import sqlite3
    new_path = tmp_path / "new.sqlite"
    fresh = SQLiteMappingStore(str(new_path))
    fresh.close()
    if os.name == "posix":
        assert new_path.stat().st_mode & 0o777 == 0o600
    legacy_path = tmp_path / "legacy.sqlite"
    with sqlite3.connect(legacy_path) as connection:
        connection.execute("CREATE TABLE vaults (id TEXT, matter_id TEXT, mapping TEXT, PRIMARY KEY (id, matter_id))")
        connection.execute("INSERT INTO vaults VALUES ('legacy', 'a', '{\"token\": \"secret\"}')")
    upgraded = SQLiteMappingStore(str(legacy_path))
    try:
        assert upgraded.fetch("legacy", "a") == {"token": "secret"}
        upgraded.delete("legacy", "a")
    finally:
        upgraded.close()


def test_sqlite_capacity_and_consume_across_connections(tmp_path) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from ogentic_redact.errors import MappingStoreError
    path = str(tmp_path / "shared.sqlite")
    first = SQLiteMappingStore(path, max_entries=1)
    second = SQLiteMappingStore(path, max_entries=1)
    try:
        mapping_id = first.store({"token": "secret"}, "a")
        with pytest.raises(MappingStoreError, match="capacity"):
            second.store({"other": "secret"}, "b")
        def consume(store):
            try:
                return store.consume(mapping_id, "a")
            except MappingNotFound:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(consume, [first, second]))
        assert results.count({"token": "secret"}) == 1
        assert results.count(None) == 1
    finally:
        first.close()
        second.close()


def test_sqlite_fetch_succeeds_while_another_connection_holds_writer_lock(tmp_path) -> None:
    path = str(tmp_path / "concurrent.sqlite")
    writer = SQLiteMappingStore(path)
    reader = SQLiteMappingStore(path)
    try:
        mapping_id = writer.store({"[t]": "secret"}, "scope")
        reader._conn.execute("PRAGMA busy_timeout = 20")
        writer._conn.execute("BEGIN IMMEDIATE")
        assert reader.fetch(mapping_id, "scope") == {"[t]": "secret"}
        assert not reader._conn.in_transaction
    finally:
        writer._conn.rollback()
        writer.close()
        reader.close()


def test_sqlite_read_only_fetch_checks_expiry_and_cleanup_is_bounded(monkeypatch) -> None:
    import ogentic_redact.stores as module
    monkeypatch.setattr(module.time, "time", lambda: 1000.0)
    store = SQLiteMappingStore(ttl_seconds=10)
    try:
        ids = [store.store({"[t]": "secret"}, "scope") for _ in range(4)]
        monkeypatch.setattr(module.time, "time", lambda: 1010.0)
        with pytest.raises(MappingNotFound):
            store.fetch(ids[0], "scope")
        # Expired records cannot be read, but fetching did no cleanup write.
        assert store._conn.execute("SELECT COUNT(*) FROM vaults").fetchone()[0] == 4
        assert store.purge_expired(limit=2) == 2
        assert store.purge_expired(limit=2) == 2
        assert store.purge_expired(limit=2) == 0
    finally:
        store.close()


def test_sqlite_capacity_ignores_expired_rows_beyond_cleanup_batch(monkeypatch) -> None:
    import ogentic_redact.stores as module
    monkeypatch.setattr(module.time, "time", lambda: 1000.0)
    store = SQLiteMappingStore(ttl_seconds=10, max_entries=1)
    try:
        with store._conn:
            store._conn.executemany(
                "INSERT INTO vaults VALUES (?, 'scope', '{}', 900)",
                [(f"expired-{i}",) for i in range(1002)],
            )
        mapping_id = store.store({"[t]": "live"}, "scope")
        assert store.fetch(mapping_id, "scope") == {"[t]": "live"}
        assert store._conn.execute("SELECT COUNT(*) FROM vaults").fetchone()[0] == 3
    finally:
        store.close()


def test_sqlite_retention_starts_after_write_wait_and_maintenance(monkeypatch) -> None:
    import ogentic_redact.stores as module
    clock = [1000.0]
    monkeypatch.setattr(module.time, "time", lambda: clock[0])
    store = SQLiteMappingStore(ttl_seconds=10)
    purge = store._purge_expired

    def delayed_maintenance():
        clock[0] = 1011.0
        return purge()

    monkeypatch.setattr(store, "_purge_expired", delayed_maintenance)
    try:
        mapping_id = store.store({"[t]": "secret"}, "scope")
        assert store.fetch(mapping_id, "scope") == {"[t]": "secret"}
        clock[0] = 1021.0
        with pytest.raises(MappingNotFound):
            store.fetch(mapping_id, "scope")
    finally:
        store.close()
