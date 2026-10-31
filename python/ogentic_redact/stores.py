"""Tenant-scoped reversible mappings with explicit deletion and optional retention limits."""

from __future__ import annotations

import json
import math
import os
import sqlite3
import threading
import time
import uuid
from typing import Protocol

from ogentic_redact.errors import MappingNotFound, MappingStoreError


class MappingStore(Protocol):
    """Vault contract. All operations must enforce the supplied matter scope.

    ``consume`` atomically retrieves and deletes a mapping; ``delete`` supports
    explicit retention and rollback after a failed redaction. Missing, expired,
    or cross-matter IDs raise ``MappingNotFound`` without disclosing identifiers.
    Mapping IDs identify immutable records; a record must never be replaced under
    an existing ID. Implementations must raise ``MappingStoreError`` for other
    storage failures. Callers may fetch and validate restoration before consuming;
    only the caller whose atomic consume succeeds may return the restored result.
    """

    def store(self, mapping: dict[str, str], matter_id: str) -> str:
        """Persist a copied token→original table and return an opaque ID."""
        ...

    def fetch(self, mapping_id: str, matter_id: str) -> dict[str, str]:
        """Retrieve a copy of an unexpired mapping without consuming it."""
        ...

    def delete(self, mapping_id: str, matter_id: str) -> None:
        """Delete an unexpired mapping under the same matter scope."""
        ...

    def consume(self, mapping_id: str, matter_id: str) -> dict[str, str]:
        """Atomically retrieve and delete an unexpired mapping."""
        ...


def _validate_limits(ttl_seconds: float | None, max_entries: int | None) -> None:
    if ttl_seconds is not None and (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, (int, float))
        or not math.isfinite(ttl_seconds)
        or ttl_seconds <= 0
    ):
        raise ValueError("ttl_seconds must be a finite positive number")
    if max_entries is not None and (type(max_entries) is not int or max_entries <= 0):
        raise ValueError("max_entries must be a positive integer")


def _validated_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not key or not isinstance(original, str)
        for key, original in value.items()
    ):
        raise MappingStoreError("mapping must contain non-empty string tokens and string values")
    return value.copy()


class InProcessMappingStore:
    """Thread-safe process-local vault; mappings disappear with the process.

    ``ttl_seconds`` limits retrieval to a retention window. Expired entries are
    purged on subsequent operations; this is not a background erasure service.
    ``max_entries`` bounds the total stored mappings across matters and rejects
    new writes at capacity, preserving existing live mappings. Both limits are
    optional. Use ``delete`` or ``consume`` to end retention explicitly.
    """

    def __init__(
        self, *, ttl_seconds: float | None = None, max_entries: int | None = None
    ) -> None:
        _validate_limits(ttl_seconds, max_entries)
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries
        self._store: dict[str, dict[str, dict[str, str]]] = {}
        self._expires: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def _purge_expired(self) -> None:
        now = time.time()
        for (matter_id, mapping_id), expires in list(self._expires.items()):
            if expires <= now:
                self._remove(mapping_id, matter_id)

    def _remove(self, mapping_id: str, matter_id: str) -> dict[str, str]:
        scoped = self._store.get(matter_id, {})
        if mapping_id not in scoped:
            raise MappingNotFound("unknown or expired mapping_id")
        mapping = scoped.pop(mapping_id)
        self._expires.pop((matter_id, mapping_id), None)
        if not scoped:
            del self._store[matter_id]
        return mapping

    def store(self, mapping: dict[str, str], matter_id: str) -> str:
        """Store a copied mapping; reject writes when configured capacity is full."""
        copied = _validated_mapping(mapping)
        with self._lock:
            self._purge_expired()
            if self._max_entries is not None:
                count = sum(len(scoped) for scoped in self._store.values())
                if count >= self._max_entries:
                    raise MappingStoreError("mapping store capacity reached")
            mapping_id = str(uuid.uuid4())
            self._store.setdefault(matter_id, {})[mapping_id] = copied
            if self._ttl_seconds is not None:
                self._expires[matter_id, mapping_id] = time.time() + self._ttl_seconds
            return mapping_id

    def fetch(self, mapping_id: str, matter_id: str) -> dict[str, str]:
        """Fetch a copy of the mapping; cross-matter lookup is indistinguishable from absence."""
        with self._lock:
            self._purge_expired()
            mapping = self._store.get(matter_id, {}).get(mapping_id)
            if mapping is None:
                raise MappingNotFound("unknown or expired mapping_id")
            return mapping.copy()

    def delete(self, mapping_id: str, matter_id: str) -> None:
        """Delete one mapping without returning the sensitive values."""
        with self._lock:
            self._purge_expired()
            self._remove(mapping_id, matter_id)

    def consume(self, mapping_id: str, matter_id: str) -> dict[str, str]:
        """Retrieve and delete a mapping in one locked operation."""
        with self._lock:
            self._purge_expired()
            return self._remove(mapping_id, matter_id)


class SQLiteMappingStore:
    """Local SQLite vault with scoped deletion, atomic consumption, and optional limits.

    Newly created database files have owner-only permissions. Existing database
    permissions are unchanged. Values remain plaintext: callers own encryption
    and backup protection. Expiry is persisted as UTC epoch seconds and checked
    on access; physical deletion occurs in bounded batches on writes or explicit
    ``purge_expired`` calls, not on a timer. Fetches are read-only point lookups.
    Deletion does not guarantee erasure from filesystem snapshots or backups.
    Legacy databases without an expiry column are migrated on opening.
    """

    def __init__(
        self,
        db_path: str | None = None,
        *,
        ttl_seconds: float | None = None,
        max_entries: int | None = None,
    ) -> None:
        _validate_limits(ttl_seconds, max_entries)
        self.db_path = db_path or ":memory:"
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries
        self._lock = threading.Lock()
        try:
            if self.db_path != ":memory:":
                try:
                    fd = os.open(self.db_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                except FileExistsError:
                    pass
                else:
                    os.close(fd)
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._init_schema()
        except (OSError, sqlite3.Error):
            raise MappingStoreError("unable to initialize mapping store") from None

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("PRAGMA secure_delete = ON")
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS vaults (
                    id TEXT NOT NULL, matter_id TEXT NOT NULL,
                    mapping TEXT NOT NULL, expires_at REAL,
                    PRIMARY KEY (id, matter_id)
                )"""
            )
            columns = {row[1] for row in self._conn.execute("PRAGMA table_info(vaults)")}
            if "expires_at" not in columns:
                self._conn.execute("ALTER TABLE vaults ADD COLUMN expires_at REAL")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS vaults_expiry ON vaults(expires_at) "
                "WHERE expires_at IS NOT NULL"
            )

    def _purge_expired(self, limit: int = 1000) -> int:
        return self._conn.execute(
            "DELETE FROM vaults WHERE rowid IN ("
            "SELECT rowid FROM vaults WHERE expires_at <= ? ORDER BY expires_at LIMIT ?)",
            (time.time(), limit),
        ).rowcount

    def purge_expired(self, *, limit: int = 1000) -> int:
        """Delete at most *limit* expired records, returning the number removed."""
        if type(limit) is not int or limit <= 0:
            raise ValueError("limit must be a positive integer")
        try:
            with self._lock, self._conn:
                return self._purge_expired(limit)
        except sqlite3.Error:
            raise MappingStoreError("unable to purge expired mappings") from None

    def close(self) -> None:
        """Close the connection after ongoing operations finish."""
        with self._lock:
            self._conn.close()

    def store(self, mapping: dict[str, str], matter_id: str) -> str:
        """Persist a copied mapping; enforce capacity transactionally across connections."""
        mapping_json = json.dumps(_validated_mapping(mapping))
        mapping_id = str(uuid.uuid4())
        try:
            with self._lock, self._conn:
                self._conn.execute("BEGIN IMMEDIATE")
                self._purge_expired()
                if self._max_entries is not None:
                    count = self._conn.execute(
                        "SELECT COUNT(*) FROM vaults WHERE expires_at IS NULL OR expires_at > ?",
                        (time.time(),),
                    ).fetchone()[0]
                    if count >= self._max_entries:
                        raise MappingStoreError("mapping store capacity reached")
                # Start retention after waiting for writer locks and cleanup;
                # a queued write must not return an already-expired mapping.
                expires = None if self._ttl_seconds is None else time.time() + self._ttl_seconds
                self._conn.execute(
                    "INSERT INTO vaults (id, matter_id, mapping, expires_at) VALUES (?, ?, ?, ?)",
                    (mapping_id, matter_id, mapping_json, expires),
                )
        except sqlite3.Error:
            raise MappingStoreError("unable to store mapping") from None
        return mapping_id

    def _read(self, mapping_id: str, matter_id: str, *, consume: bool) -> dict[str, str]:
        try:
            with self._lock, self._conn:
                self._conn.execute("BEGIN IMMEDIATE")
                row = self._conn.execute(
                    "SELECT mapping FROM vaults WHERE id = ? AND matter_id = ? "
                    "AND (expires_at IS NULL OR expires_at > ?)",
                    (mapping_id, matter_id, time.time()),
                ).fetchone()
                mapping = None if row is None else _validated_mapping(json.loads(row[0]))
                if consume and row is not None:
                    self._conn.execute(
                        "DELETE FROM vaults WHERE id = ? AND matter_id = ?", (mapping_id, matter_id)
                    )
            if mapping is None:
                raise MappingNotFound("unknown or expired mapping_id")
            return mapping
        except (sqlite3.Error, json.JSONDecodeError):
            raise MappingStoreError("unable to retrieve mapping") from None

    def fetch(self, mapping_id: str, matter_id: str) -> dict[str, str]:
        """Read one unexpired mapping without a writer lock or global cleanup."""
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT mapping FROM vaults WHERE id = ? AND matter_id = ? "
                    "AND (expires_at IS NULL OR expires_at > ?)",
                    (mapping_id, matter_id, time.time()),
                ).fetchone()
            if row is None:
                raise MappingNotFound("unknown or expired mapping_id")
            return _validated_mapping(json.loads(row[0]))
        except (sqlite3.Error, json.JSONDecodeError):
            raise MappingStoreError("unable to retrieve mapping") from None

    def delete(self, mapping_id: str, matter_id: str) -> None:
        """Delete a mapping without returning its values."""
        try:
            with self._lock, self._conn:
                self._conn.execute("BEGIN IMMEDIATE")
                removed = self._conn.execute(
                    "DELETE FROM vaults WHERE id = ? AND matter_id = ? "
                    "AND (expires_at IS NULL OR expires_at > ?)",
                    (mapping_id, matter_id, time.time()),
                ).rowcount
            if removed == 0:
                raise MappingNotFound("unknown or expired mapping_id")
        except sqlite3.Error:
            raise MappingStoreError("unable to delete mapping") from None

    def consume(self, mapping_id: str, matter_id: str) -> dict[str, str]:
        """Retrieve and delete atomically, including across separate vault connections."""
        return self._read(mapping_id, matter_id, consume=True)
