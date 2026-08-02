"""Vault interface and implementations for storing reversible redaction mappings."""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Protocol

from ogentic_redact.errors import VaultError, VaultNotFound


class Vault(Protocol):
    """Abstract vault for storing and retrieving reversible redaction mappings.

    A Vault is responsible for persisting token→original mappings, scoped by
    matter_id (tenant identifier). Implementations may use in-process memory,
    local files, or external services.
    """

    def store(
        self,
        mapping: dict[str, str],
        matter_id: str,
    ) -> str:
        """Store a token→original mapping, scoped to a matter.

        Args:
            mapping: dict mapping token (e.g. "[RTKN_abc123]") to original value.
            matter_id: Tenant/matter identifier for isolation.

        Returns:
            opaque mapping_id string (UUID recommended).

        Raises:
            VaultError if storage fails.
        """
        ...

    def fetch(
        self,
        mapping_id: str,
        matter_id: str,
    ) -> dict[str, str]:
        """Retrieve a stored mapping by ID, scoped to a matter.

        Args:
            mapping_id: The ID returned by store().
            matter_id: The matter under which the mapping was stored.

        Returns:
            The token→original dict.

        Raises:
            VaultNotFound if mapping_id does not exist under matter_id.
            VaultError for other failures (storage access, etc).
        """
        ...


class InProcessVault:
    """Development/demo vault: mappings in memory, scoped per matter.

    Mappings survive only as long as the process lives. Acceptable for
    local demos and unit tests, not for multi-request scenarios.
    """

    def __init__(self) -> None:
        self._store: dict[str, dict[str, dict[str, str]]] = {}

    def store(
        self,
        mapping: dict[str, str],
        matter_id: str,
    ) -> str:
        """Store mapping in memory.

        Args:
            mapping: Token→original dict.
            matter_id: Matter identifier for scoping.

        Returns:
            opaque mapping_id (UUID).
        """
        mapping_id = str(uuid.uuid4())
        if matter_id not in self._store:
            self._store[matter_id] = {}
        self._store[matter_id][mapping_id] = mapping.copy()
        return mapping_id

    def fetch(
        self,
        mapping_id: str,
        matter_id: str,
    ) -> dict[str, str]:
        """Fetch mapping by ID and matter.

        Args:
            mapping_id: The ID returned by store().
            matter_id: The matter under which the mapping was stored.

        Returns:
            The token→original dict (copy to prevent external mutation).

        Raises:
            VaultNotFound if not found under matter_id.
        """
        if matter_id not in self._store or mapping_id not in self._store[matter_id]:
            raise VaultNotFound(
                f"mapping_id={mapping_id!r} not found under matter_id={matter_id!r}"
            )
        return self._store[matter_id][mapping_id].copy()


class SQLiteVault:
    """On-device SQLite vault, survives process restarts.

    Mappings are persisted to a local SQLite file, fully on-device,
    with no external dependencies. Suitable for CLI and single-user
    MCP server deployments.
    """

    def __init__(self, db_path: str | None = None) -> None:
        """Initialize SQLiteVault.

        Args:
            db_path: Path to SQLite database file. If None, use ":memory:".
        """
        self.db_path = db_path or ":memory:"
        self._init_schema()

    def _init_schema(self) -> None:
        """Initialize database schema on first use."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS vaults (
                        id TEXT NOT NULL,
                        matter_id TEXT NOT NULL,
                        mapping TEXT NOT NULL,
                        PRIMARY KEY (id, matter_id)
                    )
                    """
                )
                conn.commit()
        except sqlite3.Error as e:
            raise VaultError(f"Failed to initialize vault schema: {e}") from e

    def store(
        self,
        mapping: dict[str, str],
        matter_id: str,
    ) -> str:
        """Store mapping in SQLite vault.

        Args:
            mapping: Token→original dict.
            matter_id: Matter identifier for scoping.

        Returns:
            opaque mapping_id (UUID).

        Raises:
            VaultError on storage failure.
        """
        mapping_id = str(uuid.uuid4())
        mapping_json = json.dumps(mapping)

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO vaults (id, matter_id, mapping)
                    VALUES (?, ?, ?)
                    """,
                    (mapping_id, matter_id, mapping_json),
                )
                conn.commit()
        except sqlite3.Error as e:
            raise VaultError(f"Failed to store mapping in vault: {e}") from e

        return mapping_id

    def fetch(
        self,
        mapping_id: str,
        matter_id: str,
    ) -> dict[str, str]:
        """Fetch mapping by ID and matter.

        Args:
            mapping_id: The ID returned by store().
            matter_id: The matter under which the mapping was stored.

        Returns:
            The token→original dict.

        Raises:
            VaultNotFound if not found under matter_id.
            VaultError on storage failure.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    """
                    SELECT mapping FROM vaults
                    WHERE id = ? AND matter_id = ?
                    """,
                    (mapping_id, matter_id),
                )
                row = cursor.fetchone()

            if row is None:
                raise VaultNotFound(
                    f"mapping_id={mapping_id!r} not found under matter_id={matter_id!r}"
                )

            return json.loads(row[0])
        except VaultNotFound:
            raise
        except sqlite3.Error as e:
            raise VaultError(f"Failed to fetch mapping from vault: {e}") from e
        except json.JSONDecodeError as e:
            raise VaultError(f"Corrupted mapping data in vault: {e}") from e
