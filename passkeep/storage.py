"""Слой хранилища: все работы с базой данных SQLite3.

В базе две таблицы:

* ``meta``  - служебные значения (соль и хеш мастер-пароля, счётчик ошибок,
  время блокировки ввода);
* ``vault`` - сами записи ("Название" / "Логин" / "Пароль в зашифрованном виде").

Пароли в таблице ``vault`` хранятся только в поле ``password_enc`` уже
зашифрованными (Fernet-токен), открытый пароль в базу не попадает.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .errors import DuplicateEntryError, StorageError

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    login        TEXT NOT NULL DEFAULT '',
    password_enc TEXT NOT NULL,
    notes        TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vault_name ON vault (name);
"""

META_MASTER_SALT = "master_salt"
META_MASTER_HASH = "master_hash"
META_FAIL_COUNT = "fail_count"
META_LOCK_UNTIL = "lock_until"


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


@dataclass
class Entry:
    """Строка таблицы ``vault`` (пароль в зашифрованном виде)."""

    id: int
    name: str
    login: str
    password_enc: str
    notes: str
    created_at: str
    updated_at: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Entry":
        return cls(
            id=row["id"],
            name=row["name"],
            login=row["login"],
            password_enc=row["password_enc"],
            notes=row["notes"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


class Storage:
    """Обёртка над sqlite3 с операциями над хранилищем паролей."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.conn = sqlite3.connect(str(self.db_path))
        except sqlite3.Error as exc:  # pragma: no cover - редкий случай
            raise StorageError(f"Не удалось открыть базу {self.db_path}: {exc}") from exc
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")

    # --- служебное ---------------------------------------------------------
    def init_schema(self) -> None:
        """Проверить наличие таблиц и создать их при первом запуске."""
        with self.conn:
            self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # --- таблица meta ------------------------------------------------------
    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def is_initialized(self) -> bool:
        """Создан ли уже мастер-пароль (то есть это не первый запуск)."""
        return self.get_meta(META_MASTER_HASH) is not None

    # --- таблица vault -----------------------------------------------------
    def add_entry(self, name: str, login: str, password_enc: str, notes: str = "") -> Entry:
        stamp = _now()
        try:
            with self.conn:
                cursor = self.conn.execute(
                    "INSERT INTO vault (name, login, password_enc, notes, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (name, login, password_enc, notes, stamp, stamp),
                )
        except sqlite3.IntegrityError as exc:
            raise DuplicateEntryError(f"Запись «{name}» уже существует.") from exc
        row = self.conn.execute("SELECT * FROM vault WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return Entry.from_row(row)

    def get_entry(self, name: str) -> Entry | None:
        row = self.conn.execute(
            "SELECT * FROM vault WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
        return Entry.from_row(row) if row else None

    def list_entries(self, like: str | None = None) -> list[Entry]:
        if like:
            rows = self.conn.execute(
                "SELECT * FROM vault WHERE name LIKE ? COLLATE NOCASE OR login LIKE ?"
                " ORDER BY name COLLATE NOCASE",
                (f"%{like}%", f"%{like}%"),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM vault ORDER BY name COLLATE NOCASE"
            ).fetchall()
        return [Entry.from_row(row) for row in rows]

    def delete_entry(self, name: str) -> bool:
        with self.conn:
            cursor = self.conn.execute(
                "DELETE FROM vault WHERE name = ? COLLATE NOCASE", (name,)
            )
        return cursor.rowcount > 0

    def entry_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS n FROM vault").fetchone()
        return int(row["n"])
