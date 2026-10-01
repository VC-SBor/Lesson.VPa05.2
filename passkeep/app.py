"""Основная логика приложения: разблокировка хранилища и операции над записями.

Здесь связаны вместе хранилище SQLite, шифрование и политика блокировки ввода:
после ``MAX_FAILED_ATTEMPTS`` подряд неверных мастер-паролей ввод блокируется
на ``LOCK_SECONDS`` секунд (счётчики хранятся в таблице ``meta``, поэтому
перезапуск программы блокировку не снимает).
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable

from .crypto import (
    check_master_strength,
    decrypt_password,
    encrypt_password,
    fernet_from_key,
    generate_password,
    hash_master_password,
    load_or_create_key,
    new_salt,
    verify_master_password,
)
from .errors import EntryNotFoundError, LockedError, WrongMasterPasswordError
from .paths import ENV_MASTER, Paths
from .storage import (
    META_FAIL_COUNT,
    META_LOCK_UNTIL,
    META_MASTER_HASH,
    META_MASTER_SALT,
    Entry,
    Storage,
)

MAX_FAILED_ATTEMPTS = 5
LOCK_SECONDS = 60

PromptFunc = Callable[[str], str]
NoteFunc = Callable[[str], None]


def _masked_input(text: str) -> str:
    """Ввод пароля. В некоторых терминалах пароль виден при наборе."""
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
        password = input()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit("\nВход не выполнен.") from None
    return password


class Vault:
    """Хранилище паролей: мастер-пароль, ключ Fernet, таблицы SQLite."""

    def __init__(
        self,
        paths: Paths | None = None,
        prompt: PromptFunc | None = None,
        note: NoteFunc | None = None,
    ) -> None:
        self.paths = paths or Paths()
        self.storage = Storage(self.paths.db_path)
        self._prompt = prompt or _masked_input
        self._note = note or (lambda message: print(message))
        self._fernet = None

    # --- жизненный цикл ---------------------------------------------------
    def close(self) -> None:
        self.storage.close()

    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # --- разблокировка -----------------------------------------------------
    def prepare(self) -> None:
        """Создать каталог и таблицы без ввода мастер-пароля."""
        self.paths.ensure_home()
        self.storage.init_schema()

    def is_initialized(self) -> bool:
        """Создан ли уже мастер-пароль."""
        self.prepare()
        return self.storage.is_initialized()

    def unlock(self) -> None:
        """Проверить таблицы, при первом запуске создать ключ и мастер-пароль.

        При обычных запусках запрашивает мастер-пароль и открывает ключ.
        """
        self.prepare()

        if self.storage.is_initialized():
            self._check_lock()

        self._fernet = fernet_from_key(load_or_create_key(self.paths.key_path))

        if not self.storage.is_initialized():
            self._first_run_setup()
        else:
            self._verify_master()

    @property
    def fernet(self):
        if self._fernet is None:  # pragma: no cover - защита от misuse
            raise RuntimeError("Хранилище не разблокировано: вызовите unlock().")
        return self._fernet

    def _first_run_setup(self) -> None:
        """Первый запуск: создаём файл .key и сохраняем хеш нового мастер-пароля."""
        self._note("Первый запуск PassKeep.")
        self._note(f"  каталог хранилища : {self.paths.home}")
        self._note(f"  база данных       : {self.paths.db_path}")
        self._note(f"  файл ключа        : {self.paths.key_path}")
        self._note("Придумайте мастер-пароль (не менее 8 символов).")
        self._note("Если он будет утерян, восстановить пароли невозможно.")

        while True:
            password = self._read_master("Новый мастер-пароль: ")
            check_master_strength(password, min_length=8)
            again = self._read_master("Повторите мастер-пароль:  ")
            if password != again:
                self._note("Пароли не совпадают, попробуйте ещё раз.")
                continue
            break

        salt = new_salt()
        self.storage.set_meta(META_MASTER_SALT, salt.hex())
        self.storage.set_meta(META_MASTER_HASH, hash_master_password(password, salt))
        self.storage.set_meta(META_FAIL_COUNT, "0")
        self.storage.set_meta(META_LOCK_UNTIL, "0")
        self._note("Мастер-пароль сохранён в виде соли и PBKDF2-SHA256 хеша.")

    def _read_master(self, text: str) -> str:
        """Мастер-пароль из окружения (для скриптов) либо из терминала."""
        from_env = os.environ.get(ENV_MASTER)
        return from_env if from_env else self._prompt(text)

    def _check_lock(self) -> None:
        raw = self.storage.get_meta(META_LOCK_UNTIL)
        if not raw:
            return
        try:
            lock_until = float(raw)
        except ValueError:  # pragma: no cover - защита от порчи данных
            lock_until = 0.0
        remaining = int(lock_until - time.time())
        if remaining > 0:
            raise LockedError(remaining)
        if lock_until:
            self.storage.set_meta(META_LOCK_UNTIL, "0")

    def _verify_master(self) -> None:
        salt_hex = self.storage.get_meta(META_MASTER_SALT) or ""
        hash_hex = self.storage.get_meta(META_MASTER_HASH) or ""
        password = self._read_master("Мастер-пароль: ")

        if verify_master_password(password, salt_hex, hash_hex):
            self.storage.set_meta(META_FAIL_COUNT, "0")
            self.storage.set_meta(META_LOCK_UNTIL, "0")
            return

        try:
            failures = int(self.storage.get_meta(META_FAIL_COUNT) or 0)
        except ValueError:  # pragma: no cover - защита от порчи данных
            failures = 0
        failures += 1

        if failures >= MAX_FAILED_ATTEMPTS:
            self.storage.set_meta(META_FAIL_COUNT, "0")
            self.storage.set_meta(META_LOCK_UNTIL, str(time.time() + LOCK_SECONDS))
            raise LockedError(LOCK_SECONDS)

        self.storage.set_meta(META_FAIL_COUNT, str(failures))
        left = MAX_FAILED_ATTEMPTS - failures
        raise WrongMasterPasswordError(
            f"Неверный мастер-пароль. Попыток до блокировки: {left}."
        )

    # --- операции над записями --------------------------------------------
    def add(self, name: str, login: str, password: str, notes: str = "") -> Entry:
        """Добавить запись: пароль шифруется перед записью в SQLite."""
        return self.storage.add_entry(
            name=name.strip(),
            login=(login or "").strip(),
            password_enc=encrypt_password(self.fernet, password),
            notes=(notes or "").strip(),
        )

    def get(self, name: str) -> tuple[Entry, str]:
        """Вернуть запись и расшифрованный пароль."""
        entry = self.storage.get_entry(name.strip())
        if entry is None:
            raise EntryNotFoundError(f"Запись «{name}» не найдена.")
        return entry, decrypt_password(self.fernet, entry.password_enc)

    def find(self, name: str) -> Entry | None:
        return self.storage.get_entry(name.strip())

    def list(self, like: str | None = None) -> list[Entry]:
        """Список записей (названия и логины, без паролей)."""
        return self.storage.list_entries(like)

    def remove(self, name: str) -> bool:
        return self.storage.delete_entry(name.strip())

    def count(self) -> int:
        return self.storage.entry_count()

    @staticmethod
    def generate(length: int = 16, use_digits: bool = True, use_symbols: bool = True) -> str:
        return generate_password(length=length, use_digits=use_digits, use_symbols=use_symbols)
