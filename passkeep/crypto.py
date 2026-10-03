"""Функции шифрования и генерации паролей.

Используются три механизма:

1. Мастер-пароль пользователя никогда не хранится в открытом виде - только
   случайная соль и хеш (PBKDF2-HMAC-SHA256, то есть SHA-256 с ключевой
   функцией и большим числом итераций).
2. Пароли записей шифруются симметричным шифром Fernet (AES-128-CBC + HMAC,
   библиотека ``cryptography``). Ключ лежит в отдельном файле ``.key``.
3. Новые пароли генерируются криптографически стойким ГСЧ ``secrets``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import string
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .errors import KeyNotFoundError, WeakPasswordError

# SHA-256 в режиме PBKDF2: прямой хеш пароля подбирать слишком легко.
PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 64

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*"
# Символы, которые легко перепутать при ручном вводе, исключены из алфавита.
AMBIGUOUS = "il1LIoO0"


# ---------------------------------------------------------------------------
# Мастер-пароль: соль + хеш
# ---------------------------------------------------------------------------
def new_salt() -> bytes:
    return os.urandom(SALT_BYTES)


def hash_master_password(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Вернуть hex-хеш мастер-пароля (PBKDF2-HMAC-SHA256)."""
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return digest.hex()


def verify_master_password(
    password: str, salt_hex: str, hash_hex: str, iterations: int = PBKDF2_ITERATIONS
) -> bool:
    """Проверить мастер-пароль по сохранённым соли и хешу (без side-channel)."""
    candidate = hash_master_password(password, bytes.fromhex(salt_hex), iterations)
    return hmac.compare_digest(candidate, hash_hex)


def check_master_strength(password: str, min_length: int = 8) -> None:
    """Минимальные требования к мастер-паролю."""
    if len(password) < min_length:
        raise WeakPasswordError(f"Мастер-пароль короче {min_length} символов.")
    if password.strip() != password or not password.strip():
        raise WeakPasswordError("Мастер-пароль не должен начинаться/заканчиваться пробелом.")


# ---------------------------------------------------------------------------
# Ключ Fernet в файле .key
# ---------------------------------------------------------------------------
def fernet_from_key(key: bytes) -> Fernet:
    try:
        return Fernet(key)
    except (ValueError, TypeError) as exc:
        raise KeyNotFoundError(f"Файл ключа повреждён: некорректный ключ Fernet ({exc}).") from exc


def load_or_create_key(key_path: Path) -> bytes:
    """Прочитать ключ Fernet из файла ``.key``; если файла нет - создать его."""
    key_path = Path(key_path)
    if key_path.exists():
        key = key_path.read_bytes().strip()
        if not key:
            raise KeyNotFoundError(f"Файл ключа {key_path} пуст.")
        fernet_from_key(key)  # проверка, что ключ валидный
        return key

    key = Fernet.generate_key()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key + b"\n")
    _restrict_permissions(key_path)
    return key


def _restrict_permissions(path: Path) -> None:
    """Права 600 для файла ключа (на Windows работает частично)."""
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - зависит от ОС
        pass


# ---------------------------------------------------------------------------
# Шифрование паролей записей
# ---------------------------------------------------------------------------
def encrypt_password(fernet: Fernet, password: str) -> str:
    """Зашифровать пароль, вернуть строку-Fernet-токен для хранения в БД."""
    return fernet.encrypt(password.encode("utf-8")).decode("ascii")


def decrypt_password(fernet: Fernet, token: str) -> str:
    """Расшифровать пароль из БД."""
    try:
        return fernet.decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise KeyNotFoundError(
            "Не удалось расшифровать пароль: файл .key не соответствует базе данных."
        ) from exc


# ---------------------------------------------------------------------------
# Генератор надёжных паролей
# ---------------------------------------------------------------------------
def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = True,
) -> str:
    """Сгенерировать случайный пароль через ``secrets`` (криптостойкий ГСЧ).

    Типы символов выбираются флагами; если не выбран ни один - ошибка.
    Длина ограничена диапазоном ``MIN_PASSWORD_LENGTH``..``MAX_PASSWORD_LENGTH``.
    """
    if not MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"Длина пароля должна быть от {MIN_PASSWORD_LENGTH} до "
            f"{MAX_PASSWORD_LENGTH} символов."
        )

    pools: list[str] = []
    if use_uppercase:
        pools.append(UPPERCASE)
    if use_lowercase:
        pools.append(LOWERCASE)
    if use_digits:
        pools.append(DIGITS)
    if use_symbols:
        pools.append(SYMBOLS)

    if exclude_ambiguous:
        pools = ["".join(ch for ch in pool if ch not in AMBIGUOUS) for pool in pools]
    pools = [pool for pool in pools if pool]

    if not pools:
        raise WeakPasswordError("Не выбран ни один тип символов.")

    alphabet = "".join(pools)
    # Гарантируем присутствие минимум одного символа из каждого пула.
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
