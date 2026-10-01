"""Исключения приложения."""

from __future__ import annotations


class PassKeepError(Exception):
    """Базовая ошибка приложения (текст показывается пользователю)."""


class StorageError(PassKeepError):
    """Ошибка работы с базой данных."""


class KeyNotFoundError(PassKeepError):
    """Отсутствует файл с ключом шифрования."""


class WrongMasterPasswordError(PassKeepError):
    """Мастер-пароль не совпадает с сохранённым хешем."""


class LockedError(PassKeepError):
    """Ввод заблокирован из-за серии неверных мастер-паролей."""

    def __init__(self, retry_in: int) -> None:
        super().__init__(f"Ввод заблокирован. Повторите попытку через {retry_in} сек.")
        self.retry_in = retry_in


class EntryNotFoundError(PassKeepError):
    """Запись с таким названием не найдена."""


class DuplicateEntryError(PassKeepError):
    """Запись с таким названием уже существует."""


class WeakPasswordError(PassKeepError):
    """Пароль не удовлетворяет требованиям надёжности."""
