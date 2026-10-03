"""Интерактивный консольный интерфейс PassKeep.

Запуск: ``python main.py``. При первом запуске программа сама создаёт базу
данных, файл ключа и запрашивает пароль входа, затем показывает меню действий.
"""

from __future__ import annotations

import getpass
from collections.abc import Callable, Sequence

from .app import Vault
from .clipboard import copy_to_clipboard
from .crypto import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, generate_password
from .errors import LockedError, PassKeepError, WeakPasswordError
from .paths import Paths

MENU = """============================
МЕНЕДЖЕР ПАРОЛЕЙ
============================
1. Добавить новый пароль
2. Список всех паролей
3. Получить пароль
4. Удалить пароль
5. Сгенерировать пароль
6. Выход
============================"""

DEFAULT_LENGTH = 16
SEPARATOR = "*" * 52


# ---------------------------------------------------------------------------
# Ввод/вывод
# ---------------------------------------------------------------------------
def read_line(prompt: str) -> str:
    """Прочитать строку. Ctrl+C / Ctrl+D завершают программу."""
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nДо свидания!")
        raise SystemExit(0) from None


def read_password(prompt: str) -> str:
    """Прочитать пароль без отображения на экране."""
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        print("\nДо свидания!")
        raise SystemExit(0) from None
    except Exception:  # pragma: no cover - зависит от терминала
        return read_line(prompt)


def ask_yes_no(prompt: str) -> bool:
    """Вопрос с ответом Y/N (по умолчанию N)."""
    return read_line(prompt).lower() in ("y", "yes", "д", "да")


def pause() -> None:
    """Пауза «Для продолжения нажмите Enter»."""
    read_line("Для продолжения нажмите Enter")


# ---------------------------------------------------------------------------
# Генерация пароля
# ---------------------------------------------------------------------------
def ask_length() -> int:
    """Спросить длину пароля (8-64, по умолчанию 16)."""
    raw = read_line(f"Длина пароля ({MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH}, по умолчанию {DEFAULT_LENGTH}): ")
    if not raw:
        return DEFAULT_LENGTH
    try:
        length = int(raw)
    except ValueError:
        print(f"Введите число от {MIN_PASSWORD_LENGTH} до {MAX_PASSWORD_LENGTH}. "
              f"Использовано {DEFAULT_LENGTH}.")
        return DEFAULT_LENGTH
    if not MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH:
        print(f"Допустимая длина от {MIN_PASSWORD_LENGTH} до {MAX_PASSWORD_LENGTH}. "
              f"Использовано {DEFAULT_LENGTH}.")
        return DEFAULT_LENGTH
    return length


def generate_interactive() -> str:
    """Диалог генерации пароля. Возвращает пароль или пустую строку."""
    print("=== Генерация пароля ===")
    length = ask_length()
    print("Выберите типы символов:")
    use_upper = ask_yes_no("Заглавные буквы (A-Z)? (Y/N): ")
    use_lower = ask_yes_no("Строчные буквы (a-z)? (Y/N): ")
    use_digits = ask_yes_no("Цифры (0-9)? (Y/N): ")
    use_symbols = ask_yes_no("Спецсимволы (!@#$%^&*)? (Y/N): ")

    try:
        password = generate_password(
            length=length,
            use_uppercase=use_upper,
            use_lowercase=use_lower,
            use_digits=use_digits,
            use_symbols=use_symbols,
        )
    except WeakPasswordError as exc:
        print(f"Ошибка: {exc}")
        return ""

    print(f"Сгенерированный пароль: {password}")
    if ask_yes_no("Скопировать в буфер (Y/N): "):
        if copy_to_clipboard(password):
            print("Пароль скопирован в буфер обмена.")
        else:
            print("Буфер обмена недоступен, скопируйте пароль вручную.")
    return password


# ---------------------------------------------------------------------------
# Действия меню
# ---------------------------------------------------------------------------
def action_add(vault: Vault) -> None:
    print("=== Добавление нового пароля ===")
    name = read_line("Введите название записи: ")
    if not name:
        print("Название не может быть пустым.")
        pause()
        return
    if vault.find(name) is not None:
        print(f"Запись «{name}» уже существует.")
        pause()
        return

    login = read_line("Введите логин: ")

    if ask_yes_no("Сгенерировать пароль? (Y/N): "):
        password = generate_interactive()
        if not password:
            pause()
            return
    else:
        password = read_password("Введите пароль: ")
        if not password:
            print("Пароль не может быть пустым.")
            pause()
            return

    vault.add(name, login, password)
    print(f"Пароль для «{name}» успешно добавлен")
    pause()


def action_list(vault: Vault) -> None:
    print("=== Список всех паролей ===")
    entries = vault.list()
    print(SEPARATOR)
    if entries:
        for entry in entries:
            print(f"Название: {entry.name} | Логин: {entry.login or '-'}")
    else:
        print("Записи отсутствуют.")
    print(SEPARATOR)
    pause()


def action_get(vault: Vault) -> None:
    print("=== Получение пароля ===")
    name = read_line("Введите название записи: ")
    entry = vault.find(name)
    if entry is None:
        print("Пароль с таким названием не найден")
        pause()
        return

    _, password = vault.get(entry.name)
    print(f"Название: {entry.name}")
    print(f"Логин: {entry.login or '-'}")
    print(f"Пароль: {password}")
    pause()


def action_delete(vault: Vault) -> None:
    print("=== Удаление пароля ===")
    name = read_line("Введите название записи для удаления: ")
    entry = vault.find(name)
    if entry is None:
        print("Пароль с таким названием не найден")
        pause()
        return

    if ask_yes_no(f"Вы уверены что хотите удалить «{entry.name}» (Y/N): "):
        vault.remove(entry.name)
        print(f"Пароль для «{entry.name}» успешно удален")
    pause()


def action_generate(vault: Vault) -> None:
    del vault  # список записей не нужен
    generate_interactive()
    pause()


# ---------------------------------------------------------------------------
# Запуск
# ---------------------------------------------------------------------------
def run_menu(vault: Vault) -> None:
    """Показывать меню, пока пользователь не выберет «Выход»."""
    actions: dict[str, Callable[[Vault], None]] = {
        "1": action_add,
        "2": action_list,
        "3": action_get,
        "4": action_delete,
        "5": action_generate,
    }
    while True:
        print(MENU)
        choice = read_line("Выберите действие (1-6): ")
        if choice == "6":
            print("До свидания!")
            return
        action = actions.get(choice)
        if action is None:
            print("Неверный выбор. Введите число от 1 до 6.")
            continue
        action(vault)


def main(argv: Sequence[str] | None = None) -> int:
    del argv  # аргументы командной строки не используются
    vault = Vault(Paths())
    try:
        try:
            vault.unlock()
        except LockedError as exc:
            print(f"БЛОКИРОВКА: {exc}")
            return 1
        except PassKeepError as exc:
            print(f"Ошибка: {exc}")
            return 1
        run_menu(vault)
    finally:
        vault.close()
    return 0
