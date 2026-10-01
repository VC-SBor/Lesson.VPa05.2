"""CLI-обработчик: разбор аргументов, ввод пользователя, вывод команд."""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Sequence

from . import __version__
from .app import MAX_FAILED_ATTEMPTS, Vault
from .clipboard import copy_to_clipboard
from .crypto import generate_password
from .errors import LockedError, PassKeepError, WrongMasterPasswordError
from .paths import Paths
from .storage import META_MASTER_HASH

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_WRONG_PASSWORD = 2
EXIT_LOCKED = 3


# ---------------------------------------------------------------------------
# Ввод/вывод
# ---------------------------------------------------------------------------
def prompt_visible(text: str, default: str = "") -> str:
    try:
        value = input(text).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(EXIT_ERROR) from None
    return value or default


def prompt_hidden(text: str) -> str:
    """Запрос пароля.

    Сначала пытается использовать getpass. В некоторых терминалах Windows
    getpass может не показывать приглашение, поэтому есть запасной вариант
    через обычный input.
    """
    sys.stdout.write(text)
    sys.stdout.flush()
    try:
        try:
            value = getpass.getpass("")
        except (EOFError, KeyboardInterrupt):
            raise
        except Exception:
            value = input()
        sys.stdout.write("\n")
        sys.stdout.flush()
        return value
    except EOFError as exc:
        raise PassKeepError("Нет ввода: процесс запущен без консоли?") from exc
    except KeyboardInterrupt:
        raise


def confirm(text: str, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    answer = prompt_visible(f"{text} {suffix} ", "y" if default else "n").lower()
    return answer in ("y", "yes", "д", "да")


# ---------------------------------------------------------------------------
# Парсер
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="passkeep",
        description="PassKeep - менеджер паролей: SQLite3 + шифрование Fernet.",
        epilog=(
            "Примеры:\n"
            "  python main.py init\n"
            "  python main.py add Google --login me@gmail.com --copy\n"
            "  python main.py list\n"
            "  python main.py get Google --copy\n"
            "  python main.py new --length 20 --copy\n"
            "  python main.py remove Google\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"PassKeep {__version__}")
    parser.add_argument(
        "--home",
        metavar="PATH",
        help=f"каталог с базой и файлом .key (по умолчанию ~/.passkeep или {Paths().home})",
    )

    sub = parser.add_subparsers(dest="command", metavar="КОМАНДА")

    sub.add_parser("init", help="создать базу, файл .key и мастер-пароль (первый запуск)")

    p_add = sub.add_parser("add", help="добавить новую запись")
    p_add.add_argument("name", help="название/откуда (например Google)")
    p_add.add_argument("--login", help="логин (если не указан - спросит)")
    p_add.add_argument("--password", help="пароль (не указывайте в скриптах, лучше ввод сокрытый)")
    p_add.add_argument("--notes", default="", help="заметка (например, ссылка на сайт)")
    p_add.add_argument("--copy", action="store_true", help="скопировать пароль в буфер обмена")
    p_add.add_argument(
        "--length", type=int, default=16, help="длина автоматически сгенерированного пароля"
    )

    p_get = sub.add_parser("get", help="получить пароль по названию")
    p_get.add_argument("name", help="название записи")
    p_get.add_argument("--copy", action="store_true", help="скопировать пароль в буфер обмена")
    p_get.add_argument("--no-print", action="store_true", help="не показывать пароль на экране")

    p_list = sub.add_parser("list", help="показать список записей (названия и логины)")
    p_list.add_argument("--filter", metavar="ТЕКСТ", help="фильтр по названию или логину")

    p_remove = sub.add_parser("remove", aliases=["delete"], help="удалить запись (алиас: delete)")
    p_remove.add_argument("name", help="название записи")
    p_remove.add_argument("--yes", action="store_true", help="без подтверждения удаления")

    p_new = sub.add_parser("new", help="сгенерировать новый надёжный пароль")
    p_new.add_argument("--length", type=int, default=16, help="длина (по умолчанию 16)")
    p_new.add_argument("--no-digits", action="store_true", help="без цифр")
    p_new.add_argument("--no-symbols", action="store_true", help="без спецсимволов")
    p_new.add_argument("--copy", action="store_true", help="скопировать в буфер обмена")
    p_new.add_argument("--save", metavar="НАЗВАНИЕ", help="сразу сохранить пароль в базу")
    p_new.add_argument("--login", default="", help="логин для --save")

    return parser


# ---------------------------------------------------------------------------
# Команды
# ---------------------------------------------------------------------------
def cmd_init(vault: Vault) -> int:
    if vault.is_initialized():
        print("Хранилище уже инициализировано, ничего не создано заново.")
        print(f"Записей в базе: {vault.count()}")
        return EXIT_OK
    vault.unlock()
    print(f"Записей в базе: {vault.count()}")
    return EXIT_OK


def cmd_add(vault: Vault, args: argparse.Namespace) -> int:
    if vault.find(args.name) is not None:
        print(f"Запись «{args.name}» уже существует. Сначала удалите её: remove {args.name}")
        return EXIT_ERROR

    login = args.login if args.login is not None else prompt_visible("Логин: ")
    password = args.password
    if password is None:
        password = prompt_hidden("Пароль (пустая строка - сгенерировать автоматически): ")
        if not password:
            password = generate_password(length=args.length)
            print(f"Сгенерирован пароль длиной {len(password)} символов.")

    entry = vault.add(args.name, login, password, args.notes)
    print(f"OK: запись «{entry.name}» добавлена (логин: {entry.login or '-'}).")
    if args.copy:
        _copy_secret(password)
    return EXIT_OK


def cmd_get(vault: Vault, args: argparse.Namespace) -> int:
    entry, password = vault.get(args.name)
    print(f"Название : {entry.name}")
    print(f"Логин    : {entry.login or '-'}")
    if entry.notes:
        print(f"Заметка  : {entry.notes}")
    if not args.no_print:
        print(f"Пароль   : {password}")
    print(f"Создана  : {entry.created_at}   Изменена: {entry.updated_at}")
    if args.copy:
        _copy_secret(password)
    return EXIT_OK


def cmd_list(vault: Vault, args: argparse.Namespace) -> int:
    entries = vault.list(args.filter)
    if not entries:
        print("Хранилище пусто." if not args.filter else f"Ничего не найдено по фильтру «{args.filter}».")
        return EXIT_OK

    width = max(len(e.name) for e in entries)
    width = max(width, len("НАЗВАНИЕ"))
    print(f"{'НАЗВАНИЕ'.ljust(width)}  {'ЛОГИН':<28}  ИЗМЕНЕНА")
    print("-" * (width + 40))
    for entry in entries:
        print(f"{entry.name.ljust(width)}  {(entry.login or '-'):<28}  {entry.updated_at}")
    print(f"Всего записей: {len(entries)} (пароли не показываются)")
    return EXIT_OK


def cmd_remove(vault: Vault, args: argparse.Namespace) -> int:
    entry = vault.find(args.name)
    if entry is None:
        print(f"Запись «{args.name}» не найдена.")
        return EXIT_ERROR
    if not args.yes and not confirm(f"Удалить запись «{entry.name}»?"):
        print("Отменено.")
        return EXIT_OK
    vault.remove(entry.name)
    print(f"OK: запись «{entry.name}» удалена из базы.")
    return EXIT_OK


def cmd_new(vault: Vault, args: argparse.Namespace) -> int:
    password = Vault.generate(
        length=args.length, use_digits=not args.no_digits, use_symbols=not args.no_symbols
    )
    print(f"Новый пароль: {password}")

    if args.save:
        vault.unlock()
        entry = vault.add(args.save, args.login, password, notes="сгенерирован командой new")
        print(f"Сохранён в базу под названием «{entry.name}».")
    if args.copy:
        _copy_secret(password)
    return EXIT_OK


def _copy_secret(password: str) -> None:
    if copy_to_clipboard(password):
        print("Пароль скопирован в буфер обмена. Не забудьте очистить буфер.")
    else:
        print("Внимание: буфер обмена недоступен, пароль скопировать не удалось.")


# ---------------------------------------------------------------------------
# Точка входа CLI
# ---------------------------------------------------------------------------
def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return EXIT_ERROR

    handlers = {
        "init": lambda v: cmd_init(v),
        "add": lambda v: cmd_add(v, args),
        "get": lambda v: cmd_get(v, args),
        "list": lambda v: cmd_list(v, args),
        "remove": lambda v: cmd_remove(v, args),
        "delete": lambda v: cmd_remove(v, args),
        "new": lambda v: cmd_new(v, args),
    }

    vault = Vault(Paths(args.home))
    try:
        if args.command == "init":
            vault.prepare()
            return cmd_init(vault)
        if args.command == "new":
            vault.prepare()
            if not vault.is_initialized():
                print("Хранилище ещё не создано. Сначала выполните: python main.py init")
                return EXIT_ERROR
            return cmd_new(vault, args)

        vault.unlock()
        return handlers[args.command](vault)
    except LockedError as exc:
        print(f"БЛОКИРОВКА: {exc}", file=sys.stderr)
        print(
            f"Это защита от подбора: {MAX_FAILED_ATTEMPTS} неверных мастер-паролей подряд.",
            file=sys.stderr,
        )
        return EXIT_LOCKED
    except WrongMasterPasswordError as exc:
        print(f"ОШИБКА ВВОДА: {exc}", file=sys.stderr)
        return EXIT_WRONG_PASSWORD
    except PassKeepError as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\nПрервано пользователем.", file=sys.stderr)
        return EXIT_ERROR
    finally:
        vault.close()
