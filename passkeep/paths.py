"""Расположение файлов приложения (база данных и ключ шифрования).

По умолчанию используется каталог ``~/.passkeep``. Его можно переопределить:

* переменной окружения ``PASSKEEP_HOME``;
* глобальным параметром командной строки ``--home PATH``.
"""

from __future__ import annotations

import os
from pathlib import Path

DB_FILENAME = "vault.db"
KEY_FILENAME = ".key"

ENV_HOME = "PASSKEEP_HOME"
ENV_MASTER = "PASSKEEP_MASTER_PASSWORD"

MIN_MASTER_LENGTH = 8


class Paths:
    """Каталог с файлами хранилища и доступ к ним."""

    def __init__(self, home: str | os.PathLike[str] | None = None) -> None:
        if home is None:
            home = os.environ.get(ENV_HOME) or Path.home() / ".passkeep"
        self.home = Path(home).expanduser()

    @property
    def db_path(self) -> Path:
        return self.home / DB_FILENAME

    @property
    def key_path(self) -> Path:
        return self.home / KEY_FILENAME

    def ensure_home(self) -> None:
        """Создать каталог хранилища, если его ещё нет."""
        self.home.mkdir(parents=True, exist_ok=True)

    def __str__(self) -> str:  # pragma: no cover - вспомогательный вывод
        return str(self.home)
