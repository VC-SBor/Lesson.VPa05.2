"""Копирование пароля в буфер обмена.

Основной способ - библиотека ``pyperclip``. Если её нет, используется системная
утилита (``clip.exe`` в Windows, ``pbcopy`` в macOS, ``xclip``/``xsel``/``wl-copy``
в Linux). Если буфер обмена недоступен, команда не падает - пароль будет
показан на экране с предупреждением.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

try:  # необязательная зависимость
    import pyperclip
except ImportError:  # pragma: no cover - зависит от окружения
    pyperclip = None

_FALLBACKS = {
    "Windows": ["clip"],
    "Darwin": ["pbcopy"],
    "Linux": ["wl-copy", "xclip", "xsel"],
}


def _fallback_copy(text: str) -> bool:
    for tool in _FALLBACKS.get(sys.platform, ["xclip"]):
        path = shutil.which(tool)
        if not path:
            continue
        args = {
            "xclip": ["-selection", "clipboard"],
            "xsel": ["--clipboard", "--input"],
        }.get(tool, [])
        try:
            subprocess.run([path, *args], input=text.encode("utf-8"), check=True, timeout=5)
            return True
        except (subprocess.SubprocessError, OSError):  # pragma: no cover - зависит от ОС
            continue
    return False


def copy_to_clipboard(text: str) -> bool:
    """Скопировать текст в буфер обмена. True - если получилось."""
    if pyperclip is not None:
        try:
            pyperclip.copy(text)
            return True
        except Exception:  # noqa: BLE001 - буфер может быть недоступен
            pass
    return _fallback_copy(text)


def clipboard_available() -> bool:
    if pyperclip is not None:
        return True
    tools = _FALLBACKS.get(sys.platform, [])
    return any(shutil.which(tool) for tool in tools)
