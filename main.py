#!/usr/bin/env python3
"""Точка входа: python main.py <КОМАНДА> [параметры]."""

from __future__ import annotations

import sys

from passkeep.cli import main

if __name__ == "__main__":
    sys.exit(main())
