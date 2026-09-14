"""Entry point: ``python -m aegis`` (or the ``aegis`` console script).

Dispatches to :mod:`aegis.cli`, which opens the desktop console when no
subcommand is given — preserving the original behaviour — and otherwise runs
the headless commands (``monitor``, ``status``, ``rules``, ``block``).
"""
import sys

from aegis.cli import main

if __name__ == "__main__":
    sys.exit(main())
