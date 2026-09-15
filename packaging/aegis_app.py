"""Entry point for the packaged Windows desktop app (PyInstaller)."""
import multiprocessing
import os
import sys

# A windowed build has no console, so stdout and stderr are None; give logging
# and libraries that print somewhere harmless to write.
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")  # noqa: SIM115
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")  # noqa: SIM115

from aegis.ui.app import run  # noqa: E402

if __name__ == "__main__":
    multiprocessing.freeze_support()
    run()
