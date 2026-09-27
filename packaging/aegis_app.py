"""Entry point for the packaged Windows app (PyInstaller).

With no arguments it opens the desktop window, which is what the Start-menu
shortcut does. With arguments it behaves exactly like the ``aegis`` command, so
one executable covers both: in particular ``Aegis.exe monitor``, which is what
"keep watching after I close this window" registers to run at sign-in.
"""
import multiprocessing
import os
import sys

# A windowed build has no console, so stdout and stderr are None; give logging
# and libraries that print somewhere harmless to write.
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")  # noqa: SIM115
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")  # noqa: SIM115

if __name__ == "__main__":
    multiprocessing.freeze_support()
    if len(sys.argv) > 1:
        from aegis.cli import main

        sys.exit(main(sys.argv[1:]))
    from aegis.ui.app import run

    run()
