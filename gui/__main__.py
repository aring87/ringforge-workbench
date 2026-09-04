"""Entry point for the workbench GUI: `python -m gui`, or the `ringforge` script.

`scripts/static_triage_gui.py` has been the way in since the beginning and
still is -- it is what a human double-clicks. But `scripts/` is bench tooling
rather than product: it holds corpus surveys, emulator harnesses and two files
named `test_*.py` that `SystemExit` on import (see `pytest.ini`). None of that
belongs in an installed package, so the launcher itself lives here and the
script delegates.
"""

from __future__ import annotations

import sys
import traceback


def main() -> None:
    if "--static-analysis" in sys.argv:
        from gui.main_app import App

        app = App()
    else:
        from gui.startup_app import StartupApp

        app = StartupApp()

    app.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        raise
