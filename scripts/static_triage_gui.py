"""Human entry point. The launcher itself is `gui/__main__.py`, which is
what ships in the package; this keeps the familiar path working and keeps the
project root on `sys.path` for a source checkout."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gui.__main__ import main  # noqa: E402


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        input("Press Enter to exit...")
        raise
