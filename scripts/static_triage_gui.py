"""
Static Triage GUI (v10) - Fix progress parsing for timestamped analysis.log lines

Your analysis.log lines look like:
  2026-03-05T23:57:18Z STEP_START md5
  2026-03-05T23:57:18Z STEP_DONE md5 rc=0 dur=0.028
So we cannot use line.startswith("STEP_START ").
v8 parses STEP_* markers anywhere in the line via regex.

Keeps everything from v7:
- Fixed classic progress bars
- Reads analysis.log from start
- Case_dir auto-detect from stdout + fallback tailer
- Case output selector + tool selectors + advanced settings
- UTF-8 safe streaming
"""

from __future__ import annotations

import sys
from pathlib import Path
import traceback

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gui.startup_app import StartupApp


def main():
    print("[DEBUG] Starting RingForge startup launcher")
    app = StartupApp()
    print("[DEBUG] Entering mainloop")
    app.mainloop()
    print("[DEBUG] Mainloop exited")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        input("Press Enter to exit...")
        raise

