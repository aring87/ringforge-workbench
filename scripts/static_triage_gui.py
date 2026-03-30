from __future__ import annotations

import sys
from pathlib import Path
import traceback

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gui.startup_app import StartupApp
from gui.main_app import App


def main():
    print("[DEBUG] Starting RingForge")
    if "--static-analysis" in sys.argv:
        print("[DEBUG] Launch mode: Static Analysis")
        app = App()
    else:
        print("[DEBUG] Launch mode: Startup Launcher")
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