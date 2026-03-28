from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from tkinter import filedialog, messagebox


def browse_file_into_var(tk_var, title="Select File", filetypes=None):
    path = filedialog.askopenfilename(title=title, filetypes=filetypes or [("All Files", "*.*")])
    if path:
        tk_var.set(path)
    return path


def browse_folder_into_var(tk_var, title="Select Folder"):
    path = filedialog.askdirectory(title=title)
    if path:
        tk_var.set(path)
    return path


def open_path(path: str | os.PathLike):
    if not path:
        return False
    path = str(path)
    if not os.path.exists(path):
        messagebox.showerror("Path Not Found", f"Could not find:\n{path}")
        return False

    try:
        if sys.platform.startswith("win"):
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.run(["open", path], check=False)
        else:
            subprocess.run(["xdg-open", path], check=False)
        return True
    except Exception as exc:
        messagebox.showerror("Open Failed", f"Could not open:\n{path}\n\n{exc}")
        return False


def open_if_exists(path, kind="file"):
    if not path or not os.path.exists(path):
        messagebox.showerror("Missing", f"The selected {kind} does not exist:\n{path}")
        return False
    return open_path(path)