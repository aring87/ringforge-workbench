from __future__ import annotations

import tkinter as tk
from pathlib import Path
from PIL import Image, ImageTk


class SplashScreen(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        image_path: str | Path,
        on_close=None,
        duration_ms: int = 2600,
    ):
        super().__init__(parent)
        self.parent = parent
        self.on_close = on_close
        self.duration_ms = duration_ms
        self._img_ref = None

        bg = "#05070B"
        panel = "#0B1220"
        border = "#294C8E"
        text = "#F7FAFF"
        muted = "#B8C7E6"
        accent = "#2F6BFF"

        self.overrideredirect(True)
        self.configure(bg=bg)
        self.attributes("-topmost", True)

        width = 760
        height = 520
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = int((screen_w / 2) - (width / 2))
        y = int((screen_h / 2) - (height / 2))
        self.geometry(f"{width}x{height}+{x}+{y}")

        outer = tk.Frame(
            self,
            bg=panel,
            highlightthickness=1,
            highlightbackground=border,
            highlightcolor=border,
        )
        outer.pack(fill="both", expand=True, padx=2, pady=2)

        content = tk.Frame(outer, bg=panel)
        content.place(relx=0.5, rely=0.5, anchor="center")

        image_path = Path(image_path)
        if image_path.exists():
            img = Image.open(image_path).convert("RGBA")
            img.thumbnail((320, 320), Image.LANCZOS)
            self._img_ref = ImageTk.PhotoImage(img)
            tk.Label(content, image=self._img_ref, bg=panel, bd=0).pack(pady=(8, 18))
        else:
            tk.Label(
                content,
                text="[assets/anvil.png not found]",
                bg=panel,
                fg=accent,
                font=("Segoe UI", 12, "bold"),
            ).pack(pady=(30, 18))

        tk.Label(
            content,
            text="RINGFORGE",
            bg=panel,
            fg=text,
            font=("Segoe UI", 28, "bold"),
        ).pack()

        tk.Label(
            content,
            text="Workbench",
            bg=panel,
            fg=accent,
            font=("Segoe UI", 20, "bold"),
        ).pack(pady=(2, 10))

        tk.Frame(content, bg=accent, height=2, width=260).pack(pady=(0, 14))

        tk.Label(
            content,
            text="Static • Dynamic • API • Spec • Extension Analysis",
            bg=panel,
            fg=muted,
            font=("Segoe UI", 10),
        ).pack()

        tk.Label(
            content,
            text="Forging better software triage.",
            bg=panel,
            fg=muted,
            font=("Segoe UI", 10, "italic"),
        ).pack(pady=(8, 0))

        self.bind("<Button-1>", lambda _e: self.close())
        outer.bind("<Button-1>", lambda _e: self.close())
        self.after(self.duration_ms, self.close)

    def close(self):
        if not self.winfo_exists():
            return
        self.destroy()
        if callable(self.on_close):
            self.on_close()