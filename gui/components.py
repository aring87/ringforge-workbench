"""Reusable presentation widgets for RingForge Workbench.

Tk has no rounded corners, elevation, or hover states of its own, so the pieces
that carry most of the visual weight are drawn on a ``Canvas``:

    Card           rounded surface with a hairline border and optional accent rail
    RoundedButton  canvas button with real hover / press / disabled states
    Badge          status pill coloured from :data:`gui.theme.STATUS_COLORS`
    StatTile       label + large metric readout
    HeaderBar      branded page header with logo, title, subtitle and actions
    SectionTitle   eyebrow + heading + hairline rule
    EmptyState     centred placeholder for empty tables and panes

Everything here is presentation only -- no analysis logic lives in this module.
"""

from __future__ import annotations

import math
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

from gui import theme as T


# ---------------------------------------------------------------------------
# Geometry helpers
# ---------------------------------------------------------------------------

def draw_round_rect(
    canvas: tk.Canvas,
    x1, y1, x2, y2, r,
    *,
    fill: str = "",
    outline: str = "",
    width: float = 1,
    tags: str | tuple[str, ...] | None = None,
):
    """Draw a rounded rectangle from straight edges and true corner arcs.

    Built from primitives rather than ``create_polygon(smooth=True)``. A smoothed
    polygon interpolates a spline *through* the corner points instead of round
    ing to them, so the curve bulges past the shape's own bounding box; the
    overshoot is then clipped at the canvas edge. On screen that appeared as
    outlines with pieces missing -- broken card bottoms and buttons whose right
    edge simply stopped -- and the shape was never the requested radius anyway.

    Arcs cost a dozen canvas items instead of one, which is the price of the
    geometry being exact.
    """
    x1, y1, x2, y2 = float(x1), float(y1), float(x2), float(y2)
    r = max(0.0, min(float(r), (x2 - x1) / 2.0, (y2 - y1) / 2.0))
    d = r * 2.0
    opts = {"tags": tags} if tags else {}

    if fill:
        # Corner quadrants first, then the cross of rectangles between them. The
        # pieces overlap by a hair so no seam shows along the joins.
        for bbox, start in (
            ((x1, y1, x1 + d, y1 + d), 90),
            ((x2 - d, y1, x2, y1 + d), 0),
            ((x1, y2 - d, x1 + d, y2), 180),
            ((x2 - d, y2 - d, x2, y2), 270),
        ):
            if r > 0:
                canvas.create_arc(
                    *bbox, start=start, extent=90, style="pieslice",
                    fill=fill, outline=fill, width=0, **opts,
                )
        canvas.create_rectangle(
            x1 + r - 0.5, y1, x2 - r + 0.5, y2, fill=fill, outline=fill, width=0, **opts
        )
        canvas.create_rectangle(
            x1, y1 + r - 0.5, x2, y2 - r + 0.5, fill=fill, outline=fill, width=0, **opts
        )

    if outline and width:
        for bbox, start in (
            ((x1, y1, x1 + d, y1 + d), 90),
            ((x2 - d, y1, x2, y1 + d), 0),
            ((x1, y2 - d, x1 + d, y2), 180),
            ((x2 - d, y2 - d, x2, y2), 270),
        ):
            if r > 0:
                canvas.create_arc(
                    *bbox, start=start, extent=90, style="arc",
                    outline=outline, width=width, **opts,
                )
        # Each edge runs a pixel into the arc at both ends. Tk rounds an arc's
        # endpoints independently of a line's, so butting them exactly leaves a
        # visible nick at all four corners -- obvious at small radii like the
        # glyph chips. Overlapping costs nothing and closes the join.
        o = 1.0 if r > 0 else 0.0
        for coords in (
            (x1 + r - o, y1, x2 - r + o, y1),
            (x1 + r - o, y2, x2 - r + o, y2),
            (x1, y1 + r - o, x1, y2 - r + o),
            (x2, y1 + r - o, x2, y2 - r + o),
        ):
            canvas.create_line(*coords, fill=outline, width=width, **opts)

    return None


def draw_round_gradient(canvas: tk.Canvas, x1, y1, x2, y2, r, top: str, bottom: str,
                        tags: str = "gradient") -> None:
    """Fill a rounded rectangle with a vertical gradient.

    Tk cannot fill a shape with a gradient, so this paints one horizontal line
    per pixel row and shortens the rows inside the corner radius to follow the
    rounded edge exactly.
    """
    x1, y1, x2, y2 = float(x1), float(y1), float(x2), float(y2)
    width, height = x2 - x1, y2 - y1
    if width <= 0 or height <= 0:
        return
    r = max(0.0, min(r, width / 2.0, height / 2.0))

    rows = int(height)
    for i in range(rows):
        y = y1 + i
        t = i / max(1, rows - 1)
        color = T.mix(top, bottom, t)

        # How far this row sits inside a corner arc, if at all.
        dy = 0.0
        if y < y1 + r:
            dy = (y1 + r) - y
        elif y > y2 - r:
            dy = y - (y2 - r)

        dx = r - math.sqrt(max(0.0, r * r - dy * dy)) if dy > 0 else 0.0
        canvas.create_line(x1 + dx, y + 0.5, x2 - dx, y + 0.5, fill=color, tags=tags)


def draw_horizontal_fade(canvas: tk.Canvas, x1, y1, x2, y2, start: str, end: str) -> None:
    """A one-pixel rule that fades from ``start`` to ``end`` left to right."""
    x1, x2 = float(x1), float(x2)
    span = int(x2 - x1)
    if span <= 0:
        return
    for i in range(span):
        t = i / max(1, span - 1)
        canvas.create_line(
            x1 + i, y1, x1 + i + 1, y2, fill=T.mix(start, end, t),
        )


def resolve_bg(widget: tk.Misc, fallback: str = T.BG) -> str:
    """Best-effort background colour of ``widget``, for seamless canvas blending."""
    for option in ("background", "bg"):
        try:
            value = widget.cget(option)
            if value:
                return str(value)
        except Exception:
            pass
    try:
        style_name = widget.cget("style") or widget.winfo_class()
        value = ttk.Style(widget).lookup(style_name, "background")
        if value:
            return str(value)
    except Exception:
        pass
    return fallback


# ---------------------------------------------------------------------------
# Card
# ---------------------------------------------------------------------------

class Card(tk.Frame):
    """A rounded, bordered surface that sizes itself to its content.

    Add children to :attr:`body`. The rounded background is painted on a canvas
    that is ``place``-d behind the content, so it never interferes with the
    normal pack/grid sizing of whatever you put inside.

    Parameters
    ----------
    accent:
        Optional colour for a vertical rail down the left edge -- used to tag a
        card with a status or category colour.
    hover:
        Lift the surface colour while the pointer is over the card.
    """

    def __init__(
        self,
        parent: tk.Misc,
        *,
        radius: int = T.RADIUS_LG,
        fill: str = T.SURFACE,
        border: str = T.BORDER,
        padding: int | tuple[int, int] = T.CARD_PADDING,
        accent: str | None = None,
        hover: bool = False,
        parent_bg: str | None = None,
        gradient: tuple[str, str] | None = None,
        edge: str | None = None,
        brand_strip: bool = False,
        highlight: bool = True,
        **kwargs,
    ):
        self._outer_bg = parent_bg or resolve_bg(parent)
        super().__init__(parent, bg=self._outer_bg, bd=0, highlightthickness=0, **kwargs)

        self._radius = radius
        self._fill = fill
        self._fill_hover = T.SURFACE_HOVER if fill == T.SURFACE else T.lighten(fill, 0.04)
        self._border = border
        self._border_hover = T.ACCENT_BORDER
        self._accent = accent
        self._hoverable = hover
        self._hovering = False
        self._gradient = gradient
        self._edge = edge
        self._brand_strip = brand_strip
        self._highlight = highlight
        self._shape = None
        self._rail = None

        self._canvas = tk.Canvas(
            self,
            bg=self._outer_bg,
            highlightthickness=0,
            bd=0,
            takefocus=0,
        )
        self._canvas.place(x=0, y=0, relwidth=1, relheight=1)

        if isinstance(padding, tuple):
            padx, pady = padding
        else:
            padx = pady = padding

        self.body = tk.Frame(self, bg=fill, bd=0, highlightthickness=0)
        self.body.pack(fill="both", expand=True, padx=padx, pady=pady)

        self.bind("<Configure>", self._redraw, add="+")

        if hover:
            for widget in (self, self._canvas, self.body):
                widget.bind("<Enter>", self._on_enter, add="+")
                widget.bind("<Leave>", self._on_leave, add="+")

    # -- painting ---------------------------------------------------------

    def _redraw(self, _event=None) -> None:
        w = self.winfo_width()
        h = self.winfo_height()
        if w <= 2 or h <= 2:
            return

        self._canvas.delete("all")
        hovering = self._hovering and self._hoverable
        fill = self._fill_hover if hovering else self._fill
        border = self._border_hover if hovering else self._border

        # An accented card takes a hint of its own accent into the outline, so
        # the rail reads as part of one object rather than a bright bar stuck to
        # the side of an almost invisible box.
        if self._accent and not hovering:
            border = T.mix(border, self._accent, 0.20)

        if self._gradient is not None:
            top, bottom = self._gradient
            if hovering:
                top, bottom = T.lighten(top, 0.05), T.lighten(bottom, 0.05)
            draw_round_gradient(
                self._canvas, 0.5, 0.5, w - 0.5, h - 0.5, self._radius, top, bottom
            )
            self._shape = draw_round_rect(
                self._canvas, 0.5, 0.5, w - 0.5, h - 0.5, self._radius,
                fill="", outline=border, width=1,
            )
        else:
            self._shape = draw_round_rect(
                self._canvas, 0.5, 0.5, w - 0.5, h - 0.5, self._radius,
                fill=fill, outline=border, width=1,
            )

        # A faint lit top edge; reads as light catching the panel and stops the
        # surfaces looking like flat black rectangles.
        if self._highlight:
            top_fill = self._gradient[0] if self._gradient else fill
            self._canvas.create_line(
                self._radius, 1.5, w - self._radius, 1.5,
                fill=T.lighten(top_fill, 0.10),
            )

        if self._accent:
            self._draw_accent_rail(w, h, fill)

        if self._brand_strip:
            # A blue bar across the top, running deep -> hero -> sky. It lives in
            # the card's padding ring, where no child widget can cover it, which
            # is the only place Tk lets a gradient show.
            #
            # Both ends fade into the card surface. Previously the bar held full
            # brightness right up to its last pixel and simply stopped, which
            # read as a cut-off line rather than a lit edge.
            top_fill = self._gradient[0] if self._gradient else fill
            inset = float(self._radius)
            span = int(w - 2 * inset)
            if span > 1:
                fade = 0.14  # fraction of the width spent fading in and out
                for offset in (2.0, 3.0):
                    for i in range(0, span, 2):
                        t = i / (span - 1)
                        hue = (
                            T.mix(T.ACCENT_DEEP, T.ACCENT, t * 2.0)
                            if t < 0.5
                            else T.mix(T.ACCENT, T.ACCENT_BRIGHT, (t - 0.5) * 2.0)
                        )
                        edge = min(1.0, t / fade, (1.0 - t) / fade)
                        self._canvas.create_line(
                            inset + i, offset, inset + i + 2, offset,
                            fill=T.mix(top_fill, hue, edge),
                        )

        if self._edge:
            # Accent hairline along the bottom, fading out to each side.
            inset = self._radius + 4
            mid = w / 2.0
            draw_horizontal_fade(
                self._canvas, inset, h - 1.5, mid, h - 1.5, self._outer_bg, self._edge
            )
            draw_horizontal_fade(
                self._canvas, mid, h - 1.5, w - inset, h - 1.5, self._edge, self._outer_bg
            )

        # Canvas.lower() is the canvas *item* method; reach past it to the
        # widget-stacking version so the backdrop stays behind the content.
        tk.Misc.lower(self._canvas)

    def _draw_accent_rail(self, w: int, h: int, fill: str) -> None:
        """Category rail down the left edge.

        Two things this has to get right, both of which the previous full-height
        rounded bar got wrong.

        It stops where the corner arcs do. A straight bar drawn from the top of
        the card to the bottom sits outside the rounded silhouette at both ends,
        which showed up as small bright nubs above and below every card.

        It fades downward into the card surface instead of holding full
        saturation for the whole height. At full strength the rail was the
        brightest thing on screen while the card's own hairline was nearly
        invisible, so six cards read as six loose stripes rather than six panels.
        """
        # Where the corner curve has finished enough for a straight edge to hide
        # inside it.
        inset = self._radius * 0.75
        top = 1.5 + inset
        bottom = h - 1.5 - inset
        span = int(bottom - top)
        if span <= 0:
            return

        x1, x2 = 1.5, 4.0
        for i in range(span):
            t = i / max(1, span - 1)
            # Hold near-full strength through the top third, then fall away.
            strength = 1.0 - (max(0.0, t - 0.30) / 0.70) * 0.82
            self._canvas.create_line(
                x1, top + i, x2, top + i,
                fill=T.mix(fill, self._accent, strength),
            )

    def _on_enter(self, _event=None) -> None:
        if not self._hovering:
            self._hovering = True
            self._apply_surface(self._fill_hover)
            self._redraw()

    def _on_leave(self, _event=None) -> None:
        # Leaving into a child still counts as inside the card.
        x, y = self.winfo_pointerxy()
        widget = self.winfo_containing(x, y)
        while widget is not None:
            if widget is self:
                return
            widget = getattr(widget, "master", None)
        if self._hovering:
            self._hovering = False
            self._apply_surface(self._fill)
            self._redraw()

    def _apply_surface(self, color: str) -> None:
        """Keep plain Tk children in step with the hover surface."""
        try:
            self.body.configure(bg=color)
        except Exception:
            pass
        for child in self.body.winfo_children():
            if isinstance(child, (tk.Frame, tk.Label, tk.Canvas)):
                try:
                    child.configure(bg=color)
                except Exception:
                    pass

    # -- api --------------------------------------------------------------

    def set_accent(self, color: str | None) -> None:
        self._accent = color
        self._redraw()

    def bind_click(self, command) -> None:
        """Make the whole card clickable (and show a hand cursor)."""
        def _fire(_event=None):
            command()

        for widget in (self, self._canvas, self.body):
            widget.bind("<Button-1>", _fire, add="+")
            try:
                widget.configure(cursor="hand2")
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Rounded button
# ---------------------------------------------------------------------------

_BUTTON_VARIANTS = {
    "primary": dict(
        fill=T.ACCENT, hover=T.ACCENT_HOVER, press=T.ACCENT_PRESS,
        fg=T.TEXT_ON_ACCENT, border=T.ACCENT, border_hover=T.ACCENT_HOVER,
    ),
    "secondary": dict(
        fill=T.RAISED, hover=T.RAISED_HOVER, press=T.SURFACE,
        fg=T.TEXT, border=T.BORDER_STRONG, border_hover=T.ACCENT_BORDER,
    ),
    # Tinted blue outline -- more presence than "secondary" without competing
    # with a solid primary call to action.
    "accent": dict(
        fill=T.ACCENT_SOFT, hover=T.mix(T.ACCENT_SOFT, T.ACCENT, 0.38), press=T.ACCENT_SOFT,
        fg=T.ACCENT_BRIGHT, border=T.ACCENT_BORDER, border_hover=T.ACCENT,
    ),
    "ghost": dict(
        fill=None, hover=T.RAISED, press=T.SURFACE,
        fg=T.TEXT_SECONDARY, border=None, border_hover=T.BORDER_STRONG,
    ),
    "danger": dict(
        fill=T.DANGER_SOFT, hover=T.mix(T.DANGER_SOFT, T.DANGER, 0.25), press=T.DANGER_SOFT,
        fg=T.DANGER, border=T.mix(T.DANGER, T.BG, 0.45), border_hover=T.DANGER,
    ),
    "success": dict(
        fill=T.SUCCESS_SOFT, hover=T.mix(T.SUCCESS_SOFT, T.SUCCESS, 0.25), press=T.SUCCESS_SOFT,
        fg=T.SUCCESS, border=T.mix(T.SUCCESS, T.BG, 0.45), border_hover=T.SUCCESS,
    ),
}


class RoundedButton(tk.Canvas):
    """A canvas button with rounded corners and proper interaction states.

    Mirrors the parts of the ``ttk.Button`` API this app uses: ``command``,
    ``configure(state=...)``, and ``configure(text=...)``.
    """

    def __init__(
        self,
        parent: tk.Misc,
        text: str = "",
        command=None,
        *,
        variant: str = "secondary",
        icon: str | None = None,
        radius: int = T.RADIUS_MD,
        padx: int = 18,
        pady: int = 10,
        min_width: int = 0,
        font=None,
        parent_bg: str | None = None,
        state: str = "normal",
        **kwargs,
    ):
        self._outer_bg = parent_bg or resolve_bg(parent)
        super().__init__(
            parent,
            bg=self._outer_bg,
            highlightthickness=0,
            bd=0,
            takefocus=0,
            **kwargs,
        )

        spec = _BUTTON_VARIANTS.get(variant, _BUTTON_VARIANTS["secondary"])
        self._spec = spec
        self._variant = variant
        self._radius = radius
        self._text = text
        self._icon = icon
        self._command = command
        self._state = state
        self._hovering = False
        self._pressed = False
        self._font = font or T.f_body_strong()

        label = f"{icon}  {text}" if icon else text
        metrics = tkfont.Font(font=self._font)
        width = max(min_width, metrics.measure(label) + padx * 2)
        height = metrics.metrics("linespace") + pady * 2

        self.configure(width=width, height=height)

        self._shape = None
        self._label = None
        self._draw()

        self.bind("<Enter>", self._on_enter, add="+")
        self.bind("<Leave>", self._on_leave, add="+")
        self.bind("<Button-1>", self._on_press, add="+")
        self.bind("<ButtonRelease-1>", self._on_release, add="+")
        self.bind("<Configure>", lambda _e: self._draw(), add="+")

    # -- painting ---------------------------------------------------------

    def _colors(self):
        spec = self._spec
        if self._state == "disabled":
            fill = spec["fill"]
            return (
                T.mix(fill, T.BG, 0.6) if fill else None,
                T.TEXT_DISABLED,
                T.mix(spec["border"], T.BG, 0.6) if spec["border"] else None,
            )
        if self._pressed:
            return spec["press"], spec["fg"], spec["border_hover"]
        if self._hovering:
            return spec["hover"], spec["fg"], spec["border_hover"]
        return spec["fill"], spec["fg"], spec["border"]

    def _draw(self) -> None:
        w = self.winfo_width() or int(self["width"])
        h = self.winfo_height() or int(self["height"])
        if w <= 2 or h <= 2:
            return

        fill, fg, border = self._colors()
        self.delete("all")

        # Ghost variant with no fill still needs a hit target, so paint the
        # parent background rather than leaving the canvas empty.
        self._shape = draw_round_rect(
            self, 0.5, 0.5, w - 0.5, h - 0.5, self._radius,
            fill=fill or self._outer_bg,
            outline=border or (fill or self._outer_bg),
            width=1,
        )

        # Lit top edge on the solid variants: a thin highlight that makes the
        # accent fill look like a physical, slightly convex key.
        if fill and self._state != "disabled" and self._variant in ("primary", "secondary"):
            self.create_line(
                self._radius, 1.5, w - self._radius, 1.5,
                fill=T.lighten(fill, 0.22 if self._variant == "primary" else 0.10),
            )

        label = f"{self._icon}  {self._text}" if self._icon else self._text
        self._label = self.create_text(
            w / 2, h / 2, text=label, fill=fg, font=self._font, anchor="center",
        )

    # -- events -----------------------------------------------------------

    def _on_enter(self, _event=None) -> None:
        if self._state == "disabled":
            return
        self._hovering = True
        self.configure(cursor="hand2")
        self._draw()

    def _on_leave(self, _event=None) -> None:
        self._hovering = False
        self._pressed = False
        self.configure(cursor="")
        self._draw()

    def _on_press(self, _event=None) -> None:
        if self._state == "disabled":
            return
        self._pressed = True
        self._draw()

    def _on_release(self, _event=None) -> None:
        if self._state == "disabled":
            return
        was_pressed = self._pressed
        self._pressed = False
        self._draw()
        if was_pressed and self._command is not None:
            self._command()

    # -- ttk-compatible surface -------------------------------------------

    def configure(self, cnf=None, **kwargs):  # type: ignore[override]
        redraw = False

        if "state" in kwargs:
            self._state = kwargs.pop("state")
            redraw = True
        if "text" in kwargs:
            self._text = kwargs.pop("text")
            redraw = True
        if "command" in kwargs:
            self._command = kwargs.pop("command")

        result = super().configure(cnf, **kwargs) if (cnf or kwargs) else None
        if redraw:
            self._draw()
        return result

    config = configure

    def cget(self, key):  # type: ignore[override]
        if key == "state":
            return self._state
        if key == "text":
            return self._text
        return super().cget(key)

    def invoke(self):
        if self._state != "disabled" and self._command is not None:
            self._command()


# ---------------------------------------------------------------------------
# Badge
# ---------------------------------------------------------------------------

class Badge(tk.Canvas):
    """A small status pill, coloured from the semantic status map."""

    def __init__(
        self,
        parent: tk.Misc,
        text: str = "",
        *,
        status: str | None = None,
        fg: str | None = None,
        bg: str | None = None,
        parent_bg: str | None = None,
        font=None,
        padx: int = 10,
        pady: int = 4,
        **kwargs,
    ):
        self._outer_bg = parent_bg or resolve_bg(parent)
        super().__init__(
            parent, bg=self._outer_bg, highlightthickness=0, bd=0, takefocus=0, **kwargs
        )
        self._font = font or T.f_micro()
        self._padx = padx
        self._pady = pady
        self._text = text
        auto_fg, auto_bg = T.status_colors(status if status is not None else text)
        self._fg = fg or auto_fg
        self._bg = bg or auto_bg
        self._render()

    def _render(self) -> None:
        metrics = tkfont.Font(font=self._font)
        label = self._text.upper()
        w = metrics.measure(label) + self._padx * 2
        h = metrics.metrics("linespace") + self._pady * 2
        self.configure(width=w, height=h)
        self.delete("all")
        draw_round_rect(
            self, 0.5, 0.5, w - 0.5, h - 0.5, h / 2,
            fill=self._bg, outline=T.mix(self._bg, self._fg, 0.28), width=1,
        )
        self.create_text(w / 2, h / 2, text=label, fill=self._fg, font=self._font)

    def set(self, text: str, status: str | None = None) -> None:
        """Update the pill's text and (optionally) recolour it."""
        self._text = text
        fg, bg = T.status_colors(status if status is not None else text)
        self._fg, self._bg = fg, bg
        self._render()


# ---------------------------------------------------------------------------
# Composite pieces
# ---------------------------------------------------------------------------

class Checkbox(tk.Frame):
    """A checkbox drawn on a canvas, with a real check mark.

    The stock clam indicator renders an "✗" for the *selected* state, which
    reads as "no" rather than "yes", so the control is drawn here instead.
    Supports the slice of the ttk API this app relies on: a bound variable, a
    ``command`` callback, and ``configure(state=...)``.
    """

    BOX = 17

    def __init__(
        self,
        parent: tk.Misc,
        text: str,
        variable: tk.Variable,
        *,
        command=None,
        parent_bg: str | None = None,
        state: str = "normal",
        font=None,
        **kwargs,
    ):
        self._bg = parent_bg or resolve_bg(parent)
        super().__init__(parent, bg=self._bg, bd=0, highlightthickness=0, **kwargs)

        self._variable = variable
        self._command = command
        self._state = state
        self._hovering = False

        self._canvas = tk.Canvas(
            self, width=self.BOX + 1, height=self.BOX + 1, bg=self._bg,
            highlightthickness=0, bd=0, takefocus=0,
        )
        self._canvas.pack(side="left")

        self._label = tk.Label(
            self, text=text, bg=self._bg, fg=T.TEXT_SECONDARY,
            font=font or T.f_body(), anchor="w",
        )
        self._label.pack(side="left", padx=(T.SPACE_SM, 0))

        for widget in (self, self._canvas, self._label):
            widget.bind("<Button-1>", self._toggle, add="+")
            widget.bind("<Enter>", self._on_enter, add="+")
            widget.bind("<Leave>", self._on_leave, add="+")

        try:
            variable.trace_add("write", lambda *_: self._draw())
        except Exception:
            pass

        self._draw()

    # -- painting ---------------------------------------------------------

    def _draw(self) -> None:
        self._canvas.delete("all")
        checked = bool(self._variable.get())
        disabled = self._state == "disabled"

        if disabled:
            fill = T.mix(T.ACCENT, T.BG, 0.62) if checked else T.mix(T.SUNKEN, T.BG, 0.5)
            border = T.mix(T.BORDER_STRONG, T.BG, 0.45)
            mark = T.mix(T.TEXT_ON_ACCENT, T.BG, 0.45)
            text_fg = T.TEXT_DISABLED
        else:
            fill = T.ACCENT if checked else T.SUNKEN
            border = T.ACCENT if checked else (
                T.ACCENT_BORDER if self._hovering else T.BORDER_STRONG
            )
            mark = T.TEXT_ON_ACCENT
            text_fg = T.TEXT if checked else T.TEXT_SECONDARY

        draw_round_rect(
            self._canvas, 1.5, 1.5, self.BOX - 0.5, self.BOX - 0.5, T.RADIUS_SM,
            fill=fill, outline=border, width=1,
        )

        if checked:
            self._canvas.create_line(
                5, 9.5, 7.8, 12.5, 12.5, 5.8,
                fill=mark, width=2, capstyle="round", joinstyle="round",
            )

        self._label.configure(fg=text_fg)

    # -- events -----------------------------------------------------------

    def _toggle(self, _event=None):
        if self._state == "disabled":
            return
        self._variable.set(not bool(self._variable.get()))
        self._draw()
        if self._command is not None:
            self._command()

    def _on_enter(self, _event=None):
        if self._state == "disabled":
            return
        self._hovering = True
        self.configure(cursor="hand2")
        self._draw()

    def _on_leave(self, _event=None):
        self._hovering = False
        self.configure(cursor="")
        self._draw()

    # -- ttk-compatible surface -------------------------------------------

    def configure(self, cnf=None, **kwargs):  # type: ignore[override]
        redraw = False
        if "state" in kwargs:
            self._state = kwargs.pop("state")
            redraw = True
        if "text" in kwargs:
            self._label.configure(text=kwargs.pop("text"))
        result = super().configure(cnf, **kwargs) if (cnf or kwargs) else None
        if redraw:
            self._draw()
        return result

    config = configure

    def cget(self, key):  # type: ignore[override]
        if key == "state":
            return self._state
        if key == "text":
            return self._label.cget("text")
        return super().cget(key)


class StatTile(Card):
    """A small metric readout: eyebrow label above a large value."""

    def __init__(
        self,
        parent: tk.Misc,
        label: str,
        value: str = "-",
        *,
        textvariable: tk.Variable | None = None,
        accent: str | None = None,
        value_color: str = T.TEXT,
        **kwargs,
    ):
        kwargs.setdefault("fill", T.RAISED)
        kwargs.setdefault("border", T.BORDER)
        kwargs.setdefault("radius", T.RADIUS_MD)
        kwargs.setdefault("padding", (T.SPACE_LG, T.SPACE_MD))
        super().__init__(parent, accent=accent, **kwargs)

        surface = kwargs["fill"]

        self.label = tk.Label(
            self.body, text=label.upper(), bg=surface, fg=T.TEXT_MUTED,
            font=T.f_eyebrow(), anchor="w",
        )
        self.label.pack(anchor="w")

        opts = dict(bg=surface, fg=value_color, font=T.f_metric(), anchor="w")
        if textvariable is not None:
            opts["textvariable"] = textvariable
        else:
            opts["text"] = value

        self.value = tk.Label(self.body, **opts)
        self.value.pack(anchor="w", pady=(T.SPACE_XS, 0))

    def set_value_color(self, color: str) -> None:
        self.value.configure(fg=color)


class ScrolledText(tk.Text):
    """A ``tk.Text`` with a themed ttk scrollbar attached.

    ``tkinter.scrolledtext.ScrolledText`` uses the classic ``tk.Scrollbar``,
    which Windows draws natively and which therefore ignores every colour
    option -- it stays light grey no matter what is configured. A ``ttk``
    scrollbar honours the theme, so this builds the same widget with one.

    Like the stock version, geometry calls (``pack`` / ``grid`` / ``place``)
    are forwarded to the containing frame, so callers can treat the returned
    object as a single widget.
    """

    def __init__(self, master=None, **kwargs):
        self.frame = tk.Frame(master, bd=0, highlightthickness=0, bg=kwargs.get("bg", T.SUNKEN))
        self.vbar = ttk.Scrollbar(self.frame, orient="vertical")
        self.vbar.pack(side="right", fill="y")

        kwargs.setdefault("yscrollcommand", self.vbar.set)
        super().__init__(self.frame, **kwargs)
        self.pack(side="left", fill="both", expand=True)
        self.vbar.configure(command=self.yview)

        # Forward geometry management to the frame, mirroring the stdlib trick.
        text_methods = set(vars(tk.Text).keys())
        geometry_methods = (
            set(vars(tk.Pack).keys()) | set(vars(tk.Grid).keys()) | set(vars(tk.Place).keys())
        ) - text_methods
        for name in geometry_methods:
            if name[0] != "_" and name not in ("config", "configure"):
                setattr(self, name, getattr(self.frame, name))

    def __str__(self):
        return str(self.frame)


class GradientRule(tk.Canvas):
    """A hairline that starts in the accent blue and fades into the border.

    Used under section headings so a divider reads as brand colour rather than
    another grey line.
    """

    def __init__(
        self,
        parent: tk.Misc,
        *,
        start: str = T.ACCENT,
        end: str | None = None,
        lead: float = 0.32,
        parent_bg: str | None = None,
        **kwargs,
    ):
        self._bg = parent_bg or resolve_bg(parent)
        super().__init__(
            parent, height=1, bg=self._bg, highlightthickness=0, bd=0, takefocus=0, **kwargs
        )
        self._start = start
        self._end = end or T.BORDER
        self._lead = lead
        self.bind("<Configure>", self._redraw, add="+")

    def _redraw(self, _event=None) -> None:
        w = self.winfo_width()
        if w <= 2:
            return
        self.delete("all")
        # Saturated for the first stretch, then settling into the hairline.
        split = max(1.0, w * self._lead)
        draw_horizontal_fade(self, 0, 0.5, split, 0.5, self._start, self._end)
        self.create_line(split, 0.5, w, 0.5, fill=self._end)


class SectionTitle(tk.Frame):
    """An eyebrow + heading pair with a hairline rule, for grouping content."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        *,
        eyebrow: str | None = None,
        subtitle: str | None = None,
        rule: bool = True,
        parent_bg: str | None = None,
        **kwargs,
    ):
        bg = parent_bg or resolve_bg(parent)
        super().__init__(parent, bg=bg, bd=0, highlightthickness=0, **kwargs)

        if eyebrow:
            tk.Label(
                self, text=eyebrow.upper(), bg=bg, fg=T.ACCENT_TEXT,
                font=T.f_eyebrow(), anchor="w",
            ).pack(anchor="w", pady=(0, 2))

        tk.Label(
            self, text=title, bg=bg, fg=T.TEXT, font=T.f_heading(), anchor="w",
        ).pack(anchor="w")

        if subtitle:
            tk.Label(
                self, text=subtitle, bg=bg, fg=T.TEXT_MUTED, font=T.f_small(),
                anchor="w", justify="left",
            ).pack(anchor="w", pady=(3, 0))

        if rule:
            GradientRule(self, parent_bg=bg).pack(
                fill="x", pady=(T.SPACE_MD, 0)
            )


def card_title(parent, text, *, hint=None):
    """A card's own heading row, with optional right-aligned hint text.

    The counterpart to a `ttk.LabelFrame`'s caption, for content sitting on a
    `Card`. It lived in `gui/main_sections.py` until 04 Sep, which is part of
    why the Static module was the only screen built from this kit -- the other
    five had no shared way to title a card, so they reached for `LabelFrame`
    and inherited its outline instead of a card surface.

    `parent` must be a card's `.body` (or anything else painted `T.SURFACE`).
    """
    head = tk.Frame(parent, bg=T.SURFACE)
    head.pack(fill="x", pady=(0, T.SPACE_MD))

    tk.Label(
        head, text=text, bg=T.SURFACE, fg=T.TEXT, font=T.f_subheading(),
    ).pack(side="left")

    if hint:
        tk.Label(
            head, text=hint, bg=T.SURFACE, fg=T.TEXT_MUTED, font=T.f_small(),
        ).pack(side="right")

    return head


class HeaderBar(Card):
    """Branded page header: logo, title, subtitle, description, right actions.

    Use :attr:`actions` as the parent for any right-aligned buttons.
    """

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        *,
        subtitle: str | None = None,
        description: str | None = None,
        logo_path=None,
        logo_size: int = 64,
        **kwargs,
    ):
        kwargs.setdefault("padding", (T.SPACE_XL, T.SPACE_LG + 2))
        kwargs.setdefault("radius", T.RADIUS_LG)
        # Brand bar across the top and an accent hairline along the bottom, so
        # the header carries the blue instead of being one more black slab.
        kwargs.setdefault("fill", T.HEADER_BOTTOM)
        kwargs.setdefault("brand_strip", True)
        kwargs.setdefault("edge", T.ACCENT)
        kwargs.setdefault("border", T.BORDER_STRONG)
        super().__init__(parent, **kwargs)

        surface = kwargs["fill"]
        self.body.configure(bg=surface)
        self._logo_image = None

        self.body.columnconfigure(1, weight=1)

        col = 0
        if logo_path is not None:
            image = self._load_logo(logo_path, logo_size)
            if image is not None:
                self._logo_image = image
                # The logo sits on a tinted rounded chip, which reads as the
                # brand colour catching light behind the mark.
                chip = Card(
                    self.body,
                    fill=T.ACCENT_SOFT,
                    border=T.ACCENT_BORDER,
                    radius=T.RADIUS_MD,
                    padding=T.SPACE_SM,
                    parent_bg=surface,
                    highlight=False,
                )
                chip.grid(row=0, column=0, rowspan=3, sticky="w", padx=(0, T.SPACE_LG))
                tk.Label(
                    chip.body, image=image, bg=T.ACCENT_SOFT, bd=0, highlightthickness=0,
                ).pack()
                col = 1

        title_row = tk.Frame(self.body, bg=surface)
        title_row.grid(row=0, column=col, sticky="w")

        tk.Label(
            title_row, text=title, bg=surface, fg=T.TEXT, font=T.f_display(), anchor="w",
        ).pack(side="left")

        if subtitle:
            tk.Label(
                title_row, text=subtitle, bg=surface, fg=T.ACCENT_TEXT,
                font=T.f_heading(), anchor="w",
            ).pack(side="left", padx=(T.SPACE_MD, 0), pady=(8, 0))

        if description:
            tk.Label(
                self.body, text=description, bg=surface, fg=T.TEXT_MUTED,
                font=T.f_body(), anchor="w", justify="left", wraplength=780,
            ).grid(row=1, column=col, sticky="w", pady=(T.SPACE_XS, 0))

        self.actions = tk.Frame(self.body, bg=surface)
        self.actions.grid(row=0, column=col + 1, rowspan=2, sticky="e")
        self.body.columnconfigure(col + 1, weight=0)

    @staticmethod
    def _load_logo(path, size: int):
        try:
            from PIL import Image, ImageTk

            image = Image.open(path).convert("RGBA")
            image.thumbnail((size, size), Image.LANCZOS)
            return ImageTk.PhotoImage(image)
        except Exception:
            return None


class EmptyState(tk.Frame):
    """Centred placeholder shown in place of an empty table or result pane."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        *,
        detail: str | None = None,
        glyph: str = "◌",
        parent_bg: str | None = None,
        **kwargs,
    ):
        bg = parent_bg or resolve_bg(parent)
        super().__init__(parent, bg=bg, bd=0, highlightthickness=0, **kwargs)

        inner = tk.Frame(self, bg=bg)
        inner.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(
            inner, text=glyph, bg=bg, fg=T.mix(T.TEXT_MUTED, T.BG, 0.35),
            font=T.font(30),
        ).pack()
        tk.Label(
            inner, text=title, bg=bg, fg=T.TEXT_SECONDARY, font=T.f_body_strong(),
        ).pack(pady=(T.SPACE_SM, 0))
        if detail:
            tk.Label(
                inner, text=detail, bg=bg, fg=T.TEXT_MUTED, font=T.f_small(),
                justify="center",
            ).pack(pady=(T.SPACE_XS, 0))


def divider(parent: tk.Misc, *, vertical: bool = False, color: str = T.BORDER) -> tk.Frame:
    """A one-pixel rule; pack or grid it with ``fill``."""
    if vertical:
        return tk.Frame(parent, bg=color, width=1)
    return tk.Frame(parent, bg=color, height=1)


def scrollable(parent: tk.Misc, widget: tk.Widget, *, row: int = 0, column: int = 0):
    """Attach a themed vertical scrollbar to ``widget`` inside a grid parent."""
    bar = ttk.Scrollbar(parent, orient="vertical", command=widget.yview)
    widget.configure(yscrollcommand=bar.set)
    bar.grid(row=row, column=column + 1, sticky="ns")
    return bar
