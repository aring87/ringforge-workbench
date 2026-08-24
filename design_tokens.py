"""The palette, in one place, for every medium the workbench renders into.

Phase 4b of `docs/SCORING.md`. Before this, `gui/theme.py` defined 40 colours
for the desktop application and `dynamic_analysis/report_theme.py` defined 17
for the HTML reports, and the two shared **zero values** -- which is why the
application and its own reports read as different products. There were five
report stylesheets in the repository, each with its own idea of what "the
background" is.

**Neutral by design.** `gui/theme.py` was already documented as the single
source of truth, and the obvious fix was to import it from the report side. That
would have made `dynamic_analysis` -- which runs headless, on a detonation
guest, in a subprocess -- depend on the GUI package. It works today only because
this file's ancestor happened to import nothing, and it would break the first
time somebody added a `tkinter` import to a theme module. So the tokens moved
down here instead, and both media depend on a module that depends on nothing.

`gui/theme.py` re-exports every name below, so the twelve GUI modules that
already import from it need no changes.

Palette
-------

Black and Lexus **Ultrasonic Blue Mica 2.0** -- a vivid, slightly cool electric
blue. The surfaces are not neutral black: every one carries a blue cast so the
accent reads as part of the same material rather than a sticker on grey. The
accent ramp runs deep navy -> ultrasonic -> sky, which keeps the UI blue-rich
without turning saturated blue into the background.

Naming follows a surface/elevation ladder:

    BG        the application canvas, furthest back
    SURFACE   a card or panel resting on the canvas
    RAISED    a control resting on a card (buttons, table headers)
    SUNKEN    a recessed control (entries, consoles, text areas)
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Surfaces -- blue-black, never neutral grey
# ---------------------------------------------------------------------------

BG = "#04070E"           # application canvas, near-black with a blue cast
BG_ALT = "#070C17"       # banded background
SURFACE = "#0A1121"      # card / panel
SURFACE_HOVER = "#0E182C"
RAISED = "#121D35"       # control resting on a card
RAISED_HOVER = "#182644"
SUNKEN = "#02050B"       # entries, consoles -- the deepest black

BORDER = "#16233D"       # default hairline, blue-tinted
BORDER_STRONG = "#233A63"  # emphasised divider
BORDER_MUTED = "#0E1830"

# ---------------------------------------------------------------------------
# Text -- cool whites so nothing reads warm against the blue
# ---------------------------------------------------------------------------

TEXT = "#EAF1FF"         # primary copy
TEXT_SECONDARY = "#A8BCDC"
TEXT_MUTED = "#6E82A6"   # captions, hints
TEXT_DISABLED = "#42557A"
TEXT_ON_ACCENT = "#FFFFFF"

# ---------------------------------------------------------------------------
# Accent -- Lexus Ultrasonic Blue Mica 2.0
# ---------------------------------------------------------------------------

ACCENT = "#0B63E5"        # the hero blue
ACCENT_HOVER = "#2D7DF6"
ACCENT_PRESS = "#0A4FBC"
ACCENT_DEEP = "#062F73"   # deep end of the ramp, for gradients and glows
ACCENT_BRIGHT = "#4FA3FF"  # highlights and hairlines
ACCENT_BORDER = "#1E4FA8"
ACCENT_SOFT = "#0C1E42"    # tinted fill behind accent content
ACCENT_TEXT = "#6FA8FF"    # accent-coloured copy on dark surfaces
GLOW = "#1B6FEF"           # halo colour under primary controls

#: Vertical wash used behind page headers, in both media.
HEADER_TOP = "#0D1E3E"
HEADER_BOTTOM = "#070D1C"

# ---------------------------------------------------------------------------
# Semantic status -- kept cool enough to sit beside the blue
# ---------------------------------------------------------------------------

SUCCESS = "#2FD4A0"
SUCCESS_SOFT = "#062A22"
WARNING = "#F5B849"
WARNING_SOFT = "#2A1F0C"
DANGER = "#FF6B7A"
DANGER_SOFT = "#2B1019"
CRITICAL = "#F2455A"
INFO = "#4FA3FF"
INFO_SOFT = "#0C1E42"
NEUTRAL = "#7C90B4"
NEUTRAL_SOFT = "#111B31"

#: A solid danger fill for a banner that must not be missed, with
#: `TEXT_ON_ACCENT` over it. `DANGER` is too bright to sit behind white text and
#: `DANGER_SOFT` is too quiet to alarm anyone -- this is the middle the
#: containment banner needs, and it is a token because "impossible to miss" is a
#: design decision rather than a number somebody picked in one file.
DANGER_FILL = "#85262F"


# ---------------------------------------------------------------------------
# Categorical accents
# ---------------------------------------------------------------------------

#: Used only to distinguish peer items (the six analysis modules), never to
#: imply severity -- severity always comes from STATUS_COLORS above.
#: All six stay inside the blue/cyan family so the set reads as one system.
CATEGORY = {
    "ultrasonic": "#0B63E5",   # the hero blue
    "cyan": "#22D3EE",
    "sky": "#4FA3FF",
    "periwinkle": "#7C93FF",
    "azure": "#31A8F0",
    "teal": "#2DD4BF",
}

# ---------------------------------------------------------------------------
# Colour utilities
# ---------------------------------------------------------------------------

def _to_rgb(color: str) -> tuple[int, int, int]:
    color = color.lstrip("#")
    if len(color) == 3:
        color = "".join(ch * 2 for ch in color)
    return int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)


def _to_hex(rgb: tuple[int, int, int]) -> str:
    return "#%02X%02X%02X" % tuple(max(0, min(255, int(round(c)))) for c in rgb)


def mix(color_a: str, color_b: str, t: float = 0.5) -> str:
    """Blend two hex colors. ``t=0`` returns ``color_a``, ``t=1`` returns ``color_b``."""
    ar, ag, ab = _to_rgb(color_a)
    br, bg_, bb = _to_rgb(color_b)
    return _to_hex((ar + (br - ar) * t, ag + (bg_ - ag) * t, ab + (bb - ab) * t))


def lighten(color: str, amount: float = 0.1) -> str:
    return mix(color, "#FFFFFF", amount)


def darken(color: str, amount: float = 0.1) -> str:
    return mix(color, "#000000", amount)


def alpha_over(color: str, background: str, alpha: float) -> str:
    """Flatten ``color`` at ``alpha`` over an opaque ``background``.

    Tk has no alpha channel, so translucency is pre-computed here. The HTML
    reports could use `rgba()` instead, and deliberately do not: a badge that is
    one colour in the application and a slightly different one in the exported
    report is the kind of difference nobody can name and everybody notices.
    """
    return mix(background, color, alpha)
