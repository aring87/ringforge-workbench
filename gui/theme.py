"""Design tokens for the RingForge Workbench UI.

Single source of truth for color, type, spacing, and radius. Every module in
``gui`` should pull values from here instead of embedding hex literals, so the
whole workbench can be re-skinned from one file.

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

#: Vertical wash used behind page headers.
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

#: Verdict / status keyword -> (foreground, soft background).
STATUS_COLORS = {
    "clean": (SUCCESS, SUCCESS_SOFT),
    "benign": (SUCCESS, SUCCESS_SOFT),
    "done": (SUCCESS, SUCCESS_SOFT),
    "completed": (SUCCESS, SUCCESS_SOFT),
    "pass": (SUCCESS, SUCCESS_SOFT),
    "low": (SUCCESS, SUCCESS_SOFT),
    "running": (INFO, INFO_SOFT),
    "info": (INFO, INFO_SOFT),
    "queued": (NEUTRAL, NEUTRAL_SOFT),
    "idle": (NEUTRAL, NEUTRAL_SOFT),
    "n/a": (NEUTRAL, NEUTRAL_SOFT),
    "skipped": (NEUTRAL, NEUTRAL_SOFT),
    "suspicious": (WARNING, WARNING_SOFT),
    "medium": (WARNING, WARNING_SOFT),
    "warning": (WARNING, WARNING_SOFT),
    "missing tool": (WARNING, WARNING_SOFT),
    "malicious": (DANGER, DANGER_SOFT),
    "high": (DANGER, DANGER_SOFT),
    "failed": (DANGER, DANGER_SOFT),
    "error": (DANGER, DANGER_SOFT),
    "critical": (CRITICAL, DANGER_SOFT),
}


def status_colors(status: str) -> tuple[str, str]:
    """Return ``(foreground, soft_background)`` for a status keyword."""
    return STATUS_COLORS.get(str(status).strip().lower(), (TEXT_SECONDARY, NEUTRAL_SOFT))


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
# Typography
# ---------------------------------------------------------------------------

#: Resolved at runtime by :func:`resolve_fonts`; these are safe fallbacks.
UI_FAMILY = "Segoe UI"
MONO_FAMILY = "Consolas"

_UI_PREFERENCES = ("Segoe UI Variable Text", "Segoe UI", "Inter", "Tahoma")
_MONO_PREFERENCES = ("Cascadia Mono", "Cascadia Code", "Consolas", "Courier New")


def resolve_fonts(root=None) -> None:
    """Upgrade :data:`UI_FAMILY` / :data:`MONO_FAMILY` to the best installed font.

    Safe to call more than once and safe to call without a Tk root, in which
    case the fallbacks stay in place.
    """
    global UI_FAMILY, MONO_FAMILY
    try:
        from tkinter import font as tkfont

        available = {name.lower() for name in tkfont.families(root)}
    except Exception:
        return

    for candidate in _UI_PREFERENCES:
        if candidate.lower() in available:
            UI_FAMILY = candidate
            break

    for candidate in _MONO_PREFERENCES:
        if candidate.lower() in available:
            MONO_FAMILY = candidate
            break


def font(size: int = 10, weight: str = "normal", *, mono: bool = False, slant: str = "roman"):
    """Build a Tk font tuple from the resolved family."""
    family = MONO_FAMILY if mono else UI_FAMILY
    if slant != "roman":
        return (family, size, weight, slant)
    return (family, size, weight)


# Type scale. Call these rather than hardcoding sizes, so the whole app
# rescales from one place.
def f_display():
    return font(26, "bold")


def f_title():
    return font(19, "bold")


def f_heading():
    return font(14, "bold")


def f_subheading():
    return font(11, "bold")


def f_eyebrow():
    """Small, bold, used for uppercase section labels."""
    return font(9, "bold")


def f_body():
    return font(10)


def f_body_strong():
    return font(10, "bold")


def f_small():
    return font(9)


def f_small_strong():
    return font(9, "bold")


def f_micro():
    return font(8, "bold")


def f_metric():
    """Large numeric readout."""
    return font(22, "bold")


def f_mono(size: int = 10):
    return font(size, mono=True)


# ---------------------------------------------------------------------------
# Spacing and geometry
# ---------------------------------------------------------------------------

SPACE_XXS = 2
SPACE_XS = 4
SPACE_SM = 8
SPACE_MD = 12
SPACE_LG = 16
SPACE_XL = 24
SPACE_XXL = 32

RADIUS_SM = 4
RADIUS_MD = 8
RADIUS_LG = 12

ROW_HEIGHT = 28          # treeview rows
CARD_PADDING = SPACE_LG


# ---------------------------------------------------------------------------
# Color utilities
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

    Tk has no alpha channel, so translucency is pre-computed here.
    """
    return mix(background, color, alpha)
