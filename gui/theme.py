"""Design tokens for the RingForge Workbench UI.

Type, spacing, radius and the Tk-specific status mapping. **The palette itself
lives in `design_tokens.py`** and is re-exported here unchanged, so the twelve
modules that already import from `gui.theme` need no changes -- and so the HTML
reports can share the same colours without `dynamic_analysis` having to import
the GUI package. See that module for the palette and why it moved.

Every module in ``gui`` should pull values from here rather than embedding hex
literals; `verdict/tests/test_theme_tokens.py` enforces it.
"""

from __future__ import annotations

# Re-exported deliberately. Listing them rather than star-importing keeps the
# names greppable and lets a linter see them.
from design_tokens import (  # noqa: F401
    ACCENT,
    ACCENT_BORDER,
    ACCENT_BRIGHT,
    ACCENT_DEEP,
    ACCENT_HOVER,
    ACCENT_PRESS,
    ACCENT_SOFT,
    ACCENT_TEXT,
    BG,
    BG_ALT,
    BORDER,
    BORDER_MUTED,
    BORDER_STRONG,
    CRITICAL,
    DANGER,
    DANGER_FILL,
    DANGER_SOFT,
    GLOW,
    HEADER_BOTTOM,
    HEADER_TOP,
    INFO,
    INFO_SOFT,
    NEUTRAL,
    NEUTRAL_SOFT,
    RAISED,
    RAISED_HOVER,
    SUCCESS,
    SUCCESS_SOFT,
    SUNKEN,
    SURFACE,
    SURFACE_HOVER,
    TEXT,
    TEXT_DISABLED,
    TEXT_MUTED,
    TEXT_ON_ACCENT,
    TEXT_SECONDARY,
    WARNING,
    WARNING_SOFT,
    _to_hex,
    _to_rgb,
    alpha_over,
    darken,
    lighten,
    mix,
)
from design_tokens import CATEGORY  # noqa: F401

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
    # `corroboration-v1` severities. `unknown` is Insufficient Coverage -- a
    # statement about the bench rather than the sample, so it reads as neutral
    # rather than as a clean result.
    "unknown": (NEUTRAL, NEUTRAL_SOFT),

    # --- The verdict *sentences*, added 03 Sep -----------------------------
    #
    # **Measured: 12 of 12 rendered grey.** The main window's Verdict tile
    # colours itself from this map and is handed the sentence, not the band --
    # and the sentences arrived with `corroboration-v1` while this map still
    # only knew the severities and the retired additive words. So every case
    # folder written before the scoring rewrite coloured, and every one
    # written after it did not, on the application's front page.
    #
    # The tile prefers `severity` now (see
    # `static_triage_engine.case_result.band_for`), which is the real fix.
    # These are here because anything holding only a sentence -- an old export,
    # a badge built from a verdict string -- must still read as something.
    #
    # Malware domain:
    "likely malicious": (DANGER, DANGER_SOFT),
    "elevated attention": (DANGER, DANGER_SOFT),
    "needs review": (WARNING, WARNING_SOFT),
    "no indicators found": (SUCCESS, SUCCESS_SOFT),
    "low suspicion": (SUCCESS, SUCCESS_SOFT),
    "benign / clean baseline": (SUCCESS, SUCCESS_SOFT),
    # Posture domain -- a specification or an API, not a sample:
    "serious exposure": (DANGER, DANGER_SOFT),
    "multiple weaknesses": (DANGER, DANGER_SOFT),
    "no weaknesses found": (SUCCESS, SUCCESS_SOFT),
    # Coverage, which is a statement about the bench and never a clean result:
    "insufficient coverage": (NEUTRAL, NEUTRAL_SOFT),
    "no findings, coverage incomplete": (NEUTRAL, NEUTRAL_SOFT),
    "findings not scored": (NEUTRAL, NEUTRAL_SOFT),
}


def status_colors(status: str) -> tuple[str, str]:
    """Return ``(foreground, soft_background)`` for a status keyword."""
    return STATUS_COLORS.get(str(status).strip().lower(), (TEXT_SECONDARY, NEUTRAL_SOFT))


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
