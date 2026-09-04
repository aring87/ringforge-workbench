"""Compatibility alias: this module now lives in `static_triage_engine`.

A 1,098-line CLR image parser that the static pipeline and `dynamic_analysis`
both import -- engine code that happened to sit in `scripts/`, so an installed
copy could not reach it. See the sibling shims for the full reasoning.

New code should import from `static_triage_engine.dotnet_meta`.
"""

import sys

from static_triage_engine import dotnet_meta as _moved

sys.modules[__name__] = _moved
