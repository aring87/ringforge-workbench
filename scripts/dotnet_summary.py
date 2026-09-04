"""Compatibility alias: this module now lives in `static_triage_engine`.

It was a pipeline step sitting in `scripts/`, which is bench tooling -- so an
installed copy of the engine could not import it and `ringforge-scan` failed at
`from scripts.ioc_extract import ...`. Packaging is what surfaced that; it only
ever worked because everything ran from the repo root.

The module object is aliased rather than re-exported so private names resolve
too. `scripts/` consumers keep working unchanged; new code should import from
`static_triage_engine.dotnet_summary`.
"""

import sys

from static_triage_engine import dotnet_summary as _moved

sys.modules[__name__] = _moved
