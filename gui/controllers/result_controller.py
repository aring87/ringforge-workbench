from __future__ import annotations

from pathlib import Path

from static_triage_engine.case_result import (
    band_for,
    counts_line,
    load_case_result,
    load_virustotal,
    result_headline,
    virustotal_view,
)

#: The counts line with nothing in it, for the reset and the empty case.
_NO_COUNTS = counts_line({})


class ResultController:
    """Drives the main window's Results panel.

    The reading is in `static_triage_engine.case_result`. It used to be here,
    where it referenced no widget and could not be imported without a display
    -- which is how the Verdict tile came to be grey for every case the
    current scoring model produces.
    """

    def __init__(self, app):
        self.app = app

    def reload_combined_score_from_disk(self):
        return

    def refresh_combined_score(self, case_dir=None):
        return

    def _show_virustotal(self, view) -> None:
        app = self.app
        app.vt_status_var.set(view["status"])
        app.vt_name_var.set(f"VT Name: {view['name']}")
        app.vt_counts_var.set(counts_line(view["counts"]))
        app.vt_link = view["link"]
        if getattr(app, "vt_open_btn", None) is not None:
            app.vt_open_btn.configure(
                state=("normal" if view["link"] else "disabled"))

    def reset_result_summary(self):
        app = self.app

        app.verdict_band = ""
        app.score_var.set("-")
        app.verdict_var.set("-")
        app.confidence_var.set("-")

        app.latest_static_result = {}
        app.latest_dynamic_result = {}
        app.latest_spec_result = {}

        self._show_virustotal({
            "status": ("VirusTotal: waiting for result"
                       if app.vt_api_key_var.get().strip()
                       else "VirusTotal: disabled"),
            "name": "-", "counts": {}, "link": "", "found": False,
        })

    def update_result_summary_from_case(self, case_dir: Path):
        app = self.app
        case_dir = Path(case_dir)

        data = load_case_result(case_dir)
        app.latest_static_result = data

        headline = result_headline(data)
        # **Set before `verdict_var`, which is what triggers the tint.**
        # `verdict_var` holds wording written for a reader; `band_for` returns
        # the model's severity where the folder has one and the wording where
        # it does not. Assigning it afterwards would colour each case with the
        # previous case's band.
        app.verdict_band = band_for(headline)

        app.score_var.set(headline["score"])
        app.verdict_var.set(headline["verdict"])
        app.confidence_var.set(headline["confidence"])

        self._show_virustotal(virustotal_view(
            embedded=data.get("virustotal"),
            raw=load_virustotal(case_dir),
            api_key_present=bool(app.vt_api_key_var.get().strip()),
        ))
