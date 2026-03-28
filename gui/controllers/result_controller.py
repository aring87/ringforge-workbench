from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from static_triage_engine.scoring import combined_score_from_case_dir, calculate_combined_score

def _read_json(path: Path) -> dict:
    with Path(path).open("r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}

class ResultController:
    def __init__(self, app):
        self.app = app

    def reload_combined_score_from_disk(self):
        app = self.app
        if not app.case_dir_detected:
            return
        self.refresh_combined_score(Path(app.case_dir_detected))
        app.update_idletasks()

    def reset_result_summary(self):
        app = self.app

        app.score_var.set("-")
        app.verdict_var.set("-")
        app.confidence_var.set("-")
        app.combined_score_var.set("-")
        app.combined_severity_var.set("-")
        app.static_subscore_var.set("-")
        app.dynamic_subscore_var.set("-")
        app.spec_subscore_var.set("-")
        app.combined_verdict_var.set("-")
        app.combined_confidence_var.set("-")

        if app.vt_api_key_var.get().strip():
            app.vt_status_var.set("VirusTotal: waiting for result")
        else:
            app.vt_status_var.set("VirusTotal: disabled")

        app.vt_name_var.set("VT Name: -")
        app.vt_counts_var.set("Counts: mal=0 | susp=0 | harmless=0 | undetected=0")
        app.vt_link = ""
        if getattr(app, "vt_open_btn", None) is not None:
            app.vt_open_btn.configure(state="disabled")

    def refresh_combined_score(self, case_dir: Optional[Path] = None):
        app = self.app
        combined = None

        try:
            if case_dir:
                case_dir = Path(case_dir)

            if case_dir and case_dir.exists():
                combined = combined_score_from_case_dir(
                    case_dir,
                    dynamic_result=None,
                    spec_result=None,
                    write_output=True,
                )
            else:
                static_result = app.latest_static_result or None
                dynamic_result = app.latest_dynamic_result or None
                spec_result = app.latest_spec_result or None

                combined = calculate_combined_score(
                    static_result=static_result,
                    dynamic_result=dynamic_result,
                    spec_result=spec_result,
                )
        except Exception as e:
            combined = None

        if not combined:
            app.combined_score_var.set("-")
            app.combined_severity_var.set("-")
            app.static_subscore_var.set("-")
            app.dynamic_subscore_var.set("-")
            app.spec_subscore_var.set("-")
            app.combined_verdict_var.set("-")
            app.combined_confidence_var.set("-")
            app.latest_combined_score = None
            return

        app.latest_combined_score = combined
        app.combined_verdict_var.set(str(combined.get("verdict", "-")))
        app.combined_confidence_var.set(str(combined.get("confidence", "-")))
        app.combined_score_var.set(str(combined.get("total_score", "-")))
        app.combined_severity_var.set(str(combined.get("severity", "-")))

        subs = combined.get("subscores", {}) if isinstance(combined.get("subscores"), dict) else {}
        present = combined.get("present", {}) if isinstance(combined.get("present"), dict) else {}

        app.static_subscore_var.set(str(subs.get("static", 0)) if present.get("static") else "-")
        app.dynamic_subscore_var.set(str(subs.get("dynamic", 0)) if present.get("dynamic") else "-")
        app.spec_subscore_var.set(str(subs.get("spec", 0)) if present.get("spec") else "-")

        app.update_idletasks()

    def update_result_summary_from_case(self, case_dir: Path):
        app = self.app
        case_dir = Path(case_dir)

        app.refresh_combined_score(case_dir)

        report_json = case_dir / "report.json"
        summary_json = case_dir / "summary.json"
        vt_raw_path = case_dir / "virustotal.json"

        data = {}

        if report_json.exists():
            try:
                data = _read_json(report_json)
            except Exception as e:
                data = {}
        elif summary_json.exists():
            try:
                data = _read_json(summary_json)
            except Exception as e:
                data = {}
        else:
            data = {}

        app.latest_static_result = data

        combined = app.latest_combined_score if isinstance(app.latest_combined_score, dict) else {}
        subs = combined.get("subscores", {}) if isinstance(combined.get("subscores"), dict) else {}
        present = combined.get("present", {}) if isinstance(combined.get("present"), dict) else {}

        score = data.get("score")
        if score in (None, "", "-") and present.get("static"):
            score = subs.get("static", "-")
        if score in (None, ""):
            score = "-"

        verdict = data.get("verdict", "-")
        confidence = data.get("confidence", "-")

        app.score_var.set(str(score))
        app.verdict_var.set(str(verdict))
        app.confidence_var.set(str(confidence))

        vt = data.get("virustotal") if isinstance(data.get("virustotal"), dict) else {}

        vt_raw = {}
        if vt_raw_path.exists():
            try:
                vt_raw = _read_json(vt_raw_path)
            except Exception as e:
                vt_raw = {}

        vt_display = vt_raw or vt

        if not vt_display:
            if app.vt_api_key_var.get().strip():
                app.vt_status_var.set("VirusTotal: no result available")
            else:
                app.vt_status_var.set("VirusTotal: disabled")

            app.vt_name_var.set("VT Name: -")
            app.vt_counts_var.set("Counts: mal=0 | susp=0 | harmless=0 | undetected=0")
            app.vt_link = ""
            if getattr(app, "vt_open_btn", None) is not None:
                app.vt_open_btn.configure(state="disabled")
            return

        if isinstance(vt_display.get("last_analysis_stats"), dict):
            stats = vt_display.get("last_analysis_stats", {}) or {}
            mal = int(stats.get("malicious", 0) or 0)
            susp = int(stats.get("suspicious", 0) or 0)
            harmless = int(stats.get("harmless", 0) or 0)
            undetected = int(stats.get("undetected", 0) or 0)
            name = str(vt_display.get("meaningful_name", "") or vt_display.get("file_name", "") or "-")
            link = str(vt_display.get("permalink", "") or "")
            found = bool(vt_display.get("found", False))
        else:
            mal = int(vt_display.get("malicious", 0) or 0)
            susp = int(vt_display.get("suspicious", 0) or 0)
            harmless = int(vt_display.get("harmless", 0) or 0)
            undetected = int(vt_display.get("undetected", 0) or 0)
            name = str(
                vt_display.get("meaningful_name", "")
                or vt_display.get("file_name", "")
                or vt_display.get("name", "")
                or "-"
            )
            link = str(vt_display.get("permalink", "") or "")
            found = bool(vt_display.get("found", False) or link or name != "-")

        status = "VirusTotal: report found" if found else "VirusTotal: no report available"

        app.vt_status_var.set(status)
        app.vt_name_var.set(f"VT Name: {name}")
        app.vt_counts_var.set(
            f"Counts: mal={mal} | susp={susp} | harmless={harmless} | undetected={undetected}"
        )
        app.vt_link = link

        if getattr(app, "vt_open_btn", None) is not None:
            app.vt_open_btn.configure(state=("normal" if link else "disabled"))
        