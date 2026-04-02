from __future__ import annotations

import json
from pathlib import Path


def _read_json(path: Path) -> dict:
    with Path(path).open("r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


class ResultController:
    def __init__(self, app):
        self.app = app

    def _safe_read_json(self, path: Path) -> dict:
        try:
            if path.exists():
                return _read_json(path)
        except Exception:
            pass
        return {}

    def _load_static_result_from_case(self, case_dir: Path) -> dict:
        candidates = [
            case_dir / "report.json",
            case_dir / "summary.json",
            case_dir / "metadata" / "run_summary.json",
        ]

        merged = {}
        for path in candidates:
            data = self._safe_read_json(path)
            if isinstance(data, dict) and data:
                merged.update(data)

        return merged

    def reload_combined_score_from_disk(self):
        return

    def reset_result_summary(self):
        app = self.app

        app.score_var.set("-")
        app.verdict_var.set("-")
        app.confidence_var.set("-")

        app.latest_static_result = {}
        app.latest_dynamic_result = {}
        app.latest_spec_result = {}

        if app.vt_api_key_var.get().strip():
            app.vt_status_var.set("VirusTotal: waiting for result")
        else:
            app.vt_status_var.set("VirusTotal: disabled")

        app.vt_name_var.set("VT Name: -")
        app.vt_counts_var.set("Counts: mal=0 | susp=0 | harmless=0 | undetected=0")
        app.vt_link = ""
        if getattr(app, "vt_open_btn", None) is not None:
            app.vt_open_btn.configure(state="disabled")

    def refresh_combined_score(self, case_dir=None):
        return

    def update_result_summary_from_case(self, case_dir: Path):
        app = self.app
        case_dir = Path(case_dir)

        data = self._load_static_result_from_case(case_dir)
        app.latest_static_result = data

        score = data.get("score")
        if score in (None, ""):
            score = data.get("risk_score")
        if score in (None, ""):
            score = data.get("static_score")
        if score in (None, ""):
            score = data.get("total_score")
        if score in (None, ""):
            scoring = data.get("scoring", {})
            if isinstance(scoring, dict):
                score = scoring.get("score")
                if score in (None, ""):
                    score = scoring.get("risk_score")
                if score in (None, ""):
                    score = scoring.get("static_score")
                if score in (None, ""):
                    score = scoring.get("total_score")
        if score in (None, ""):
            summary = data.get("summary", {})
            if isinstance(summary, dict):
                score = summary.get("score")
                if score in (None, ""):
                    score = summary.get("risk_score")
                if score in (None, ""):
                    score = summary.get("static_score")
                if score in (None, ""):
                    score = summary.get("total_score")
        if score in (None, ""):
            score = "-"

        verdict = data.get("verdict", "-")
        if verdict in (None, ""):
            summary = data.get("summary", {})
            if isinstance(summary, dict):
                verdict = summary.get("verdict", "-")

        confidence = data.get("confidence", "-")
        if confidence in (None, ""):
            summary = data.get("summary", {})
            if isinstance(summary, dict):
                confidence = summary.get("confidence", "-")

        app.score_var.set(str(score))
        app.verdict_var.set(str(verdict))
        app.confidence_var.set(str(confidence))

        vt_raw_path = case_dir / "virustotal.json"
        vt = data.get("virustotal") if isinstance(data.get("virustotal"), dict) else {}

        vt_raw = {}
        if vt_raw_path.exists():
            try:
                vt_raw = _read_json(vt_raw_path)
            except Exception:
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