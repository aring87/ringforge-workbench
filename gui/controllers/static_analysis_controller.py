from __future__ import annotations

import json
import os
import queue
import threading
import time
from datetime import datetime
from pathlib import Path
from tkinter import messagebox

from gui.gui_utils import (
    CASE_DIR_RE,
    CASE_LINE_RE,
    REPORT_STDOUT_MDHTML_RE,
    REPORT_STDOUT_PDF_RE,
    STEP_DISPLAY_ORDER,
    STEP_DONE_RE,
    STEP_FAIL_RE,
    STEP_NAME_MAP,
    STEP_START_RE,
    build_cli_args,
    choose_python_exe,
    run_cli_streaming,
)


class StaticAnalysisController:
    def __init__(self, app):
        self.app = app
        
    def _save_static_test_summary(self, case_dir: Path):
        app = self.app

        try:
            meta_dir = case_dir / "metadata"
            meta_dir.mkdir(parents=True, exist_ok=True)

            score_value = app.score_var.get().strip()
            combined_score_value = app.combined_score_var.get().strip()

            payload = {
                "test_name": app.case_var.get().strip() or case_dir.name,
                "analysis_type": "static",
                "sample_path": app.sample_var.get().strip(),
                "completed_at": datetime.now().isoformat(timespec="seconds"),
                "score": score_value if score_value else "-",
                "static_score": score_value if score_value else "-",
                "combined_score": combined_score_value if combined_score_value else (score_value if score_value else "-"),
                "status": "completed",
                "verdict": app.verdict_var.get().strip() or "-",
                "confidence": app.confidence_var.get().strip() or "-",
                "combined_verdict": app.combined_verdict_var.get().strip() or "-",
                "combined_confidence": app.combined_confidence_var.get().strip() or "-",
                "static_subscore": app.static_subscore_var.get().strip() or "-",
                "dynamic_subscore": app.dynamic_subscore_var.get().strip() or "-",
                "spec_subscore": app.spec_subscore_var.get().strip() or "-",
            }

            summary_path = meta_dir / "static_run_summary.json"
            summary_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            launcher = getattr(app, "launcher_frame", None)
            if launcher is not None and hasattr(launcher, "refresh_saved_tests"):
                try:
                    launcher.refresh_saved_tests()
                except Exception:
                    pass

        except Exception as e:
            app.output.insert("end", f"[warn] Could not save static test summary: {e}\n")
            app.output.see("end")

    def start_analysis(self):
        app = self.app

        if app.worker_thread and app.worker_thread.is_alive():
            return

        try:
            sample, case, case_root, rules, sigs = app._validate_inputs()
        except Exception as e:
            messagebox.showerror("Analysis failed", str(e))
            return

        if not app.CLI_SCRIPT.exists():
            messagebox.showerror("Missing CLI", f"Could not find CLI script:\n{app.CLI_SCRIPT}")
            return

        extract, subfiles, limit, sm = app._effective_settings()
        args = build_cli_args(sample, case, extract, subfiles, limit, sm)

        vt_api_key = app.vt_api_key_var.get().strip()
        env_overrides = {
            "CASE_ROOT_DIR": str(case_root),
            "CAPA_RULES_DIR": str(rules),
            "CAPA_SIGS_DIR": str(sigs),
            "PYTHONIOENCODING": "utf-8",
        }
        if vt_api_key:
            env_overrides["VT_API_KEY"] = vt_api_key

        py_exe = choose_python_exe()

        app.case_dir_detected = None
        app.stop_tail.set()
        app.stop_tail.clear()

        app._reset_progress()
        app._reset_result_summary()
        app.output.delete("1.0", "end")
        app.output.insert("end", "Starting analysis:\n")
        app.output.insert("end", f"  sample={sample}\n  case={case}\n")
        app.output.insert("end", f"  case_root={case_root}\n")
        app.output.insert("end", f"  rules={rules}\n  sigs={sigs}\n\n")
        app.output.see("end")

        self.start_log_tail(case_root / case)

        app.run_btn.configure(state="disabled")
        app.running_var.set("Running...")

        def worker():
            rc = 1
            try:
                rc = run_cli_streaming(py_exe, args, env_overrides, app.output_q)
            except Exception as e:
                app.output_q.put(f"[error] {e}\n")
                rc = 1
            finally:
                app.output_q.put(f"\n[done] exit_code={rc}\n")
                app.after(0, lambda: self.on_done(rc))

        app.worker_thread = threading.Thread(target=worker, daemon=True)
        app.worker_thread.start()

    def on_done(self, rc: int):
        app = self.app

        app.stop_tail.set()
        app.current_log_path = None

        if rc == 0:
            if app.case_dir_detected:
                report_md = app.case_dir_detected / "report.md"
                report_html = app.case_dir_detected / "report.html"
                report_pdf = app.case_dir_detected / "report.pdf"

                if report_md.exists() or report_html.exists() or report_pdf.exists():
                    app._set_step("report", 100, "done")

                app._update_result_summary_from_case(app.case_dir_detected)
                self._save_static_test_summary(app.case_dir_detected)

            app._set_step("finalize", 100, "done")

            for step_key in STEP_DISPLAY_ORDER:
                st_lbl = app.step_widgets.get(step_key, {}).get("status")
                if st_lbl is not None and st_lbl.cget("text") in ("idle", "running"):
                    app._set_step(step_key, 100, "done")

            app._recalc_overall()
            app.overall_var.set(100)
            app.overall_text.configure(text="100%")
        else:
            if app.case_dir_detected:
                app._update_result_summary_from_case(app.case_dir_detected)
            app._recalc_overall()

        app.run_btn.configure(state="normal")
        app.running_var.set("Idle")

        if rc == 0:
            messagebox.showinfo("Completed", "Analysis completed successfully.")
        else:
            messagebox.showwarning("Completed", f"Analysis finished with exit code {rc}.\nCheck output for details.")

    def drain_output(self):
        app = self.app

        try:
            while True:
                line = app.output_q.get_nowait()

                if app.case_dir_detected is None:
                    cd = self.maybe_detect_case_dir_from_stdout(line)
                    if cd is not None:
                        app.case_dir_detected = cd
                        app.output.insert("end", f"[info] Detected case_dir: {cd}\n")
                        self.start_log_tail(cd)
                        app._update_result_summary_from_case(cd)

                if REPORT_STDOUT_MDHTML_RE.search(line):
                    app._set_step("report", 100, "done")
                    app._recalc_overall()

                mpdf = REPORT_STDOUT_PDF_RE.search(line)
                if mpdf:
                    val = (mpdf.group("p") or "").strip()
                    if val.lower() != "none":
                        app._set_step("report", 100, "done")
                        app._recalc_overall()

                app.output.insert("end", line)
                app.output.see("end")

                if line.startswith("[done]") and app.case_dir_detected:
                    app._update_result_summary_from_case(app.case_dir_detected)

        except queue.Empty:
            pass

        app.after(100, self.drain_output)

    def start_log_tail(self, case_dir: Path):
        app = self.app
        log_path = case_dir / "analysis.log"

        if app.current_log_path == log_path and app.log_tail_thread and app.log_tail_thread.is_alive():
            return

        app.stop_tail.set()

        if app.log_tail_thread and app.log_tail_thread.is_alive():
            app.log_tail_thread.join(timeout=1.0)

        app.stop_tail.clear()
        app.current_log_path = log_path

        app.log_tail_thread = threading.Thread(
            target=self.tail_analysis_log,
            args=(log_path,),
            daemon=True,
        )
        app.log_tail_thread.start()

    def tail_analysis_log(self, log_path: Path):
        app = self.app

        deadline = time.time() + 60
        while not log_path.exists() and time.time() < deadline and not app.stop_tail.is_set():
            time.sleep(0.25)

        if not log_path.exists():
            return

        with log_path.open("r", encoding="utf-8", errors="replace") as f:
            while not app.stop_tail.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.25)
                    continue

                line = line.strip()
                if not line:
                    continue

                m = STEP_START_RE.search(line)
                if m:
                    raw = m.group("step")
                    step_key = STEP_NAME_MAP.get(raw, raw)
                    app.after(0, lambda s=step_key: (app._set_step(s, 15, "running"), app._recalc_overall()))
                    continue

                m = STEP_DONE_RE.search(line)
                if m:
                    raw = m.group("step")
                    step_key = STEP_NAME_MAP.get(raw, raw)
                    app.after(0, lambda s=step_key: (app._set_step(s, 100, "done"), app._recalc_overall()))
                    continue

                m = STEP_FAIL_RE.search(line)
                if m:
                    raw = m.group("step")
                    step_key = STEP_NAME_MAP.get(raw, raw)
                    line_lower = line.lower()
                    optional_na_steps = {"extract", "file", "filetype", "strings", "capa"}

                    if (
                        os.name == "nt"
                        and step_key in optional_na_steps
                        and (
                            "winerror 2" in line_lower
                            or "cannot find the file specified" in line_lower
                            or "rc=127" in line_lower
                            or "tool not found" in line_lower
                        )
                    ):
                        fail_label = "n/a"
                    else:
                        fail_label = "failed"

                    app.after(
                        0,
                        lambda s=step_key, lbl=fail_label: (
                            app._set_step(s, 100, lbl),
                            app._recalc_overall(),
                        ),
                    )

    def maybe_detect_case_dir_from_stdout(self, line: str):
        m = CASE_LINE_RE.match(line)
        if m:
            p = m.group("p").strip().strip('"')
            pp = Path(p)
            if pp.is_dir():
                return pp

        m2 = CASE_DIR_RE.search(line)
        if m2:
            p = m2.group("p").strip().strip('"').strip("'")
            pp = Path(p)
            if pp.is_dir():
                return pp

        return None