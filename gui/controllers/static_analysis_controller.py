from __future__ import annotations

import json
import os
import queue
import re
import threading
import time
import subprocess
import signal
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

from static_triage_engine.scoring import combined_score_from_case_dir


class StaticAnalysisController:
    """
    Static-analysis controller with RingForge case-home layout support.

    New preferred layout:

        cases\\<case_name>\\
            case_metadata.json
            static_analysis\\
                summary.json
                iocs.json
                pe_metadata.json
                lief_metadata.json
                report.md
                report.html
                report.pdf
                metadata\\
                    static_run_summary.json
            dynamic_analysis\\
            metadata\\
                static_run_summary.json
                combined_score.json
            combined_score.json

    How this works:

    The CLI already writes to:
        CASE_ROOT_DIR\\<case>

    So for the new layout, the GUI launches the CLI with:
        CASE_ROOT_DIR = cases\\<case_name>
        case          = static_analysis

    That makes the static engine write to:
        cases\\<case_name>\\static_analysis

    The controller still keeps the case home as:
        cases\\<case_name>

    This lets dynamic analysis later write to:
        cases\\<case_name>\\dynamic_analysis
    """

    def __init__(self, app):
        self.app = app
        self.cancel_event = threading.Event()

    # ---------------------------------------------------------------------
    # Folder layout helpers
    # ---------------------------------------------------------------------

    @staticmethod
    def _safe_case_name(value: str) -> str:
        value = (value or "static_case").strip()
        value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
        value = value.strip("._-")
        return value or "static_case"

    def _case_layout(self, case_root: Path, case: str) -> tuple[Path, Path]:
        """
        Returns:
            case_home_dir, static_output_dir
        """
        safe_case = self._safe_case_name(case)
        case_home_dir = Path(case_root) / safe_case
        static_output_dir = case_home_dir / "static_analysis"
        return case_home_dir, static_output_dir

    def _normalize_case_home(self, path: Path) -> Path:
        """
        If a module folder is provided, return its parent case home.
        """
        if path.name in {
            "static_analysis",
            "dynamic_analysis",
            "spec_analysis",
            "api_analysis",
            "extension_analysis",
        }:
            return path.parent
        return path

    def _static_output_from_home_or_detected(self, path: Path) -> Path:
        """
        If a detected path is already the static_analysis folder, return it.
        If it is the case home, return case_home/static_analysis.
        """
        if path.name == "static_analysis":
            return path
        return path / "static_analysis"

    def _ensure_case_layout(self, case_home_dir: Path, static_output_dir: Path, sample: Path):
        case_home_dir.mkdir(parents=True, exist_ok=True)
        static_output_dir.mkdir(parents=True, exist_ok=True)

        # Create module folders so the case home looks organized immediately.
        (case_home_dir / "static_analysis").mkdir(parents=True, exist_ok=True)
        (case_home_dir / "dynamic_analysis").mkdir(parents=True, exist_ok=True)
        (case_home_dir / "metadata").mkdir(parents=True, exist_ok=True)
        (static_output_dir / "metadata").mkdir(parents=True, exist_ok=True)

        metadata = {
            "case_name": case_home_dir.name,
            "case_home": str(case_home_dir),
            "static_analysis_dir": str(static_output_dir),
            "dynamic_analysis_dir": str(case_home_dir / "dynamic_analysis"),
            "sample_path": str(sample),
            "sample_name": sample.name,
            "layout_version": "ringforge-case-layout-1.0",
            "updated_at": datetime.now().isoformat(timespec="seconds"),
        }

        (case_home_dir / "case_metadata.json").write_text(
            json.dumps(metadata, indent=2),
            encoding="utf-8",
        )

    # ---------------------------------------------------------------------
    # Summary save
    # ---------------------------------------------------------------------

    def _save_static_test_summary(self, static_output_dir: Path, case_home_dir: Path | None = None):
        app = self.app

        try:
            static_output_dir = Path(static_output_dir)
            case_home_dir = Path(case_home_dir) if case_home_dir else self._normalize_case_home(static_output_dir)

            static_meta_dir = static_output_dir / "metadata"
            case_meta_dir = case_home_dir / "metadata"
            static_meta_dir.mkdir(parents=True, exist_ok=True)
            case_meta_dir.mkdir(parents=True, exist_ok=True)

            score_value = app.score_var.get().strip()
            verdict_value = app.verdict_var.get().strip()
            confidence_value = app.confidence_var.get().strip()

            payload = {
                "test_name": app.case_var.get().strip() or case_home_dir.name,
                "analysis_type": "static",
                "sample_path": app.sample_var.get().strip(),
                "case_home": str(case_home_dir),
                "static_analysis_dir": str(static_output_dir),
                "completed_at": datetime.now().isoformat(timespec="seconds"),
                "score": score_value if score_value else "-",
                "status": "completed",
                "verdict": verdict_value if verdict_value else "-",
                "confidence": confidence_value if confidence_value else "-",
            }

            # Write in the static module folder.
            (static_meta_dir / "static_run_summary.json").write_text(
                json.dumps(payload, indent=2),
                encoding="utf-8",
            )

            # Compatibility / launcher-friendly copy at the case-home metadata level.
            (case_meta_dir / "static_run_summary.json").write_text(
                json.dumps(payload, indent=2),
                encoding="utf-8",
            )

            launcher = getattr(app, "launcher_frame", None)
            if launcher is not None and hasattr(launcher, "refresh_saved_tests"):
                try:
                    launcher.refresh_saved_tests()
                except Exception:
                    pass

        except Exception as e:
            app.output.insert("end", f"[warn] Could not save static test summary: {e}\n")
            app.output.see("end")

    # ---------------------------------------------------------------------
    # Start/cancel execution
    # ---------------------------------------------------------------------

    def start_analysis(self):
        app = self.app

        if app.worker_thread and app.worker_thread.is_alive():
            return

        try:
            sample, case, case_root, rules, sigs = app._validate_inputs()
        except Exception as e:
            messagebox.showerror("Analysis failed", str(e))
            app._set_static_running_state(False)
            return

        sample = Path(sample)
        case_root = Path(case_root)
        case = self._safe_case_name(case)

        case_home_dir, static_output_dir = self._case_layout(case_root, case)
        self._ensure_case_layout(case_home_dir, static_output_dir, sample)

        if not app.CLI_SCRIPT.exists():
            messagebox.showerror("Missing CLI", f"Could not find CLI script:\n{app.CLI_SCRIPT}")
            app._set_static_running_state(False)
            return

        extract, subfiles, limit, sm = app._effective_settings()
        
        if subfiles and int(limit) >= 15:
            proceed = messagebox.askyesno(
                "Deep Triage Notice",
                (
                    "This analysis may take several minutes.\n\n"
                    f"RingForge is configured to analyze up to {limit} extracted subfiles. "
                    "Large installers can appear idle while each extracted EXE/DLL is processed.\n\n"
                    "The Output window will show [subfile:start] and [subfile:done] progress messages.\n\n"
                    "Continue?"
                ),
            )
            if not proceed:
                app.running_var.set("Idle")
                return

        # Important:
        # We want the CLI to write to cases\\<case>\\static_analysis.
        # The CLI writes CASE_ROOT_DIR\\case, so pass:
        #   CASE_ROOT_DIR = cases\\<case>
        #   case          = static_analysis
        args = build_cli_args(sample, "static_analysis", extract, subfiles, limit, sm)

        vt_api_key = app.vt_api_key_var.get().strip()
        env_overrides = {
            "CASE_ROOT_DIR": str(case_home_dir),
            "CAPA_RULES_DIR": str(rules),
            "CAPA_SIGS_DIR": str(sigs),
            "PYTHONIOENCODING": "utf-8",
        }
        if vt_api_key:
            env_overrides["VT_API_KEY"] = vt_api_key

        py_exe = choose_python_exe()

        app.case_dir_detected = None
        app.static_case_dir_detected = static_output_dir
        app.case_home_dir_detected = case_home_dir

        app.stop_tail.set()
        app.stop_tail.clear()
        self.cancel_event.clear()
        app.active_process = None

        app._reset_progress()
        app._reset_result_summary()
        try:
            old_log = static_output_dir / "analysis.log"
            if old_log.exists():
                old_log.unlink()
        except Exception:
            pass
            
        app.output.delete("1.0", "end")
        app.output.insert("end", "Starting analysis:\n")
        app.output.insert("end", f"  sample={sample}\n")
        app.output.insert("end", f"  case={case}\n")
        app.output.insert("end", f"  case_home={case_home_dir}\n")
        app.output.insert("end", f"  static_output={static_output_dir}\n")
        app.output.insert("end", f"  rules={rules}\n  sigs={sigs}\n\n")
        app.output.see("end")

        self.start_log_tail(static_output_dir)

        app.run_btn.configure(state="disabled")
        if getattr(app, "cancel_btn", None) is not None:
            app.cancel_btn.configure(state="normal")
        app.running_var.set("Running...")

        def worker():
            rc = 1
            try:
                cmd = [str(py_exe)] + [str(x) for x in args]
                env = os.environ.copy()
                env.update(env_overrides)

                creationflags = 0
                if os.name == "nt":
                    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    env=env,
                    creationflags=creationflags,
                )
                app.active_process = proc

                if proc.stdout is not None:
                    for line in iter(proc.stdout.readline, ""):
                        if self.cancel_event.is_set():
                            self._terminate_process(proc)
                            break

                        line_lower = line.lower()

                        # Suppress noisy Authenticode timestamp parser output.
                        # This is usually a non-fatal timestamp parsing warning from a signing
                        # parser, not a static-analysis failure.
                        if "can't parse pkcs9 tstinfo" in line_lower or "pkcs9 tstinfo" in line_lower:
                            app.output_q.put(
                                "[warn] Authenticode timestamp metadata could not be fully parsed; continuing analysis.\n"
                            )
                            continue

                        app.output_q.put(line)

                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._terminate_process(proc)
                    proc.wait(timeout=5)

                rc = proc.returncode if proc.returncode is not None else 1
                was_cancelled = self.cancel_event.is_set()

                if was_cancelled:
                    rc = -1

            except Exception as e:
                app.output_q.put(f"[error] {e}\n")
                rc = 1
            finally:
                app.active_process = None
                if self.cancel_event.is_set():
                    app.output_q.put("\n[cancelled] analysis cancelled by user\n")

                app.output_q.put(f"\n[done] exit_code={rc}\n")
                app.after(0, lambda cancelled=self.cancel_event.is_set(): self.on_done(rc, cancelled))

        app.worker_thread = threading.Thread(target=worker, daemon=True)
        app.worker_thread.start()

    def cancel_analysis(self):
        app = self.app
        self.cancel_event.set()
        app.stop_tail.set()
        app.running_var.set("Cancelling...")

        proc = getattr(app, "active_process", None)
        if proc is not None:
            self._terminate_process(proc)

    def _terminate_process(self, proc):
        try:
            if proc.poll() is not None:
                return

            if os.name == "nt":
                try:
                    subprocess.run(
                        ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10,
                    )
                except Exception:
                    try:
                        proc.terminate()
                    except Exception:
                        pass

                time.sleep(0.5)

                if proc.poll() is None:
                    try:
                        proc.kill()
                    except Exception:
                        pass

            else:
                try:
                    proc.send_signal(signal.SIGTERM)
                except Exception:
                    try:
                        proc.terminate()
                    except Exception:
                        pass

                time.sleep(0.5)

                if proc.poll() is None:
                    try:
                        proc.kill()
                    except Exception:
                        pass

        except Exception:
            pass

    # ---------------------------------------------------------------------
    # Completion handling
    # ---------------------------------------------------------------------

    def on_done(self, rc: int, was_cancelled: bool = False):
        app = self.app

        app.stop_tail.set()
        app.current_log_path = None

        detected = Path(app.case_dir_detected) if getattr(app, "case_dir_detected", None) else None
        configured_static = Path(app.static_case_dir_detected) if getattr(app, "static_case_dir_detected", None) else None
        configured_home = Path(app.case_home_dir_detected) if getattr(app, "case_home_dir_detected", None) else None

        if detected:
            static_output_dir = self._static_output_from_home_or_detected(detected)
            case_home_dir = self._normalize_case_home(static_output_dir)
        elif configured_static:
            static_output_dir = configured_static
            case_home_dir = configured_home or self._normalize_case_home(static_output_dir)
        else:
            case_home_dir = configured_home
            static_output_dir = self._static_output_from_home_or_detected(case_home_dir) if case_home_dir else None

        if rc == 0:
            if static_output_dir:
                report_md = static_output_dir / "report.md"
                report_html = static_output_dir / "report.html"
                report_pdf = static_output_dir / "report.pdf"

                if report_md.exists() or report_html.exists() or report_pdf.exists():
                    app._set_step("report", 100, "done")

                app._update_result_summary_from_case(static_output_dir)
                self._save_static_test_summary(static_output_dir, case_home_dir)

                try:
                    combined_score_from_case_dir(case_home_dir or static_output_dir, write_output=True)
                except Exception as e:
                    app.output.insert("end", f"[warn] Combined score refresh failed: {e}\n")
                    app.output.see("end")

                # After static summary is updated, expose the case home to the rest
                # of the app so dynamic/spec modules use the shared case folder.
                if case_home_dir:
                    app.case_dir_detected = case_home_dir

            app._set_step("finalize", 100, "done")

            for step_key in STEP_DISPLAY_ORDER:
                st_lbl = app.step_widgets.get(step_key, {}).get("status")
                if st_lbl is not None and st_lbl.cget("text") in ("idle", "running"):
                    app._set_step(step_key, 100, "done")

            app._recalc_overall()
            app.overall_var.set(100)
            app.overall_text.configure(text="100%")
        else:
            if static_output_dir:
                app._update_result_summary_from_case(static_output_dir)
            app._recalc_overall()

        app.run_btn.configure(state="normal")
        if getattr(app, "cancel_btn", None) is not None:
            app.cancel_btn.configure(state="disabled")
        app.running_var.set("Idle")

        if rc == 0:
            messagebox.showinfo("Completed", "Analysis completed successfully.")
        elif was_cancelled:
            app.status_var.set("Analysis cancelled.")
            messagebox.showinfo("Cancelled", "Analysis was cancelled.")
        else:
            messagebox.showwarning(
                "Completed",
                f"Analysis finished with exit code {rc}.\nCheck output for details.",
            )

    # ---------------------------------------------------------------------
    # Output/log handling
    # ---------------------------------------------------------------------

    def drain_output(self):
        app = self.app

        try:
            while True:
                line = app.output_q.get_nowait()

                if app.case_dir_detected is None:
                    cd = self.maybe_detect_case_dir_from_stdout(line)
                    if cd is not None:
                        # During the static run, this will normally be:
                        # cases\\<case>\\static_analysis
                        app.case_dir_detected = cd
                        app.static_case_dir_detected = self._static_output_from_home_or_detected(cd)
                        app.case_home_dir_detected = self._normalize_case_home(app.static_case_dir_detected)

                        app.output.insert("end", f"[info] Detected static_output: {app.static_case_dir_detected}\n")
                        app.output.insert("end", f"[info] Detected case_home: {app.case_home_dir_detected}\n")

                        self.start_log_tail(app.static_case_dir_detected)
                        app._update_result_summary_from_case(app.static_case_dir_detected)

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

                if line.startswith("[done]"):
                    target = getattr(app, "static_case_dir_detected", None) or getattr(app, "case_dir_detected", None)
                    if target:
                        app._update_result_summary_from_case(Path(target))

        except queue.Empty:
            pass

        app.after(100, self.drain_output)

    def start_log_tail(self, case_dir: Path):
        app = self.app
        log_path = Path(case_dir) / "analysis.log"

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

                    if "cancelled" in line_lower or "canceled" in line_lower:
                        fail_label = "cancelled"
                    elif (
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
            p = m2.group("p").strip().strip("'").strip('"')
            pp = Path(p)
            if pp.is_dir():
                return pp

        return None
