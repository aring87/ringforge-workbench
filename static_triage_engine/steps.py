from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any
from .yara_scan import run_yara_scan, save_yara_results

from .config import TriageConfig

try:
    from tqdm import tqdm  # type: ignore
except Exception:
    tqdm = None  # type: ignore

from scripts.ioc_extract import build_iocs, write_iocs_json, write_iocs_csv  # type: ignore

try:
    from scripts.pe_meta import extract_pe_metadata, write_pe_metadata  # type: ignore
except Exception:
    extract_pe_metadata = None
    write_pe_metadata = None

try:
    from scripts.lief_meta import extract_lief_metadata, write_lief_metadata  # type: ignore
except Exception:
    extract_lief_metadata = None
    write_lief_metadata = None


def safe_write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", errors="replace")


def sha_hash(path: Path, algo: str, show_progress: bool = True) -> str:
    h = hashlib.new(algo)
    total = path.stat().st_size

    pbar = None
    if show_progress and tqdm is not None:
        pbar = tqdm(total=total, unit="B", unit_scale=True, desc=algo.upper(), leave=True, dynamic_ncols=True)

    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
                if pbar:
                    pbar.update(len(chunk))
        return h.hexdigest()
    finally:
        if pbar:
            pbar.close()


def run_cmd(cmd: list[str], cwd: Path | None = None, timeout: int = 900) -> dict[str, Any]:
    start = time.time()
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return {
            "cmd": cmd,
            "returncode": p.returncode,
            "duration_sec": round(time.time() - start, 3),
            "stdout": p.stdout or "",
            "stderr": p.stderr or "",
        }
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout if isinstance(e.stdout, str) else ""
        stderr = e.stderr if isinstance(e.stderr, str) else ""
        return {
            "cmd": cmd,
            "returncode": -1,
            "duration_sec": round(time.time() - start, 3),
            "stdout": stdout,
            "stderr": (stderr + "\n[!] TIMEOUT").strip(),
        }
    except Exception as e:
        return {
            "cmd": cmd,
            "returncode": -1,
            "duration_sec": round(time.time() - start, 3),
            "stdout": "",
            "stderr": f"[!] EXCEPTION: {e}",
        }

def ensure_capa_paths(cfg: TriageConfig) -> None:
    """Validate capa rules/signatures paths.

    Supports GUI/CLI overrides via environment variables:
      - CAPA_RULES_DIR: may point to either ...\\tools\\capa-rules OR ...\\tools\\capa-rules\\rules
      - CAPA_SIGS_DIR : should point to ...\\tools\\capa\\sigs

    If CAPA_RULES_DIR points to the parent folder (capa-rules), this function will
    automatically append \\rules when present.

    Note: TriageConfig may be a frozen dataclass; we use object.__setattr__.
    """
    import os
    from pathlib import Path

    # --- Env overrides (GUI passes these) ---
    env_rules = os.getenv("CAPA_RULES_DIR")
    env_sigs = os.getenv("CAPA_SIGS_DIR")

    if env_rules:
        p = Path(env_rules).expanduser()
        # accept either ...\\tools\\capa-rules OR ...\\tools\\capa-rules\\rules
        if (p / "rules").is_dir():
            p = p / "rules"
        object.__setattr__(cfg, "capa_rules", p)

    if env_sigs:
        object.__setattr__(cfg, "capa_sigs", Path(env_sigs).expanduser())

    # --- Validate rules directory ---
    if not cfg.capa_rules.exists() or not cfg.capa_rules.is_dir():
        raise FileNotFoundError(f"capa rules directory not found: {cfg.capa_rules}")

    # sanity check: should contain many YAML files
    rule_files = list(cfg.capa_rules.rglob("*.yml")) + list(cfg.capa_rules.rglob("*.yaml"))
    if len(rule_files) < 50:
        raise RuntimeError(f"capa rules directory exists but looks wrong: {cfg.capa_rules}")

    # --- Validate sigs directory ---
    if not cfg.capa_sigs.exists() or not cfg.capa_sigs.is_dir():
        raise FileNotFoundError(f"capa signatures directory not found: {cfg.capa_sigs}")

    sig_files = list(cfg.capa_sigs.glob("*.sig"))
    if len(sig_files) < 1:
        raise RuntimeError(f"capa signatures directory has no *.sig files: {cfg.capa_sigs}")


def step_file(sample: Path, case_dir: Path) -> dict[str, Any]:
    out = case_dir / "file.txt"
    res = run_cmd(["file", str(sample)], cwd=case_dir, timeout=60)
    safe_write(out, res.get("stdout", ""))
    res["output_file"] = str(out)
    return res


def _truncate_lines(path: Path, max_lines: int) -> None:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if len(lines) <= max_lines:
            return
        path.write_text("\n".join(lines[:max_lines]) + "\n\n[...truncated...]\n", encoding="utf-8", errors="replace")
    except Exception:
        pass


def step_strings(sample: Path, case_dir: Path, lite: bool = False) -> dict[str, Any]:
    """
    lite=False: full strings
    lite=True : faster/smaller strings output
    """
    out = case_dir / "strings.txt"
    if lite:
        res = run_cmd(["strings", "-a", "-n", "8", str(sample)], cwd=case_dir, timeout=180)
        safe_write(out, res.get("stdout", ""))
        _truncate_lines(out, max_lines=20000)
    else:
        res = run_cmd(["strings", "-a", "-n", "6", str(sample)], cwd=case_dir, timeout=300)
        safe_write(out, res.get("stdout", ""))
    res["output_file"] = str(out)
    res["lite"] = bool(lite)
    return res
    
def step_capa(sample: Path, case_dir: Path, cfg: TriageConfig) -> dict[str, Any]:
    ensure_capa_paths(cfg)
    capa_json = case_dir / "capa.json"
    capa_txt = case_dir / "capa.txt"

    cmd_json = ["capa", "-r", str(cfg.capa_rules), "-s", str(cfg.capa_sigs), "-j", str(sample)]
    json_res = run_cmd(cmd_json, cwd=case_dir, timeout=1800)

    if json_res.get("returncode") == 0 and (json_res.get("stdout") or "").strip():
        try:
            json.loads(json_res["stdout"])
            safe_write(capa_json, json_res["stdout"])
        except Exception as e:
            json_res["returncode"] = 2
            json_res["stderr"] = (json_res.get("stderr") or "") + f"\n[!] capa JSON parse failed: {e}"
            return {**json_res, "capa_json": str(capa_json), "capa_txt": str(capa_txt)}
    else:
        json_res["returncode"] = 2
        if not (json_res.get("stderr") or "").strip():
            json_res["stderr"] = "[!] capa failed or produced empty stdout in -j mode"
        return {**json_res, "capa_json": str(capa_json), "capa_txt": str(capa_txt)}

    cmd_text = ["capa", "-r", str(cfg.capa_rules), "-s", str(cfg.capa_sigs), str(sample)]
    text_res = run_cmd(cmd_text, cwd=case_dir, timeout=1800)
    if (text_res.get("stdout") or "").strip():
        safe_write(capa_txt, text_res["stdout"])

    return {
        **json_res,
        "capa_json": str(capa_json),
        "capa_txt": str(capa_txt),
        "text_pass": {"returncode": text_res.get("returncode"), "duration_sec": text_res.get("duration_sec")},
    }


def step_yara(sample: Path, case_dir: Path, cfg: TriageConfig) -> dict[str, Any]:
    out = case_dir / "yara_results.json"

    rules_dir = getattr(cfg, "yara_rules_dir", None)
    if not rules_dir:
        rules_dir = Path("tools") / "yara" / "rules"
    else:
        rules_dir = Path(rules_dir)

    try:
        result = run_yara_scan(sample, rules_dir)
        save_yara_results(out, result)

        return {
            "returncode": 0 if not result.get("error") else 2,
            "output_file": str(out),
            "matched": bool(result.get("matched", False)),
            "match_count": int(result.get("match_count", 0) or 0),
            "rule_file_count": int(result.get("rule_file_count", 0) or 0),
            "error": result.get("error"),
        }
    except Exception as e:
        return {
            "returncode": 2,
            "output_file": str(out),
            "stderr": str(e),
        }


def _best_effort_imphash(sample: Path) -> str | None:
    try:
        import pefile  # type: ignore
        pe = pefile.PE(str(sample), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        return pe.get_imphash()
    except Exception:
        return None


def _best_effort_tlsh(sample: Path) -> str | None:
    try:
        import tlsh  # type: ignore
        data = sample.read_bytes()
        h = tlsh.hash(data)
        return h if h and h != "TNULL" else None
    except Exception:
        return None


def _best_effort_ssdeep(sample: Path) -> str | None:
    try:
        import ssdeep  # type: ignore
        return ssdeep.hash_from_file(str(sample))
    except Exception:
        return None


def step_pe_metadata(sample: Path, case_dir: Path) -> dict[str, Any]:
    out = case_dir / "pe_metadata.json"
    if not extract_pe_metadata or not write_pe_metadata:
        return {"returncode": 0, "skipped": True, "reason": "pe_meta.py not available (install pefile + ensure pe_meta.py exists)"}
    try:
        meta = extract_pe_metadata(sample)

        # Upgrade #6: add hashes used for clustering (best-effort)
        imph = _best_effort_imphash(sample)
        if imph:
            meta["imphash"] = imph

        tl = _best_effort_tlsh(sample)
        if tl:
            meta["tlsh"] = tl

        sd = _best_effort_ssdeep(sample)
        if sd:
            meta["ssdeep"] = sd

        write_pe_metadata(out, meta)
        return {"returncode": 0, "skipped": False, "output_file": str(out)}
    except Exception as e:
        return {"returncode": 2, "skipped": False, "stderr": str(e)}


def step_lief_metadata(sample: Path, case_dir: Path) -> dict[str, Any]:
    out = case_dir / "lief_metadata.json"
    if not extract_lief_metadata or not write_lief_metadata:
        return {"returncode": 0, "skipped": True, "reason": "lief_meta.py not available (install lief + ensure lief_meta.py exists)"}
    try:
        meta = extract_lief_metadata(sample)
        write_lief_metadata(out, meta)
        return {"returncode": 0, "skipped": False, "output_file": str(out), "parsed": bool(meta.get("parsed", False))}
    except Exception as e:
        return {"returncode": 2, "skipped": False, "stderr": str(e)}


def _norm_url(u: str) -> str | None:
    from urllib.parse import urlparse
    u = (u or "").strip()
    u = re.sub(r"[\x00-\x1f\x7f]+", "", u)
    u = re.sub(r"[)\]>,\"'\\]+$", "", u)
    if len(u) > 2048:
        return None
    try:
        p = urlparse(u)
        if p.scheme not in {"http", "https"}:
            return None
        if not p.netloc:
            return None
        host = p.netloc.split("@")[-1].split(":")[0].strip(".")
        if not host or "." not in host:
            return None
        return u
    except Exception:
        return None


def _norm_domain(d: str) -> str | None:
    d = (d or "").strip().lower().strip(".")
    if not d or len(d) > 255:
        return None
    # simple sanity: must include a dot and only sane chars
    if "." not in d:
        return None
    if not re.fullmatch(r"[a-z0-9.-]+", d):
        return None
    return d


def _norm_ip(s: str) -> str | None:
    s = (s or "").strip()
    try:
        return str(ipaddress.ip_address(s))
    except Exception:
        return None


def _sanitize_iocs(iocs: dict[str, Any]) -> dict[str, Any]:
    obs = iocs.get("observables") if isinstance(iocs.get("observables"), dict) else {}
    domains = obs.get("domains") if isinstance(obs.get("domains"), list) else []
    urls = obs.get("urls") if isinstance(obs.get("urls"), list) else []
    ips = obs.get("ips") if isinstance(obs.get("ips"), list) else []

    nd = sorted({x for x in (_norm_domain(str(d)) for d in domains) if x})
    nu = sorted({x for x in (_norm_url(str(u)) for u in urls) if x})
    ni = sorted({x for x in (_norm_ip(str(ip)) for ip in ips) if x})

    obs["domains"] = nd
    obs["urls"] = nu
    obs["ips"] = ni
    iocs["observables"] = obs

    # Update stats counts if present
    if isinstance(iocs.get("stats"), dict):
        stats = iocs["stats"].get("counts")
        if isinstance(stats, dict):
            stats["domains"] = len(nd)
            stats["urls"] = len(nu)
            stats["ips"] = len(ni)
            iocs["stats"]["counts"] = stats

    return iocs


def step_iocs(case_dir: Path) -> dict[str, Any]:
    out_json = case_dir / "iocs.json"
    out_csv = case_dir / "iocs.csv"
    strings_path = case_dir / "strings.txt"
    capa_json_path = case_dir / "capa.json"

    if not strings_path.exists():
        return {"returncode": 2, "stderr": "strings.txt missing; cannot extract IOCs"}

    iocs = build_iocs(strings_path, capa_json_path if capa_json_path.exists() else None)
    iocs = _sanitize_iocs(iocs)

    write_iocs_json(out_json, iocs)
    write_iocs_csv(out_csv, iocs)
    counts = {}
    try:
        counts = iocs.get("stats", {}).get("counts", {}) or {}
    except Exception:
        counts = {}
    return {"returncode": 0, "output_files": [str(out_json), str(out_csv)], "counts": counts}
