"""Ship RingForge events to Splunk's HTTP Event Collector.

Configured entirely from the environment, matching how TriageConfig resolves
its paths, so no credential is ever written into the repository:

    SPLUNK_HEC_URL         https://splunk.lab.local:8088
    SPLUNK_HEC_TOKEN       the HEC token
    SPLUNK_HEC_INDEX       malware_analysis
    SPLUNK_HEC_SOURCETYPE  ringforge:static
    SPLUNK_HEC_SOURCE      ringforge
    SPLUNK_HEC_VERIFY_TLS  true | false
    SPLUNK_HEC_TIMEOUT     seconds

Two design points worth stating, because both are easy to get wrong in a lab.

Nothing here raises into a triage run. A SIEM that is unreachable -- which in
this environment is the *normal* state, since the analysis VM spends most of its
life with its internet-facing adapter disarmed -- must cost the shipping step
and nothing else. Callers get a status dict.

TLS verification defaults to on and has to be turned off explicitly. Lab Splunk
instances almost always present a self-signed certificate, so the temptation is
to default this off and forget it. Leaving it on by default means the person
who disables it knows they did.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

#: HEC rejects a request whose body exceeds its configured maximum (1 MB by
#: default). Batches are split well under that rather than at it, since the
#: limit applies to the encoded body, not the events.
_MAX_BATCH_BYTES = 700_000

#: Retried once each, on the failures that are actually transient. A 400 from
#: HEC means the event or token is wrong and will be wrong again.
_RETRY_STATUS = {500, 502, 503, 504}
_MAX_ATTEMPTS = 3


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


@dataclass
class HecConfig:
    url: str = field(default_factory=lambda: os.getenv("SPLUNK_HEC_URL", "").strip())
    token: str = field(default_factory=lambda: os.getenv("SPLUNK_HEC_TOKEN", "").strip())
    index: str = field(default_factory=lambda: os.getenv("SPLUNK_HEC_INDEX", "malware_analysis").strip())
    sourcetype: str = field(default_factory=lambda: os.getenv("SPLUNK_HEC_SOURCETYPE", "ringforge:static").strip())
    source: str = field(default_factory=lambda: os.getenv("SPLUNK_HEC_SOURCE", "ringforge").strip())
    verify_tls: bool = field(default_factory=lambda: _env_bool("SPLUNK_HEC_VERIFY_TLS", True))
    timeout: int = field(default_factory=lambda: int(os.getenv("SPLUNK_HEC_TIMEOUT", "30") or 30))

    @property
    def endpoint(self) -> str:
        return self.url.rstrip("/") + "/services/collector/event"


def hec_status(config: Optional[HecConfig] = None) -> dict[str, Any]:
    """Preflight summary describing whether events can be shipped."""
    cfg = config or HecConfig()

    if requests is None:
        available, note = False, "requests is not installed (pip install -r requirements.txt)."
    elif not cfg.url:
        available, note = False, "SPLUNK_HEC_URL is not set; nothing will be shipped."
    elif not cfg.token:
        available, note = False, "SPLUNK_HEC_TOKEN is not set; nothing will be shipped."
    else:
        available, note = True, f"Ready to ship to {cfg.endpoint} (index={cfg.index})."

    return {
        "available": available,
        "endpoint": cfg.endpoint if cfg.url else "",
        "index": cfg.index,
        "sourcetype": cfg.sourcetype,
        "verify_tls": cfg.verify_tls,
        "note": note,
    }


def _envelope(record: dict[str, Any], cfg: HecConfig, host: str) -> dict[str, Any]:
    """Wrap one event in the HEC envelope."""
    payload: dict[str, Any] = {
        "event": record.get("event", record),
        "index": cfg.index,
        "sourcetype": cfg.sourcetype,
        "source": cfg.source,
    }
    if host:
        payload["host"] = host
    # Only set an explicit time when the caller supplied one. Omitting it lets
    # HEC stamp arrival time, which is the right fallback -- an event with a
    # bad parsed timestamp is far worse than one stamped slightly late.
    if record.get("time"):
        payload["time"] = record["time"]
    return payload


def _batches(payloads: list[str]) -> Iterable[str]:
    """Group encoded events into bodies under the size limit."""
    current: list[str] = []
    size = 0
    for payload in payloads:
        encoded_size = len(payload.encode("utf-8"))
        # A single oversized event still goes on its own rather than being
        # dropped silently; HEC will reject it and the error will say so.
        if current and size + encoded_size > _MAX_BATCH_BYTES:
            yield "".join(current)
            current, size = [], 0
        current.append(payload)
        size += encoded_size
    if current:
        yield "".join(current)


def send_events(
    records: list[dict[str, Any]],
    config: Optional[HecConfig] = None,
    host: str = "",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Ship events to HEC. Never raises."""
    cfg = config or HecConfig()
    result: dict[str, Any] = {
        "shipped": False,
        "event_count": len(records),
        "batches": 0,
        "endpoint": cfg.endpoint if cfg.url else "",
        "index": cfg.index,
        "dry_run": bool(dry_run),
        "error": "",
    }

    if not records:
        result["shipped"] = True
        return result

    # HEC bodies are concatenated JSON objects, not a JSON array.
    payloads = [json.dumps(_envelope(r, cfg, host), separators=(",", ":")) for r in records]

    if dry_run:
        result["shipped"] = True
        result["batches"] = sum(1 for _ in _batches(payloads))
        result["preview"] = payloads[0][:2000] if payloads else ""
        return result

    status = hec_status(cfg)
    if not status["available"]:
        result["error"] = status["note"]
        return result

    headers = {
        "Authorization": f"Splunk {cfg.token}",
        "Content-Type": "application/json",
    }

    for body in _batches(payloads):
        result["batches"] += 1
        last_error = ""

        for attempt in range(1, _MAX_ATTEMPTS + 1):
            try:
                response = requests.post(
                    cfg.endpoint,
                    data=body.encode("utf-8"),
                    headers=headers,
                    timeout=cfg.timeout,
                    verify=cfg.verify_tls,
                )
            except Exception as error:
                last_error = f"{type(error).__name__}: {error}"
                if attempt < _MAX_ATTEMPTS:
                    time.sleep(2 ** attempt)
                    continue
                result["error"] = last_error
                return result

            if response.status_code == 200:
                last_error = ""
                break

            last_error = f"HTTP {response.status_code}: {response.text[:300]}"
            if response.status_code in _RETRY_STATUS and attempt < _MAX_ATTEMPTS:
                time.sleep(2 ** attempt)
                continue
            break

        if last_error:
            result["error"] = last_error
            return result

    result["shipped"] = True
    return result
