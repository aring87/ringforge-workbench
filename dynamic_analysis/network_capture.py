"""Full packet capture for dynamic analysis runs.

Procmon reports that a connection happened; it does not report what crossed the
wire. A pcap adds DNS answers, HTTP hosts and URIs, TLS SNI and JA3-able
handshakes, which is usually where C2 attribution actually comes from.

Two backends are supported:

``dumpcap``
    Ships with Wireshark and writes standard pcapng. Preferred.
``pktmon``
    Built into Windows 10 1809+, so it needs no install, but records to ETL and
    has to be converted afterwards. Used only as a fallback.

The pcap is the artifact that matters, so parsing is strictly best-effort: if
``tshark`` is missing the capture is still written and kept for manual review.
Both backends need Administrator rights.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
from pathlib import Path
from typing import Any, Optional

#: Ports that are ordinary for outbound traffic; anything else is worth a look.
COMMON_PORTS = {80, 443, 53, 123, 8080, 8443, 445, 139, 22, 21, 25, 587, 993, 995}

#: A capture records the whole host, not just the sample. Windows generates a
#: steady stream of certificate-revocation, telemetry, update and connectivity
#: traffic on its own, and reporting it as though the sample caused it produces
#: pure false positives. These suffixes mark that background, which is
#: classified separately rather than discarded -- C2 does sometimes hide behind
#: a CDN, so an analyst must still be able to see it.
BASELINE_DOMAIN_SUFFIXES = (
    "microsoft.com", "microsoftonline.com", "windows.com", "windowsupdate.com",
    "msftconnecttest.com", "msftncsi.com", "windows.net", "azure.com",
    "azureedge.net", "office.com", "office365.com", "live.com", "msn.com",
    "bing.com", "skype.com", "digicert.com", "verisign.com", "entrust.net",
    "sectigo.com", "usertrust.com", "globalsign.com", "letsencrypt.org",
    "godaddy.com", "ntp.org", "root-servers.net", "akamaitechnologies.com",
    "akamaiedge.net", "edgesuite.net", "edgekey.net",
)

#: Local service discovery: mDNS/Bonjour, reverse lookups, WPAD, and bare
#: single-label hostnames such as the VM's own computer name. Distinct from the
#: Windows suffixes above -- these are the host's LAN talking to itself through
#: the host-only adapter, not Windows phoning home.
LOCAL_DISCOVERY_MARKERS = (".local", ".arpa", ".home", ".lan", "wpad", "isatap")

#: Retained name for anything importing it; the classification split into
#: LOCAL_DISCOVERY_MARKERS and BASELINE_DOMAIN_SUFFIXES.
BASELINE_DOMAIN_MARKERS = LOCAL_DISCOVERY_MARKERS

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class NetworkCaptureError(Exception):
    pass


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

def _tools_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "tools"


def _find_tool(name: str, configured: str | Path | None = None) -> Optional[Path]:
    """Find a Wireshark-family binary in tools/, the default install, or PATH."""
    if configured:
        candidate = Path(configured)
        if candidate.exists():
            return candidate

    local = _tools_dir() / name
    if local.exists():
        return local

    for base in (
        Path(r"C:\Program Files\Wireshark"),
        Path(r"C:\Program Files (x86)\Wireshark"),
    ):
        candidate = base / name
        if candidate.exists():
            return candidate

    found = shutil.which(name)
    return Path(found) if found else None


def find_dumpcap(configured: str | Path | None = None) -> Optional[Path]:
    return _find_tool("dumpcap.exe", configured)


def find_tshark(configured: str | Path | None = None) -> Optional[Path]:
    return _find_tool("tshark.exe", configured)


def pktmon_available() -> bool:
    return shutil.which("pktmon.exe") is not None or shutil.which("pktmon") is not None


def list_interfaces(dumpcap_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Enumerate capture interfaces.

    Prefers ``dumpcap -D -M``, whose JSON includes each interface's addresses --
    that is what makes it possible to pick the interface actually carrying
    traffic rather than whichever one happens to be listed first.
    """
    dumpcap = find_dumpcap(dumpcap_path)
    if dumpcap is None:
        return []

    interfaces = _list_interfaces_json(dumpcap)
    if interfaces:
        return interfaces
    return _list_interfaces_text(dumpcap)


def _list_interfaces_json(dumpcap: Path) -> list[dict[str, Any]]:
    try:
        result = subprocess.run(
            [str(dumpcap), "-D", "-M"],
            capture_output=True, text=True, timeout=30, errors="replace",
        )
    except Exception:
        return []

    if result.returncode != 0 or not (result.stdout or "").strip():
        return []

    try:
        raw = json.loads(result.stdout)
    except Exception:
        return []

    interfaces: list[dict[str, Any]] = []
    for position, entry in enumerate(raw, start=1):
        if not isinstance(entry, dict):
            continue
        for name, meta in entry.items():
            meta = meta if isinstance(meta, dict) else {}
            interfaces.append(
                {
                    "index": str(position),
                    "name": name,
                    "description": (
                        meta.get("friendly_name") or meta.get("vendor_description") or ""
                    ),
                    "vendor_description": meta.get("vendor_description") or "",
                    "addrs": [a for a in (meta.get("addrs") or []) if isinstance(a, str)],
                    "loopback": bool(meta.get("loopback")),
                }
            )
    return interfaces


def _list_interfaces_text(dumpcap: Path) -> list[dict[str, Any]]:
    """Fallback for Wireshark builds without ``-M``."""
    try:
        result = subprocess.run(
            [str(dumpcap), "-D"], capture_output=True, text=True, timeout=30, errors="replace"
        )
    except Exception:
        return []

    interfaces: list[dict[str, Any]] = []
    for line in (result.stdout or "").splitlines():
        # Format: "1. \Device\NPF_{GUID} (Ethernet)"
        match = re.match(r"\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?", line.strip())
        if match:
            description = (match.group(3) or "").strip()
            interfaces.append(
                {
                    "index": match.group(1),
                    "name": match.group(2),
                    "description": description,
                    "vendor_description": description,
                    "addrs": [],
                    "loopback": "loopback" in f"{description} {match.group(2)}".lower(),
                }
            )
    return interfaces


def _local_route_ip() -> str:
    """IPv4 address the default route would use.

    ``connect`` on a UDP socket sends nothing; it only asks the OS to resolve
    the outbound route, so this works offline and generates no traffic.
    """
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except Exception:
        return ""
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _is_usable_ipv4(address: str) -> bool:
    if not _IPV4_RE.match(address):
        return False
    # Link-local means the adapter never got a real lease.
    return not address.startswith("169.254.") and not address.startswith("127.")


def select_capture_interfaces(
    dumpcap_path: str | Path | None = None,
    limit: int = 8,
) -> list[str]:
    """Every interface worth capturing on, best candidate first.

    Capturing a single interface is fragile. A properly contained VM has no
    default route at all, so there is nothing to anchor the choice to, and
    picking wrong yields an empty capture that looks exactly like "the sample
    made no connections". dumpcap accepts repeated -i flags, so all plausible
    interfaces are recorded into one pcapng instead.
    """
    interfaces = list_interfaces(dumpcap_path)
    if not interfaces:
        return []

    candidates = [i for i in interfaces if not i.get("loopback")]
    selected: list[str] = []

    def add(name: str) -> None:
        if name and name not in selected and len(selected) < limit:
            selected.append(name)

    # The default-route interface first, when one exists.
    route_ip = _local_route_ip()
    if route_ip:
        for interface in candidates:
            if route_ip in (interface.get("addrs") or []):
                add(interface["name"])

    # Then anything holding a real lease -- this is what catches the host-only
    # adapter on an isolated VM.
    for interface in candidates:
        if any(_is_usable_ipv4(a) for a in (interface.get("addrs") or [])):
            add(interface["name"])

    # Then anything addressed at all.
    for interface in candidates:
        if interface.get("addrs"):
            add(interface["name"])

    return selected


def pick_default_interface(dumpcap_path: str | Path | None = None) -> str:
    """Capture interface carrying the default route.

    Returns the device *name* rather than its index: indexes shift as adapters
    appear and disappear, and picking the wrong one yields a silently empty
    capture, which is the worst possible failure for an analyst.
    """
    interfaces = list_interfaces(dumpcap_path)
    if not interfaces:
        return "1"

    candidates = [i for i in interfaces if not i.get("loopback")]

    # Best signal: the interface holding the default-route source address.
    route_ip = _local_route_ip()
    if route_ip:
        for interface in candidates:
            if route_ip in (interface.get("addrs") or []):
                return interface["name"]

    # Next best: any adapter with a real (non link-local) IPv4 lease.
    for interface in candidates:
        if any(_is_usable_ipv4(a) for a in (interface.get("addrs") or [])):
            return interface["name"]

    # Then: anything with an address at all.
    for interface in candidates:
        if interface.get("addrs"):
            return interface["name"]

    if candidates:
        return candidates[0]["name"]
    return "1"


def default_route_interfaces() -> list[dict[str, str]]:
    """Local addresses that hold an IPv4 default route.

    Parsed from ``route print`` rather than Get-NetIPConfiguration: the CIM
    namespaces that cmdlet depends on are missing on stripped Windows images,
    which are common as analysis VM bases.
    """
    try:
        result = subprocess.run(
            ["route", "print", "-4"],
            capture_output=True, text=True, timeout=30, errors="replace",
        )
    except Exception:
        return []

    routes: list[dict[str, str]] = []
    for line in (result.stdout or "").splitlines():
        parts = line.split()
        # "0.0.0.0  0.0.0.0  <gateway>  <interface ip>  <metric>"
        if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            entry = {"gateway": parts[2], "interface_ip": parts[3], "metric": parts[4]}
            if entry not in routes:
                routes.append(entry)
    return routes


def has_ipv6_default_route() -> bool:
    """True when an IPv6 default route exists, which can also carry traffic out."""
    try:
        result = subprocess.run(
            ["route", "print", "-6"],
            capture_output=True, text=True, timeout=30, errors="replace",
        )
    except Exception:
        return False
    return any("::/0" in line for line in (result.stdout or "").splitlines())


def network_isolation_status(dumpcap_path: str | Path | None = None) -> dict[str, Any]:
    """Report how many ways traffic can leave this machine.

    FakeNet redirects DNS on the adapter it is bound to. When a VM has both a
    host-only and a NAT/bridged adapter, a sample can simply use the other one
    and reach real infrastructure -- which is a containment failure, not just
    noisy data. The failure is silent, so it is checked before every run.
    """
    routes = default_route_interfaces()
    ipv6 = has_ipv6_default_route()
    adapters = list_interfaces(dumpcap_path)

    # Name each egress path by matching its address against the capture list.
    egress: list[dict[str, str]] = []
    for route in routes:
        name = ""
        for adapter in adapters:
            if route["interface_ip"] in (adapter.get("addrs") or []):
                name = adapter.get("description") or adapter.get("name", "")
                break
        egress.append(
            {
                "interface_ip": route["interface_ip"],
                "gateway": route["gateway"],
                "adapter": name,
                "private": "yes" if is_private_ip(route["interface_ip"]) else "no",
            }
        )

    count = len(egress)
    isolated = count == 0 and not ipv6

    if count > 1:
        level = "warning"
        note = (
            f"{count} adapters hold a default route. FakeNet-NG redirects DNS on one "
            "adapter only, so a sample can reach real infrastructure through another. "
            "Disable all but one adapter before detonating live malware."
        )
    elif count == 1 and ipv6:
        level = "warning"
        note = (
            "One IPv4 default route plus an IPv6 default route. IPv6 traffic can "
            "bypass the IPv4 redirect; disable IPv6 on the adapter before detonating."
        )
    elif count == 1:
        level = "ok"
        note = f"Single egress path via {egress[0]['adapter'] or egress[0]['interface_ip']}."
    elif isolated:
        level = "ok"
        note = "No default route: this machine is fully isolated."
    else:
        level = "warning"
        note = "No IPv4 default route, but an IPv6 default route exists."

    return {
        "level": level,
        "isolated": isolated,
        "egress_count": count,
        "egress": egress,
        "ipv6_default_route": ipv6,
        "note": note,
    }


def capture_status(dumpcap_path: str | Path | None = None) -> dict[str, Any]:
    """Preflight summary describing whether packet capture can run."""
    dumpcap = find_dumpcap(dumpcap_path)
    tshark = find_tshark()
    pktmon = pktmon_available()

    if dumpcap is not None:
        backend, available = "dumpcap", True
        note = "dumpcap found; captures will be written as pcapng."
    elif pktmon:
        backend, available = "pktmon", True
        note = (
            "Wireshark/dumpcap not found. Falling back to the built-in pktmon, "
            "which needs an extra ETL to pcap conversion step."
        )
    else:
        backend, available = "", False
        note = (
            "No capture backend found. Install Wireshark (provides dumpcap and "
            "tshark) in the analysis VM to record network traffic."
        )

    return {
        "available": available,
        "backend": backend,
        "dumpcap_path": str(dumpcap) if dumpcap else "",
        "tshark_path": str(tshark) if tshark else "",
        "tshark_available": tshark is not None,
        "pktmon_available": pktmon,
        "note": note,
        "parse_note": (
            "" if tshark is not None
            else "tshark not found; the pcap is saved but will not be parsed automatically."
        ),
    }


# ---------------------------------------------------------------------------
# Capture lifecycle
# ---------------------------------------------------------------------------

class PacketCapture:
    """Starts a capture on construction-free ``start()`` and stops on ``stop()``.

    Kept as an object because the caller must hold the running process handle
    across the sample detonation.
    """

    def __init__(
        self,
        output_path: str | Path,
        interface: str | None = None,
        dumpcap_path: str | Path | None = None,
        capture_filter: str = "",
    ):
        self.output_path = Path(output_path)
        self.interface = interface or ""
        self.dumpcap_path = dumpcap_path
        self.capture_filter = capture_filter
        self.backend = ""
        self.process: Optional[subprocess.Popen] = None
        self._etl_path: Optional[Path] = None
        self.started = False
        self.error = ""

    # -- start ------------------------------------------------------------

    def start(self) -> dict[str, Any]:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        dumpcap = find_dumpcap(self.dumpcap_path)
        if dumpcap is not None:
            return self._start_dumpcap(dumpcap)
        if pktmon_available():
            return self._start_pktmon()

        self.error = "no capture backend available"
        return {"started": False, "backend": "", "error": self.error}

    def _start_dumpcap(self, dumpcap: Path) -> dict[str, Any]:
        if self.interface:
            interfaces = [str(self.interface)]
        else:
            interfaces = select_capture_interfaces(dumpcap)
            if not interfaces:
                interfaces = [pick_default_interface(dumpcap)]

        cmd = [str(dumpcap)]
        for interface in interfaces:
            cmd.extend(["-i", str(interface)])
        cmd.extend(["-w", str(self.output_path), "-q"])
        if self.capture_filter:
            cmd.extend(["-f", self.capture_filter])

        try:
            # A new process group lets us send CTRL+BREAK, which makes dumpcap
            # finalise the capture file instead of being killed mid-write.
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
        except Exception as error:
            self.error = f"failed to start dumpcap: {error}"
            return {"started": False, "backend": "dumpcap", "error": self.error}

        self.backend = "dumpcap"
        self.started = True
        return {
            "started": True,
            "backend": "dumpcap",
            "interface": ", ".join(interfaces),
            "interface_count": len(interfaces),
            "error": "",
        }

    def _start_pktmon(self) -> dict[str, Any]:
        self._etl_path = self.output_path.with_suffix(".etl")
        if self._etl_path.exists():
            self._etl_path.unlink()

        try:
            result = subprocess.run(
                [
                    "pktmon", "start", "--capture",
                    "--pkt-size", "0",
                    "-f", str(self._etl_path),
                ],
                capture_output=True, text=True, timeout=60, errors="replace",
            )
        except Exception as error:
            self.error = f"failed to start pktmon: {error}"
            return {"started": False, "backend": "pktmon", "error": self.error}

        if result.returncode != 0:
            self.error = (result.stderr or result.stdout or "").strip()
            return {"started": False, "backend": "pktmon", "error": self.error}

        self.backend = "pktmon"
        self.started = True
        return {"started": True, "backend": "pktmon", "error": ""}

    # -- stop -------------------------------------------------------------

    def stop(self, timeout: int = 30) -> dict[str, Any]:
        if not self.started:
            return {"stopped": False, "backend": self.backend, "error": "capture was not started"}

        if self.backend == "dumpcap":
            return self._stop_dumpcap(timeout)
        return self._stop_pktmon(timeout)

    def _stop_dumpcap(self, timeout: int) -> dict[str, Any]:
        if self.process is None:
            return {"stopped": False, "backend": "dumpcap", "error": "no process handle"}

        error = ""
        try:
            # CTRL+BREAK first so the pcapng gets a clean trailer.
            if hasattr(signal, "CTRL_BREAK_EVENT"):
                os.kill(self.process.pid, signal.CTRL_BREAK_EVENT)
            else:
                self.process.terminate()
            self.process.wait(timeout=timeout)
        except Exception:
            try:
                self.process.terminate()
                self.process.wait(timeout=10)
            except Exception as inner:
                error = f"failed to stop dumpcap cleanly: {inner}"

        exists = self.output_path.exists()
        return {
            "stopped": True,
            "backend": "dumpcap",
            "error": error,
            "pcap_path": str(self.output_path),
            "pcap_exists": exists,
            "pcap_bytes": self.output_path.stat().st_size if exists else 0,
        }

    def _stop_pktmon(self, timeout: int) -> dict[str, Any]:
        error = ""
        try:
            subprocess.run(
                ["pktmon", "stop"], capture_output=True, text=True, timeout=timeout, errors="replace"
            )
        except Exception as inner:
            error = f"failed to stop pktmon: {inner}"

        # Convert ETL to pcapng so downstream parsing is backend-independent.
        if self._etl_path and self._etl_path.exists():
            try:
                subprocess.run(
                    [
                        "pktmon", "etl2pcap", str(self._etl_path),
                        "-o", str(self.output_path),
                    ],
                    capture_output=True, text=True, timeout=300, errors="replace",
                )
            except Exception as inner:
                error = error or f"failed to convert pktmon ETL: {inner}"

        exists = self.output_path.exists()
        return {
            "stopped": True,
            "backend": "pktmon",
            "error": error,
            "pcap_path": str(self.output_path),
            "etl_path": str(self._etl_path) if self._etl_path else "",
            "pcap_exists": exists,
            "pcap_bytes": self.output_path.stat().st_size if exists else 0,
        }


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _tshark_fields(
    tshark: Path,
    pcap: Path,
    display_filter: str,
    fields: list[str],
    timeout: int = 300,
) -> list[list[str]]:
    cmd = [str(tshark), "-r", str(pcap), "-T", "fields"]
    if display_filter:
        cmd.extend(["-Y", display_filter])
    for field in fields:
        cmd.extend(["-e", field])
    cmd.extend(["-E", "separator=\t", "-E", "occurrence=f"])

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace"
        )
    except Exception:
        return []

    if result.returncode != 0:
        return []

    rows: list[list[str]] = []
    for line in (result.stdout or "").splitlines():
        if not line.strip():
            continue
        rows.append(line.split("\t"))
    return rows


def parse_pcap(pcap_path: str | Path, tshark_path: str | Path | None = None) -> dict[str, Any]:
    """Extract DNS, TLS SNI, HTTP and outbound connections from a capture."""
    pcap = Path(pcap_path)
    summary: dict[str, Any] = {
        "parsed": False,
        "note": "",
        "dns_queries": [],
        "tls_sni": [],
        "http_requests": [],
        "connections": [],
        "unique_destinations": [],
        "unusual_ports": [],
        "counts": {},
    }

    if not pcap.exists():
        summary["note"] = "capture file not found"
        return summary

    tshark = find_tshark(tshark_path)
    if tshark is None:
        summary["note"] = (
            "tshark not found; pcap saved for manual analysis but not parsed."
        )
        return summary

    # DNS questions.
    dns: list[str] = []
    for row in _tshark_fields(tshark, pcap, "dns.flags.response == 0", ["dns.qry.name"]):
        name = row[0].strip() if row else ""
        if name and name not in dns:
            dns.append(name)

    # TLS SNI from ClientHello.
    sni: list[str] = []
    for row in _tshark_fields(
        tshark, pcap, "tls.handshake.type == 1", ["tls.handshake.extensions_server_name"]
    ):
        name = row[0].strip() if row else ""
        if name and name not in sni:
            sni.append(name)

    # Plaintext HTTP requests.
    http: list[dict[str, str]] = []
    for row in _tshark_fields(
        tshark, pcap, "http.request",
        ["http.request.method", "http.host", "http.request.uri"],
    ):
        row += [""] * (3 - len(row))
        entry = {"method": row[0].strip(), "host": row[1].strip(), "uri": row[2].strip()}
        if entry["host"] and entry not in http:
            http.append(entry)

    # Outbound TCP connection attempts (SYN without ACK).
    connections: list[dict[str, str]] = []
    destinations: list[str] = []
    unusual: list[dict[str, str]] = []
    for row in _tshark_fields(
        tshark, pcap, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        ["ip.dst", "tcp.dstport"],
    ):
        row += [""] * (2 - len(row))
        dst, port = row[0].strip(), row[1].strip()
        if not dst:
            continue
        entry = {"dst": dst, "port": port}
        if entry not in connections:
            connections.append(entry)
        if dst not in destinations:
            destinations.append(dst)
        try:
            if int(port) not in COMMON_PORTS and entry not in unusual:
                unusual.append(entry)
        except ValueError:
            pass

    summary.update(
        {
            "parsed": True,
            "dns_queries": dns[:300],
            "tls_sni": sni[:300],
            "http_requests": http[:300],
            "connections": connections[:300],
            "unique_destinations": destinations[:300],
            "unusual_ports": unusual[:100],
            "counts": {
                "dns_queries": len(dns),
                "tls_sni": len(sni),
                "http_requests": len(http),
                "connections": len(connections),
                "unique_destinations": len(destinations),
                "unusual_ports": len(unusual),
            },
        }
    )
    return summary


def is_local_discovery_domain(name: str) -> bool:
    """True for local service discovery: mDNS, LLMNR, NetBIOS, WPAD.

    Kept apart from Windows baseline traffic because they are not the same
    thing and the difference is visible to anyone reading the report. Names like
    ``_googlecast._tcp.local`` and ``_spotify-connect._tcp.local`` are other
    devices on the *host's* LAN announcing themselves, arriving through the
    host-only adapter -- nothing to do with Windows, and nothing to do with the
    sample. Filing them under "Windows Baseline Traffic" suppressed them for the
    right reason under the wrong name.
    """
    value = (name or "").strip().lower().rstrip(".")
    if not value:
        return False

    if any(marker in value for marker in LOCAL_DISCOVERY_MARKERS):
        return True

    # A bare single-label name is a NetBIOS/LLMNR style local lookup.
    return "." not in value


def is_windows_baseline_domain(name: str) -> bool:
    """True for the Microsoft, CDN and certificate-authority traffic Windows
    generates on its own."""
    value = (name or "").strip().lower().rstrip(".")
    if not value:
        return False

    return any(
        value == suffix or value.endswith("." + suffix)
        for suffix in BASELINE_DOMAIN_SUFFIXES
    )


def is_baseline_domain(name: str) -> bool:
    """True when a name is not attributable to the sample, of either kind.

    Baseline does not mean safe -- it means "this host would have requested it
    with no sample running", so it must not be presented as a finding.
    """
    return is_local_discovery_domain(name) or is_windows_baseline_domain(name)


def classify_domain(name: str) -> str:
    """Bucket a domain exactly once, so nothing is counted twice."""
    if is_local_discovery_domain(name):
        return "local_discovery"
    if is_windows_baseline_domain(name):
        return "windows_baseline"
    return "notable"


def _parse_ip(address: str) -> ipaddress._BaseAddress | None:
    """Parse an address, tolerating a zone index. Returns None if it is not one."""
    value = (address or "").strip()
    if not value:
        return None
    # fe80::1%12 -- Windows appends the interface index to link-local v6.
    value = value.split("%", 1)[0]
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_private_ip(address: str) -> bool:
    """True for RFC1918, loopback and link-local addresses.

    Backed by the stdlib rather than octet arithmetic so that IPv6 is covered
    too. The hand-rolled version matched an IPv4 regex first, so every IPv6
    address fell through as though it were routable.
    """
    parsed = _parse_ip(address)
    if parsed is None:
        return False
    return bool(parsed.is_private or parsed.is_loopback or parsed.is_link_local)


def is_non_routable_ip(address: str) -> bool:
    """True for addresses that can never be a remote destination.

    Multicast, broadcast, unspecified and reserved space. SSDP discovery to
    239.255.255.250 is the case this exists for: it was being reported as a
    contacted external IP *and* as a notable URL. On a real sample that is not
    merely noise in the score, it is a lead an analyst can spend time chasing.
    """
    parsed = _parse_ip(address)
    if parsed is None:
        return False
    if parsed.is_multicast or parsed.is_unspecified or parsed.is_reserved:
        return True
    return isinstance(parsed, ipaddress.IPv4Address) and int(parsed) == 0xFFFFFFFF


def _url_host(url: str) -> str:
    """The bare host of a URL, without scheme, path or port."""
    return (url or "").split("//", 1)[-1].split("/", 1)[0].split(":")[0]


def extract_network_iocs(summary: dict[str, Any]) -> dict[str, list[str]]:
    """Collapse a parsed capture into deduplicated domain and IP indicators."""
    domains: list[str] = []
    ips: list[str] = []
    urls: list[str] = []

    for name in list(summary.get("dns_queries", [])) + list(summary.get("tls_sni", [])):
        name = (name or "").strip().rstrip(".")
        if not name:
            continue
        if _IPV4_RE.match(name):
            if name not in ips:
                ips.append(name)
        elif name not in domains:
            domains.append(name)

    for entry in summary.get("http_requests", []):
        host = (entry.get("host") or "").strip()
        if host:
            bare = host.split(":")[0]
            if _IPV4_RE.match(bare):
                if bare not in ips:
                    ips.append(bare)
            elif bare not in domains:
                domains.append(bare)
        uri = (entry.get("uri") or "").strip()
        if host and uri:
            url = f"http://{host}{uri}"
            if url not in urls:
                urls.append(url)

    for entry in summary.get("connections", []):
        dst = (entry.get("dst") or "").strip()
        if dst and dst not in ips:
            ips.append(dst)

    # Split host background traffic from anything the sample plausibly caused.
    # Both are kept: the analyst decides, but only one is presented as a lead.
    # Classified once each, so a name cannot land in two buckets and be counted
    # twice.
    notable_domains: list[str] = []
    baseline_domains: list[str] = []
    local_discovery_domains: list[str] = []
    for domain in domains:
        bucket = classify_domain(domain)
        if bucket == "local_discovery":
            local_discovery_domains.append(domain)
        elif bucket == "windows_baseline":
            baseline_domains.append(domain)
        else:
            notable_domains.append(domain)

    notable_urls = [
        u for u in urls
        if not is_baseline_domain(_url_host(u)) and not is_non_routable_ip(_url_host(u))
    ]

    # Non-routable addresses are separated rather than dropped, the same way
    # baseline domains are: an analyst can still confirm what the guest was
    # doing, but discovery chatter is not offered as a destination the sample
    # contacted.
    non_routable_ips = [ip for ip in ips if is_non_routable_ip(ip)]
    external_ips = [
        ip for ip in ips
        if not is_private_ip(ip) and not is_non_routable_ip(ip)
    ]

    return {
        "domains": domains[:300],
        "ips": ips[:300],
        "urls": urls[:300],
        "notable_domains": notable_domains[:300],
        "baseline_domains": baseline_domains[:300],
        "local_discovery_domains": local_discovery_domains[:300],
        "notable_urls": notable_urls[:300],
        "external_ips": external_ips[:300],
        "non_routable_ips": non_routable_ips[:300],
        "counts": {
            "domains": len(domains),
            "notable_domains": len(notable_domains),
            "baseline_domains": len(baseline_domains),
            "local_discovery_domains": len(local_discovery_domains),
            "ips": len(ips),
            "external_ips": len(external_ips),
            "non_routable_ips": len(non_routable_ips),
            "urls": len(urls),
            "notable_urls": len(notable_urls),
        },
    }
