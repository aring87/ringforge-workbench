"""Generate a FakeNet-NG config that routes port 8545 to this project's handler.

`0bw` phase 1 needs the implant's `eth_call` to reach
`dynamic_analysis/fakenet_custom/etherhiding_rpc.py`. FakeNet's own mechanism
for that is a listener with a `Custom:` response config naming a `TcpDynamic`
module, and **it resolves both of those relative to the directory holding the
main config** -- so the config and the two support files have to end up in one
directory together. That is most of what this script is for.

**It appends text; it does not round-trip the config through a parser.**
`configparser` drops every comment and lowercases option names, and FakeNet's
default config is largely comments explaining containment-relevant switches.
Rewriting it would silently reformat the one file on the bench where a wrong
setting means traffic leaves the guest. Sections are order-independent, so
appending is both safe and complete.

**The alternative that was rejected: blacklisting 8545 in the diverter.** That
would leave the port undiverted, and an undiverted connection follows whatever
address DNS returned -- which is not guaranteed to be local. Routing through a
custom response keeps every packet inside FakeNet's diversion.

    ..\\.venv\\Scripts\\python.exe make_fakenet_config.py --out C:\\fakenet-0bw

Then run the detonation with `fakenet_config_path` pointing at the generated
`fakenet.ini`, and the environment the script prints.
"""

from __future__ import annotations

import argparse
import configparser
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dynamic_analysis.fakenet_runner import find_fakenet  # noqa: E402
from dynamic_analysis.jsonrpc_responder import DEFAULT_PORT  # noqa: E402
from scripts.make_tls_cert import (  # noqa: E402
    BACKUP_SUFFIX,
    LEAF_CERT_NAME,
    CertError,
    ssl_utils_dir,
)

#: The listener section appended to FakeNet's config.
#:
#: `RawListener` rather than `HTTPListener`: the HTTP hook hands the handler an
#: already-parsed request, and phase 1 records raw bytes precisely because phase
#: 2 gets encoded against them. It also captures a client that does not speak
#: HTTP, which a hand-rolled implant may well not.
_SECTION_TEMPLATE = """

; ---------------------------------------------------------------------------
; Added by make_fakenet_config.py for HANDOFF.md entry 0bw, phase 1.
; Routes the EtherHiding JSON-RPC port to this project's recording handler.
; Removing this section returns the bench to stock behaviour.
; ---------------------------------------------------------------------------
[EtherHidingRPC]
Enabled:     True
Port:        {port}
Protocol:    TCP
Listener:    RawListener
UseSSL:      {usessl}
Timeout:     10
Hidden:      False
Custom:      {custom}
"""

_SUPPORT_FILES = ("etherhiding_response.ini", "etherhiding_rpc.py")


def _custom_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "dynamic_analysis" / "fakenet_custom"


def find_default_config(configured: str | Path | None = None) -> Path | None:
    """Locate FakeNet's stock config, which is the base this appends to."""
    if configured:
        candidate = Path(configured)
        return candidate if candidate.exists() else None

    binary = find_fakenet()
    if binary is None:
        return None

    base = Path(binary).resolve().parent
    for relative in ("configs/default.ini", "fakenet/configs/default.ini",
                     "default.ini"):
        candidate = base / relative
        if candidate.exists():
            return candidate
    return None


def fakenet_root_from(base_config: Path) -> Path | None:
    """Find the installation the generated config will actually be served by.

    `--fakenet-config` may point anywhere, so the located binary is tried first
    and the config's own ancestors after it. `ssl_utils_dir` is the test: a
    directory that has one is a FakeNet install, and that is the only property
    being asked about here.
    """
    candidates: list[Path] = []
    binary = find_fakenet()
    if binary:
        candidates.append(Path(binary).resolve().parent)
    here = base_config.resolve().parent
    candidates += [here, here.parent, here.parent.parent]

    for candidate in candidates:
        try:
            ssl_utils_dir(candidate)
        except CertError:
            continue
        return candidate
    return None


def leaf_source(fakenet_root: Path | None) -> tuple[str, str]:
    """Which certificate `RawListener` will actually serve, and how it is known.

    **This used to be asserted rather than checked**, and it printed "cert is
    FakeNet's own" whether or not `make_tls_cert.py` had already swapped the
    leaf. That sentence is read at exactly one moment -- when someone is
    deciding whether a `no_connection` summary means the port was not routed or
    the client refused the certificate -- so a confident wrong answer there
    sends the next hour in the wrong direction. See the 22 Aug entry in
    docs/HANDOFF.md: four defects that day each looked like a rejected answer.

    Returns `("ringforge" | "fakenet" | "unknown", detail)`. `unknown` is a
    real answer and is printed as one; guessing is what this replaces.
    """
    if fakenet_root is None:
        return "unknown", "no FakeNet install found from the config's location"
    try:
        target = ssl_utils_dir(fakenet_root)
    except CertError as error:
        return "unknown", str(error)

    leaf = target / LEAF_CERT_NAME
    backup = target / (LEAF_CERT_NAME + BACKUP_SUFFIX)
    if not leaf.is_file():
        return "unknown", f"{leaf} does not exist"
    if not backup.is_file():
        return "fakenet", f"no {BACKUP_SUFFIX} backup beside {LEAF_CERT_NAME}"
    if leaf.read_bytes() == backup.read_bytes():
        # `restore` removes the backup; a hand-copy does not. The marker then
        # says swapped and the bytes say otherwise, and the bytes are what
        # FakeNet serves.
        return "fakenet", (f"{LEAF_CERT_NAME} is byte-identical to its backup, "
                           f"so the swap has been undone by hand")
    return "ringforge", f"{LEAF_CERT_NAME}{BACKUP_SUFFIX} holds FakeNet's original"


def inspect(config_text: str, port: int = DEFAULT_PORT) -> dict[str, object]:
    """Read the base config for the three things that would defeat this.

    Reported rather than corrected. A generator that quietly edits containment
    settings is exactly the kind of tool that makes a run unexplainable later.
    """
    parser = configparser.ConfigParser(strict=False)
    findings: dict[str, object] = {
        "redirect_all_traffic": "",
        "port_blacklisted": False,
        "port_already_used_by": "",
        "readable": True,
    }
    try:
        parser.read_string(config_text)
    except Exception:
        findings["readable"] = False
        return findings

    for section in parser.sections():
        if section.strip().lower() == "diverter":
            findings["redirect_all_traffic"] = parser.get(
                section, "RedirectAllTraffic", fallback="").strip()
            blacklist = parser.get(section, "BlackListPortsTCP", fallback="")
            ports = {p.strip() for p in blacklist.split(",") if p.strip()}
            findings["port_blacklisted"] = str(port) in ports
        elif parser.get(section, "Port", fallback="").strip() == str(port):
            if parser.get(section, "Protocol", fallback="TCP").strip().upper() == "TCP":
                findings["port_already_used_by"] = section

    return findings


def build(
    base_config: Path,
    out_dir: Path,
    port: int = DEFAULT_PORT,
    tls: bool = True,
) -> dict[str, object]:
    """Write the merged config and its two support files into one directory."""
    text = base_config.read_text(encoding="utf-8", errors="replace")
    findings = inspect(text, port)

    out_dir.mkdir(parents=True, exist_ok=True)
    config_path = out_dir / "fakenet.ini"

    section = _SECTION_TEMPLATE.format(
        port=port, custom=_SUPPORT_FILES[0], usessl="Yes" if tls else "No")
    # The original text first, byte for byte. Anything this script gets wrong
    # should be visible as an addition at the end rather than as a diff
    # scattered through a file nobody re-reads.
    config_path.write_text(text.rstrip("\n") + "\n" + section, encoding="utf-8")

    copied = []
    for name in _SUPPORT_FILES:
        source = _custom_dir() / name
        shutil.copyfile(source, out_dir / name)
        copied.append(name)

    return {"config": config_path, "copied": copied, "findings": findings,
            "port": port, "tls": tls}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fakenet-config", default="",
                        help="FakeNet's stock default.ini; found automatically "
                             "if FakeNet is installed where the runner looks")
    parser.add_argument("--out", required=True,
                        help="directory to write fakenet.ini and its support "
                             "files into -- they must share a directory")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--no-tls", dest="tls", action="store_false",
                        help="serve plain TCP instead of terminating TLS. The "
                             "measured client speaks TLS, so this is the arm "
                             "that cannot be spoken to -- keep it for A/B only")
    parser.set_defaults(tls=True)
    args = parser.parse_args(argv)

    base = find_default_config(args.fakenet_config or None)
    if base is None:
        print("could not find FakeNet's default.ini -- pass --fakenet-config")
        return 1

    result = build(base, Path(args.out), args.port, tls=args.tls)
    findings = result["findings"]
    assert isinstance(findings, dict)

    print(f"base config : {base}")
    print(f"written     : {result['config']}")
    print(f"support     : {', '.join(result['copied'])}")
    print(f"TLS         : {'terminated (UseSSL: Yes)' if args.tls else 'OFF -- plain TCP'}")
    if args.tls:
        # Measured on run `b610dea4`: the client offers 0x009c/0x009d,
        # 0x003c/0x003d and 0x002f/0x0035, so FakeNet's hardcoded
        # `ciphers='RSA'` has six suites to choose from. Which certificate is
        # served is a separate question, and it is now read rather than assumed.
        source, detail = leaf_source(fakenet_root_from(base))
        if source == "ringforge":
            print(f"cert        : RingForge's leaf is installed ({detail}).")
            print("              The names it covers still have to include what")
            print("              the implant asks for -- re-mint with")
            print("              make_tls_cert.py --hostname if they do not.")
        elif source == "fakenet":
            print(f"cert        : FakeNet's own ({detail}). If the implant")
            print("              validates it, the handshake fails before the")
            print("              handler is reached. Swap it with")
            print("              make_tls_cert.py --fakenet <install root>.")
        else:
            print(f"cert        : UNKNOWN -- {detail}. Check by hand which")
            print("              certificate this install serves before reading")
            print("              a no_connection summary as a rejected answer.")

    problems = []
    if findings.get("port_already_used_by"):
        problems.append(
            f"port {args.port} already has a listener: "
            f"[{findings['port_already_used_by']}]. Two sections on one port is "
            f"undefined -- remove one before running.")
    if findings.get("port_blacklisted"):
        problems.append(
            f"port {args.port} is in BlackListPortsTCP, so the diverter will "
            f"not route it and the handler will never be reached.")
    redirect = str(findings.get("redirect_all_traffic", "")).lower()
    if redirect and redirect not in ("yes", "true", "on", "1"):
        problems.append(
            f"RedirectAllTraffic is {findings['redirect_all_traffic']!r}. An "
            f"explicit listener section is still honoured, but check C1 "
            f"carefully -- this is the setting that decides whether anything "
            f"arrives at all.")

    for problem in problems:
        print(f"  WARNING: {problem}")
    if not problems:
        print("  checks   : ok (port free, not blacklisted, redirect on)")

    repo = Path(__file__).resolve().parent.parent
    print("\nrun the detonation with fakenet_config_path pointing at the config")
    print("above, and this environment set for the FakeNet process:\n")
    print(f'    set RINGFORGE_REPO_ROOT={repo}')
    print(f'    set RINGFORGE_RPC_OUTPUT_DIR=<case>\\network')
    print(f'    set RINGFORGE_RPC_REPLY=error')
    if args.tls:
        print(f'    set RINGFORGE_RPC_TLS=1')
    print("\nC1 is the control. Prove the bench with your own client before the")
    print("sample: a no_connection summary means the port was not routed --")
    if args.tls:
        print("or, with TLS on, that the client refused the certificate. Those")
        print("are different findings and the pcap separates them: look for a")
        print("TLS alert after the ServerHello.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
