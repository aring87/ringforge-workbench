"""Build a corpus of real HTTP responses, so `api` can be measured.

`api` is the last scorer on this bench that has never been measured, and it is
held context-only in `verdict.CONTEXT_ONLY` for that one reason. The other
three corpora are collections of *files*; this one cannot be, because an HTTP
response only exists if somebody sends a request.

**The specs already name their servers.** `scripts/spec_corpus.py` fetched 300
OpenAPI documents across 300 distinct providers, and every one of them declares
a base URL and a set of operations. Replaying a documented, parameterless GET
against the documented server yields a genuine response -- real headers, real
`Set-Cookie` flags, real `Server:` strings -- which is exactly the population
the categories claim to describe and exactly what no synthetic corpus can be.

This is the one script in the repo that talks to hosts nobody here controls, so
the rules it follows are narrow and none of them are configurable:

**GET only, always.** No POST, PUT, PATCH or DELETE is ever sent, by any flag.
A measurement is not worth mutating a stranger's service for.

**Only operations the document says need nothing.** An endpoint with a required
parameter is skipped rather than guessed at: inventing an ID produces a 404
that measures the invention. Path templates are skipped for the same reason.

**Verb-shaped paths are skipped even under GET.** Real APIs route `/logout`,
`/reset`, `/send` and `/purge` through GET, and the method being safe by
specification does not make the handler safe in fact.

**One request per provider, and no redirects followed.** 300 requests spread
over 300 organisations is a single hit each -- less load than one person
opening the docs. A 3xx is recorded as the response it is rather than chased
somewhere unannounced.

**Nothing is ever authenticated.** No credential is sent, no cookie is stored,
no session persists between requests. A 401 is a fine result and is recorded as
one.

    .venv\\Scripts\\python.exe scripts\\api_corpus.py --specs G:\\spec-corpus --out G:\\api-corpus
    .venv\\Scripts\\python.exe scripts\\benign_rates.py --module api --responses G:\\api-corpus

Runs on the HOST. These are public documented endpoints, and the guest has no
network by design.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

USER_AGENT = "Mozilla/5.0 (compatible; ringforge-corpus/1.0)"

#: Enough body for a credential or a stack trace to be visible, and not enough
#: to make this a download. `analyze_response` reads the body for values.
MAX_BODY_BYTES = 256 * 1024

#: Path segments that mean the handler *does* something, whatever the method
#: says. `GET /logout` is common, and it is still a logout.
VERB_PATH_HINTS = (
    "logout", "signout", "sign-out", "delete", "remove", "destroy", "purge",
    "drop", "truncate", "reset", "revoke", "cancel", "shutdown", "restart",
    "reboot", "kill", "stop", "start", "send", "email", "sms", "notify",
    "invite", "pay", "charge", "refund", "order", "checkout", "subscribe",
    "unsubscribe", "install", "uninstall", "deploy", "execute", "run", "exec",
    "import", "export", "upload", "sync", "migrate", "rotate", "generate",
    "create", "update", "activate", "deactivate", "enable", "disable",
)

_TEMPLATE = re.compile(r"\{[^}]*\}")


def host_status(host: str) -> str:
    """`"public"`, or the reason this host will not be contacted.

    A spec may name `localhost` or `192.168.x.x` as its server -- several do.
    Sending even a GET there points this script at whatever happens to be
    listening on the bench, which is the one thing it must never do.

    The two rejections are reported apart because they mean different things
    about the corpus. `your-domain.atlassian.net` is a placeholder in somebody's
    documentation and says nothing about the population; a server resolving to
    10.x says the document describes an API that was never public.
    """
    host = (host or "").split(":")[0].strip().lower()
    if not host or host in {"localhost", "localhost.localdomain"}:
        return "server is a loopback name"
    if host.endswith(".local") or host.endswith(".internal"):
        return "server is an internal name"
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except (socket.gaierror, UnicodeError, OSError):
        return "server name does not resolve"
    if not addresses:
        return "server name does not resolve"
    for raw in addresses:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            return "server name does not resolve"
        if (address.is_private or address.is_loopback or address.is_reserved
                or address.is_link_local or address.is_multicast):
            return "server resolves inside the network"
    return "public"


def _is_public_host(host: str) -> bool:
    return host_status(host) == "public"


def server_urls(spec: dict[str, Any]) -> list[str]:
    """Base URLs the document declares, in both dialects, templates resolved.

    OpenAPI 3 allows `{region}` style variables in a server URL and supplies a
    `default` for each. Substituting the document's own default is reading the
    spec; inventing a value would not be.
    """
    out: list[str] = []
    servers = spec.get("servers")
    if isinstance(servers, list):
        for item in servers:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", "") or "").strip()
            if not url:
                continue
            variables = item.get("variables")
            if isinstance(variables, dict):
                for name, meta in variables.items():
                    if isinstance(meta, dict) and meta.get("default") is not None:
                        url = url.replace("{" + str(name) + "}",
                                          str(meta["default"]))
            if not _TEMPLATE.search(url):
                out.append(url)

    # Swagger 2.0: host plus basePath plus schemes.
    host = spec.get("host")
    if isinstance(host, str) and host.strip():
        base = str(spec.get("basePath", "") or "")
        schemes = spec.get("schemes")
        schemes = ([s for s in schemes if isinstance(s, str)]
                   if isinstance(schemes, list) else ["https"])
        for scheme in schemes or ["https"]:
            candidate = f"{scheme}://{host.strip()}{base}"
            if not _TEMPLATE.search(candidate):
                out.append(candidate)

    # https first: if a document offers both, the cleartext one is a choice the
    # corpus should not make on the server's behalf.
    seen: dict[str, None] = {}
    for url in sorted(out, key=lambda u: not u.lower().startswith("https://")):
        seen.setdefault(url.rstrip("/"), None)
    return [u for u in seen if u.lower().startswith(("http://", "https://"))]


def _parameters_required(spec: dict[str, Any], item: dict[str, Any],
                         operation: dict[str, Any]) -> bool:
    """Does this operation require anything the document did not supply?

    `$ref` parameters count as required. They cannot be read without resolving
    the reference, and an unread parameter is not a known-optional one.
    """
    for group in (item.get("parameters"), operation.get("parameters")):
        if not isinstance(group, list):
            continue
        for param in group:
            if not isinstance(param, dict):
                return True
            if "$ref" in param:
                return True
            if param.get("required") and str(param.get("in", "")).lower() != "header":
                return True
            # A required header is usually the credential; treat it the same.
            if param.get("required"):
                return True
    return False


def choose_endpoint(spec: dict[str, Any]) -> str | None:
    """A documented GET that needs nothing, or None.

    Shortest path first. A short path is closer to the root of the API and more
    likely to be an index, a status or a version -- the endpoints a stranger is
    welcome to call.
    """
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return None

    candidates: list[str] = []
    for path, item in paths.items():
        if not isinstance(item, dict) or not isinstance(path, str):
            continue
        if _TEMPLATE.search(path):
            continue
        lowered = path.lower()
        if any(hint in lowered for hint in VERB_PATH_HINTS):
            continue
        operation = item.get("get")
        if not isinstance(operation, dict):
            continue
        if operation.get("deprecated"):
            continue
        if _parameters_required(spec, item, operation):
            continue
        candidates.append(path)

    if not candidates:
        return None
    return sorted(candidates, key=lambda p: (len(p), p))[0]


def plan(spec_path: Path) -> dict[str, Any] | None:
    """What one specification would have this script send, if anything."""
    try:
        spec = json.loads(spec_path.read_text(encoding="utf-8", errors="replace"))
    except (ValueError, OSError):
        return None
    if not isinstance(spec, dict):
        return None

    servers = server_urls(spec)
    if not servers:
        return {"spec": spec_path.name, "skipped": "no usable server URL"}
    path = choose_endpoint(spec)
    if not path:
        return {"spec": spec_path.name, "skipped": "no parameterless GET"}

    base = servers[0]
    url = base + ("" if path == "/" else path)
    host = urllib.parse.urlsplit(url).netloc
    # Checked here as well as before sending. The send-time guard is the one
    # that matters and it stays, but a plan that lists `1password.local` and
    # `adobe.local` as things this script will do is a plan that misreports
    # itself -- and those two are real entries in the spec corpus.
    status = host_status(host)
    if status != "public":
        return {"spec": spec_path.name, "skipped": status}
    return {"spec": spec_path.name,
            "title": str((spec.get("info") or {}).get("title", ""))[:60],
            "url": url, "host": host, "path": path}


def send(url: str, timeout: float) -> dict[str, Any]:
    """One GET, no redirects, no credentials, capped body."""

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):  # noqa: D401
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, method="GET", headers={
        "User-Agent": USER_AGENT, "Accept": "*/*"})

    started = time.time()
    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            pairs = list(response.headers.items())
            body = response.read(MAX_BODY_BYTES)
    except urllib.error.HTTPError as error:
        # **A 4xx or 5xx is a response, not a failure.** `status_denied` and
        # `status_server_error` are findings the categories are built on, and
        # discarding them would measure only the endpoints that said yes.
        status = error.code
        pairs = list(error.headers.items()) if error.headers else []
        try:
            body = error.read(MAX_BODY_BYTES)
        except Exception:
            body = b""
    except Exception as error:
        return {"error": f"{type(error).__name__}: {error}",
                "elapsed": round(time.time() - started, 2)}

    # **Pairs, because a response may repeat a header and `Set-Cookie` is the
    # one that does.** `dict(...)` over an HTTP message keeps the last value,
    # so a response setting three cookies recorded one, and the two the server
    # sent first -- the ones that might be missing `HttpOnly` -- vanished
    # before anything could measure them. `headers` stays beside it for
    # readers that want the simple shape.
    return {"status": status, "header_pairs": pairs, "headers": dict(pairs),
            "body": body.decode("utf-8", "replace"),
            "elapsed": round(time.time() - started, 2)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--specs", required=True,
                        help="the spec corpus from scripts/spec_corpus.py")
    parser.add_argument("--out", required=True, help="response corpus directory")
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--seed", type=int, default=20260826)
    parser.add_argument("--delay", type=float, default=1.0,
                        help="seconds between requests; they go to different "
                             "hosts, so this is politeness rather than a limit")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--plan-only", action="store_true",
                        help="work out what would be sent and send nothing")
    args = parser.parse_args(argv)

    spec_dir = Path(args.specs)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    spec_files = [p for p in sorted(spec_dir.glob("*.json"))
                  if not p.name.startswith("_")]
    if not spec_files:
        print(f"failed: no specifications in {spec_dir}")
        return 1
    print(f"Reading {len(spec_files)} specifications from {spec_dir}")

    plans: list[dict[str, Any]] = []
    skipped: dict[str, int] = {}
    for path in spec_files:
        entry = plan(path)
        if entry is None:
            skipped["unreadable"] = skipped.get("unreadable", 0) + 1
        elif "skipped" in entry:
            skipped[entry["skipped"]] = skipped.get(entry["skipped"], 0) + 1
        else:
            plans.append(entry)

    print(f"  {len(plans)} specs yield a parameterless GET")
    for reason, n in sorted(skipped.items(), key=lambda kv: -kv[1]):
        print(f"  {n:>4} skipped: {reason}")

    # One request per host, whatever the specs say. Two documents from the same
    # provider must not become two hits on the same service.
    rng = random.Random(args.seed)
    rng.shuffle(plans)
    per_host: dict[str, None] = {}
    unique: list[dict[str, Any]] = []
    for entry in plans:
        if entry["host"] in per_host:
            continue
        per_host[entry["host"]] = None
        unique.append(entry)
    unique = sorted(unique, key=lambda e: e["spec"])[:args.count]
    print(f"  {len(unique)} distinct hosts, seed {args.seed}")

    (out_dir / "_plan.json").write_text(json.dumps({
        "seed": args.seed, "specs": len(spec_files),
        "planned": len(unique), "skipped": skipped,
        "requests": [{"spec": e["spec"], "url": e["url"]} for e in unique],
    }, indent=2), encoding="utf-8")

    if args.plan_only:
        print(f"  plan written to {out_dir / '_plan.json'}; nothing sent")
        return 0

    print(f"Sending {len(unique)} GETs at {args.delay}s intervals. "
          f"Ctrl-C is safe; re-running resumes.")
    outcomes: dict[str, int] = {}
    for index, entry in enumerate(unique, 1):
        target = out_dir / (entry["spec"].removesuffix(".json") + ".response.json")
        if target.exists():
            outcomes["skipped"] = outcomes.get("skipped", 0) + 1
            continue

        host = urllib.parse.urlsplit(entry["url"]).netloc
        if not _is_public_host(host):
            outcomes["not-public"] = outcomes.get("not-public", 0) + 1
            continue

        result = send(entry["url"], args.timeout)
        record = {"spec": entry["spec"], "title": entry.get("title", ""),
                  "method": "GET", "url": entry["url"], **result}
        target.write_text(json.dumps(record, indent=2, ensure_ascii=False),
                          encoding="utf-8", errors="replace")

        key = ("error" if "error" in result
               else f"{int(result['status']) // 100}xx")
        outcomes[key] = outcomes.get(key, 0) + 1
        if index % 25 == 0 or index == len(unique):
            print(f"  {index}/{len(unique)}  " +
                  ", ".join(f"{k} {v}" for k, v in sorted(outcomes.items())))
        time.sleep(args.delay)

    have = list(out_dir.glob("*.response.json"))
    print()
    print(f"corpus: {len(have)} responses in {out_dir}")
    print("Measure it with:")
    print("    .venv\\Scripts\\python.exe scripts\\benign_rates.py "
          "--module api --responses " + str(out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
