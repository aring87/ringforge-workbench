from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


SENSITIVE_PARAM_HINTS = {
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "access_token",
    "refresh_token",
    "authorization",
    "auth",
    "session",
    "cookie",
    "ssn",
    "dob",
    "email",
    "phone",
    "creditcard",
    "card",
    "cvv",
}

ADMIN_ROUTE_HINTS = {
    "admin",
    "manage",
    "config",
    "settings",
    "internal",
    "debug",
    "health",
    "metrics",
    "actuator",
}

DESTRUCTIVE_METHODS = {"DELETE", "PATCH", "PUT"}
AUTH_HINT_KEYS = {
    "authorization",
    "x-api-key",
    "api-key",
    "apikey",
    "bearer",
    "oauth",
    "token",
    "jwt",
    "basic",
}


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8", errors="replace")


def _safe_read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _load_spec(path: Path) -> tuple[dict[str, Any], str]:
    text = _safe_read_text(path)
    suffix = path.suffix.lower()

    if suffix == ".json":
        return json.loads(text), "json"

    if suffix in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("PyYAML is not installed")
        return yaml.safe_load(text), "yaml"

    try:
        return json.loads(text), "json"
    except Exception:
        if yaml is None:
            raise RuntimeError("Unknown spec format and PyYAML is not installed")
        return yaml.safe_load(text), "yaml"


def _normalize_method(m: str) -> str:
    return str(m or "").upper().strip()


def _looks_sensitive(name: str) -> bool:
    n = re.sub(r"[^a-z0-9_]+", "", name.lower())
    return any(h in n for h in SENSITIVE_PARAM_HINTS)


def _looks_admin_route(path: str) -> bool:
    p = path.lower()
    return any(f"/{h}" in p or p.endswith(f"/{h}") for h in ADMIN_ROUTE_HINTS)


def _extract_server_hosts(spec: dict[str, Any]) -> list[str]:
    hosts: list[str] = []

    servers = spec.get("servers", [])
    if isinstance(servers, list):
        for item in servers:
            if isinstance(item, dict):
                url = str(item.get("url", "") or "").strip()
                if url:
                    parsed = urlparse(url)
                    if parsed.netloc:
                        hosts.append(parsed.netloc.lower())

    host = spec.get("host")
    if isinstance(host, str) and host.strip():
        hosts.append(host.strip().lower())

    return sorted(set(hosts))


def _extract_security_schemes(spec: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    components = spec.get("components", {})
    if isinstance(components, dict):
        schemes = components.get("securitySchemes", {})
        if isinstance(schemes, dict):
            for name, item in schemes.items():
                if isinstance(item, dict):
                    out.append(
                        {
                            "name": str(name),
                            "type": str(item.get("type", "") or ""),
                            "scheme": str(item.get("scheme", "") or ""),
                            "in": str(item.get("in", "") or ""),
                            "header_name": str(item.get("name", "") or ""),
                        }
                    )

    sec_defs = spec.get("securityDefinitions", {})
    if isinstance(sec_defs, dict):
        for name, item in sec_defs.items():
            if isinstance(item, dict):
                out.append(
                    {
                        "name": str(name),
                        "type": str(item.get("type", "") or ""),
                        "scheme": str(item.get("scheme", "") or ""),
                        "in": str(item.get("in", "") or ""),
                        "header_name": str(item.get("name", "") or ""),
                    }
                )

    return out


def _extract_parameters(op: dict[str, Any], path_item: dict[str, Any]) -> list[dict[str, str]]:
    params: list[dict[str, str]] = []

    for source in (path_item.get("parameters", []), op.get("parameters", [])):
        if isinstance(source, list):
            for p in source:
                if isinstance(p, dict):
                    params.append(
                        {
                            "name": str(p.get("name", "") or ""),
                            "in": str(p.get("in", "") or ""),
                        }
                    )

    request_body = op.get("requestBody")
    if isinstance(request_body, dict):
        content = request_body.get("content", {})
        if isinstance(content, dict):
            for ctype, body in content.items():
                if isinstance(body, dict):
                    schema = body.get("schema", {})
                    if isinstance(schema, dict):
                        props = schema.get("properties", {})
                        if isinstance(props, dict):
                            for name in props.keys():
                                params.append({"name": str(name), "in": f"body:{ctype}"})

    return params


def _summarize_auth(security_schemes: list[dict[str, Any]], spec_text: str) -> list[str]:
    found: list[str] = []

    for item in security_schemes:
        t = (item.get("type", "") or "").lower()
        scheme = (item.get("scheme", "") or "").lower()
        header_name = (item.get("header_name", "") or "").lower()

        if t == "apikey":
            found.append("apiKey")
        elif t == "http" and scheme == "bearer":
            found.append("bearer")
        elif t == "http" and scheme == "basic":
            found.append("basic")
        elif t == "oauth2":
            found.append("oauth2")
        elif t == "openidconnect":
            found.append("openidConnect")

        if header_name and any(k in header_name for k in AUTH_HINT_KEYS):
            found.append(header_name)

    text_l = spec_text.lower()
    for hint in AUTH_HINT_KEYS:
        if hint in text_l:
            found.append(hint)

    return sorted(set(found))


def analyze_api_spec(spec_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    spec_path = Path(spec_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    result: dict[str, Any] = {
        "returncode": 0,
        "error": "",
        "input_file": str(spec_path),
        "format": "",
        "spec_type": "",
        "title": "",
        "version": "",
        "servers": [],
        "auth_summary": [],
        "security_schemes": [],
        "endpoints": [],
        "risk_notes": [],
        "summary": {
            "endpoint_count": 0,
            "get_count": 0,
            "post_count": 0,
            "put_count": 0,
            "patch_count": 0,
            "delete_count": 0,
            "admin_like_route_count": 0,
            "sensitive_param_count": 0,
            "auth_scheme_count": 0,
        },
    }

    try:
        spec, fmt = _load_spec(spec_path)
        if not isinstance(spec, dict):
            raise RuntimeError("Spec root is not an object")

        spec_text = _safe_read_text(spec_path)
        info = spec.get("info", {}) if isinstance(spec.get("info"), dict) else {}
        paths = spec.get("paths", {}) if isinstance(spec.get("paths"), dict) else {}

        result["format"] = fmt
        result["spec_type"] = "openapi" if ("openapi" in spec or "swagger" in spec) else "unknown"
        result["title"] = str(info.get("title", "") or "")
        result["version"] = str(info.get("version", "") or "")
        result["servers"] = _extract_server_hosts(spec)

        security_schemes = _extract_security_schemes(spec)
        result["security_schemes"] = security_schemes
        result["auth_summary"] = _summarize_auth(security_schemes, spec_text)

        endpoints: list[dict[str, Any]] = []
        method_counts = {"GET": 0, "POST": 0, "PUT": 0, "PATCH": 0, "DELETE": 0}
        admin_like_route_count = 0
        sensitive_param_count = 0

        valid_methods = {"get", "post", "put", "patch", "delete", "head", "options"}

        for route, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            if _looks_admin_route(str(route)):
                admin_like_route_count += 1

            for method, op in path_item.items():
                if method.lower() not in valid_methods or not isinstance(op, dict):
                    continue

                m = _normalize_method(method)
                if m in method_counts:
                    method_counts[m] += 1

                params = _extract_parameters(op, path_item)
                sensitive_params = [p for p in params if _looks_sensitive(p.get("name", ""))]
                sensitive_param_count += len(sensitive_params)

                endpoints.append(
                    {
                        "path": str(route),
                        "method": m,
                        "operation_id": str(op.get("operationId", "") or ""),
                        "summary": str(op.get("summary", "") or ""),
                        "description": str(op.get("description", "") or "")[:500],
                        "admin_like_route": _looks_admin_route(str(route)),
                        "destructive_method": m in DESTRUCTIVE_METHODS,
                        "parameters": params,
                        "sensitive_parameters": sensitive_params,
                    }
                )

        result["endpoints"] = endpoints
        result["summary"] = {
            "endpoint_count": len(endpoints),
            "get_count": method_counts["GET"],
            "post_count": method_counts["POST"],
            "put_count": method_counts["PUT"],
            "patch_count": method_counts["PATCH"],
            "delete_count": method_counts["DELETE"],
            "admin_like_route_count": admin_like_route_count,
            "sensitive_param_count": sensitive_param_count,
            "auth_scheme_count": len(result["auth_summary"]),
        }

        risk_notes: list[str] = []

        if not result["servers"]:
            risk_notes.append("No server/base URL definitions found in API spec")

        if method_counts["DELETE"] > 0 or method_counts["PATCH"] > 0:
            risk_notes.append("Spec exposes destructive or update-oriented methods (DELETE/PATCH)")

        if admin_like_route_count > 0:
            risk_notes.append(f"Admin/config/internal-like routes detected ({admin_like_route_count})")

        if sensitive_param_count > 0:
            risk_notes.append(f"Sensitive-looking parameters detected ({sensitive_param_count})")

        if not result["auth_summary"]:
            risk_notes.append("No obvious authentication scheme detected in spec")

        result["risk_notes"] = risk_notes

    except Exception as e:
        result["returncode"] = 1
        result["error"] = f"{type(e).__name__}: {e}"

    _write_json(output_dir / "api_spec_analysis.json", result)
    return result
