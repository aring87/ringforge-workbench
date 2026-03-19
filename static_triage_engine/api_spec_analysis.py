
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
    "password", "passwd", "secret", "token", "apikey", "api_key", "access_token", "refresh_token",
    "authorization", "auth", "session", "cookie", "ssn", "dob", "email", "phone", "creditcard", "card", "cvv",
}
ADMIN_ROUTE_HINTS = {"admin", "manage", "config", "settings", "internal", "debug", "health", "metrics", "actuator"}
DESTRUCTIVE_METHODS = {"DELETE", "PATCH", "PUT"}
AUTH_HINT_KEYS = {"authorization", "x-api-key", "api-key", "apikey", "bearer", "oauth", "token", "jwt", "basic"}
PII_FIELD_HINTS = {"email", "phone", "dob", "birth", "ssn", "social", "address", "name", "first_name", "last_name", "zip", "postal"}


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8", errors="replace")


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


def _looks_pii(name: str) -> bool:
    n = re.sub(r"[^a-z0-9_]+", "", name.lower())
    return any(h in n for h in PII_FIELD_HINTS)


def _looks_admin_route(path: str) -> bool:
    p = path.lower()
    return any(f"/{h}" in p or p.endswith(f"/{h}") for h in ADMIN_ROUTE_HINTS)


def _extract_server_entries(spec: dict[str, Any]) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    servers = spec.get("servers", [])
    if isinstance(servers, list):
        for item in servers:
            if isinstance(item, dict):
                url = str(item.get("url", "") or "").strip()
                if url:
                    parsed = urlparse(url)
                    entries.append(
                        {
                            "raw": url,
                            "host": parsed.netloc.lower() if parsed.netloc else "",
                            "scheme": parsed.scheme.lower() if parsed.scheme else "",
                        }
                    )
    host = spec.get("host")
    schemes = spec.get("schemes", []) if isinstance(spec.get("schemes"), list) else []
    if isinstance(host, str) and host.strip():
        if schemes:
            for scheme in schemes:
                entries.append({"raw": f"{scheme}://{host}", "host": host.strip().lower(), "scheme": str(scheme).lower()})
        else:
            entries.append({"raw": host.strip(), "host": host.strip().lower(), "scheme": ""})
    deduped = []
    seen = set()
    for item in entries:
        key = (item["raw"], item["host"], item["scheme"])
        if key not in seen:
            deduped.append(item)
            seen.add(key)
    return deduped


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


def _operation_auth_required(spec: dict[str, Any], path_item: dict[str, Any], op: dict[str, Any]) -> bool:
    if isinstance(op.get("security"), list):
        return len(op.get("security") or []) > 0
    if isinstance(path_item.get("security"), list):
        return len(path_item.get("security") or []) > 0
    if isinstance(spec.get("security"), list):
        return len(spec.get("security") or []) > 0
    return False


def _extract_parameters(op: dict[str, Any], path_item: dict[str, Any]) -> list[dict[str, str]]:
    params: list[dict[str, str]] = []
    for source in (path_item.get("parameters", []), op.get("parameters", [])):
        if isinstance(source, list):
            for p in source:
                if isinstance(p, dict):
                    params.append({"name": str(p.get("name", "") or ""), "in": str(p.get("in", "") or "")})
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


def _extract_schema_field_names(spec: dict[str, Any]) -> list[str]:
    names: list[str] = []

    def walk(node: Any):
        if isinstance(node, dict):
            props = node.get("properties", {})
            if isinstance(props, dict):
                for k, v in props.items():
                    names.append(str(k))
                    walk(v)
            items = node.get("items")
            if items is not None:
                walk(items)
            for v in node.values():
                if isinstance(v, (dict, list)):
                    walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(spec.get("components", {}))
    walk(spec.get("definitions", {}))
    return sorted(set(names))


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


def _best_autofill_candidate(endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    if not endpoints:
        return {"method": "GET", "path": "", "body": {}}

    def endpoint_rank(ep: dict[str, Any]) -> tuple[int, int, int]:
        method = str(ep.get("method", "GET"))
        destructive = 1 if ep.get("destructive_method") else 0
        auth_required = 1 if ep.get("auth_required") else 0
        sensitive = 1 if ep.get("sensitive_parameters") else 0
        method_pref = {"GET": 0, "POST": 1, "PUT": 2, "PATCH": 3, "DELETE": 4}.get(method, 9)
        return (destructive + sensitive + auth_required, method_pref, len(ep.get("parameters", [])))

    candidate = sorted(endpoints, key=endpoint_rank)[0]
    body: dict[str, Any] = {}
    for p in candidate.get("parameters", []):
        name = str(p.get("name", "") or "")
        if p.get("in", "").startswith("body:"):
            if _looks_sensitive(name):
                body[name] = f"<{name.upper()}>"
            else:
                body[name] = "test"
    return {"method": candidate.get("method", "GET"), "path": candidate.get("path", ""), "body": body}


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
        "server_entries": [],
        "auth_summary": [],
        "security_schemes": [],
        "endpoints": [],
        "risk_notes": [],
        "scoring": {},
        "autofill": {},
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
            "file_upload_endpoint_count": 0,
            "unauthenticated_endpoint_count": 0,
            "sensitive_unauthenticated_endpoint_count": 0,
            "pii_field_count": 0,
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

        server_entries = _extract_server_entries(spec)
        result["server_entries"] = server_entries
        result["servers"] = [x["raw"] for x in server_entries]

        security_schemes = _extract_security_schemes(spec)
        result["security_schemes"] = security_schemes
        result["auth_summary"] = _summarize_auth(security_schemes, spec_text)

        endpoints: list[dict[str, Any]] = []
        method_counts = {"GET": 0, "POST": 0, "PUT": 0, "PATCH": 0, "DELETE": 0}
        admin_like_route_count = 0
        sensitive_param_count = 0
        file_upload_endpoint_count = 0
        unauthenticated_endpoint_count = 0
        sensitive_unauthenticated_endpoint_count = 0
        destructive_admin_routes = 0

        valid_methods = {"get", "post", "put", "patch", "delete", "head", "options"}

        for route, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            route_is_admin = _looks_admin_route(str(route))
            if route_is_admin:
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
                auth_required = _operation_auth_required(spec, path_item, op)

                request_body = op.get("requestBody")
                request_body_text = json.dumps(request_body, ensure_ascii=False).lower() if isinstance(request_body, dict) else ""
                file_upload = "multipart/form-data" in request_body_text or "application/octet-stream" in request_body_text
                if file_upload:
                    file_upload_endpoint_count += 1

                if not auth_required:
                    unauthenticated_endpoint_count += 1
                    if sensitive_params or route_is_admin or m in DESTRUCTIVE_METHODS:
                        sensitive_unauthenticated_endpoint_count += 1

                if route_is_admin and m in DESTRUCTIVE_METHODS:
                    destructive_admin_routes += 1

                endpoints.append(
                    {
                        "path": str(route),
                        "method": m,
                        "operation_id": str(op.get("operationId", "") or ""),
                        "summary": str(op.get("summary", "") or ""),
                        "description": str(op.get("description", "") or "")[:500],
                        "admin_like_route": route_is_admin,
                        "destructive_method": m in DESTRUCTIVE_METHODS,
                        "auth_required": auth_required,
                        "file_upload": file_upload,
                        "parameters": params,
                        "sensitive_parameters": sensitive_params,
                    }
                )

        schema_field_names = _extract_schema_field_names(spec)
        pii_field_count = len([x for x in schema_field_names if _looks_pii(x)])
        http_server_detected = any((x.get("scheme") == "http") for x in server_entries)
        no_auth_detected = not bool(result["auth_summary"])

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
            "file_upload_endpoint_count": file_upload_endpoint_count,
            "unauthenticated_endpoint_count": unauthenticated_endpoint_count,
            "sensitive_unauthenticated_endpoint_count": sensitive_unauthenticated_endpoint_count,
            "pii_field_count": pii_field_count,
        }

        result["scoring"] = {
            "no_auth_detected": no_auth_detected,
            "sensitive_unauthenticated_endpoints": sensitive_unauthenticated_endpoint_count,
            "destructive_admin_routes": destructive_admin_routes,
            "http_server_detected": http_server_detected,
            "file_upload_endpoints": file_upload_endpoint_count,
            "pii_field_count": pii_field_count,
        }

        risk_notes: list[str] = []
        if not result["servers"]:
            risk_notes.append("No server/base URL definitions found in API spec")
        if http_server_detected:
            risk_notes.append("HTTP server URL detected; transport security may be weak or unspecified")
        if method_counts["DELETE"] > 0 or method_counts["PATCH"] > 0:
            risk_notes.append("Spec exposes destructive or update-oriented methods (DELETE/PATCH)")
        if admin_like_route_count > 0:
            risk_notes.append(f"Admin/config/internal-like routes detected ({admin_like_route_count})")
        if sensitive_param_count > 0:
            risk_notes.append(f"Sensitive-looking parameters detected ({sensitive_param_count})")
        if file_upload_endpoint_count > 0:
            risk_notes.append(f"File upload endpoints detected ({file_upload_endpoint_count})")
        if pii_field_count > 0:
            risk_notes.append(f"PII-like schema fields detected ({pii_field_count})")
        if no_auth_detected:
            risk_notes.append("No obvious authentication scheme detected in spec")
        if sensitive_unauthenticated_endpoint_count > 0:
            risk_notes.append(f"Sensitive/admin/destructive endpoints appear unauthenticated ({sensitive_unauthenticated_endpoint_count})")
        result["risk_notes"] = risk_notes

        result["autofill"] = _best_autofill_candidate(endpoints)

    except Exception as e:
        result["returncode"] = 1
        result["error"] = f"{type(e).__name__}: {e}"

    _write_json(output_dir / "api_spec_analysis.json", result)
    return result
