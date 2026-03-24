
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
SENSITIVE_ENDPOINT_HINTS = {
    "auth": {"login", "logout", "token", "oauth", "session", "password", "reset", "mfa", "sso", "signin", "signup", "refresh"},
    "admin": {"admin", "manage", "internal", "settings", "config", "role", "permission"},
    "user_account": {"user", "account", "profile", "member", "customer"},
    "upload": {"upload", "import", "attach", "file", "document", "avatar", "image"},
    "download": {"download", "export", "report", "archive"},
    "search": {"search", "query", "filter"},
    "webhook": {"webhook", "callback", "hook"},
    "health_debug": {"health", "metrics", "status", "debug", "ready", "live"},
    "config": {"config", "setting", "feature-flag", "feature_flag"},
    "bulk_operation": {"bulk", "batch", "mass", "sync"},
}
HIGH_RISK_CLASSIFIERS = {"auth", "admin", "upload", "config", "webhook", "bulk_operation"}
RISKY_RESPONSE_FIELDS = {"password", "secret", "token", "access_token", "refresh_token", "api_key", "authorization"}
VALID_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


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


def _normalize_token(text: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "", str(text or "").lower())


def _looks_sensitive(name: str) -> bool:
    n = _normalize_token(name)
    return any(h in n for h in SENSITIVE_PARAM_HINTS)


def _looks_pii(name: str) -> bool:
    n = _normalize_token(name)
    return any(h in n for h in PII_FIELD_HINTS)


def _looks_admin_route(path: str) -> bool:
    p = str(path or "").lower()
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


def _extract_security_requirement_names(reqs: Any) -> list[str]:
    names: list[str] = []
    if isinstance(reqs, list):
        for item in reqs:
            if isinstance(item, dict):
                for k in item.keys():
                    names.append(str(k))
    return sorted(set(names))


def _resolve_auth_context(spec: dict[str, Any], path_item: dict[str, Any], op: dict[str, Any]) -> dict[str, Any]:
    op_sec = op.get("security")
    path_sec = path_item.get("security")
    spec_sec = spec.get("security")

    if isinstance(op_sec, list):
        names = _extract_security_requirement_names(op_sec)
        return {
            "auth_required": len(op_sec) > 0,
            "auth_source": "operation" if len(op_sec) > 0 else "explicit_none",
            "auth_schemes_applied": names,
            "auth_gap": False,
        }
    if isinstance(path_sec, list):
        names = _extract_security_requirement_names(path_sec)
        return {
            "auth_required": len(path_sec) > 0,
            "auth_source": "path" if len(path_sec) > 0 else "explicit_none",
            "auth_schemes_applied": names,
            "auth_gap": False,
        }
    if isinstance(spec_sec, list):
        names = _extract_security_requirement_names(spec_sec)
        return {
            "auth_required": len(spec_sec) > 0,
            "auth_source": "global" if len(spec_sec) > 0 else "explicit_none",
            "auth_schemes_applied": names,
            "auth_gap": False,
        }

    return {
        "auth_required": False,
        "auth_source": "none",
        "auth_schemes_applied": [],
        "auth_gap": True,
    }


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


def _summarize_auth(security_schemes: list[dict[str, Any]], spec_text: str = "") -> list[str]:
    found: list[str] = []
    for item in security_schemes:
        if not isinstance(item, dict):
            continue

        t = (item.get("type", "") or "").lower()
        scheme = (item.get("scheme", "") or "").lower()
        header_name = (item.get("header_name", "") or "").lower()
        scheme_name = (item.get("name", "") or "").lower()

        if t == "apikey":
            found.append("api-key")
        elif t == "http" and scheme == "bearer":
            found.append("bearer")
        elif t == "http" and scheme == "basic":
            found.append("basic")
        elif t == "oauth2":
            found.append("oauth2")
        elif t == "openidconnect":
            found.append("openid-connect")
        elif "token" in scheme_name:
            found.append("token")
        elif header_name and "authorization" in header_name:
            found.append("bearer")

    return sorted(set(found))


def _request_content_types(op: dict[str, Any], spec: dict[str, Any]) -> list[str]:
    cts: list[str] = []
    request_body = op.get("requestBody")
    if isinstance(request_body, dict):
        content = request_body.get("content", {})
        if isinstance(content, dict):
            cts.extend(str(k) for k in content.keys())
    consumes = op.get("consumes")
    if isinstance(consumes, list):
        cts.extend(str(x) for x in consumes)
    elif isinstance(spec.get("consumes"), list):
        cts.extend(str(x) for x in spec.get("consumes"))
    return sorted(set([x for x in cts if x]))


def _response_content_types(op: dict[str, Any], spec: dict[str, Any]) -> list[str]:
    cts: list[str] = []
    responses = op.get("responses", {})
    if isinstance(responses, dict):
        for resp in responses.values():
            if isinstance(resp, dict):
                content = resp.get("content", {})
                if isinstance(content, dict):
                    cts.extend(str(k) for k in content.keys())
    produces = op.get("produces")
    if isinstance(produces, list):
        cts.extend(str(x) for x in produces)
    elif isinstance(spec.get("produces"), list):
        cts.extend(str(x) for x in spec.get("produces"))
    return sorted(set([x for x in cts if x]))


def _collect_response_codes(op: dict[str, Any]) -> list[str]:
    responses = op.get("responses", {})
    if isinstance(responses, dict):
        return sorted(str(k) for k in responses.keys())
    return []


def _walk_schema_fields(schema: Any) -> list[str]:
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

    walk(schema)
    return sorted(set(names))


def _extract_request_schema(op: dict[str, Any]) -> dict[str, Any] | None:
    request_body = op.get("requestBody")
    if isinstance(request_body, dict):
        content = request_body.get("content", {})
        if isinstance(content, dict):
            for body in content.values():
                if isinstance(body, dict) and isinstance(body.get("schema"), dict):
                    return body.get("schema")
    for p in op.get("parameters", []) if isinstance(op.get("parameters"), list) else []:
        if isinstance(p, dict) and p.get("in") == "body" and isinstance(p.get("schema"), dict):
            return p.get("schema")
    return None


def _extract_response_schemas(op: dict[str, Any]) -> list[dict[str, Any]]:
    schemas: list[dict[str, Any]] = []
    responses = op.get("responses", {})
    if not isinstance(responses, dict):
        return schemas
    for code, resp in responses.items():
        if not isinstance(resp, dict):
            continue
        content = resp.get("content", {})
        if isinstance(content, dict):
            for ctype, body in content.items():
                if isinstance(body, dict) and isinstance(body.get("schema"), dict):
                    schemas.append({"code": str(code), "content_type": str(ctype), "schema": body["schema"]})
        elif isinstance(resp.get("schema"), dict):
            schemas.append({"code": str(code), "content_type": "", "schema": resp["schema"]})
    return schemas


def _evaluate_schema_quality(op: dict[str, Any]) -> dict[str, Any]:
    findings: list[str] = []
    request_schema = _extract_request_schema(op)
    response_schemas = _extract_response_schemas(op)
    response_fields: list[str] = []

    if op.get("requestBody") is not None or any(
        isinstance(p, dict) and p.get("in") == "body"
        for p in (op.get("parameters", []) if isinstance(op.get("parameters"), list) else [])
    ):
        if request_schema is None:
            findings.append("request body declared without a usable schema")
    if request_schema is not None:
        if request_schema.get("type") == "object" and not isinstance(request_schema.get("properties"), dict):
            findings.append("request body uses a generic object schema")
        if request_schema.get("additionalProperties") is True:
            findings.append("request body allows additionalProperties=true")
        required = request_schema.get("required")
        if request_schema.get("type") == "object" and not required:
            findings.append("request body object has no required fields")

    if not response_schemas:
        findings.append("no explicit response schema found")
    else:
        for resp in response_schemas:
            schema = resp.get("schema", {})
            response_fields.extend(_walk_schema_fields(schema))
            if isinstance(schema, dict) and schema.get("type") == "object" and not isinstance(schema.get("properties"), dict):
                findings.append(f"response {resp.get('code')} uses a generic object schema")

    risky_response_fields = sorted({f for f in response_fields if _normalize_token(f) in RISKY_RESPONSE_FIELDS})
    if risky_response_fields:
        findings.append(f"sensitive-looking response fields exposed: {', '.join(risky_response_fields[:8])}")

    return {
        "findings": sorted(set(findings)),
        "response_fields": sorted(set(response_fields)),
        "risky_response_fields": risky_response_fields,
        "has_request_schema": request_schema is not None,
        "has_response_schema": bool(response_schemas),
    }


def _classify_endpoint(route: str, method: str, op: dict[str, Any]) -> list[str]:
    blob = " ".join(
        [
            str(route or ""),
            str(method or ""),
            str(op.get("operationId", "") or ""),
            str(op.get("summary", "") or ""),
            str(op.get("description", "") or ""),
            " ".join(str(x) for x in (op.get("tags", []) if isinstance(op.get("tags"), list) else [])),
        ]
    ).lower()
    classes: list[str] = []
    for label, hints in SENSITIVE_ENDPOINT_HINTS.items():
        if any(h in blob for h in hints):
            classes.append(label)
    return sorted(set(classes))


def _score_endpoint(ep: dict[str, Any], http_server_detected: bool) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []

    if ep.get("auth_gap"):
        score += 2
        reasons.append("no auth requirement is applied")
    if ep.get("destructive_method") and not ep.get("auth_required"):
        score += 4
        reasons.append("destructive method appears unauthenticated")
    elif ep.get("destructive_method"):
        score += 1
        reasons.append("destructive/update method exposed")
    if ep.get("admin_like_route"):
        score += 3
        reasons.append("admin/config/internal-like route")
    if ep.get("file_upload"):
        score += 3
        reasons.append("file upload endpoint")
    if ep.get("sensitive_parameters"):
        score += min(3, len(ep.get("sensitive_parameters", [])))
        reasons.append("sensitive-looking parameters present")
    if any(cls in HIGH_RISK_CLASSIFIERS for cls in ep.get("endpoint_classes", [])):
        score += 2
        reasons.append(f"high-value endpoint class: {', '.join(ep.get('endpoint_classes', []))}")
    schema_findings = ep.get("schema_findings", [])
    if schema_findings:
        score += min(3, len(schema_findings))
        reasons.append("schema quality issues detected")
    if ep.get("risky_response_fields"):
        score += 2
        reasons.append("sensitive-looking fields returned in responses")
    if http_server_detected:
        score += 1
        reasons.append("HTTP server URL present in spec")

    if score >= 9:
        level = "high"
    elif score >= 5:
        level = "medium"
    elif score >= 2:
        level = "low"
    else:
        level = "informational"

    return {"risk_score": score, "risk_level": level, "risk_reasons": reasons}


def _recommended_tests(ep: dict[str, Any]) -> list[str]:
    tests: list[str] = []
    if ep.get("auth_gap") or (ep.get("destructive_method") and not ep.get("auth_required")):
        tests.append("Test unauthenticated access to confirm authorization is enforced.")
    if "admin" in ep.get("endpoint_classes", []) or ep.get("admin_like_route"):
        tests.append("Test role bypass with low-privileged credentials against admin/config operations.")
    if ep.get("file_upload"):
        tests.append("Test file type, size, and content validation on uploads.")
    if ep.get("sensitive_parameters"):
        tests.append("Test mass assignment and over-posting using sensitive-looking fields.")
    if "auth" in ep.get("endpoint_classes", []):
        tests.append("Test rate limiting, account lockout, and token/session handling.")
    if "user_account" in ep.get("endpoint_classes", []):
        tests.append("Test horizontal and vertical access control for resource identifiers.")
    if ep.get("schema_findings"):
        tests.append("Test malformed and extra fields to validate schema enforcement.")
    if ep.get("risky_response_fields"):
        tests.append("Check whether sensitive fields are returned unnecessarily in responses.")
    return sorted(set(tests))


def _best_autofill_candidate(endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    if not endpoints:
        return {"method": "GET", "path": "", "body": {}, "auth_hint": "", "risk_level": "informational"}

    def endpoint_rank(ep: dict[str, Any]) -> tuple[int, int, int, int]:
        method = str(ep.get("method", "GET"))
        method_pref = {"GET": 0, "POST": 1, "PUT": 2, "PATCH": 3, "DELETE": 4}.get(method, 9)
        return (
            int(ep.get("risk_score", 0)),
            1 if ep.get("auth_required") else 0,
            method_pref,
            len(ep.get("parameters", [])),
        )

    candidate = sorted(endpoints, key=endpoint_rank)[0]
    body: dict[str, Any] = {}
    for p in candidate.get("parameters", []):
        name = str(p.get("name", "") or "")
        if str(p.get("in", "")).startswith("body:"):
            body[name] = f"<{name.upper()}>" if _looks_sensitive(name) else "test"

    auth_hint = ""
    if candidate.get("auth_required"):
        schemes = candidate.get("auth_schemes_applied", [])
        auth_hint = f"Auth likely required ({', '.join(schemes)})" if schemes else "Auth likely required"

    return {
        "method": candidate.get("method", "GET"),
        "path": candidate.get("path", ""),
        "body": body,
        "auth_hint": auth_hint,
        "risk_level": candidate.get("risk_level", "informational"),
    }
def _collect_defined_ref_paths(obj: Any, base: str = "#") -> set[str]:
    paths: set[str] = set()

    if isinstance(obj, dict):
        paths.add(base)
        for key, value in obj.items():
            child = f"{base}/{key}"
            paths.update(_collect_defined_ref_paths(value, child))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            child = f"{base}/{i}"
            paths.update(_collect_defined_ref_paths(value, child))

    return paths


def _find_unresolved_refs(obj: Any, defined_ref_paths: set[str]) -> list[str]:
    found: set[str] = set()

    def walk(x: Any):
        if isinstance(x, dict):
            ref = x.get("$ref")
            if isinstance(ref, str) and ref.startswith("#/"):
                if ref not in defined_ref_paths:
                    found.add(ref)
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(obj)
    return sorted(found)


def _detect_spec_type(spec: dict[str, Any]) -> str:
    if not isinstance(spec, dict):
        return "unknown"
    if "openapi" in spec:
        return "openapi"
    if "swagger" in spec:
        return "swagger"
    if "paths" in spec:
        return "openapi_like"
    return "unknown"

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
        "top_risky_endpoints": [],
        "unauthenticated_risky_endpoints": [],
        "recommended_tests": [],
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
            "high_risk_endpoint_count": 0,
            "medium_risk_endpoint_count": 0,
            "explicit_no_auth_count": 0,
            "auth_gap_count": 0,
            "schema_issue_endpoint_count": 0,
        },
        "parser_warnings": [],
        "confidence": "high",
        "unresolved_refs": [],
        "unresolved_refs_count": 0,
    }

    try:
        spec, fmt = _load_spec(spec_path)

        if not isinstance(spec, dict):
            result["returncode"] = 1
            result["error"] = f"Spec root must be an object/dictionary, got {type(spec).__name__}"
            _write_json(output_dir / "api_spec_analysis.json", result)
            return result

        info = spec.get("info", {}) if isinstance(spec.get("info"), dict) else {}
        paths = spec.get("paths", {}) if isinstance(spec.get("paths"), dict) else {}

        spec_text = _safe_read_text(spec_path)
        defined_ref_paths = _collect_defined_ref_paths(spec)
        unresolved_refs = _find_unresolved_refs(spec, defined_ref_paths)

        result["format"] = fmt
        result["spec_type"] = _detect_spec_type(spec)
        result["title"] = str(info.get("title", "") or "")
        result["version"] = str(info.get("version", "") or "")
        result["unresolved_refs"] = unresolved_refs
        result["unresolved_refs_count"] = len(unresolved_refs)

        server_entries = _extract_server_entries(spec)
        result["server_entries"] = server_entries
        result["servers"] = [x["raw"] for x in server_entries]
        http_server_detected = any((x.get("scheme") or "").lower() == "http" for x in server_entries)

        security_schemes = _extract_security_schemes(spec)
        result["security_schemes"] = security_schemes
        result["auth_summary"] = _summarize_auth(security_schemes, "")

        endpoints: list[dict[str, Any]] = []
        method_counts = {"GET": 0, "POST": 0, "PUT": 0, "PATCH": 0, "DELETE": 0}
        admin_like_route_count = 0
        sensitive_param_count = 0
        file_upload_endpoint_count = 0
        unauthenticated_endpoint_count = 0
        sensitive_unauthenticated_endpoint_count = 0
        destructive_admin_routes = 0
        explicit_no_auth_count = 0
        auth_gap_count = 0
        schema_issue_endpoint_count = 0

        for route, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            endpoint_classes_for_route = _classify_endpoint(str(route), "", {})
            route_is_admin = _looks_admin_route(str(route))
            if route_is_admin and "health_debug" in endpoint_classes_for_route and not any(
                x in endpoint_classes_for_route for x in {"admin", "config"}
            ):
                route_is_admin = False

            if route_is_admin:
                admin_like_route_count += 1

            for method, op in path_item.items():
                if method.lower() not in VALID_METHODS or not isinstance(op, dict):
                    continue

                m = _normalize_method(method)
                if m in method_counts:
                    method_counts[m] += 1

                params = _extract_parameters(op, path_item)
                sensitive_params = [p for p in params if _looks_sensitive(p.get("name", ""))]
                sensitive_param_count += len(sensitive_params)

                auth_ctx = _resolve_auth_context(spec, path_item, op)
                auth_required = auth_ctx["auth_required"]
                auth_source = auth_ctx["auth_source"]
                auth_schemes_applied = auth_ctx["auth_schemes_applied"]
                auth_gap = auth_ctx["auth_gap"]

                if auth_source == "explicit_none":
                    explicit_no_auth_count += 1
                if auth_gap:
                    auth_gap_count += 1

                request_ct = _request_content_types(op, spec)
                response_ct = _response_content_types(op, spec)
                file_upload = any(x in {"multipart/form-data", "application/octet-stream"} for x in request_ct)
                if file_upload:
                    file_upload_endpoint_count += 1

                if not auth_required:
                    unauthenticated_endpoint_count += 1
                    if sensitive_params or route_is_admin or m in DESTRUCTIVE_METHODS:
                        sensitive_unauthenticated_endpoint_count += 1

                if route_is_admin and m in DESTRUCTIVE_METHODS:
                    destructive_admin_routes += 1

                endpoint_classes = _classify_endpoint(str(route), m, op)
                schema_quality = _evaluate_schema_quality(op)

                if schema_quality["findings"]:
                    schema_issue_endpoint_count += 1

                endpoint = {
                    "path": str(route),
                    "method": m,
                    "operation_id": str(op.get("operationId", "") or ""),
                    "summary": str(op.get("summary", "") or ""),
                    "description": str(op.get("description", "") or "")[:500],
                    "tags": [str(x) for x in (op.get("tags", []) if isinstance(op.get("tags"), list) else [])],
                    "deprecated": bool(op.get("deprecated", False)),
                    "admin_like_route": route_is_admin,
                    "destructive_method": m in DESTRUCTIVE_METHODS,
                    "auth_required": auth_required,
                    "auth_source": auth_source,
                    "auth_schemes_applied": auth_schemes_applied,
                    "auth_gap": auth_gap,
                    "file_upload": file_upload,
                    "request_content_types": request_ct,
                    "response_content_types": response_ct,
                    "response_codes": _collect_response_codes(op),
                    "parameters": params,
                    "sensitive_parameters": sensitive_params,
                    "endpoint_classes": endpoint_classes,
                    "schema_findings": schema_quality["findings"],
                    "risky_response_fields": schema_quality["risky_response_fields"],
                }

                endpoint.update(_score_endpoint(endpoint, http_server_detected))
                endpoint["recommended_tests"] = _recommended_tests(endpoint)
                endpoints.append(endpoint)

        endpoints = sorted(
            endpoints,
            key=lambda ep: (-int(ep.get("risk_score", 0)), str(ep.get("path", "")), str(ep.get("method", ""))),
        )

        schema_field_names = _extract_schema_field_names(spec)
        pii_field_count = len([x for x in schema_field_names if _looks_pii(x)])
        no_auth_detected = not bool(result["auth_summary"])

        high_risk_endpoints = [ep for ep in endpoints if ep.get("risk_level") == "high"]
        medium_risk_endpoints = [ep for ep in endpoints if ep.get("risk_level") == "medium"]
        unauth_risky = [ep for ep in endpoints if (not ep.get("auth_required")) and int(ep.get("risk_score", 0)) >= 5]

        result["endpoints"] = endpoints

        top_risky_source = high_risk_endpoints[:]
        if not top_risky_source:
            top_risky_source = [ep for ep in endpoints if int(ep.get("risk_score", 0)) > 0]

        top_risky_source = sorted(
            top_risky_source,
            key=lambda ep: (-int(ep.get("risk_score", 0)), str(ep.get("path", "")), str(ep.get("method", "")))
        )[:10]

        result["top_risky_endpoints"] = [
            {
                "method": ep.get("method", ""),
                "path": ep.get("path", ""),
                "summary": ep.get("summary", ""),
                "risk_score": ep.get("risk_score", 0),
                "risk_level": ep.get("risk_level", ""),
                "risk_reasons": ep.get("risk_reasons", []) or [],
                "auth_required": ep.get("auth_required", False),
                "auth_source": ep.get("auth_source", ""),
                "auth_schemes_applied": ep.get("auth_schemes_applied", []) or [],
            }
            for ep in top_risky_source
        ]

        result["unauthenticated_risky_endpoints"] = [
            {
                "method": ep.get("method", ""),
                "path": ep.get("path", ""),
                "summary": ep.get("summary", ""),
                "risk_score": ep.get("risk_score", 0),
                "risk_level": ep.get("risk_level", ""),
                "risk_reasons": ep.get("risk_reasons", []) or [],
                "auth_source": ep.get("auth_source", ""),
            }
            for ep in sorted(
                unauth_risky,
                key=lambda ep: (-int(ep.get("risk_score", 0)), str(ep.get("path", "")), str(ep.get("method", "")))
            )[:20]
        ]

        result["recommended_tests"] = [
            {
                "method": ep.get("method", ""),
                "path": ep.get("path", ""),
                "summary": ep.get("summary", ""),
                "risk_level": ep.get("risk_level", ""),
                "risk_score": ep.get("risk_score", 0),
                "tests": ep.get("recommended_tests", []) or [],
            }
            for ep in sorted(
                [ep for ep in endpoints if ep.get("recommended_tests")],
                key=lambda ep: (-int(ep.get("risk_score", 0)), str(ep.get("path", "")), str(ep.get("method", "")))
            )[:20]
        ]

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
            "high_risk_endpoint_count": len(high_risk_endpoints),
            "medium_risk_endpoint_count": len(medium_risk_endpoints),
            "top_risky_endpoint_count": len(result["top_risky_endpoints"]),
            "explicit_no_auth_count": explicit_no_auth_count,
            "auth_gap_count": auth_gap_count,
            "schema_issue_endpoint_count": schema_issue_endpoint_count,
        }

        result["scoring"] = {
            "no_auth_detected": no_auth_detected,
            "sensitive_unauthenticated_endpoints": sensitive_unauthenticated_endpoint_count,
            "destructive_admin_routes": destructive_admin_routes,
            "http_server_detected": http_server_detected,
            "file_upload_endpoints": file_upload_endpoint_count,
            "pii_field_count": pii_field_count,
            "high_risk_endpoint_count": len(high_risk_endpoints),
            "auth_gap_count": auth_gap_count,
            "schema_issue_endpoint_count": schema_issue_endpoint_count,
        }

        warnings: list[str] = []
        if not result["servers"]:
            warnings.append("No server/base URL definitions found in the spec.")
        if unresolved_refs:
            warnings.append(f"Unresolved internal refs detected ({len(unresolved_refs)}).")
        if not security_schemes and isinstance(spec.get("security"), list):
            warnings.append("Global security requirements are present but named security schemes were not resolved.")
        if schema_issue_endpoint_count > 0:
            warnings.append(f"Schema quality issues were detected on {schema_issue_endpoint_count} endpoint(s).")
        if auth_gap_count > 0:
            warnings.append(f"{auth_gap_count} endpoint(s) have no explicit auth requirement applied.")
        if not result["title"]:
            warnings.append("Spec title is missing.")
        if not result["version"]:
            warnings.append("Spec version is missing.")
        if isinstance(paths, dict) and paths and not endpoints:
            warnings.append("Paths were present but no operations were extracted.")
        if result["spec_type"] == "unknown":
            warnings.append("Spec type could not be confidently identified.")

        result["parser_warnings"] = warnings

        if len(warnings) >= 3:
            result["confidence"] = "medium"
        if len(warnings) >= 5:
            result["confidence"] = "low"

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
            risk_notes.append(
                f"Sensitive/admin/destructive endpoints appear unauthenticated ({sensitive_unauthenticated_endpoint_count})"
            )
        if len(high_risk_endpoints) > 0:
            risk_notes.append(f"High-risk endpoints identified ({len(high_risk_endpoints)})")

        result["risk_notes"] = risk_notes
        result["autofill"] = _best_autofill_candidate(endpoints)

    except Exception as e:
        result["returncode"] = 1
        result["error"] = f"{type(e).__name__}: {e}"

    _write_json(output_dir / "api_spec_analysis.json", result)
    return result
