from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    import pefile
except Exception:
    pefile = None


API_CATEGORIES = {
    "process_injection": {
        "OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
        "CreateRemoteThread", "NtWriteVirtualMemory", "NtCreateThreadEx",
        "QueueUserAPC", "SetThreadContext", "ResumeThread",
    },
    "memory_execution": {
        "VirtualAlloc", "VirtualProtect", "VirtualProtectEx",
        "HeapAlloc", "NtAllocateVirtualMemory", "CreateThread",
        "MapViewOfFile", "MapViewOfFileEx",
    },
    "network_http": {
        "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
        "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
        "URLDownloadToFileA", "URLDownloadToFileW",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
        "WinHttpReceiveResponse", "WinHttpReadData",
    },
    "network_socket": {
        "socket", "connect", "send", "recv", "bind", "listen", "accept",
        "WSAStartup", "WSASocketA", "WSASocketW",
    },
    "process_execution": {
        "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteW",
        "ShellExecuteExA", "ShellExecuteExW", "CreateProcessAsUserW",
    },
    "registry": {
        "RegOpenKeyA", "RegOpenKeyW", "RegOpenKeyExA", "RegOpenKeyExW",
        "RegCreateKeyA", "RegCreateKeyW", "RegCreateKeyExA", "RegCreateKeyExW",
        "RegSetValueA", "RegSetValueW", "RegSetValueExA", "RegSetValueExW",
        "NtSetValueKey",
    },
    "services": {
        "OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW",
        "OpenServiceA", "OpenServiceW", "StartServiceA", "StartServiceW",
        "ChangeServiceConfigA", "ChangeServiceConfigW",
    },
    "file_system": {
        "CreateFileA", "CreateFileW", "WriteFile", "ReadFile", "CopyFileA", "CopyFileW",
        "MoveFileA", "MoveFileW", "DeleteFileA", "DeleteFileW",
    },
    "credential_access": {
        "CredEnumerateA", "CredEnumerateW", "CredReadA", "CredReadW",
        "LsaOpenPolicy", "LsaRetrievePrivateData", "LogonUserA", "LogonUserW",
        "CryptUnprotectData",
    },
    "anti_analysis": {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA",
        "OutputDebugStringW", "NtQueryInformationProcess", "FindWindowA", "FindWindowW",
        "QueryPerformanceCounter", "GetTickCount", "Sleep",
    },
    "persistence": {
        "SetWindowsHookExA", "SetWindowsHookExW",
        "WritePrivateProfileStringA", "WritePrivateProfileStringW",
        "MoveFileExA", "MoveFileExW",
    },
    "crypto": {
        "CryptAcquireContextA", "CryptAcquireContextW", "CryptEncrypt", "CryptDecrypt",
        "BCryptEncrypt", "BCryptDecrypt", "CryptGenRandom",
    },
    "discovery": {
        "GetComputerNameA", "GetComputerNameW", "GetUserNameA", "GetUserNameW",
        "GetAdaptersInfo", "GetAdaptersAddresses", "NetUserEnum", "GetVersionExA", "GetVersionExW",
    },
}

API_CHAINS = {
    "possible_process_injection": {
        "all_of": {"OpenProcess", "WriteProcessMemory"},
        "any_of": {"CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext"},
        "severity": "high",
    },
    "possible_downloader": {
        "any_of": {
            "URLDownloadToFileA", "URLDownloadToFileW",
            "HttpSendRequestA", "HttpSendRequestW",
            "WinHttpSendRequest",
        },
        "severity": "medium",
    },
    "possible_registry_persistence": {
        "all_of": {"RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW"},
        "severity": "medium",
    },
    "possible_service_install": {
        "all_of": {"OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW"},
        "any_of": {"StartServiceA", "StartServiceW", "ChangeServiceConfigA", "ChangeServiceConfigW"},
        "severity": "high",
    },
    "possible_memory_execution": {
        "all_of": {"VirtualAlloc", "CreateThread"},
        "any_of": {"VirtualProtect", "VirtualProtectEx"},
        "severity": "medium",
    },
}


def _safe_write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8", errors="replace")


def _decode_name(value: bytes | None) -> str:
    if not value:
        return ""
    try:
        return value.decode("utf-8", errors="replace")
    except Exception:
        return ""


def extract_pe_imports(sample_path: Path) -> dict[str, list[str]]:
    if pefile is None:
        raise RuntimeError("pefile not installed")

    pe = pefile.PE(str(sample_path))
    imports: dict[str, list[str]] = {}

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = _decode_name(getattr(entry, "dll", b"")).lower()
        funcs: list[str] = []

        for imp in getattr(entry, "imports", []):
            name = _decode_name(getattr(imp, "name", None))
            if name:
                funcs.append(name)

        imports[dll_name] = sorted(set(funcs))

    return imports


def categorize_apis(imports: dict[str, list[str]]) -> dict[str, list[str]]:
    all_funcs = set()
    for funcs in imports.values():
        all_funcs.update(funcs)

    categorized: dict[str, list[str]] = {}
    for category, api_set in API_CATEGORIES.items():
        hits = sorted(f for f in all_funcs if f in api_set)
        if hits:
            categorized[category] = hits

    return categorized


def detect_api_chains(imports: dict[str, list[str]]) -> list[dict[str, Any]]:
    all_funcs = set()
    for funcs in imports.values():
        all_funcs.update(funcs)

    findings: list[dict[str, Any]] = []

    for name, rule in API_CHAINS.items():
        all_of = set(rule.get("all_of", set()))
        any_of = set(rule.get("any_of", set()))

        all_of_present = True
        if all_of:
            grouped_hits = {x for x in all_funcs if x in all_of}
            if len(grouped_hits) < 2 and len(all_of) > 1:
                all_of_present = False
            elif len(grouped_hits) == 0:
                all_of_present = False

        any_of_present = True
        any_hits = set()
        if any_of:
            any_hits = {x for x in all_funcs if x in any_of}
            any_of_present = len(any_hits) > 0

        if all_of_present and any_of_present:
            hits = sorted(({x for x in all_funcs if x in all_of} | any_hits))
            findings.append(
                {
                    "name": name,
                    "severity": rule.get("severity", "low"),
                    "matched_apis": hits,
                }
            )

    return findings


def analyze_apis(sample_path: str | Path, case_dir: str | Path) -> dict[str, Any]:
    sample_path = Path(sample_path)
    case_dir = Path(case_dir)

    result: dict[str, Any] = {
        "returncode": 0,
        "error": "",
        "imports_by_dll": {},
        "all_imports": [],
        "category_hits": {},
        "chain_findings": [],
        "summary": {
            "dll_count": 0,
            "import_count": 0,
            "category_count": 0,
            "high_severity_chain_count": 0,
        },
    }

    try:
        imports = extract_pe_imports(sample_path)
        categorized = categorize_apis(imports)
        chains = detect_api_chains(imports)

        all_imports = sorted({fn for funcs in imports.values() for fn in funcs})

        result["imports_by_dll"] = imports
        result["all_imports"] = all_imports
        result["category_hits"] = categorized
        result["chain_findings"] = chains
        result["summary"] = {
            "dll_count": len(imports),
            "import_count": len(all_imports),
            "category_count": len(categorized),
            "high_severity_chain_count": sum(1 for x in chains if x.get("severity") == "high"),
        }

    except Exception as e:
        result["returncode"] = 1
        result["error"] = f"{type(e).__name__}: {e}"

    _safe_write_json(case_dir / "api_analysis.json", result)
    return result
