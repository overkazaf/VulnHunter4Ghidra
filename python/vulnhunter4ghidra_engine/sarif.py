"""OASIS SARIF 2.1.0 report generator and baseline fingerprint loader."""
from __future__ import annotations

import json
from pathlib import Path

from . import __init__ as _pkg  # noqa: F401

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_VERSION = "2.0.0"

_CWE_METADATA: dict[str, tuple[str, str, str]] = {
    # cwe -> (short_name, full_description, security_severity_score)
    "CWE-78": (
        "OSCommandInjection",
        "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection').",
        "9.8",
    ),
    "CWE-119": (
        "ImproperMemoryBounds",
        "Improper Restriction of Operations within the Bounds of a Memory Buffer.",
        "9.0",
    ),
    "CWE-120": (
        "BufferCopyWithoutCheckingSize",
        "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow').",
        "8.8",
    ),
    "CWE-134": (
        "UncontrolledFormatString",
        "Use of Externally-Controlled Format String.",
        "9.0",
    ),
    "CWE-190": (
        "IntegerOverflow",
        "Integer Overflow or Wraparound feeding memory allocation or copy size.",
        "7.8",
    ),
    "CWE-415": (
        "DoubleFree",
        "Double Free of heap memory resource without intervening reassignment.",
        "8.8",
    ),
    "CWE-416": (
        "UseAfterFree",
        "Use After Free — dereference or call argument use of deallocated memory.",
        "8.8",
    ),
    "CWE-476": (
        "NULLPointerDereference",
        "NULL Pointer Dereference of unchecked allocation return value.",
        "5.9",
    ),
    "CWE-787": (
        "OutOfBoundsWrite",
        "Out-of-bounds Write to stack or heap memory buffer.",
        "9.0",
    ),
}

_SEVERITY_TO_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def findings_to_sarif(
    findings: list[dict],
    binary_path: str | None = None,
    arch: str | None = None,
) -> dict:
    """Convert serialized VulnFinding dicts into a valid SARIF 2.1.0 document."""
    artifact_uri = Path(binary_path).name if binary_path else "binary"
    seen_cwes: list[str] = []
    for f in findings:
        cwe = f.get("cwe", "CWE-119")
        if cwe not in seen_cwes:
            seen_cwes.append(cwe)

    rules = []
    for cwe in seen_cwes:
        short_name, desc, score = _CWE_METADATA.get(
            cwe, ("BinaryVulnerability", f"Potential binary vulnerability ({cwe}).", "7.0")
        )
        rules.append({
            "id": cwe,
            "name": short_name,
            "shortDescription": {"text": f"{cwe}: {short_name}"},
            "fullDescription": {"text": desc},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html",
            "properties": {
                "tags": ["security", "binary", f"external/cwe/{cwe.lower()}"],
                "security-severity": score,
            },
        })

    results = []
    for f in findings:
        cwe = f.get("cwe", "CWE-119")
        sev = f.get("severity", "medium").lower()
        level = _SEVERITY_TO_SARIF_LEVEL.get(sev, "warning")
        tp = f.get("taint_path", {})
        src = tp.get("source", {})
        snk = tp.get("sink", {})
        sink_addr_hex = snk.get("address", "0x0")
        sink_addr_int = int(sink_addr_hex, 16) if isinstance(sink_addr_hex, str) else int(sink_addr_hex)

        thread_locs = []
        if src:
            src_hex = src.get("address", "0x0")
            thread_locs.append({
                "location": {
                    "message": {
                        "text": f"Source ({src.get('source_type', 'input')}): {src.get('description', '')}"
                    },
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_uri},
                        "address": {
                            "absoluteAddress": int(src_hex, 16) if isinstance(src_hex, str) else int(src_hex),
                        },
                    },
                    "logicalLocations": [
                        {"name": src.get("func_name", ""), "kind": "function"}
                    ],
                }
            })

        path_addrs = tp.get("path_addrs", [])
        path_funcs = tp.get("path_funcs", [])
        for idx, hop_hex in enumerate(path_addrs):
            fn_name = path_funcs[idx] if idx < len(path_funcs) else ""
            thread_locs.append({
                "location": {
                    "message": {"text": f"Propagation hop {idx + 1} in {fn_name or 'block'} @ {hop_hex}"},
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_uri},
                        "address": {
                            "absoluteAddress": int(hop_hex, 16) if isinstance(hop_hex, str) else int(hop_hex),
                        },
                    },
                }
            })

        if snk:
            thread_locs.append({
                "location": {
                    "message": {
                        "text": f"Sink: {snk.get('callee_name', '')}() in {snk.get('func_name', '')}"
                    },
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_uri},
                        "address": {"absoluteAddress": sink_addr_int},
                    },
                    "logicalLocations": [
                        {"name": snk.get("func_name", ""), "kind": "function"}
                    ],
                }
            })

        result_entry = {
            "ruleId": cwe,
            "level": level,
            "message": {
                "text": f"{f.get('title', cwe)} — {f.get('description', '')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_uri},
                        "address": {"absoluteAddress": sink_addr_int},
                    },
                    "logicalLocations": [
                        {
                            "name": snk.get("func_name", ""),
                            "fullyQualifiedName": snk.get("func_name", ""),
                            "kind": "function",
                        }
                    ],
                }
            ],
            "partialFingerprints": {
                "vulnhunterFindingHash/v1": f.get("fingerprint", ""),
            },
            "codeFlows": [
                {
                    "threadFlows": [
                        {"locations": thread_locs}
                    ]
                }
            ],
            "properties": {
                "severity": sev,
                "confidence": f.get("confidence", "medium"),
                "verified": bool(f.get("verified", False)),
                "evidence": f.get("evidence", []),
            },
        }
        results.append(result_entry)

    run_props = {}
    if arch:
        run_props["architecture"] = arch

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnHunter4Ghidra",
                        "version": TOOL_VERSION,
                        "informationUri": "https://overkazaf.github.io/VulnHunter4Ghidra/",
                        "rules": rules,
                    }
                },
                "artifacts": [
                    {"location": {"uri": artifact_uri}}
                ],
                "results": results,
                "properties": run_props,
            }
        ],
    }


def load_baseline_fingerprints(baseline_path: str | Path) -> set[str]:
    """Extract finding fingerprints from either a VulnHunter JSON report or a SARIF 2.1.0 file."""
    data = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    fps: set[str] = set()

    # Format 1: SARIF 2.1.0
    if "runs" in data:
        for run in data.get("runs", []):
            for res in run.get("results", []):
                pfp = res.get("partialFingerprints", {})
                val = pfp.get("vulnhunterFindingHash/v1")
                if val:
                    fps.add(val)
        return fps

    # Format 2: VulnHunter JSON report / taint output
    for f in data.get("findings", []):
        fp = f.get("fingerprint")
        if fp:
            fps.add(fp)
    return fps
