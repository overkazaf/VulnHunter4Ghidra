"""VulnHunter4Ghidra standalone CLI — run vulnerability scans without Ghidra.

Usage:
    vulnhunter scan   <binary> [--rules FILE] [--json]
    vulnhunter taint  <binary> [--depth N] [--verify] [--rules FILE] [--format text|json|sarif]
    vulnhunter report <binary> [--depth N] [--verify] [--baseline FILE] [--fail-on SEV] [--format text|json|sarif] [-o OUT]

Designed for CI/CD integration: exits 0 if no gating findings, 1 if findings trigger gate,
2 on error. Supports JSON and OASIS SARIF 2.1.0 outputs plus baseline diff gating.
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys

from .engine import VulnHunterEngine, resolve_import_stubs
from .rules import canonical_func_name
from .sarif import findings_to_sarif, load_baseline_fingerprints
from .taint import _get_abi_reg_offsets

logger = logging.getLogger("vulnhunter4ghidra")

_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

_CONFIDENCE_RANK = {
    "high": 3,
    "medium": 2,
    "low": 1,
}


def _normalize_func_name(name: str) -> str:
    """Normalize platform-specific function names to canonical form."""
    return canonical_func_name(name)


def _build_stub_map(project) -> dict[int, str]:
    raw_map = resolve_import_stubs(project)
    return {addr: canonical_func_name(name) for addr, name in raw_map.items()}


def _infer_cli_params(project, func, clean_name: str, treat_as_library_export: bool) -> list[dict]:
    """Infer function parameter descriptors for standalone CLI binaries."""
    if clean_name in ("main", "wmain"):
        return [
            {"index": 0, "name": "argc", "type": "int"},
            {"index": 1, "name": "argv", "type": "char * *"},
        ]
    if not treat_as_library_export:
        return []

    arg_offsets, _, _, _ = _get_abi_reg_offsets(project)
    if not arg_offsets:
        return []

    used_arg_indices: set[int] = set()
    written_regs: set[int] = set()
    try:
        entry_block = project.factory.block(func.addr)
        irsb = entry_block.vex
        for stmt in irsb.statements:
            stag = getattr(stmt, "tag", "")
            for expr in getattr(stmt, "expressions", []):
                if getattr(expr, "tag", "") == "Iex_Get" and expr.offset not in written_regs:
                    if expr.offset in arg_offsets:
                        used_arg_indices.add(arg_offsets.index(expr.offset))
            if stag == "Ist_Put":
                written_regs.add(stmt.offset)
    except Exception:
        pass

    return [
        {"index": idx, "name": f"arg{idx}", "type": "void *"}
        for idx in sorted(used_arg_indices)
    ]


def _build_function_info(project, registry=None) -> list[dict]:
    """Extract function metadata from angr's knowledge base."""
    from .rules import ALLOCATOR_FUNCTIONS, DEALLOCATOR_FUNCTIONS
    from .sinks import get_sink_functions
    from .sources import get_source_functions

    known_callees = (
        get_source_functions(registry)
        | get_sink_functions(registry)
        | set(ALLOCATOR_FUNCTIONS.keys())
        | set(DEALLOCATOR_FUNCTIONS.keys())
    )
    kb_funcs = project.kb.functions
    main_obj = project.loader.main_object

    stub_map = _build_stub_map(project)

    exported = set()
    export_names: dict[int, str] = {}
    for sym in main_obj.symbols:
        if sym.is_export and sym.rebased_addr:
            exported.add(sym.rebased_addr)
            export_names[sym.rebased_addr] = _normalize_func_name(sym.name)

    func_name_map: dict[int, str] = {}
    has_main = False
    for addr, func in kb_funcs.items():
        if addr in stub_map:
            cname = stub_map[addr]
        elif addr in export_names:
            cname = export_names[addr]
        else:
            cname = _normalize_func_name(func.name)
        func_name_map[addr] = cname
        if cname in ("main", "wmain") and not func.is_plt and not func.is_simprocedure:
            has_main = True

    is_shared_lib = not has_main

    results = []
    for addr, func in kb_funcs.items():
        if func.is_simprocedure or func.is_plt or addr in stub_map:
            continue
        if len(func.graph) < 1:
            continue

        clean_name = func_name_map.get(addr, func.name)
        if clean_name.startswith("_") or clean_name in (
            "start", "deregister_tm_clones", "register_tm_clones",
            "frame_dummy", "call_weak_fn", "fini", "init",
        ):
            continue

        callsites = []
        for site_block in func.get_call_sites():
            target_addr = func.get_call_target(site_block)
            if target_addr is not None and target_addr in kb_funcs:
                callee_raw = kb_funcs[target_addr].name
                callee_canon = func_name_map.get(target_addr, _normalize_func_name(callee_raw))
                if callee_canon in known_callees:
                    call_ins_addr = site_block
                    try:
                        blk = project.factory.block(site_block)
                        if blk.instruction_addrs:
                            call_ins_addr = blk.instruction_addrs[-1]
                    except Exception:
                        pass
                    callsites.append({
                        "address": call_ins_addr,
                        "callee_name": callee_raw if "chk" in callee_raw else callee_canon,
                    })

        is_exp = addr in exported
        params = _infer_cli_params(project, func, clean_name, is_shared_lib and is_exp)

        if not callsites and not params:
            continue

        results.append({
            "func_addr": addr,
            "func_name": clean_name,
            "callsites": callsites,
            "params": params,
            "is_exported": is_shared_lib and is_exp,
        })
    return results


def _prepare_engine_scan(binary_path: str, rules_path: str | None = None) -> tuple[VulnHunterEngine, list[dict]]:
    engine = VulnHunterEngine()
    engine.init(binary_path)
    if rules_path:
        engine.load_rules(rules_path)
    logger.info("Building CFG...")
    engine.ensure_cfg()
    funcs = _build_function_info(engine.project, registry=engine.rules)
    logger.info("Scanning %d functions...", len(funcs))
    for fi in funcs:
        engine.scan_function(
            func_addr=fi["func_addr"],
            func_name=fi["func_name"],
            callsites=fi["callsites"],
            params=fi["params"],
            is_exported=fi["is_exported"],
        )
    return engine, funcs


def _resolve_output_format(args) -> str:
    fmt = getattr(args, "format", None)
    if fmt:
        return fmt
    if getattr(args, "json", False):
        return "json"
    return "text"


def _emit_output(text: str, output_path: str | None) -> None:
    if output_path:
        Path(output_path).write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
    else:
        print(text)


def _filter_findings(
    findings: list[dict],
    baseline_path: str | None,
    min_confidence: str,
) -> tuple[list[dict], int]:
    min_conf_rank = _CONFIDENCE_RANK.get(min_confidence, 1)
    baseline_fps = load_baseline_fingerprints(baseline_path) if baseline_path else set()

    kept = []
    baseline_suppressed = 0
    for f in findings:
        conf_rank = _CONFIDENCE_RANK.get(f.get("confidence", "medium"), 2)
        if conf_rank < min_conf_rank:
            continue
        if baseline_fps and f.get("fingerprint") in baseline_fps:
            baseline_suppressed += 1
            continue
        kept.append(f)
    return kept, baseline_suppressed


def _should_fail_gate(findings: list[dict], fail_on: str) -> bool:
    threshold = _SEVERITY_RANK.get(fail_on, 0)
    return any(_SEVERITY_RANK.get(f.get("severity", "medium"), 2) >= threshold for f in findings)


def cmd_scan(args):
    engine, funcs = _prepare_engine_scan(args.binary, rules_path=args.rules)
    sources = engine.get_sources()
    sinks = engine.get_sinks()

    if args.json:
        _emit_output(json.dumps({
            "binary": args.binary,
            "functions_scanned": len(funcs),
            "sources": sources,
            "sinks": sinks,
        }, indent=2), args.output)
    else:
        lines = [
            f"Binary: {args.binary}",
            f"Functions scanned: {len(funcs)}",
            f"Sources found: {len(sources)}",
            f"Sinks found: {len(sinks)}",
        ]
        if sources:
            lines.append("\nSources:")
            for s in sources:
                lines.append(f"  [{s['source_type']}] {s['func_name']} @ {s['address']}: {s['description']}")
        if sinks:
            lines.append("\nSinks:")
            for s in sinks:
                lines.append(f"  [{s['sink_type']}] {s['func_name']} @ {s['address']}: {s['callee_name']}() [{s['cwe']}]")
        _emit_output("\n".join(lines), args.output)


def cmd_taint(args):
    engine, _ = _prepare_engine_scan(args.binary, rules_path=args.rules)
    logger.info("Running taint analysis (depth=%d, verify=%s)...", args.depth, args.verify)
    result = engine.analyze_taint(max_depth=args.depth, verify_symbolic=args.verify)
    findings, suppressed = _filter_findings(
        result["findings"], args.baseline, args.min_confidence,
    )
    result["findings"] = findings
    result["taint_paths"] = len(findings)
    if args.baseline:
        result["suppressed_by_baseline"] = suppressed

    fmt = _resolve_output_format(args)
    if fmt == "sarif":
        sarif_doc = findings_to_sarif(findings, binary_path=args.binary, arch=engine.project.arch.name)
        _emit_output(json.dumps(sarif_doc, indent=2), args.output)
    elif fmt == "json":
        _emit_output(json.dumps(result, indent=2), args.output)
    else:
        lines = [
            f"Sources: {result['total_sources']}, Sinks: {result['total_sinks']}",
            f"Taint paths: {result['taint_paths']}, Findings: {len(findings)}",
        ]
        if suppressed:
            lines.append(f"Suppressed by baseline: {suppressed}")
        if findings:
            lines.append("")
            for f in findings:
                sev = f["severity"].upper()
                conf = f.get("confidence", "medium").upper()
                ver = " [Z3-VERIFIED]" if f.get("verified") else ""
                lines.append(f"  [{sev} | conf:{conf}]{ver} {f['cwe']} — {f['title']}")
                lines.append(f"         {f['description']}")
                tp = f["taint_path"]
                lines.append(f"         Path: {' → '.join(tp['path_funcs'])} ({tp['path_length']} nodes)")
                lines.append("")
        _emit_output("\n".join(lines), args.output)

    sys.exit(1 if _should_fail_gate(findings, args.fail_on) else 0)


def cmd_report(args):
    engine, funcs = _prepare_engine_scan(args.binary, rules_path=args.rules)
    logger.info("Running taint analysis (depth=%d, verify=%s)...", args.depth, args.verify)
    result = engine.analyze_taint(max_depth=args.depth, verify_symbolic=args.verify)
    findings, suppressed = _filter_findings(
        result["findings"], args.baseline, args.min_confidence,
    )

    report = {
        "binary": args.binary,
        "arch": engine.project.arch.name,
        "base_addr": hex(engine.base_addr) if engine.base_addr is not None else None,
        "functions_scanned": len(funcs),
        "total_sources": result["total_sources"],
        "total_sinks": result["total_sinks"],
        "taint_paths": len(findings),
        "findings_count": len(findings),
        "suppressed_by_baseline": suppressed,
        "findings": findings,
        "severity_summary": {},
    }
    for f in findings:
        sev = f["severity"]
        report["severity_summary"][sev] = report["severity_summary"].get(sev, 0) + 1

    fmt = _resolve_output_format(args)
    if fmt == "sarif":
        sarif_doc = findings_to_sarif(findings, binary_path=args.binary, arch=engine.project.arch.name)
        _emit_output(json.dumps(sarif_doc, indent=2), args.output)
    elif fmt == "json":
        _emit_output(json.dumps(report, indent=2), args.output)
    else:
        lines = [
            "=" * 60,
            f"VulnHunter4Ghidra Report — {args.binary}",
            "=" * 60,
            f"Architecture: {report['arch']}",
            f"Functions:    {report['functions_scanned']}",
            f"Sources:      {report['total_sources']}",
            f"Sinks:        {report['total_sinks']}",
            f"Findings:     {report['findings_count']}",
        ]
        if suppressed:
            lines.append(f"Suppressed:   {suppressed} (matched baseline)")
        if report["severity_summary"]:
            lines.append(f"  Severity:   {report['severity_summary']}")
        lines.append("-" * 60)
        if findings:
            for i, f in enumerate(findings, 1):
                sev = f["severity"].upper()
                conf = f.get("confidence", "medium").upper()
                ver = " [Z3-VERIFIED]" if f.get("verified") else ""
                lines.append(f"\n#{i} [{sev} | {conf}]{ver} {f['cwe']} — {f['title']}")
                lines.append(f"   {f['description']}")
                tp = f["taint_path"]
                src = tp["source"]
                snk = tp["sink"]
                lines.append(f"   Source: {src['func_name']} @ {src['address']} ({src['source_type']})")
                lines.append(f"   Sink:   {snk['func_name']} @ {snk['address']} ({snk['callee_name']})")
                lines.append(f"   Path:   {' → '.join(tp['path_funcs'])}")
        else:
            lines.append("\nNo vulnerabilities found.")
        lines.append("=" * 60)
        _emit_output("\n".join(lines), args.output)

    sys.exit(1 if _should_fail_gate(findings, args.fail_on) else 0)


def _add_common_analysis_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("binary", help="Path to the binary to analyze")
    p.add_argument("--depth", type=int, default=5, help="Max inter-procedural call depth (default: 5)")
    p.add_argument("--verify", action="store_true", help="Enable bounded Z3 symbolic path verification")
    p.add_argument("--rules", default=None, help="Path to custom rules file (.toml / .json)")
    p.add_argument("--baseline", default=None, help="Suppress findings present in baseline (.json or .sarif)")
    p.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="Minimum severity that causes exit code 1 (default: info = any finding)",
    )
    p.add_argument(
        "--min-confidence",
        choices=["high", "medium", "low"],
        default="low",
        help="Filter out findings below confidence level (default: low)",
    )
    p.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default=None,
        help="Output format: text, json, or sarif (SARIF 2.1.0)",
    )
    p.add_argument("--json", action="store_true", help="Shorthand for --format json")
    p.add_argument("-o", "--output", default=None, help="Write report to file instead of stdout")


def main():
    parser = argparse.ArgumentParser(
        prog="vulnhunter",
        description="VulnHunter4Ghidra — Binary CWE & taint vulnerability scanner",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Identify sources and sinks")
    p_scan.add_argument("binary", help="Path to the binary to analyze")
    p_scan.add_argument("--rules", default=None, help="Path to custom rules file (.toml / .json)")
    p_scan.add_argument("--json", action="store_true", help="Output JSON")
    p_scan.add_argument("-o", "--output", default=None, help="Write output to file")

    p_taint = sub.add_parser("taint", help="Run full taint & CWE lifecycle analysis")
    _add_common_analysis_args(p_taint)

    p_report = sub.add_parser("report", help="Generate full vulnerability report (text, JSON, or SARIF)")
    _add_common_analysis_args(p_report)

    args = parser.parse_args()

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[vulnhunter] %(levelname)s %(message)s",
    )

    try:
        {"scan": cmd_scan, "taint": cmd_taint, "report": cmd_report}[args.command](args)
    except Exception as e:
        logger.error("Fatal: %s", e)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()
