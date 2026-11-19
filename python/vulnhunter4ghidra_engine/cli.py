"""VulnHunter4Ghidra standalone CLI — run vulnerability scans without Ghidra.

Usage:
    vulnhunter scan   <binary>               # quick source/sink identification
    vulnhunter taint  <binary> [--depth N]    # full taint analysis
    vulnhunter report <binary> [--json]       # scan + taint + report

Designed for CI/CD integration: exits 0 if no findings, 1 if findings found,
2 on error. JSON output (--json) is machine-parseable.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys

from .engine import VulnHunterEngine, resolve_import_stubs
from .rules import canonical_func_name
from .taint import _get_abi_reg_offsets

logger = logging.getLogger("vulnhunter4ghidra")


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
            # Check expressions reading argument registers before they are overwritten
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


def _prepare_engine_scan(binary_path: str) -> tuple[VulnHunterEngine, list[dict]]:
    engine = VulnHunterEngine()
    engine.init(binary_path)
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


def cmd_scan(args):
    engine, funcs = _prepare_engine_scan(args.binary)
    sources = engine.get_sources()
    sinks = engine.get_sinks()

    if args.json:
        print(json.dumps({
            "binary": args.binary,
            "functions_scanned": len(funcs),
            "sources": sources,
            "sinks": sinks,
        }, indent=2))
    else:
        print(f"Binary: {args.binary}")
        print(f"Functions scanned: {len(funcs)}")
        print(f"Sources found: {len(sources)}")
        print(f"Sinks found: {len(sinks)}")
        if sources:
            print("\nSources:")
            for s in sources:
                print(f"  [{s['source_type']}] {s['func_name']} @ {s['address']}: {s['description']}")
        if sinks:
            print("\nSinks:")
            for s in sinks:
                print(f"  [{s['sink_type']}] {s['func_name']} @ {s['address']}: {s['callee_name']}() [{s['cwe']}]")


def cmd_taint(args):
    engine, _ = _prepare_engine_scan(args.binary)
    logger.info("Running taint analysis (depth=%d)...", args.depth)
    result = engine.analyze_taint(max_depth=args.depth)
    findings = result["findings"]

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Sources: {result['total_sources']}, Sinks: {result['total_sinks']}")
        print(f"Taint paths: {result['taint_paths']}, Findings: {len(findings)}")
        if findings:
            print()
            for f in findings:
                sev = f["severity"].upper()
                conf = f.get("confidence", "medium").upper()
                print(f"  [{sev} | conf:{conf}] {f['cwe']} — {f['title']}")
                print(f"         {f['description']}")
                tp = f["taint_path"]
                print(f"         Path: {' → '.join(tp['path_funcs'])} ({tp['path_length']} nodes)")
                print()

    sys.exit(1 if findings else 0)


def cmd_report(args):
    engine, funcs = _prepare_engine_scan(args.binary)
    logger.info("Running taint analysis...")
    result = engine.analyze_taint(max_depth=args.depth)
    findings = result["findings"]

    report = {
        "binary": args.binary,
        "arch": engine.project.arch.name,
        "base_addr": hex(engine.base_addr) if engine.base_addr is not None else None,
        "functions_scanned": len(funcs),
        "total_sources": result["total_sources"],
        "total_sinks": result["total_sinks"],
        "taint_paths": result["taint_paths"],
        "findings_count": len(findings),
        "findings": findings,
        "severity_summary": {},
    }
    for f in findings:
        sev = f["severity"]
        report["severity_summary"][sev] = report["severity_summary"].get(sev, 0) + 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("=" * 60)
        print(f"VulnHunter4Ghidra Report — {args.binary}")
        print("=" * 60)
        print(f"Architecture: {report['arch']}")
        print(f"Functions:    {report['functions_scanned']}")
        print(f"Sources:      {report['total_sources']}")
        print(f"Sinks:        {report['total_sinks']}")
        print(f"Taint Paths:  {report['taint_paths']}")
        print(f"Findings:     {report['findings_count']}")
        if report["severity_summary"]:
            print(f"  Severity:   {report['severity_summary']}")
        print("-" * 60)
        if findings:
            for i, f in enumerate(findings, 1):
                sev = f["severity"].upper()
                conf = f.get("confidence", "medium").upper()
                print(f"\n#{i} [{sev} | {conf}] {f['cwe']} — {f['title']}")
                print(f"   {f['description']}")
                tp = f["taint_path"]
                src = tp["source"]
                snk = tp["sink"]
                print(f"   Source: {src['func_name']} @ {src['address']} ({src['source_type']})")
                print(f"   Sink:   {snk['func_name']} @ {snk['address']} ({snk['callee_name']})")
                print(f"   Path:   {' → '.join(tp['path_funcs'])}")
        else:
            print("\nNo vulnerabilities found.")
        print("=" * 60)

    sys.exit(1 if findings else 0)


def main():
    parser = argparse.ArgumentParser(
        prog="vulnhunter",
        description="VulnHunter4Ghidra — Binary vulnerability scanner (standalone CLI)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Identify sources and sinks")
    p_scan.add_argument("binary", help="Path to the binary to analyze")
    p_scan.add_argument("--json", action="store_true", help="Output JSON")

    p_taint = sub.add_parser("taint", help="Run full taint analysis")
    p_taint.add_argument("binary", help="Path to the binary to analyze")
    p_taint.add_argument("--depth", type=int, default=5, help="Max call depth (default: 5)")
    p_taint.add_argument("--json", action="store_true", help="Output JSON")

    p_report = sub.add_parser("report", help="Generate full vulnerability report")
    p_report.add_argument("binary", help="Path to the binary to analyze")
    p_report.add_argument("--depth", type=int, default=5, help="Max call depth (default: 5)")
    p_report.add_argument("--json", action="store_true", help="Output JSON for CI/CD")

    args = parser.parse_args()

    logging.basicConfig(
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
