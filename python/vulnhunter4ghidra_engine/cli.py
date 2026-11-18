"""VulnHunter4Ghidra standalone CLI — run vulnerability scans without Ghidra.

Usage:
    vulnhunter scan   <binary>               # quick source/sink identification
    vulnhunter taint  <binary> [--depth N]    # full taint analysis
    vulnhunter report <binary> [--json]       # scan + taint + report

Designed for CI/CD integration: exits 0 if no findings, 1 if findings found,
2 on error. JSON output (--json) is machine-parseable.
"""
import argparse
import json
import logging
import sys

logger = logging.getLogger("vulnhunter4ghidra")


def _normalize_func_name(name: str) -> str:
    """Normalize platform-specific function names to canonical form.

    Handles: macOS leading underscore (_fgets -> fgets),
    hardened variants (___memcpy_chk -> memcpy, ___sprintf_chk -> sprintf).
    """
    if name.startswith("___") and name.endswith("_chk"):
        name = name[3:-4]
    name = name.lstrip("_")
    return name


def _build_stub_map(project) -> dict[int, str]:
    """Map Mach-O stub addresses to resolved import names.

    On Mach-O, external calls go through short stub functions that jump
    through GOT slots. angr names these sub_XXXXX instead of the import name.
    """
    main_obj = project.loader.main_object
    if not hasattr(main_obj, "imports"):
        return {}

    got_to_name: dict[int, str] = {}
    for imp_name, reloc in main_obj.imports.items():
        if reloc.rebased_addr:
            got_to_name[reloc.rebased_addr] = _normalize_func_name(imp_name)

    if not got_to_name:
        return {}

    stub_map: dict[int, str] = {}
    for addr, func in project.kb.functions.items():
        if func.is_simprocedure or len(func.graph) != 1:
            continue
        block = next(iter(func.graph.nodes()))
        try:
            irsb = project.factory.block(block.addr, size=block.size).vex
            for stmt in irsb.statements:
                if hasattr(stmt, "constants"):
                    for const in stmt.constants:
                        if const.value in got_to_name:
                            stub_map[addr] = got_to_name[const.value]
        except Exception:
            pass
    return stub_map


def _build_function_info(project) -> list[dict]:
    """Extract function metadata from angr's knowledge base."""
    from .sinks import get_sink_functions
    from .sources import INPUT_FUNCTIONS

    known_callees = set(INPUT_FUNCTIONS.keys()) | get_sink_functions()
    kb_funcs = project.kb.functions
    main_obj = project.loader.main_object

    stub_map = _build_stub_map(project)

    exported = set()
    for sym in main_obj.symbols:
        if sym.is_export:
            exported.add(sym.rebased_addr)

    export_names: dict[int, str] = {}
    for sym in main_obj.symbols:
        if sym.is_export and sym.rebased_addr:
            export_names[sym.rebased_addr] = _normalize_func_name(sym.name)

    func_name_map: dict[int, str] = {}
    for addr, func in kb_funcs.items():
        if addr in stub_map:
            func_name_map[addr] = stub_map[addr]
        elif addr in export_names:
            func_name_map[addr] = export_names[addr]
        else:
            func_name_map[addr] = _normalize_func_name(func.name)

    results = []
    for addr, func in kb_funcs.items():
        if func.is_simprocedure or func.is_plt:
            continue
        if len(func.graph) < 2:
            continue

        clean_name = func_name_map.get(addr, func.name)

        callsites = []
        for site in func.get_call_sites():
            target_addr = func.get_call_target(site)
            if target_addr is not None and target_addr in kb_funcs:
                callee_name = func_name_map.get(target_addr, kb_funcs[target_addr].name)
                if callee_name in known_callees:
                    callsites.append({
                        "address": site,
                        "callee_name": callee_name,
                    })

        results.append({
            "func_addr": addr,
            "func_name": clean_name,
            "callsites": callsites,
            "params": [],
            "is_exported": addr in exported,
        })
    return results


def cmd_scan(args):
    import angr
    from .engine import VulnHunterEngine

    engine = VulnHunterEngine()
    engine.init(args.binary)

    logger.info("Building CFG...")
    engine.project.analyses.CFGFast(normalize=True, show_progressbar=False)
    funcs = _build_function_info(engine.project)
    logger.info("Scanning %d functions...", len(funcs))

    total_sources = 0
    total_sinks = 0
    for fi in funcs:
        result = engine.scan_function(
            func_addr=fi["func_addr"],
            func_name=fi["func_name"],
            callsites=fi["callsites"],
            params=fi["params"],
            is_exported=fi["is_exported"],
        )
        total_sources += result["sources_found"]
        total_sinks += result["sinks_found"]

    if args.json:
        print(json.dumps({
            "binary": args.binary,
            "functions_scanned": len(funcs),
            "sources": engine.get_sources(),
            "sinks": engine.get_sinks(),
        }, indent=2))
    else:
        print(f"Binary: {args.binary}")
        print(f"Functions scanned: {len(funcs)}")
        print(f"Sources found: {total_sources}")
        print(f"Sinks found: {total_sinks}")
        if total_sources:
            print("\nSources:")
            for s in engine.get_sources():
                print(f"  [{s['source_type']}] {s['func_name']} @ {s['address']}: {s['description']}")
        if total_sinks:
            print("\nSinks:")
            for s in engine.get_sinks():
                print(f"  [{s['sink_type']}] {s['func_name']} @ {s['address']}: {s['callee_name']}() [{s['cwe']}]")


def cmd_taint(args):
    import angr
    from .engine import VulnHunterEngine

    engine = VulnHunterEngine()
    engine.init(args.binary)

    logger.info("Building CFG...")
    engine.project.analyses.CFGFast(normalize=True, show_progressbar=False)
    funcs = _build_function_info(engine.project)
    logger.info("Scanning %d functions...", len(funcs))

    for fi in funcs:
        engine.scan_function(
            func_addr=fi["func_addr"],
            func_name=fi["func_name"],
            callsites=fi["callsites"],
            params=fi["params"],
            is_exported=fi["is_exported"],
        )

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
                print(f"  [{sev}] {f['cwe']} — {f['title']}")
                print(f"         {f['description']}")
                tp = f["taint_path"]
                print(f"         Path: {' → '.join(tp['path_funcs'])} ({tp['path_length']} nodes)")
                print()

    sys.exit(1 if findings else 0)


def cmd_report(args):
    import angr
    from .engine import VulnHunterEngine

    engine = VulnHunterEngine()
    engine.init(args.binary)

    logger.info("Building CFG...")
    engine.project.analyses.CFGFast(normalize=True, show_progressbar=False)
    funcs = _build_function_info(engine.project)
    logger.info("Scanning %d functions...", len(funcs))

    for fi in funcs:
        engine.scan_function(
            func_addr=fi["func_addr"],
            func_name=fi["func_name"],
            callsites=fi["callsites"],
            params=fi["params"],
            is_exported=fi["is_exported"],
        )

    logger.info("Running taint analysis...")
    result = engine.analyze_taint(max_depth=args.depth)
    findings = result["findings"]

    report = {
        "binary": args.binary,
        "arch": engine.project.arch.name,
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
                print(f"\n#{i} [{sev}] {f['cwe']} — {f['title']}")
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
