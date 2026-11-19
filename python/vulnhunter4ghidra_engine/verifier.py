"""Bounded Z3 symbolic path feasibility verifier for false-positive reduction.

Strictly evaluates boolean path reachability and constraint satisfiability
(`solver.satisfiable()`) without concretizing or synthesizing inputs.
"""
from __future__ import annotations

import logging
import time

from .models import Confidence, VulnFinding
from .rules import canonical_func_name
from .taint import _find_nearest_node, _is_real_angr_project

logger = logging.getLogger("vulnhunter4ghidra")


def _ensure_stub_hooks(project, func) -> list[int]:
    """Hook external PLT/Mach-O import stubs called by `func` with ReturnUnconstrained
    so symbolic execution returns cleanly to caller with symbolic return values."""
    import angr

    hooked_addrs: list[int] = []
    ret_unconstrained = angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]

    main_obj = project.loader.main_object
    import_names = {
        canonical_func_name(k) for k in getattr(main_obj, "imports", {}).keys()
    }

    for site_block in func.get_call_sites():
        target = func.get_call_target(site_block)
        if target is None or project.is_hooked(target):
            continue
        callee = project.kb.functions.get(target)
        if callee is None:
            continue
        cname = canonical_func_name(callee.name)
        is_stub = (
            callee.is_plt
            or len(callee.graph) <= 1
            or cname in import_names
            or getattr(callee, "has_unresolved_jumps", False)
        )
        if is_stub:
            project.hook(target, ret_unconstrained(display_name=cname or callee.name))
            hooked_addrs.append(target)
    return hooked_addrs


def verify_finding_reachability(
    project,
    finding: VulnFinding,
    max_steps: int = 48,
    max_active: int = 16,
    timeout_sec: float = 2.5,
) -> str:
    """Check symbolic path feasibility for an intra-procedural finding.

    Returns:
        "sat"     — Z3 confirmed a satisfiable execution path to the sink
        "unsat"   — All paths in the function terminated without reaching the sink (infeasible)
        "unknown" — Inter-procedural or bounded budget exceeded
    """
    if not _is_real_angr_project(project):
        return "unknown"

    tp = finding.taint_path
    if tp.source.func_addr != tp.sink.func_addr:
        return "unknown"

    func_addr = tp.sink.func_addr
    func = project.kb.functions.get(func_addr)
    if func is None:
        return "unknown"

    node_map = {n.addr: n for n in func.graph.nodes()}
    snk_node = _find_nearest_node(node_map, tp.sink.address, func.graph)
    if snk_node is None:
        return "unknown"
    target_block_addr = snk_node.addr

    if func_addr == target_block_addr:
        return "sat"

    temp_hooks: list[int] = []
    try:
        import angr
        import claripy

        temp_hooks = _ensure_stub_hooks(project, func)
        opts = {
            angr.options.LAZY_SOLVES,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
        }
        sym_args = [claripy.BVS(f"vh_arg_{i}", project.arch.bits) for i in range(4)]
        state = project.factory.call_state(
            func_addr, *sym_args,
            prototype="int f(long, long, long, long)",
            add_options=opts,
        )
        simgr = project.factory.simulation_manager(state)

        deadline = time.monotonic() + timeout_sec
        steps = 0
        budget_exceeded = False

        stop_points = {tp.sink.address, target_block_addr}

        while simgr.active and steps < max_steps:
            if time.monotonic() > deadline:
                budget_exceeded = True
                break

            # Prune unsatisfiable states (essential with LAZY_SOLVES)
            simgr.drop(stash="active", filter_func=lambda s: not s.solver.satisfiable())

            for s in simgr.active:
                if s.addr in stop_points:
                    return "sat"

            if not simgr.active:
                break

            if len(simgr.active) > max_active:
                simgr.stashes["active"] = simgr.active[:max_active]
                budget_exceeded = True

            simgr.step(extra_stop_points=stop_points)
            steps += 1

        for s in simgr.active:
            if s.addr in stop_points and s.solver.satisfiable():
                return "sat"

        if not simgr.active and not simgr.errored and not budget_exceeded and steps < max_steps:
            return "unsat"
    except Exception as exc:
        logger.debug("Symbolic reachability check skipped for %#x: %s", tp.sink.address, exc)
    finally:
        for haddr in temp_hooks:
            try:
                project.unhook(haddr)
            except Exception:
                pass

    return "unknown"


def verify_findings_batch(
    project,
    findings: list[VulnFinding],
    timeout_per_finding: float = 2.0,
) -> list[VulnFinding]:
    """Verify a list of findings and filter out provably infeasible ('unsat') paths."""
    kept: list[VulnFinding] = []
    for f in findings:
        verdict = verify_finding_reachability(
            project, f, timeout_sec=timeout_per_finding,
        )
        if verdict == "sat":
            f.verified = True
            f.confidence = Confidence.HIGH
            ev_msg = "Z3 symbolic feasibility verified (satisfiable path constraints)"
            if ev_msg not in f.evidence:
                f.evidence.append(ev_msg)
            kept.append(f)
        elif verdict == "unsat":
            logger.info(
                "Filtered infeasible path for %s in %s @ %#x",
                f.cwe, f.taint_path.sink.func_name, f.taint_path.sink.address,
            )
        else:
            kept.append(f)
    return kept
