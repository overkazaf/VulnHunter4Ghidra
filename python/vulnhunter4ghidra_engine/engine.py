from __future__ import annotations

import logging
import threading

from .models import (
    Confidence,
    Sink,
    Source,
    TaintPath,
    VulnFinding,
    classify_severity,
)
from .rules import RuleRegistry, canonical_func_name
from .sinks import identify_sinks
from .sources import (
    identify_argv_source,
    identify_sources_from_callsites,
    identify_sources_from_params,
)
from .taint import find_taint_paths_interprocedural, find_taint_paths_intraprocedural

logger = logging.getLogger("vulnhunter4ghidra")


def resolve_import_stubs(project) -> dict[int, str]:
    """Resolve Mach-O / GOT import stub functions and rename them in project.kb.functions."""
    main_obj = project.loader.main_object
    stub_map: dict[int, str] = {}

    if hasattr(main_obj, "imports") and main_obj.imports:
        got_to_name: dict[int, str] = {}
        for imp_name, reloc in main_obj.imports.items():
            if getattr(reloc, "rebased_addr", None):
                got_to_name[reloc.rebased_addr] = imp_name

        if got_to_name:
            for addr, func in project.kb.functions.items():
                if func.is_simprocedure or len(func.graph) != 1:
                    continue
                block_node = next(iter(func.graph.nodes()))
                try:
                    irsb = project.factory.block(block_node.addr, size=block_node.size).vex
                    for stmt in irsb.statements:
                        if hasattr(stmt, "constants"):
                            for const in stmt.constants:
                                if const.value in got_to_name:
                                    raw_imp = got_to_name[const.value]
                                    stub_map[addr] = raw_imp
                                    func.name = raw_imp
                except Exception:
                    pass

    for sym in getattr(main_obj, "symbols", []):
        if getattr(sym, "is_export", False) and getattr(sym, "rebased_addr", None):
            rebased = sym.rebased_addr
            if rebased in project.kb.functions:
                fn = project.kb.functions[rebased]
                if fn.name.startswith("sub_"):
                    fn.name = sym.name

    return stub_map


class VulnHunterEngine:
    def __init__(self):
        self.project = None
        self.binary_path: str | None = None
        self.base_addr: int | None = None
        self.rules = RuleRegistry()
        self._lock = threading.RLock()
        self._cancel_event = threading.Event()
        self._finding_counter = 0
        self._sources_by_func: dict[int, list[Source]] = {}
        self._sinks_by_func: dict[int, list[Sink]] = {}
        self._all_sources: list[Source] = []
        self._all_sinks: list[Sink] = []
        self._findings: list[VulnFinding] = []

    def cancel(self) -> dict:
        self._cancel_event.set()
        return {"cancelled": True}

    def _rebuild_flat_lists(self) -> None:
        self._all_sources = [
            s for addr in sorted(self._sources_by_func) for s in self._sources_by_func[addr]
        ]
        self._all_sinks = [
            s for addr in sorted(self._sinks_by_func) for s in self._sinks_by_func[addr]
        ]

    def init(self, binary_path: str, base_addr: int | str | None = None) -> dict:
        import angr

        with self._lock:
            self._cancel_event.clear()
            parsed_base: int | None = None
            if base_addr is not None:
                parsed_base = int(base_addr, 16) if isinstance(base_addr, str) else int(base_addr)

            main_opts = {"base_addr": parsed_base} if parsed_base is not None else {}
            self.project = angr.Project(
                binary_path,
                auto_load_libs=False,
                main_opts=main_opts,
            )
            self.binary_path = binary_path
            self.base_addr = self.project.loader.main_object.mapped_base
            self._finding_counter = 0
            self._sources_by_func = {}
            self._sinks_by_func = {}
            self._all_sources = []
            self._all_sinks = []
            self._findings = []
            logger.info(
                "Loaded binary: %s (%s, base=%#x)",
                binary_path,
                self.project.arch.name,
                self.base_addr,
            )
            return {
                "arch": self.project.arch.name,
                "entry": hex(self.project.entry),
                "base_addr": hex(self.base_addr),
                "binary": binary_path,
            }

    def ensure_cfg(self):
        if self.project is None:
            raise RuntimeError("Binary not loaded — call init first")
        with self._lock:
            cfg = self.project.kb.cfgs.get_most_accurate()
            if cfg is None:
                cfg = self.project.analyses.CFGFast(normalize=True, show_progressbar=False)
                resolve_import_stubs(self.project)
            return cfg

    def clear_scan(self) -> dict:
        with self._lock:
            self._sources_by_func.clear()
            self._sinks_by_func.clear()
            self._all_sources = []
            self._all_sinks = []
            self._findings = []
            return {"cleared": True}

    def scan_function(
        self,
        func_addr: int,
        func_name: str,
        callsites: list[dict],
        params: list[dict],
        is_exported: bool = False,
    ) -> dict:
        """Scan a single function for sources and sinks (idempotent per func_addr)."""
        with self._lock:
            sources = identify_sources_from_callsites(
                func_addr, func_name, callsites, registry=self.rules,
            )
            sources += identify_sources_from_params(func_addr, func_name, params, is_exported)
            argv_src = identify_argv_source(func_addr, func_name, params)
            if argv_src:
                sources.append(argv_src)

            sinks = identify_sinks(func_addr, func_name, callsites, registry=self.rules)

            self._sources_by_func[func_addr] = sources
            self._sinks_by_func[func_addr] = sinks
            self._rebuild_flat_lists()

            return {
                "func_addr": hex(func_addr),
                "func_name": func_name,
                "sources_found": len(sources),
                "sinks_found": len(sinks),
                "sources": [s.to_dict() for s in sources],
                "sinks": [s.to_dict() for s in sinks],
            }

    def analyze_taint(self, max_depth: int = 5, func_filter: int | None = None) -> dict:
        """Run taint analysis across collected sources and sinks."""
        if self.project is None:
            raise RuntimeError("Binary not loaded — call init first")

        with self._lock:
            self._cancel_event.clear()
            self.ensure_cfg()

            intra_by_func: dict[int, tuple[list[Source], list[Sink]]] = {}
            for src in self._all_sources:
                if func_filter is not None and src.func_addr != func_filter:
                    continue
                intra_by_func.setdefault(src.func_addr, ([], []))[0].append(src)
            for snk in self._all_sinks:
                if func_filter is not None and snk.func_addr != func_filter:
                    continue
                intra_by_func.setdefault(snk.func_addr, ([], []))[1].append(snk)

            all_paths: list[TaintPath] = []

            for func_addr, (func_sources, func_sinks) in intra_by_func.items():
                if self._cancel_event.is_set():
                    break
                if func_sources and func_sinks:
                    paths = find_taint_paths_intraprocedural(
                        self.project,
                        func_addr,
                        func_sources,
                        func_sinks,
                        registry=self.rules,
                    )
                    all_paths.extend(paths)

            if func_filter is None and not self._cancel_event.is_set():
                inter_paths = find_taint_paths_interprocedural(
                    self.project,
                    self._all_sources,
                    self._all_sinks,
                    max_depth,
                    registry=self.rules,
                )
                all_paths.extend(inter_paths)

            seen = set()
            unique_paths: list[TaintPath] = []
            for p in all_paths:
                key = (p.source.address, p.sink.address, p.sink.cwe)
                if key not in seen:
                    seen.add(key)
                    unique_paths.append(p)

            self._findings = []
            for path in unique_paths:
                self._finding_counter += 1
                cwe = path.sink.cwe
                severity = classify_severity(cwe)
                finding = VulnFinding(
                    finding_id=self._finding_counter,
                    taint_path=path,
                    cwe=cwe,
                    severity=severity,
                    confidence=path.confidence,
                    title=f"{path.sink.sink_type.value}: {path.sink.callee_name} in {path.sink.func_name}",
                    description=(
                        f"User-controlled data from {path.source.description} "
                        f"flows to {path.sink.callee_name}() at {hex(path.sink.address)}"
                    ),
                    evidence=list(path.evidence),
                )
                self._findings.append(finding)

            logger.info(
                "Taint analysis complete: %d paths, %d findings",
                len(unique_paths), len(self._findings),
            )

            return {
                "total_sources": len(self._all_sources),
                "total_sinks": len(self._all_sinks),
                "taint_paths": len(unique_paths),
                "findings": [f.to_dict() for f in self._findings],
            }

    def load_rules(self, path: str) -> dict:
        with self._lock:
            return self.rules.load_file(path)

    def mark_custom_node(
        self,
        role: str,
        func_name: str | None = None,
        address: int | None = None,
        cwe: str = "CWE-120",
        sink_type: str = "buffer_overflow",
        vulnerable_arg_index: int = 0,
    ) -> dict:
        with self._lock:
            if role == "source":
                if func_name:
                    self.rules.add_custom_source_func(func_name)
                if address is not None:
                    self.rules.custom_source_addrs.add(address)
            elif role == "sink":
                if func_name:
                    self.rules.add_custom_sink_func(
                        func_name,
                        sink_type=sink_type,
                        cwe=cwe,
                        vulnerable_arg_index=vulnerable_arg_index,
                    )
                if address is not None:
                    from .models import SinkType
                    from .rules import SinkSpec
                    self.rules.custom_sink_addrs[address] = SinkSpec(
                        sink_type=SinkType(sink_type),
                        cwe=cwe,
                        vulnerable_arg_index=vulnerable_arg_index,
                        tainted_arg_indices=(vulnerable_arg_index,),
                    )
            elif role == "sanitizer":
                if func_name:
                    self.rules.add_sanitizer_func(func_name)
                if address is not None:
                    self.rules.sanitizer_addrs.add(address)
            else:
                raise ValueError(f"Unknown custom role: {role}")
            return {"role": role, "func_name": func_name, "address": hex(address) if address is not None else None}

    def get_findings(self) -> list[dict]:
        with self._lock:
            return [f.to_dict() for f in self._findings]

    def get_sources(self) -> list[dict]:
        with self._lock:
            return [s.to_dict() for s in self._all_sources]

    def get_sinks(self) -> list[dict]:
        with self._lock:
            return [s.to_dict() for s in self._all_sinks]
