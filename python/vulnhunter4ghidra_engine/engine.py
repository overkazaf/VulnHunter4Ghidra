import logging
from .models import Source, Sink, TaintPath, VulnFinding, classify_severity
from .sources import (
    identify_sources_from_callsites,
    identify_sources_from_params,
    identify_argv_source,
)
from .sinks import identify_sinks
from .taint import find_taint_paths_intraprocedural, find_taint_paths_interprocedural

logger = logging.getLogger("vulnhunter4ghidra")


class VulnHunterEngine:
    def __init__(self):
        self.project = None
        self.binary_path: str | None = None
        self._finding_counter = 0
        self._all_sources: list[Source] = []
        self._all_sinks: list[Sink] = []
        self._findings: list[VulnFinding] = []

    def init(self, binary_path: str) -> dict:
        import angr
        self.project = angr.Project(binary_path, auto_load_libs=False)
        self.binary_path = binary_path
        self._finding_counter = 0
        self._all_sources = []
        self._all_sinks = []
        self._findings = []
        logger.info("Loaded binary: %s (%s)", binary_path, self.project.arch.name)
        return {
            "arch": self.project.arch.name,
            "entry": hex(self.project.entry),
            "binary": binary_path,
        }

    def scan_function(
        self,
        func_addr: int,
        func_name: str,
        callsites: list[dict],
        params: list[dict],
        is_exported: bool = False,
    ) -> dict:
        """Scan a single function for sources and sinks. Returns counts."""
        sources = identify_sources_from_callsites(func_addr, func_name, callsites)
        sources += identify_sources_from_params(func_addr, func_name, params, is_exported)
        argv_src = identify_argv_source(func_addr, func_name, params)
        if argv_src:
            sources.append(argv_src)

        sinks = identify_sinks(func_addr, func_name, callsites)

        self._all_sources.extend(sources)
        self._all_sinks.extend(sinks)

        return {
            "func_addr": hex(func_addr),
            "func_name": func_name,
            "sources_found": len(sources),
            "sinks_found": len(sinks),
            "sources": [s.to_dict() for s in sources],
            "sinks": [s.to_dict() for s in sinks],
        }

    def analyze_taint(self, max_depth: int = 5) -> dict:
        """Run taint analysis across all collected sources and sinks."""
        if self.project is None:
            raise RuntimeError("Binary not loaded — call init first")

        self.project.analyses.CFGFast(normalize=True, show_progressbar=False)

        intra_by_func: dict[int, tuple[list[Source], list[Sink]]] = {}
        for src in self._all_sources:
            intra_by_func.setdefault(src.func_addr, ([], []))[0].append(src)
        for snk in self._all_sinks:
            intra_by_func.setdefault(snk.func_addr, ([], []))[1].append(snk)

        all_paths: list[TaintPath] = []

        for func_addr, (func_sources, func_sinks) in intra_by_func.items():
            if func_sources and func_sinks:
                paths = find_taint_paths_intraprocedural(
                    self.project, func_addr, func_sources, func_sinks,
                )
                all_paths.extend(paths)

        inter_paths = find_taint_paths_interprocedural(
            self.project, self._all_sources, self._all_sinks, max_depth,
        )
        all_paths.extend(inter_paths)

        seen = set()
        unique_paths = []
        for p in all_paths:
            key = (p.source.address, p.sink.address)
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
                title=f"{path.sink.sink_type.value}: {path.sink.callee_name} in {path.sink.func_name}",
                description=(
                    f"User-controlled data from {path.source.description} "
                    f"flows to {path.sink.callee_name}() at {hex(path.sink.address)}"
                ),
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

    def get_findings(self) -> list[dict]:
        return [f.to_dict() for f in self._findings]

    def get_sources(self) -> list[dict]:
        return [s.to_dict() for s in self._all_sources]

    def get_sinks(self) -> list[dict]:
        return [s.to_dict() for s in self._all_sinks]
