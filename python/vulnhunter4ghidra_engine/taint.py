import logging
from .models import Source, Sink, TaintPath

logger = logging.getLogger("vulnhunter4ghidra")


def find_taint_paths_intraprocedural(
    project,
    func_addr: int,
    sources: list[Source],
    sinks: list[Sink],
) -> list[TaintPath]:
    """Find taint paths within a single function using CFG reachability.

    Uses angr's CFG to check if there is a path from each source address
    to each sink address within the function's graph.
    """
    if not sources or not sinks:
        return []

    cfg = project.kb.cfgs.get_most_accurate()
    if cfg is None:
        cfg = project.analyses.CFGFast(
            regions=[(func_addr, func_addr + 0x10000)],
            normalize=True,
            show_progressbar=False,
        )

    func = project.kb.functions.get(func_addr)
    if func is None:
        logger.warning("Function at %#x not found in KB", func_addr)
        return []

    func_graph = func.graph
    node_map: dict[int, object] = {}
    for node in func_graph.nodes():
        node_map[node.addr] = node

    paths = []
    for source in sources:
        for sink in sinks:
            if source.address == sink.address:
                continue
            src_node = _find_nearest_node(node_map, source.address, func_graph)
            snk_node = _find_nearest_node(node_map, sink.address, func_graph)
            if src_node is None or snk_node is None:
                continue
            if src_node == snk_node:
                has_cycle = any(
                    _is_reachable(func_graph, succ, snk_node)
                    for succ in func_graph.successors(src_node)
                )
                if source.address < sink.address or has_cycle:
                    paths.append(TaintPath(
                        source=source,
                        sink=sink,
                        path_addrs=[src_node.addr],
                        path_funcs=[func.name],
                    ))
            elif _is_reachable(func_graph, src_node, snk_node):
                path_addrs = _extract_path_addrs(func_graph, src_node, snk_node)
                paths.append(TaintPath(
                    source=source,
                    sink=sink,
                    path_addrs=path_addrs,
                    path_funcs=[func.name],
                ))
    return paths


def find_taint_paths_interprocedural(
    project,
    sources: list[Source],
    sinks: list[Sink],
    max_depth: int = 5,
) -> list[TaintPath]:
    """Find taint paths across function boundaries using the call graph.

    Checks if a function containing a source can reach a function containing
    a sink within max_depth calls.
    """
    if not sources or not sinks:
        return []

    cfg = project.kb.cfgs.get_most_accurate()
    if cfg is None:
        cfg = project.analyses.CFGFast(normalize=True, show_progressbar=False)

    call_graph = project.kb.callgraph

    source_funcs: dict[int, list[Source]] = {}
    for s in sources:
        source_funcs.setdefault(s.func_addr, []).append(s)

    sink_funcs: dict[int, list[Sink]] = {}
    for s in sinks:
        sink_funcs.setdefault(s.func_addr, []).append(s)

    paths = []
    for src_func_addr, func_sources in source_funcs.items():
        reachable = _bfs_reachable_funcs(call_graph, src_func_addr, max_depth)
        for snk_func_addr, func_sinks in sink_funcs.items():
            if snk_func_addr == src_func_addr or snk_func_addr not in reachable:
                continue
            func_path = reachable[snk_func_addr]
            func_names = []
            for addr in func_path:
                f = project.kb.functions.get(addr)
                func_names.append(f.name if f else hex(addr))
            for source in func_sources:
                for sink in func_sinks:
                    paths.append(TaintPath(
                        source=source,
                        sink=sink,
                        path_addrs=func_path,
                        path_funcs=func_names,
                    ))
    return paths


def _find_nearest_node(node_map, addr, graph):
    if addr in node_map:
        return node_map[addr]
    for node in graph.nodes():
        if node.addr <= addr < node.addr + node.size:
            return node
    return None


def _is_reachable(graph, src_node, dst_node) -> bool:
    visited = set()
    queue = [src_node]
    while queue:
        node = queue.pop(0)
        if node == dst_node:
            return True
        if node in visited:
            continue
        visited.add(node)
        for succ in graph.successors(node):
            queue.append(succ)
    return False


def _extract_path_addrs(graph, src_node, dst_node) -> list[int]:
    if src_node == dst_node:
        return [src_node.addr]
    visited = {}
    queue = [src_node]
    visited[src_node] = None
    while queue:
        node = queue.pop(0)
        if node == dst_node:
            path = []
            cur = node
            while cur is not None:
                path.append(cur.addr)
                cur = visited[cur]
            return list(reversed(path))
        for succ in graph.successors(node):
            if succ not in visited:
                visited[succ] = node
                queue.append(succ)
    return [src_node.addr, dst_node.addr]


def _bfs_reachable_funcs(
    call_graph, start_addr: int, max_depth: int
) -> dict[int, list[int]]:
    """BFS over the call graph. Returns {reachable_addr: [path from start]}."""
    reachable = {start_addr: [start_addr]}
    queue = [(start_addr, [start_addr], 0)]
    while queue:
        addr, path, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        try:
            successors = list(call_graph.successors(addr))
        except Exception:
            continue
        for succ in successors:
            if succ not in reachable:
                new_path = path + [succ]
                reachable[succ] = new_path
                queue.append((succ, new_path, depth + 1))
    return reachable
