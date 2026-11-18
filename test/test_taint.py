import types
from vulnhunter4ghidra_engine.models import Source, Sink, SourceType, SinkType
from vulnhunter4ghidra_engine.taint import (
    _is_reachable,
    _extract_path_addrs,
    _find_nearest_node,
    _bfs_reachable_funcs,
    find_taint_paths_intraprocedural,
    find_taint_paths_interprocedural,
)


class MockNode:
    def __init__(self, addr, size=16):
        self.addr = addr
        self.size = size

    def __repr__(self):
        return f"Node({hex(self.addr)})"

    def __hash__(self):
        return hash(self.addr)

    def __eq__(self, other):
        return isinstance(other, MockNode) and self.addr == other.addr


class MockGraph:
    def __init__(self):
        self._adj: dict[MockNode, list[MockNode]] = {}

    def add_node(self, node):
        if node not in self._adj:
            self._adj[node] = []

    def add_edge(self, src, dst):
        self.add_node(src)
        self.add_node(dst)
        self._adj[src].append(dst)

    def nodes(self):
        return self._adj.keys()

    def successors(self, node):
        return self._adj.get(node, [])


def test_is_reachable_direct():
    g = MockGraph()
    a = MockNode(0x1000)
    b = MockNode(0x1010)
    g.add_edge(a, b)
    assert _is_reachable(g, a, b) is True


def test_is_reachable_indirect():
    g = MockGraph()
    a, b, c = MockNode(0x1000), MockNode(0x1010), MockNode(0x1020)
    g.add_edge(a, b)
    g.add_edge(b, c)
    assert _is_reachable(g, a, c) is True


def test_is_not_reachable():
    g = MockGraph()
    a, b = MockNode(0x1000), MockNode(0x1010)
    g.add_node(a)
    g.add_node(b)
    assert _is_reachable(g, a, b) is False


def test_extract_path_addrs_direct():
    g = MockGraph()
    a = MockNode(0x1000)
    b = MockNode(0x1010)
    g.add_edge(a, b)
    path = _extract_path_addrs(g, a, b)
    assert path == [0x1000, 0x1010]


def test_extract_path_addrs_same_node():
    g = MockGraph()
    a = MockNode(0x1000)
    g.add_node(a)
    path = _extract_path_addrs(g, a, a)
    assert path == [0x1000]


def test_extract_path_addrs_multi_hop():
    g = MockGraph()
    a, b, c, d = MockNode(0x1000), MockNode(0x1010), MockNode(0x1020), MockNode(0x1030)
    g.add_edge(a, b)
    g.add_edge(b, c)
    g.add_edge(c, d)
    path = _extract_path_addrs(g, a, d)
    assert path == [0x1000, 0x1010, 0x1020, 0x1030]


def test_find_nearest_node_exact():
    a = MockNode(0x1000, size=16)
    node_map = {0x1000: a}
    g = MockGraph()
    g.add_node(a)
    assert _find_nearest_node(node_map, 0x1000, g) == a


def test_find_nearest_node_within_block():
    a = MockNode(0x1000, size=32)
    node_map = {}
    g = MockGraph()
    g.add_node(a)
    result = _find_nearest_node(node_map, 0x1010, g)
    assert result == a


def test_find_nearest_node_not_found():
    node_map = {}
    g = MockGraph()
    a = MockNode(0x1000, size=16)
    g.add_node(a)
    result = _find_nearest_node(node_map, 0x2000, g)
    assert result is None


def test_bfs_reachable_funcs():
    g = MockGraph()
    g.add_edge(0x1000, 0x2000)
    g.add_edge(0x2000, 0x3000)
    g.add_edge(0x3000, 0x4000)
    result = _bfs_reachable_funcs(g, 0x1000, max_depth=3)
    assert 0x1000 in result
    assert 0x2000 in result
    assert 0x3000 in result
    assert 0x4000 in result


def test_bfs_reachable_funcs_depth_limit():
    g = MockGraph()
    g.add_edge(0x1000, 0x2000)
    g.add_edge(0x2000, 0x3000)
    g.add_edge(0x3000, 0x4000)
    result = _bfs_reachable_funcs(g, 0x1000, max_depth=1)
    assert 0x1000 in result
    assert 0x2000 in result
    assert 0x3000 not in result


def _make_mock_project(func_addr, func_name, graph):
    func = types.SimpleNamespace(name=func_name, graph=graph)
    cfgs = types.SimpleNamespace(get_most_accurate=lambda: object())
    functions = types.SimpleNamespace(get=lambda addr: func if addr == func_addr else None)
    kb = types.SimpleNamespace(cfgs=cfgs, functions=functions)
    return types.SimpleNamespace(kb=kb)


def test_intraprocedural_ignores_same_address_self_flow():
    g = MockGraph()
    g.add_node(MockNode(0x1000, size=64))
    proj = _make_mock_project(0x1000, "vuln_func", g)

    src = Source(
        address=0x1020, func_addr=0x1000, func_name="vuln_func",
        source_type=SourceType.READ, description="Call to read()",
    )
    snk = Sink(
        address=0x1020, func_addr=0x1000, func_name="vuln_func",
        callee_name="read", sink_type=SinkType.BUFFER_OVERFLOW,
        cwe="CWE-120", vulnerable_arg_index=1,
    )

    paths = find_taint_paths_intraprocedural(proj, 0x1000, [src], [snk])
    assert paths == []


def test_intraprocedural_same_block_forward_flow():
    g = MockGraph()
    g.add_node(MockNode(0x1000, size=64))
    proj = _make_mock_project(0x1000, "vuln_func", g)

    src = Source(
        address=0x1010, func_addr=0x1000, func_name="vuln_func",
        source_type=SourceType.READ, description="Call to read()",
    )
    snk = Sink(
        address=0x1030, func_addr=0x1000, func_name="vuln_func",
        callee_name="memcpy", sink_type=SinkType.BUFFER_OVERFLOW,
        cwe="CWE-120", vulnerable_arg_index=0,
    )

    paths = find_taint_paths_intraprocedural(proj, 0x1000, [src], [snk])
    assert len(paths) == 1
    assert paths[0].path_addrs == [0x1000]


def test_intraprocedural_same_block_backward_without_cycle_ignored():
    g = MockGraph()
    g.add_node(MockNode(0x1000, size=64))
    proj = _make_mock_project(0x1000, "vuln_func", g)

    src = Source(
        address=0x1030, func_addr=0x1000, func_name="vuln_func",
        source_type=SourceType.READ, description="Call to read()",
    )
    snk = Sink(
        address=0x1010, func_addr=0x1000, func_name="vuln_func",
        callee_name="memcpy", sink_type=SinkType.BUFFER_OVERFLOW,
        cwe="CWE-120", vulnerable_arg_index=0,
    )

    paths = find_taint_paths_intraprocedural(proj, 0x1000, [src], [snk])
    assert paths == []


def test_intraprocedural_same_block_backward_with_cycle_detected():
    g = MockGraph()
    n0 = MockNode(0x1000, size=64)
    n1 = MockNode(0x1040, size=16)
    g.add_edge(n0, n1)
    g.add_edge(n1, n0)
    proj = _make_mock_project(0x1000, "vuln_func", g)

    src = Source(
        address=0x1030, func_addr=0x1000, func_name="vuln_func",
        source_type=SourceType.READ, description="Call to read()",
    )
    snk = Sink(
        address=0x1010, func_addr=0x1000, func_name="vuln_func",
        callee_name="memcpy", sink_type=SinkType.BUFFER_OVERFLOW,
        cwe="CWE-120", vulnerable_arg_index=0,
    )

    paths = find_taint_paths_intraprocedural(proj, 0x1000, [src], [snk])
    assert len(paths) == 1
    assert paths[0].path_addrs == [0x1000]


def test_interprocedural_skips_same_function():
    cg = MockGraph()
    cg.add_edge(0x1000, 0x2000)

    funcs = {
        0x1000: types.SimpleNamespace(name="caller_fn"),
        0x2000: types.SimpleNamespace(name="callee_fn"),
    }
    kb = types.SimpleNamespace(
        cfgs=types.SimpleNamespace(get_most_accurate=lambda: object()),
        callgraph=cg,
        functions=types.SimpleNamespace(get=lambda addr: funcs.get(addr)),
    )
    proj = types.SimpleNamespace(kb=kb)

    src = Source(
        address=0x1020, func_addr=0x1000, func_name="caller_fn",
        source_type=SourceType.READ, description="Call to read()",
    )
    same_fn_snk = Sink(
        address=0x1020, func_addr=0x1000, func_name="caller_fn",
        callee_name="read", sink_type=SinkType.BUFFER_OVERFLOW,
        cwe="CWE-120", vulnerable_arg_index=1,
    )
    other_fn_snk = Sink(
        address=0x2040, func_addr=0x2000, func_name="callee_fn",
        callee_name="memcpy", sink_type=SinkType.BUFFER_OVERFLOW,
        cwe="CWE-120", vulnerable_arg_index=0,
    )

    paths = find_taint_paths_interprocedural(
        proj, [src], [same_fn_snk, other_fn_snk], max_depth=3,
    )
    assert len(paths) == 1
    assert paths[0].sink.func_addr == 0x2000
    assert paths[0].path_funcs == ["caller_fn", "callee_fn"]
