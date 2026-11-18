import pytest
from vulnhunter4ghidra_engine.engine import VulnHunterEngine


def test_engine_init_state():
    engine = VulnHunterEngine()
    assert engine.project is None
    assert engine.binary_path is None
    assert engine._all_sources == []
    assert engine._all_sinks == []
    assert engine._findings == []


def test_engine_init_nonexistent_binary():
    engine = VulnHunterEngine()
    with pytest.raises(Exception):
        engine.init("/nonexistent/binary")


def test_analyze_taint_requires_init():
    engine = VulnHunterEngine()
    with pytest.raises(RuntimeError, match="not loaded"):
        engine.analyze_taint()


def test_scan_function_with_source_and_sink():
    engine = VulnHunterEngine()
    result = engine.scan_function(
        func_addr=0x401000,
        func_name="handle_request",
        callsites=[
            {"address": 0x401010, "callee_name": "fgets"},
            {"address": 0x401040, "callee_name": "memcpy"},
        ],
        params=[
            {"index": 0, "name": "sock", "type": "int"},
        ],
        is_exported=False,
    )
    assert result["sources_found"] == 1  # fgets
    assert result["sinks_found"] == 1    # memcpy
    assert len(engine._all_sources) == 1
    assert len(engine._all_sinks) == 1


def test_scan_function_no_sources_or_sinks():
    engine = VulnHunterEngine()
    result = engine.scan_function(
        func_addr=0x401000,
        func_name="safe_func",
        callsites=[
            {"address": 0x401010, "callee_name": "strlen"},
        ],
        params=[{"index": 0, "name": "n", "type": "int"}],
    )
    assert result["sources_found"] == 0
    assert result["sinks_found"] == 0


def test_scan_function_with_buffer_param():
    engine = VulnHunterEngine()
    result = engine.scan_function(
        func_addr=0x401000,
        func_name="parse",
        callsites=[],
        params=[
            {"index": 0, "name": "buf", "type": "char *"},
            {"index": 1, "name": "len", "type": "int"},
        ],
        is_exported=True,
    )
    # char * is a buffer type, always a source
    # len with type "int" and is_exported -> also a source for exported funcs with ptr param
    assert result["sources_found"] >= 1


def test_scan_function_argv_in_main():
    engine = VulnHunterEngine()
    result = engine.scan_function(
        func_addr=0x401000,
        func_name="main",
        callsites=[],
        params=[
            {"index": 0, "name": "argc", "type": "int"},
            {"index": 1, "name": "argv", "type": "char * *"},
        ],
    )
    assert result["sources_found"] == 1  # argv


def test_get_findings_empty():
    engine = VulnHunterEngine()
    assert engine.get_findings() == []


def test_get_sources_empty():
    engine = VulnHunterEngine()
    assert engine.get_sources() == []


def test_get_sinks_empty():
    engine = VulnHunterEngine()
    assert engine.get_sinks() == []


def test_scan_accumulates():
    engine = VulnHunterEngine()
    engine.scan_function(
        0x401000, "func_a",
        [{"address": 0x401010, "callee_name": "fgets"}],
        [],
    )
    engine.scan_function(
        0x402000, "func_b",
        [{"address": 0x402010, "callee_name": "memcpy"}],
        [],
    )
    assert len(engine._all_sources) == 1
    assert len(engine._all_sinks) == 1
