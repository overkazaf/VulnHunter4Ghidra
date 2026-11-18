from vulnhunter4ghidra_engine.models import (
    Source, Sink, TaintPath, VulnFinding,
    SourceType, SinkType, Severity,
    classify_severity,
)


def _make_source(addr=0x401000, func_addr=0x401000, func_name="parse_input"):
    return Source(
        address=addr, func_addr=func_addr, func_name=func_name,
        source_type=SourceType.FUNC_PARAM,
        description="Parameter 0 of parse_input",
        param_index=0,
    )


def _make_sink(addr=0x401050, func_addr=0x401000, func_name="parse_input"):
    return Sink(
        address=addr, func_addr=func_addr, func_name=func_name,
        callee_name="memcpy", sink_type=SinkType.BUFFER_OVERFLOW,
        cwe="CWE-120", vulnerable_arg_index=0,
    )


def test_source_to_dict():
    s = _make_source()
    d = s.to_dict()
    assert d["address"] == "0x401000"
    assert d["source_type"] == "func_param"
    assert d["param_index"] == 0


def test_source_to_dict_no_param_index():
    s = Source(
        address=0x402000, func_addr=0x402000, func_name="main",
        source_type=SourceType.ARGV, description="argv",
    )
    d = s.to_dict()
    assert "param_index" not in d


def test_sink_to_dict():
    s = _make_sink()
    d = s.to_dict()
    assert d["callee_name"] == "memcpy"
    assert d["cwe"] == "CWE-120"
    assert d["sink_type"] == "buffer_overflow"


def test_taint_path_to_dict():
    src = _make_source()
    snk = _make_sink()
    tp = TaintPath(
        source=src, sink=snk,
        path_addrs=[0x401000, 0x401020, 0x401050],
        path_funcs=["parse_input"],
    )
    d = tp.to_dict()
    assert d["path_length"] == 3
    assert d["path_addrs"] == ["0x401000", "0x401020", "0x401050"]


def test_vuln_finding_to_dict():
    src = _make_source()
    snk = _make_sink()
    tp = TaintPath(source=src, sink=snk, path_addrs=[0x401000, 0x401050], path_funcs=["parse_input"])
    f = VulnFinding(
        finding_id=1, taint_path=tp, cwe="CWE-120",
        severity=Severity.CRITICAL,
        title="Buffer overflow in parse_input",
        description="memcpy with user-controlled size",
    )
    d = f.to_dict()
    assert d["finding_id"] == 1
    assert d["cwe"] == "CWE-120"
    assert d["severity"] == "critical"
    assert d["verified"] is False


def test_classify_severity_known():
    assert classify_severity("CWE-119") == Severity.CRITICAL
    assert classify_severity("CWE-476") == Severity.MEDIUM


def test_classify_severity_unknown():
    assert classify_severity("CWE-999") == Severity.MEDIUM


def test_source_types():
    assert SourceType.RECV.value == "recv"
    assert SourceType.SCANF.value == "scanf"


def test_sink_types():
    assert SinkType.FORMAT_STRING.value == "format_string"
    assert SinkType.DOUBLE_FREE.value == "double_free"
