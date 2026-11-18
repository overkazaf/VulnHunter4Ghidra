from vulnhunter4ghidra_engine.sinks import (
    identify_sinks,
    get_sink_functions,
    get_cwe_for_function,
)
from vulnhunter4ghidra_engine.models import SinkType


def test_identify_memcpy_sink():
    callsites = [{"address": 0x401050, "callee_name": "memcpy"}]
    sinks = identify_sinks(0x401000, "process_data", callsites)
    assert len(sinks) == 1
    assert sinks[0].callee_name == "memcpy"
    assert sinks[0].cwe == "CWE-120"
    assert sinks[0].sink_type == SinkType.BUFFER_OVERFLOW
    assert sinks[0].vulnerable_arg_index == 0


def test_identify_format_string_sink():
    callsites = [{"address": 0x401080, "callee_name": "sprintf"}]
    sinks = identify_sinks(0x401000, "log_msg", callsites)
    assert len(sinks) == 1
    assert sinks[0].cwe == "CWE-134"
    assert sinks[0].sink_type == SinkType.FORMAT_STRING


def test_identify_command_injection():
    callsites = [{"address": 0x401090, "callee_name": "system"}]
    sinks = identify_sinks(0x401000, "run_cmd", callsites)
    assert len(sinks) == 1
    assert sinks[0].cwe == "CWE-78"
    assert sinks[0].sink_type == SinkType.COMMAND_INJECTION


def test_multiple_sinks():
    callsites = [
        {"address": 0x401050, "callee_name": "memcpy"},
        {"address": 0x401060, "callee_name": "strcpy"},
        {"address": 0x401070, "callee_name": "printf"},
    ]
    sinks = identify_sinks(0x401000, "vulnerable_func", callsites)
    assert len(sinks) == 3


def test_no_sinks_from_safe_calls():
    callsites = [
        {"address": 0x401050, "callee_name": "strlen"},
        {"address": 0x401060, "callee_name": "malloc"},
    ]
    sinks = identify_sinks(0x401000, "safe_func", callsites)
    assert len(sinks) == 0


def test_get_sink_functions():
    fns = get_sink_functions()
    assert "memcpy" in fns
    assert "system" in fns
    assert "strlen" not in fns


def test_get_cwe_for_function_known():
    assert get_cwe_for_function("memcpy") == "CWE-120"
    assert get_cwe_for_function("printf") == "CWE-134"


def test_get_cwe_for_function_unknown():
    assert get_cwe_for_function("strlen") is None
