from vulnhunter4ghidra_engine.sources import (
    identify_sources_from_callsites,
    identify_sources_from_params,
    identify_argv_source,
)
from vulnhunter4ghidra_engine.models import SourceType


def test_identify_recv_source():
    callsites = [{"address": 0x401020, "callee_name": "recv"}]
    sources = identify_sources_from_callsites(0x401000, "handle_client", callsites)
    assert len(sources) == 1
    assert sources[0].source_type == SourceType.RECV
    assert sources[0].address == 0x401020


def test_identify_multiple_sources():
    callsites = [
        {"address": 0x401020, "callee_name": "recv"},
        {"address": 0x401040, "callee_name": "fgets"},
        {"address": 0x401060, "callee_name": "memcpy"},  # not a source
    ]
    sources = identify_sources_from_callsites(0x401000, "process", callsites)
    assert len(sources) == 2


def test_no_sources_from_safe_calls():
    callsites = [
        {"address": 0x401020, "callee_name": "memcpy"},
        {"address": 0x401040, "callee_name": "strlen"},
    ]
    sources = identify_sources_from_callsites(0x401000, "safe_func", callsites)
    assert len(sources) == 0


def test_identify_buffer_param_source():
    params = [
        {"index": 0, "name": "buf", "type": "char *"},
        {"index": 1, "name": "len", "type": "int"},
    ]
    sources = identify_sources_from_params(0x401000, "parse", params, is_exported=False)
    assert len(sources) == 1
    assert sources[0].param_index == 0
    assert sources[0].source_type == SourceType.FUNC_PARAM


def test_exported_pointer_param_is_source():
    params = [
        {"index": 0, "name": "data", "type": "mystruct *"},
    ]
    sources = identify_sources_from_params(0x401000, "api_call", params, is_exported=True)
    assert len(sources) == 1


def test_non_exported_struct_ptr_not_source():
    params = [
        {"index": 0, "name": "ctx", "type": "context *"},
    ]
    sources = identify_sources_from_params(0x401000, "internal", params, is_exported=False)
    assert len(sources) == 0


def test_identify_argv():
    params = [
        {"index": 0, "name": "argc", "type": "int"},
        {"index": 1, "name": "argv", "type": "char * *"},
    ]
    src = identify_argv_source(0x401000, "main", params)
    assert src is not None
    assert src.source_type == SourceType.ARGV
    assert src.param_index == 1


def test_argv_not_in_non_main():
    params = [{"index": 0, "name": "argv", "type": "char * *"}]
    src = identify_argv_source(0x401000, "helper", params)
    assert src is None
