import json
from vulnhunter4ghidra_engine.protocol import parse_command, ok, error, progress, Command, Response


def test_parse_command_basic():
    cmd = parse_command('{"type": "scan_vulns", "params": {"binary_path": "/tmp/a.out"}}')
    assert cmd.type == "scan_vulns"
    assert cmd.params["binary_path"] == "/tmp/a.out"


def test_parse_command_no_params():
    cmd = parse_command('{"type": "ping"}')
    assert cmd.type == "ping"
    assert cmd.params == {}


def test_ok_response():
    r = ok({"count": 5})
    d = json.loads(r.to_json())
    assert d["status"] == "ok"
    assert d["data"]["count"] == 5


def test_ok_response_no_data():
    r = ok()
    d = json.loads(r.to_json())
    assert d["status"] == "ok"
    assert "data" not in d


def test_error_response():
    r = error("bad thing")
    d = json.loads(r.to_json())
    assert d["status"] == "error"
    assert d["message"] == "bad thing"


def test_progress_response():
    r = progress({"step": 3, "total": 10})
    d = json.loads(r.to_json())
    assert d["status"] == "progress"
    assert d["data"]["step"] == 3


def test_response_to_json_roundtrip():
    r = ok({"findings": [{"id": 1, "cwe": "CWE-119"}]})
    j = r.to_json()
    parsed = json.loads(j)
    assert parsed["status"] == "ok"
    assert parsed["data"]["findings"][0]["cwe"] == "CWE-119"
