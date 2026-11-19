import json
import os
import pathlib
import subprocess
import sys


def test_stdio_server_auth_progress_and_commands():
    python_dir = str(
        pathlib.Path(__file__).resolve().parent.parent / "python"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = python_dir

    token = "test_session_secret_9f8e7d"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "vulnhunter4ghidra_engine.server",
            "--stdio",
            "--auth-token",
            token,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        assert proc.stdin is not None and proc.stdout is not None

        # 1. Missing/wrong token MUST be rejected
        proc.stdin.write(json.dumps({"type": "ping", "token": "wrong"}) + "\n")
        proc.stdin.flush()
        unauth = json.loads(proc.stdout.readline())
        assert unauth["status"] == "error"
        assert "Unauthorized" in unauth["message"]

        # 2. Authorized ping succeeds
        proc.stdin.write(json.dumps({"type": "ping", "token": token}) + "\n")
        proc.stdin.flush()
        pong = json.loads(proc.stdout.readline())
        assert pong["status"] == "ok"
        assert pong["data"]["pong"] is True

        # 3. Mark custom source & sink and scan_functions with progress
        proc.stdin.write(json.dumps({
            "type": "mark_custom",
            "token": token,
            "params": {"role": "source", "func_name": "custom_read_packet"},
        }) + "\n")
        proc.stdin.flush()
        mark_resp = json.loads(proc.stdout.readline())
        assert mark_resp["status"] == "ok"

        proc.stdin.write(json.dumps({
            "type": "scan_functions",
            "token": token,
            "params": {
                "functions": [
                    {
                        "func_addr": "0x401000",
                        "func_name": "packet_handler",
                        "callsites": [
                            {"address": 0x401010, "callee_name": "custom_read_packet"},
                            {"address": 0x401030, "callee_name": "strcpy"},
                        ],
                        "params": [],
                        "is_exported": False,
                    }
                ]
            },
        }) + "\n")
        proc.stdin.flush()

        seen_progress = False
        while True:
            msg = json.loads(proc.stdout.readline())
            if msg["status"] == "progress":
                seen_progress = True
                continue
            assert msg["status"] == "ok"
            assert msg["data"]["total_sources"] == 1
            assert msg["data"]["total_sinks"] == 1
            break
        assert seen_progress is True

        # 4. Graceful shutdown
        proc.stdin.write(json.dumps({"type": "shutdown", "token": token}) + "\n")
        proc.stdin.flush()
        bye = json.loads(proc.stdout.readline())
        assert bye["status"] == "ok"
        proc.wait(timeout=5)
        assert proc.returncode == 0
    finally:
        if proc.poll() is None:
            proc.kill()
