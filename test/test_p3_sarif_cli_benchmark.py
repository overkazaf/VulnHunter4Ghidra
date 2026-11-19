import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import pytest

from vulnhunter4ghidra_engine.sarif import findings_to_sarif, load_baseline_fingerprints


def test_sarif_v210_generation_and_baseline_fingerprint_roundtrip(tmp_path):
    sample_findings = [
        {
            "finding_id": 1,
            "fingerprint": "a1b2c3d4e5f60718",
            "cwe": "CWE-78",
            "severity": "critical",
            "confidence": "high",
            "title": "command_injection: system in handle_cgi",
            "description": "User-controlled data from fgets() flows to system() at 0x401220",
            "verified": True,
            "evidence": ["VEX data-flow confirmed taint in system() arg [0]"],
            "taint_path": {
                "source": {
                    "address": "0x401190",
                    "func_addr": "0x401180",
                    "func_name": "handle_cgi",
                    "source_type": "fgets",
                    "description": "Call to fgets()",
                },
                "sink": {
                    "address": "0x401220",
                    "func_addr": "0x401180",
                    "func_name": "handle_cgi",
                    "callee_name": "system",
                    "sink_type": "command_injection",
                    "cwe": "CWE-78",
                    "vulnerable_arg_index": 0,
                },
                "path_addrs": ["0x401180", "0x401200"],
                "path_funcs": ["handle_cgi", "handle_cgi"],
                "path_length": 2,
            },
        }
    ]

    sarif = findings_to_sarif(sample_findings, binary_path="/opt/bin/httpd", arch="AMD64")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "VulnHunter4Ghidra"
    assert run["tool"]["driver"]["rules"][0]["id"] == "CWE-78"
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "9.8"

    res = run["results"][0]
    assert res["ruleId"] == "CWE-78"
    assert res["level"] == "error"
    assert res["partialFingerprints"]["vulnhunterFindingHash/v1"] == "a1b2c3d4e5f60718"
    assert len(res["codeFlows"][0]["threadFlows"][0]["locations"]) == 4

    sarif_path = tmp_path / "baseline.sarif"
    sarif_path.write_text(json.dumps(sarif), encoding="utf-8")
    loaded_fps = load_baseline_fingerprints(sarif_path)
    assert loaded_fps == {"a1b2c3d4e5f60718"}


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang required for CLI e2e test")
def test_cli_sarif_and_baseline_differential_gate(tmp_path):
    c_v1 = tmp_path / "app_v1.c"
    bin_v1 = tmp_path / "app_v1"
    c_v1.write_text(
        r"""
        #include <stdio.h>
        void legacy_issue(void) {
            char buf[64];
            if (fgets(buf, 64, stdin)) printf(buf);
        }
        int main(void) { legacy_issue(); return 0; }
        """,
        encoding="utf-8",
    )
    subprocess.run(
        ["clang", "-O0", "-fno-stack-protector", "-Wno-format-security", str(c_v1), "-o", str(bin_v1)],
        check=True,
    )

    python_dir = str(Path(__file__).resolve().parent.parent / "python")
    env = dict(os.environ)
    env["PYTHONPATH"] = python_dir

    baseline_sarif = tmp_path / "v1.sarif"
    # 1. Initial scan finds legacy_issue -> exits with code 1 and writes SARIF baseline
    run1 = subprocess.run(
        [
            sys.executable, "-m", "vulnhunter4ghidra_engine.cli",
            "report", str(bin_v1), "--format", "sarif", "-o", str(baseline_sarif),
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert run1.returncode == 1
    assert baseline_sarif.is_file()

    # 2. Re-running with --baseline suppresses pre-existing legacy_issue -> exits 0 (green CI!)
    run2 = subprocess.run(
        [
            sys.executable, "-m", "vulnhunter4ghidra_engine.cli",
            "report", str(bin_v1), "--baseline", str(baseline_sarif), "--json",
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert run2.returncode == 0
    rep2 = json.loads(run2.stdout)
    assert rep2["findings_count"] == 0
    assert rep2["suppressed_by_baseline"] == 1

    # 3. Introducing a NEW vulnerability in v2 -> --baseline blocks ONLY the new issue (exit 1)!
    c_v2 = tmp_path / "app_v2.c"
    bin_v2 = tmp_path / "app_v2"
    c_v2.write_text(
        r"""
        #include <stdio.h>
        #include <stdlib.h>
        void legacy_issue(void) {
            char buf[64];
            if (fgets(buf, 64, stdin)) printf(buf);
        }
        void new_regression(void) {
            char *p = (char *)malloc(32);
            if (!p) return;
            free(p);
            free(p);
        }
        int main(void) { legacy_issue(); new_regression(); return 0; }
        """,
        encoding="utf-8",
    )
    subprocess.run(
        ["clang", "-O0", "-fno-stack-protector", "-Wno-format-security", str(c_v2), "-o", str(bin_v2)],
        check=True,
    )
    run3 = subprocess.run(
        [
            sys.executable, "-m", "vulnhunter4ghidra_engine.cli",
            "report", str(bin_v2), "--baseline", str(baseline_sarif), "--json",
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert run3.returncode == 1
    rep3 = json.loads(run3.stdout)
    assert rep3["suppressed_by_baseline"] == 1
    assert rep3["findings_count"] == 1
    assert rep3["findings"][0]["cwe"] == "CWE-415"


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang required for CWE benchmark")
@pytest.mark.parametrize("opt_level", ["-O0", "-O2"])
def test_7_cwe_benchmark_achieves_100_percent_precision_and_recall(opt_level):
    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root))
    try:
        from benchmark.run_benchmark import run_cwe_benchmark
        metrics = run_cwe_benchmark(verify_symbolic=(opt_level == "-O0"), opt_level=opt_level)
        assert metrics["precision"] == 1.0, f"[{opt_level}] Unexpected FPs: {metrics['false_positive_details']}"
        assert metrics["recall"] == 1.0, f"[{opt_level}] Missed cases: {metrics['missed_cases']}"
        assert metrics["f1_score"] == 1.0
    finally:
        sys.path.pop(0)
