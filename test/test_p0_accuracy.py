import subprocess
import shutil
import pytest

from vulnhunter4ghidra_engine.cli import _build_function_info
from vulnhunter4ghidra_engine.engine import VulnHunterEngine
from vulnhunter4ghidra_engine.rules import normalize_func_name
from vulnhunter4ghidra_engine.sinks import identify_sinks
from vulnhunter4ghidra_engine.sources import identify_sources_from_callsites


def test_symbol_normalization_variants():
    assert normalize_func_name("_fgets") == ("fgets", False)
    assert normalize_func_name("___memcpy_chk") == ("memcpy", True)
    assert normalize_func_name("__sprintf_chk") == ("sprintf", True)
    assert normalize_func_name("<EXTERNAL>::strcpy") == ("strcpy", False)
    assert normalize_func_name("printf@plt") == ("printf", False)
    assert normalize_func_name("__imp_recv") == ("recv", False)
    assert normalize_func_name("__isoc99_scanf") == ("scanf", False)


def test_decorated_callsites_detected_in_plugin_mode():
    callsites = [
        {"address": 0x101010, "callee_name": "_fgets"},
        {"address": 0x101020, "callee_name": "__isoc99_scanf"},
        {"address": 0x101030, "callee_name": "___memcpy_chk"},
        {"address": 0x101040, "callee_name": "<EXTERNAL>::system"},
    ]
    sources = identify_sources_from_callsites(0x101000, "handler", callsites)
    sinks = identify_sinks(0x101000, "handler", callsites)
    assert len(sources) == 2
    assert len(sinks) == 2
    assert sinks[0].callee_name == "memcpy"
    assert sinks[0].is_fortified is True
    assert sinks[1].callee_name == "system"


def test_rescan_same_function_is_idempotent():
    engine = VulnHunterEngine()
    cs = [{"address": 0x401010, "callee_name": "fgets"}]
    engine.scan_function(0x401000, "fn", cs, [])
    engine.scan_function(0x401000, "fn", cs, [])
    assert len(engine.get_sources()) == 1


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang required for native binary tests")
def test_vex_taint_precision_and_pie_base_alignment(tmp_path):
    c_src = tmp_path / "p0_sample.c"
    bin_path = tmp_path / "p0_sample"
    c_src.write_text(
        r"""
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>

        __attribute__((noinline))
        void vuln_sink_helper(const char *tainted_in) {
            char small[16];
            strcpy(small, tainted_in);
            puts(small);
        }

        __attribute__((noinline))
        void safe_sink_helper(const char *fixed_in) {
            char small[32];
            strcpy(small, fixed_in);
            puts(small);
        }

        __attribute__((noinline))
        void safe_cases(void) {
            char buf[64];
            char other[32];
            if (fgets(buf, sizeof(buf), stdin)) {
                printf("Safe constant fmt: %s\n", buf);
                memcpy(other, "hello", 5);
                system("echo constant_cmd");
                safe_sink_helper("constant_literal");
            }
        }

        __attribute__((noinline))
        void bad_format_case(void) {
            char buf[64];
            if (fgets(buf, sizeof(buf), stdin)) {
                printf(buf);
            }
        }

        __attribute__((noinline))
        void bad_cmd_via_snprintf(void) {
            char user[64];
            char cmd[128];
            if (fgets(user, sizeof(user), stdin)) {
                snprintf(cmd, sizeof(cmd), "ping -c 1 %s", user);
                system(cmd);
            }
        }

        int main(int argc, char **argv) {
            safe_cases();
            bad_format_case();
            bad_cmd_via_snprintf();
            if (argc > 1) {
                vuln_sink_helper(argv[1]);
            }
            return 0;
        }
        """,
        encoding="utf-8",
    )
    subprocess.run(
        ["clang", "-O0", "-fno-stack-protector", "-D_FORTIFY_SOURCE=0", str(c_src), "-o", str(bin_path)],
        check=True,
    )

    # Load at custom Ghidra-like image base 0x100000 to verify PIE base alignment
    engine = VulnHunterEngine()
    init_info = engine.init(str(bin_path), base_addr="0x100000")
    assert init_info["base_addr"] == "0x100000"

    engine.ensure_cfg()
    funcs = _build_function_info(engine.project, registry=engine.rules)
    for fi in funcs:
        engine.scan_function(
            fi["func_addr"], fi["func_name"], fi["callsites"], fi["params"], fi["is_exported"]
        )

    res = engine.analyze_taint(max_depth=4)
    findings = res["findings"]

    by_sink_fn = {(f["taint_path"]["sink"]["func_name"], f["cwe"]) for f in findings}

    # True positives MUST be detected:
    assert ("bad_format_case", "CWE-134") in by_sink_fn
    assert ("bad_cmd_via_snprintf", "CWE-78") in by_sink_fn
    assert ("vuln_sink_helper", "CWE-120") in by_sink_fn

    # False positives MUST be suppressed:
    sink_funcs_flagged = {f["taint_path"]["sink"]["func_name"] for f in findings}
    assert "safe_cases" not in sink_funcs_flagged
    assert "safe_sink_helper" not in sink_funcs_flagged
    # snprintf in bad_cmd_via_snprintf has a constant format string -> NOT CWE-134!
    assert ("bad_cmd_via_snprintf", "CWE-134") not in by_sink_fn
