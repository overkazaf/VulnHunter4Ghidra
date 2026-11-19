import json
import shutil
import subprocess
import pytest

from vulnhunter4ghidra_engine.cli import _build_function_info
from vulnhunter4ghidra_engine.engine import VulnHunterEngine


def test_custom_toml_and_json_rule_packs(tmp_path):
    toml_file = tmp_path / "custom_rules.toml"
    toml_file.write_text(
        """
        sanitizers = ["clean_packet"]

        [[sources]]
        name = "usb_bulk_read"
        source_type = "read"
        taints_return = true
        tainted_out_args = [1]

        [[sinks]]
        name = "dma_raw_write"
        sink_type = "buffer_overflow"
        cwe = "CWE-787"
        vulnerable_arg_index = 1
        tainted_arg_indices = [1, 2]
        """,
        encoding="utf-8",
    )

    engine = VulnHunterEngine()
    stats = engine.load_rules(str(toml_file))
    assert stats == {"sources_added": 1, "sinks_added": 1, "sanitizers_added": 1}

    res = engine.scan_function(
        0x500000,
        "usb_dispatch",
        [
            {"address": 0x500010, "callee_name": "_usb_bulk_read"},
            {"address": 0x500030, "callee_name": "dma_raw_write@plt"},
        ],
        [],
    )
    assert res["sources_found"] == 1
    assert res["sinks_found"] == 1
    assert res["sinks"][0]["cwe"] == "CWE-787"

    json_file = tmp_path / "extra.json"
    json_file.write_text(
        json.dumps({
            "sources": [{"name": "ipc_recv_msg", "source_type": "recv", "tainted_out_args": [0]}],
            "sinks": [{"name": "run_shell_wrapper", "sink_type": "command_injection", "cwe": "CWE-78"}],
        }),
        encoding="utf-8",
    )
    stats2 = engine.load_rules(str(json_file))
    assert stats2["sources_added"] == 1
    assert stats2["sinks_added"] == 1


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang required for native CWE tests")
def test_stateful_lifecycle_and_integer_overflow_detectors(tmp_path):
    c_src = tmp_path / "p2_lifecycle.c"
    bin_path = tmp_path / "p2_lifecycle"
    c_src.write_text(
        r"""
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>

        __attribute__((noinline))
        void bad_uaf(void) {
            char *p = (char *)malloc(32);
            if (!p) return;
            strcpy(p, "hello");
            free(p);
            puts(p);
        }

        __attribute__((noinline))
        void good_free_and_reassign(void) {
            char *p = (char *)malloc(32);
            if (!p) return;
            puts(p);
            free(p);
            p = NULL;
            free(p);
            p = (char *)malloc(16);
            if (p) {
                p[0] = 'A';
                free(p);
            }
        }

        __attribute__((noinline))
        void bad_double_free(void) {
            char *p = (char *)malloc(32);
            if (!p) return;
            free(p);
            free(p);
        }

        __attribute__((noinline))
        void bad_null_deref(void) {
            char *p = (char *)malloc(64);
            p[0] = 'Z';
            free(p);
        }

        __attribute__((noinline))
        void good_null_checked(void) {
            char *p = (char *)malloc(64);
            if (p == NULL) return;
            p[0] = 'Y';
            free(p);
        }

        __attribute__((noinline))
        void bad_const_stack_smash(void) {
            char tiny[16];
            fgets(tiny, 128, stdin);
        }

        __attribute__((noinline))
        void good_const_stack_ok(void) {
            char okbuf[64];
            fgets(okbuf, 64, stdin);
        }

        int main(int argc, char **argv) {
            bad_uaf();
            good_free_and_reassign();
            bad_double_free();
            bad_null_deref();
            good_null_checked();
            bad_const_stack_smash();
            good_const_stack_ok();
            if (argc > 1) {
                int n = atoi(argv[1]);
                char *arr = (char *)malloc((size_t)(n * 16));
                if (arr) free(arr);
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

    engine = VulnHunterEngine()
    engine.init(str(bin_path))
    engine.ensure_cfg()
    for fi in _build_function_info(engine.project, registry=engine.rules):
        engine.scan_function(
            fi["func_addr"], fi["func_name"], fi["callsites"], fi["params"], fi["is_exported"]
        )

    res = engine.analyze_taint(max_depth=3)
    findings = res["findings"]
    pairs = {(f["taint_path"]["sink"]["func_name"].lstrip("_"), f["cwe"]) for f in findings}

    # True positives across all P2 detectors:
    assert ("bad_uaf", "CWE-416") in pairs
    assert ("bad_double_free", "CWE-415") in pairs
    assert ("bad_null_deref", "CWE-476") in pairs
    assert ("bad_const_stack_smash", "CWE-120") in pairs
    assert ("main", "CWE-190") in pairs or ("_start", "CWE-190") in pairs

    # Safe counterparts MUST have 0 findings:
    flagged_funcs = {f["taint_path"]["sink"]["func_name"].lstrip("_") for f in findings}
    assert "good_free_and_reassign" not in flagged_funcs
    assert "good_null_checked" not in flagged_funcs
    assert "good_const_stack_ok" not in flagged_funcs


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang required for Z3 test")
def test_z3_feasibility_verifies_reachable_and_prunes_contradictory_branch(tmp_path):
    c_src = tmp_path / "p2_z3.c"
    bin_path = tmp_path / "p2_z3"
    c_src.write_text(
        r"""
        #include <stdio.h>

        __attribute__((noinline))
        void reachable_vuln(int x) {
            char buf[64];
            if (fgets(buf, 64, stdin)) {
                if (x == 42) {
                    printf(buf);
                }
            }
        }

        __attribute__((noinline))
        void unreachable_dead_vuln(int x) {
            char buf[64];
            fgets(buf, 64, stdin);
            if (x > 10 && x < 5) {
                printf(buf);
            }
        }

        int main(int argc, char **argv) {
            reachable_vuln(argc);
            unreachable_dead_vuln(argc);
            return 0;
        }
        """,
        encoding="utf-8",
    )
    # Compile at -O0 so clang preserves the contradictory branch in the binary CFG
    subprocess.run(
        ["clang", "-O0", "-fno-stack-protector", str(c_src), "-o", str(bin_path)],
        check=True,
    )

    engine = VulnHunterEngine()
    engine.init(str(bin_path))
    engine.ensure_cfg()
    for fi in _build_function_info(engine.project, registry=engine.rules):
        engine.scan_function(
            fi["func_addr"], fi["func_name"], fi["callsites"], fi["params"], fi["is_exported"]
        )

    res = engine.analyze_taint(max_depth=2, verify_symbolic=True)
    findings = res["findings"]
    by_fn = {f["taint_path"]["sink"]["func_name"].lstrip("_"): f for f in findings}

    assert "reachable_vuln" in by_fn
    assert by_fn["reachable_vuln"]["verified"] is True
    assert "unreachable_dead_vuln" not in by_fn
