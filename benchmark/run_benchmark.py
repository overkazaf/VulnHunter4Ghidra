"""Juliet-style CWE Precision & Recall Benchmark Suite for VulnHunter4Ghidra.

Compiles paired `bad_*` (vulnerable) and `good_*` (patched/safe) native C functions
across all 7 supported CWE classes (CWE-120, CWE-134, CWE-78, CWE-415, CWE-416,
CWE-190, CWE-476), runs VulnHunterEngine (+ Z3 verification), and reports
TP, FP, FN, Precision, Recall, and F1 Score.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from vulnhunter4ghidra_engine.cli import _build_function_info
from vulnhunter4ghidra_engine.engine import VulnHunterEngine

BENCHMARK_C_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 1. CWE-120: Classic Buffer Overflow */
__attribute__((noinline))
void bad_cwe120_overflow(const char *tainted) {
    char dst[16];
    strcpy(dst, tainted);
    puts(dst);
}

__attribute__((noinline))
void good_cwe120_safe_copy(void) {
    char buf[64];
    char dst[32];
    if (fgets(buf, sizeof(buf), stdin)) {
        memcpy(dst, "fixed_header", 12);
        puts(dst);
    }
}

/* 2. CWE-134: Uncontrolled Format String */
__attribute__((noinline))
void bad_cwe134_format(void) {
    char buf[64];
    if (fgets(buf, sizeof(buf), stdin)) {
        printf(buf);
    }
}

__attribute__((noinline))
void good_cwe134_format(void) {
    char buf[64];
    if (fgets(buf, sizeof(buf), stdin)) {
        printf("Safe log: %s\n", buf);
    }
}

/* 3. CWE-78: OS Command Injection */
__attribute__((noinline))
void bad_cwe78_cmd(void) {
    char user[64];
    char cmd[128];
    if (fgets(user, sizeof(user), stdin)) {
        snprintf(cmd, sizeof(cmd), "nslookup %s", user);
        system(cmd);
    }
}

__attribute__((noinline))
void good_cwe78_cmd(void) {
    char user[64];
    if (fgets(user, sizeof(user), stdin)) {
        system("uptime");
    }
}

/* 4. CWE-416: Use After Free */
__attribute__((noinline))
void bad_cwe416_uaf(void) {
    char *p = (char *)malloc(32);
    if (!p) return;
    strcpy(p, "item");
    free(p);
    puts(p);
}

__attribute__((noinline))
void good_cwe416_clean_free(void) {
    char *p = (char *)malloc(32);
    if (!p) return;
    strcpy(p, "item");
    puts(p);
    free(p);
}

/* 5. CWE-415: Double Free */
__attribute__((noinline))
void bad_cwe415_double_free(void) {
    char *p = (char *)malloc(32);
    if (!p) return;
    free(p);
    free(p);
}

__attribute__((noinline))
void good_cwe415_nullified(void) {
    char *p = (char *)malloc(32);
    if (!p) return;
    free(p);
    p = NULL;
    free(p);
}

/* 6. CWE-476: NULL Pointer Dereference */
__attribute__((noinline))
void bad_cwe476_null_deref(void) {
    char *p = (char *)malloc(64);
    p[0] = 'A';
    free(p);
}

__attribute__((noinline))
void good_cwe476_checked(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    p[0] = 'A';
    free(p);
}

/* 7. CWE-190: Integer Overflow to Allocation */
__attribute__((noinline))
void bad_cwe190_int_overflow(const char *num_str) {
    int n = atoi(num_str);
    char *buf = (char *)malloc((size_t)(n * 32));
    if (buf) free(buf);
}

__attribute__((noinline))
void good_cwe190_const_alloc(void) {
    char *buf = (char *)malloc(128);
    if (buf) free(buf);
}

int main(int argc, char **argv) {
    good_cwe120_safe_copy();
    bad_cwe134_format();
    good_cwe134_format();
    bad_cwe78_cmd();
    good_cwe78_cmd();
    bad_cwe416_uaf();
    good_cwe416_clean_free();
    bad_cwe415_double_free();
    good_cwe415_nullified();
    bad_cwe476_null_deref();
    good_cwe476_checked();
    good_cwe190_const_alloc();
    if (argc > 1) {
        bad_cwe120_overflow(argv[1]);
        bad_cwe190_int_overflow(argv[1]);
    }
    return 0;
}
"""

EXPECTED_BAD: dict[str, str] = {
    "bad_cwe120_overflow": "CWE-120",
    "bad_cwe134_format": "CWE-134",
    "bad_cwe78_cmd": "CWE-78",
    "bad_cwe416_uaf": "CWE-416",
    "bad_cwe415_double_free": "CWE-415",
    "bad_cwe476_null_deref": "CWE-476",
    "bad_cwe190_int_overflow": "CWE-190",
}

EXPECTED_GOOD: set[str] = {
    "good_cwe120_safe_copy",
    "good_cwe134_format",
    "good_cwe78_cmd",
    "good_cwe416_clean_free",
    "good_cwe415_nullified",
    "good_cwe476_checked",
    "good_cwe190_const_alloc",
}


def run_cwe_benchmark(verify_symbolic: bool = True, opt_level: str = "-O0") -> dict:
    compiler = shutil.which("clang") or shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("Neither clang nor gcc is installed on PATH")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        c_file = tmp_dir / "juliet_mini_corpus.c"
        bin_file = tmp_dir / "juliet_mini_corpus"
        c_file.write_text(BENCHMARK_C_SOURCE, encoding="utf-8")

        subprocess.run(
            [
                compiler,
                opt_level,
                "-fno-builtin",
                "-fno-stack-protector",
                "-D_FORTIFY_SOURCE=0",
                "-Wno-format-security",
                str(c_file),
                "-o",
                str(bin_file),
            ],
            check=True,
        )

        t0 = time.perf_counter()
        engine = VulnHunterEngine()
        engine.init(str(bin_file))
        engine.ensure_cfg()
        for fi in _build_function_info(engine.project, registry=engine.rules):
            engine.scan_function(
                fi["func_addr"],
                fi["func_name"],
                fi["callsites"],
                fi["params"],
                fi["is_exported"],
            )
        result = engine.analyze_taint(max_depth=4, verify_symbolic=verify_symbolic)
        elapsed_s = round(time.perf_counter() - t0, 3)

    detected_pairs: set[tuple[str, str]] = set()
    false_positives: list[dict] = []

    for f in result["findings"]:
        fn = f["taint_path"]["sink"]["func_name"].lstrip("_")
        cwe = f["cwe"]
        detected_pairs.add((fn, cwe))
        if fn in EXPECTED_GOOD:
            false_positives.append({"func": fn, "cwe": cwe, "title": f["title"]})

    tp = 0
    fn_list: list[dict] = []
    for bad_fn, expected_cwe in EXPECTED_BAD.items():
        if (bad_fn, expected_cwe) in detected_pairs:
            tp += 1
        else:
            fn_list.append({"func": bad_fn, "expected_cwe": expected_cwe})

    fp = len(false_positives)
    fn_count = len(fn_list)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn_count) if (tp + fn_count) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "opt_level": opt_level,
        "cases_bad": len(EXPECTED_BAD),
        "cases_good": len(EXPECTED_GOOD),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn_count,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "elapsed_seconds": elapsed_s,
        "missed_cases": fn_list,
        "false_positive_details": false_positives,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run VulnHunter4Ghidra CWE benchmark suite")
    parser.add_argument("--opt", choices=["-O0", "-O1", "-O2", "all"], default="all", help="Compiler optimization level")
    parser.add_argument("--no-verify", action="store_true", help="Disable Z3 symbolic check")
    parser.add_argument("--json", action="store_true", help="Output JSON metrics")
    args = parser.parse_args()

    opts = ["-O0", "-O2"] if args.opt == "all" else [args.opt]
    reports = [run_cwe_benchmark(verify_symbolic=not args.no_verify, opt_level=o) for o in opts]

    if args.json:
        print(json.dumps(reports if len(reports) > 1 else reports[0], indent=2))
    else:
        for metrics in reports:
            print("=" * 56)
            print(f"VulnHunter4Ghidra 7-CWE Scorecard ({metrics['opt_level']})")
            print("=" * 56)
            print(f"Vulnerable (bad_*) cases:  {metrics['cases_bad']}")
            print(f"Patched    (good_*) cases: {metrics['cases_good']}")
            print(f"True Positives  (TP):      {metrics['true_positives']}")
            print(f"False Positives (FP):      {metrics['false_positives']}")
            print(f"False Negatives (FN):      {metrics['false_negatives']}")
            print(f"Precision:                 {metrics['precision'] * 100:.1f}%")
            print(f"Recall:                    {metrics['recall'] * 100:.1f}%")
            print(f"F1 Score:                  {metrics['f1_score'] * 100:.1f}%")
            print(f"Elapsed Time:              {metrics['elapsed_seconds']}s")
        print("=" * 56)


if __name__ == "__main__":
    main()
