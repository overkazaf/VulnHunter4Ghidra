# VulnHunter4Ghidra

**Interactive vulnerability detection and taint analysis for native binaries.**

[中文文档](README_CN.md)

---

VulnHunter4Ghidra finds vulnerabilities in compiled binaries (ELF, PE, Mach-O) by tracing data flow from user-controlled inputs (sources) to dangerous function calls (sinks). It runs as a Ghidra plugin for interactive analysis, or as a standalone CLI tool for CI/CD integration.

## Key Features

- **Source-Sink Taint Analysis** — traces data flow from `recv`, `read`, `fgets`, `scanf`, `argv`, and function parameters to dangerous sinks like `memcpy`, `strcpy`, `sprintf`, `system`, and `free`
- **CWE Classification** — maps each finding to a CWE ID (CWE-120 Buffer Overflow, CWE-134 Format String, CWE-78 Command Injection, CWE-416 Use-After-Free, etc.) with severity levels
- **Intra & Inter-procedural Analysis** — tracks taint within functions and across call boundaries up to configurable depth
- **20+ Architecture Support** — inherits Ghidra's architecture support: x86, x64, ARM, MIPS, PowerPC, RISC-V, and more
- **Dual Mode** — Ghidra plugin (interactive GUI) or standalone CLI (headless, CI/CD-ready)
- **JSON Output** — machine-parseable findings for pipeline integration

## Architecture

```
┌────────────────────┐     JSON-line TCP      ┌─────────────────────┐
│   Ghidra Plugin    │◄──────────────────────►│   Python Engine     │
│   (Java)           │      port 13372        │   (angr + Z3)       │
│                    │                        │                     │
│  • ScanVulnsAction │                        │  • CFG Analysis     │
│  • AnalyzeTaint    │                        │  • Source/Sink ID   │
│  • Result Display  │                        │  • Taint Propagation│
└────────────────────┘                        └─────────────────────┘
```

The Java side extracts function metadata (callsites, parameters, exports) from Ghidra's program model and sends it to the Python engine over a JSON-line TCP protocol. The engine uses [angr](https://angr.io/) for CFG construction and data-flow analysis, with optional Z3-based symbolic verification of reachability.

## Installation

### Prerequisites

- **Ghidra** 11.x+
- **Python** 3.10+ with angr: `pip install angr`
- **Java** 17+ (for building)

### Build

```bash
# Set your Ghidra installation path
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.x

# Build the extension
gradle buildExtension -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR

# Install: copy dist/*.zip to $GHIDRA_INSTALL_DIR/Extensions/Ghidra
```

### Python Engine Setup

```bash
# Create a virtualenv with angr
python3 -m venv .venv
source .venv/bin/activate
pip install angr

# Verify
python -c "import angr; print(angr.__version__)"
```

## Usage

### Ghidra Plugin

1. Open a binary in Ghidra's CodeBrowser
2. Enable the plugin: **File → Configure → Analysis → VulnHunter4Ghidra**
3. **VulnHunter4Ghidra → Scan Functions** — identifies sources and sinks across all functions
4. **VulnHunter4Ghidra → Analyze Taint** — runs taint analysis and displays findings with CWE classifications

The plugin automatically starts the Python engine and initializes it with the current binary.

### Standalone CLI

The Python engine runs independently without Ghidra, designed for CI/CD pipelines:

```bash
# Quick scan: identify sources and sinks
python -m vulnhunter4ghidra_engine.cli scan ./target_binary

# Full taint analysis (default depth: 5)
python -m vulnhunter4ghidra_engine.cli taint ./target_binary --depth 8

# Full report with JSON output for CI/CD
python -m vulnhunter4ghidra_engine.cli report ./target_binary --json
```

**Exit codes** (CI-friendly):
| Code | Meaning |
|------|---------|
| 0    | No findings |
| 1    | Findings detected |
| 2    | Analysis error |

**JSON output example:**

```json
{
  "binary": "./target_binary",
  "arch": "AMD64",
  "functions_scanned": 142,
  "total_sources": 23,
  "total_sinks": 18,
  "taint_paths": 7,
  "findings_count": 5,
  "findings": [
    {
      "finding_id": 1,
      "cwe": "CWE-120",
      "severity": "high",
      "title": "buffer_overflow: memcpy in handle_request",
      "description": "User-controlled data from recv() flows to memcpy() at 0x401234",
      "taint_path": {
        "source": { "func_name": "handle_request", "source_type": "RECV" },
        "sink": { "func_name": "handle_request", "callee_name": "memcpy" },
        "path_funcs": ["handle_request"],
        "path_length": 3
      }
    }
  ],
  "severity_summary": { "high": 3, "medium": 2 }
}
```

### CI/CD Integration

**GitHub Actions:**

```yaml
- name: Binary Vulnerability Scan
  run: |
    pip install angr
    python -m vulnhunter4ghidra_engine.cli report \
      ./build/output/binary --json > vulnhunter-report.json
    python -m vulnhunter4ghidra_engine.cli report \
      ./build/output/binary  # exits 1 if findings → fails the step
```

**Pre-merge gate:**

```bash
#!/bin/bash
# pre-merge-vuln-check.sh
python -m vulnhunter4ghidra_engine.cli taint "$1" --json \
  | jq -e '.findings | length == 0' > /dev/null
```

**DefectDojo import:** The JSON output maps directly to DefectDojo's generic findings format — CWE IDs, severity levels, and file paths are all present.

---

## Comparison with Other Tools

### VulnHunter4Ghidra vs. AppShark (ByteDance)

[AppShark](https://github.com/niceas/appshark) is ByteDance's open-source static analysis tool for Android applications. While both tools perform taint analysis, they operate in completely different domains:

| | VulnHunter4Ghidra | AppShark |
|---|---|---|
| **Target** | Native binaries (ELF, PE, Mach-O, .so) | Android APK (Java/Dalvik bytecode) |
| **Analysis Level** | Machine code (stripped binaries OK) | Java source / Jimple IR |
| **Engine** | angr + Z3 (CFG + symbolic execution) | Soot / FlowDroid (Jimple-based) |
| **Architecture** | x86, x64, ARM, MIPS, PowerPC, RISC-V, ... | Dalvik only |
| **Stripped Binary Support** | Yes — works without symbols | N/A (requires class metadata) |
| **Native Code (.so)** | Yes — primary target | No — cannot analyze JNI native code |
| **Interactive UI** | Ghidra plugin with decompiler integration | Config-driven batch only |
| **CI/CD Mode** | Standalone CLI with JSON output | CLI with JSON rules |
| **CWE Coverage** | Memory corruption, format string, command injection, UAF | Privacy leaks, SQL injection, WebView XSS, intent redirect |
| **License** | Apache 2.0 | Apache 2.0 |

**When to use VulnHunter4Ghidra:**

- Analyzing compiled C/C++ binaries, firmware, IoT devices, or shared libraries (.so, .dylib)
- Reverse engineering stripped binaries without source code
- Auditing native code for memory corruption vulnerabilities (buffer overflow, UAF, format string)
- Integrating binary security scanning into build pipelines

**When to use AppShark:**

- Auditing Android Java/Kotlin application code for privacy leaks and API misuse
- Detecting intent redirect, WebView JavaScript injection, or SQL injection in APKs
- Policy compliance scanning of Android apps

**Together:** For Android applications with JNI native libraries, use AppShark for the Java layer and VulnHunter4Ghidra for the native .so libraries. AppShark cannot see into native code, and VulnHunter4Ghidra cannot analyze Dalvik bytecode — they are complementary.

### VulnHunter4Ghidra vs. cwe_checker

[cwe_checker](https://github.com/fkie-cad/cwe_checker) is a pattern-matching tool that uses Ghidra as a disassembly frontend:

| | VulnHunter4Ghidra | cwe_checker |
|---|---|---|
| **Analysis Method** | Data-flow taint analysis (source → sink paths) | Pattern matching on IR |
| **Ghidra Integration** | Native plugin (menu actions, decompiler view) | External CLI only (uses Ghidra headless) |
| **Findings** | Concrete taint paths with full call chain | CWE pattern matches (no data-flow proof) |
| **False Positive Rate** | Lower (requires actual data flow) | Higher (pattern match without flow context) |
| **Symbolic Verification** | Z3-backed reachability check (planned) | None |
| **Interactive Use** | Click-through from finding to decompiler | Batch output only |

VulnHunter4Ghidra provides deeper analysis with actual data-flow evidence, while cwe_checker is faster for broad pattern sweeps. Use cwe_checker for a quick first pass and VulnHunter4Ghidra for confirmed, path-verified findings.

---

## Supported Vulnerability Classes

| CWE | Type | Severity | Sink Functions |
|-----|------|----------|----------------|
| CWE-120 | Buffer Overflow | High | `memcpy`, `strcpy`, `strncpy`, `strcat`, `gets`, `recv`, `read` |
| CWE-134 | Format String | High | `printf`, `sprintf`, `fprintf`, `snprintf`, `syslog` |
| CWE-78 | OS Command Injection | Critical | `system`, `popen`, `execve` |
| CWE-416 | Use-After-Free | High | `free` (tracked across subsequent dereferences) |
| CWE-415 | Double Free | High | `free` (duplicate call detection) |
| CWE-190 | Integer Overflow | Medium | Size arguments to allocation/copy functions |
| CWE-476 | NULL Pointer Dereference | Medium | Unchecked return values from allocation |

## Source Types

| Type | Description | Examples |
|------|-------------|---------|
| `FUNC_PARAM` | Buffer-type parameters of exported functions | `void parse(char *buf, int len)` |
| `ARGV` | Command-line arguments via main() | `main(int argc, char **argv)` |
| `RECV` / `READ` | Network/file input functions | `recv()`, `read()` |
| `FGETS` / `SCANF` | Formatted input | `fgets()`, `scanf()`, `fscanf()` |
| `STDIN` | Standard input reads | `getchar()`, `getline()` |
| `ENV` | Environment variables | `getenv()` |
| `FILE_READ` | File content reads | `fread()` |

## Development

```bash
# Run Python tests (59 tests)
PYTHONPATH=python python -m pytest test/ -v

# Build Java extension
gradle buildExtension -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR

# Start engine in development mode
PYTHONPATH=python python -m vulnhunter4ghidra_engine -v
```

### Project Structure

```
VulnHunter4Ghidra/
├── src/main/java/vulnhunter4ghidra/
│   ├── VulnHunter4GhidraPlugin.java    # Plugin entry point
│   ├── engine/
│   │   ├── EngineProtocol.java          # JSON-line protocol
│   │   └── EngineManager.java           # Python process lifecycle
│   └── actions/
│       ├── ScanVulnsAction.java          # Scan menu action
│       └── AnalyzeTaintAction.java       # Taint analysis action
├── python/vulnhunter4ghidra_engine/
│   ├── protocol.py     # JSON-line command/response
│   ├── models.py       # Source, Sink, TaintPath, VulnFinding
│   ├── sources.py      # Source identification
│   ├── sinks.py        # Sink identification + CWE mapping
│   ├── taint.py        # Taint propagation (intra + inter-procedural)
│   ├── engine.py       # Orchestration
│   ├── server.py       # TCP server (port 13372)
│   └── cli.py          # Standalone CLI
└── test/               # 59 unit tests
```

## License

Apache License 2.0
