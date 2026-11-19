# VulnHunter4Ghidra

**融合 Ghidra High P-Code SSA 与 angr VEX/Z3 的原生二进制交互式漏洞挖掘与污点分析工作台。**

[English](README.md)

---

VulnHunter4Ghidra 面向已编译原生二进制文件（`ELF`、`PE`、`Mach-O`、`.so`、`.dylib` 及裸机固件），深度检测内存破坏、指针生命周期异常、整数溢出与命令注入漏洞。它既可作为 **Ghidra 交互式逆向工作台**（融合 Ghidra 反编译器 High P-Code SSA 与 Python `angr` VEX + Z3 双引擎），也可作为 **无头 CLI / Docker 扫描器**直接输出标准 SARIF 2.1.0 接入企业 CI/CD 安全门禁。

## 核心特性

- **双引擎混合融合架构（Ghidra High P-Code SSA + angr VEX/Z3）** — 同时内置原生 Java 端 Ghidra 反编译器 `HighFunction` SSA 数据流引擎（支持全部 20+ 种 SLEIGH 处理器、无本地文件的裸固件镜像及零 Python 离线模式）与 Python `angr` VEX + Z3 引擎；双引擎交叉印证告警自动升级置信度并合并证据链
- **抗编译器优化（`-O0` 至 `-O2`/`-Os`）污点追踪** — 完整覆盖寄存器、栈槽偏移、跨函数实参/返回值传递与 `-O2` 尾调用优化（Tail-Call `jmp`/`b` 跨函数跳转），自动过滤只读段常量格式串/命令字面量与安全定长栈拷贝
- **有状态指针生命周期与整数溢出检测器** — 内置释放后重用（`CWE-416`，精准识别 `p = NULL` 与重新分配消解，正常 `free` 零误报）、双重释放（`CWE-415`）、未判空解引用（`CWE-476`）、整数溢出流入分配/拷贝大小（`CWE-190`）以及定长栈越界写入（`CWE-120`）语义状态机
- **Z3 符号路径可行性验证** — 有界符号执行（`--verify`）验证路径约束可满足性（`verified: true`），自动剪除互斥死分支（Dead Path）假阳性
- **专业级 Ghidra 逆向工作台** — 可停靠 `Findings` / `Sources` / `Sinks` 表格面板、`Taint Path` 步进树一键联动跳转、`ColorizingService` 路径三色高亮、后台可取消 `Task` 进度条，以及基于 Ghidra `Bookmark` 的审计结论（`CONFIRMED` / `FALSE_POSITIVE`）项目级持久化
- **可扩展规则库** — 支持加载外部 `.toml` / `.json` 规则包（内置 `rules/embedded_iot.toml` 嵌入式固件规则示例），或在 Ghidra 反汇编/反编译器视图直接右键标注自定义 `Source` / `Sink` / `Sanitizer`
- **SARIF 2.1.0 与增量基线门禁** — 原生导出含 `codeFlows` 与 `security-severity` 的 OASIS SARIF 2.1.0 报告（无缝对接 GitHub Code Scanning、VS Code SARIF Viewer 与 DefectDojo），支持 `--baseline` 存量基线差分门禁与 `--fail-on` 阻断级别控制

## 架构设计

```
┌────────────────────────────┐   鉴权 JSON-line stdio 管道  ┌────────────────────────────┐
│   Ghidra 工作台 (Java)     │◄────────────────────────────►│   Python 分析引擎          │
│                            │      按实例隔离，零端口冲突  │   (angr VEX + Z3)          │
│  • PCodeTaintAnalyzer (SSA)│                              │  • VEX 数据流污点引擎      │
│  • VulnHunterProvider UI   │                              │  • 指针生命周期状态机      │
│  • TaintPathHighlighter    │                              │  • Z3 路径可行性验证       │
│  • 后台 Task 与书签持久化  │                              │  • SARIF 2.1.0 & 规则引擎  │
└────────────────────────────┘                              └────────────────────────────┘
```

Java 插件端自动将 Ghidra 程序的加载基址（`getImageBase()`）同步至 Python 引擎，并通过带随机一次性会话 Token 鉴权的独立 `stdio` 管道通信（彻底消除多开 Ghidra 窗口的端口冲突与本地端口未授权访问风险）。在默认的 **Hybrid 混合模式**下，Ghidra High P-Code SSA 与 `angr` VEX 双引擎独立命中的漏洞会自动标记 `[HYBRID]` 高置信度证据。

## 安装指南

### 环境要求

- **Ghidra** 11.x+
- **Java** 21+（用于构建插件）
- **Python** 3.10+ 且安装 `angr` *（纯 `P-Code SSA Only` 离线模式无需 Python；Hybrid / CLI / Z3 验证需配置）*

### 构建 Ghidra 扩展包

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.x
gradle buildExtension -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR

# 安装：在 Ghidra 中通过 File → Install Extensions... 选择 dist/*.zip，或解压至 $GHIDRA_INSTALL_DIR/Extensions/Ghidra
```

### 配置 Python 引擎与 CLI

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# 验证命令行入口
vulnhunter --help
```

## 使用方法

### Ghidra 交互式工作台模式

1. 在 Ghidra CodeBrowser 中打开目标二进制或固件，启用插件（**File → Configure → Analysis → VulnHunter4Ghidra**）。
2. 在停靠面板 **VulnHunter4Ghidra — Taint & CWE Workbench** 工具栏中：
   - 选择分析引擎模式：**`Hybrid (P-Code + angr)`**（默认推荐）、**`P-Code SSA Only`**（纯离线/特殊单片机固件）或 **`angr VEX Only`**。
   - 设置跨函数调用深度 **Depth**、按需勾选 **Z3 Verify**，点击 **Scan & Analyze** 后台运行。
3. **交互式审计与路径溯源**：
   - 在 **Findings** 表格中点击任一告警，自动跳转至汇聚点并以蓝（Source）、黄（传播节点）、红（Sink）三色同步高亮反汇编与反编译器视图。
   - 点击下方 **Taint Path** 树节点可逐跳回溯数据流；右键告警可标记 **`CONFIRMED`** 或 **`FALSE_POSITIVE`**（自动写入 Ghidra Bookmark 随 `.gpr` 保存），或点击 **Export...** 导出 `.sarif` / `.json`。
   - 在 Listing 或 Decompiler 任意位置右键可执行 **Analyze Current Function**（单函数秒级分析）或将函数/调用点标记为 **Custom Source / Custom Sink / Sanitizer**。

### 独立 CLI 与 Docker 模式

```bash
# 快速扫描：识别 Source 与 Sink（可加载自定义固件/业务规则包）
vulnhunter scan ./target_binary --rules rules/embedded_iot.toml

# 完整污点与指针生命周期分析 + Z3 符号可行性验证
vulnhunter taint ./target_binary --depth 8 --verify

# 导出符合 GitHub Code Scanning / DefectDojo 标准的 SARIF 2.1.0 报告
vulnhunter report ./target_binary --verify --format sarif -o vulnhunter.sarif

# 增量基线门禁：屏蔽存量基线告警，仅在新增 High/Critical 漏洞时返回退出码 1 阻断流水线
vulnhunter report ./target_binary --baseline baseline.sarif --fail-on high --json

# 使用 Docker 容器运行扫描
docker build -t vulnhunter .
docker run --rm -v "$PWD:/workspace" vulnhunter report /workspace/target_binary --format sarif
```

**退出码说明**（便于 CI 门禁集成）：

| 退出码 | 含义 |
|---|---|
| `0` | 通过（经 `--baseline` 过滤后无触发 `--fail-on` 阈值的告警） |
| `1` | 检出触发门禁阈值的潜在漏洞 |
| `2` | 分析或运行异常 |

**JSON 输出示例：**

```json
{
  "binary": "./target_binary",
  "arch": "AMD64",
  "base_addr": "0x400000",
  "functions_scanned": 142,
  "total_sources": 23,
  "total_sinks": 18,
  "taint_paths": 2,
  "findings_count": 2,
  "suppressed_by_baseline": 0,
  "findings": [
    {
      "finding_id": 1,
      "fingerprint": "9f82c10e4a7b31d2",
      "cwe": "CWE-78",
      "severity": "critical",
      "confidence": "high",
      "verified": true,
      "title": "command_injection: system in handle_cgi",
      "description": "User-controlled data from Call to fgets() flows to system() at 0x401234",
      "evidence": [
        "VEX data-flow confirmed taint in system() arg [0]",
        "Z3 symbolic feasibility verified (satisfiable path constraints)"
      ],
      "taint_path": {
        "source": { "address": "0x401190", "func_name": "handle_cgi", "source_type": "fgets" },
        "sink": { "address": "0x401234", "func_name": "handle_cgi", "callee_name": "system", "cwe": "CWE-78" },
        "path_addrs": ["0x401180", "0x401220"],
        "path_funcs": ["handle_cgi"],
        "path_length": 2,
        "confidence": "high"
      }
    }
  ],
  "severity_summary": { "critical": 2 }
}
```

### CI/CD 集成（GitHub Code Scanning + 增量基线门禁）

```yaml
- name: Binary CWE Scan & SARIF Upload
  run: |
    pip install .
    vulnhunter report ./build/app --verify --format sarif -o vulnhunter.sarif
    vulnhunter report ./build/app --baseline .sec/baseline.sarif --fail-on high

- name: Upload SARIF to GitHub Security
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: vulnhunter.sarif
```

---

## 准确率与召回率基准评测（Benchmark Scorecard）

项目内置对标 NIST Juliet 风格的 7 类 CWE 正负样本原生编译基准套件（`python -m benchmark.run_benchmark --opt all`），同时覆盖未优化（`-O0`）与高阶发布优化（`-O2`，含尾调用跳转优化与寄存器提升）：

| 编译优化级别 | 漏洞样本 (`bad_*`) | 修复样本 (`good_*`) | 真正例 (TP) | 误报 (FP) | 准确率 (Precision) | 召回率 (Recall) | F1 分数 |
|---|---|---|---|---|---|---|---|
| `clang -O0`（开启 Z3 验证） | 7 | 7 | 7 | 0 | **100.0%** | **100.0%** | **100.0%** |
| `clang -O2`（含尾调用与寄存器优化） | 7 | 7 | 7 | 0 | **100.0%** | **100.0%** | **100.0%** |

---

## 与其他工具对比

### VulnHunter4Ghidra vs. AppShark（字节跳动）

[AppShark](https://github.com/niceas/appshark) 面向 Android Java/Kotlin 字节码污点分析。审计含 JNI 原生库的 Android 应用时，可用 AppShark 扫描 Java 层、用 VulnHunter4Ghidra 审计 `.so` 原生库，实现全栈覆盖：

| | VulnHunter4Ghidra | AppShark |
|---|---|---|
| **分析目标** | 原生二进制（`ELF`、`PE`、`Mach-O`、`.so`、固件镜像） | Android APK（Java/Dalvik 字节码） |
| **分析层次** | 机器码 / 反编译器 High P-Code SSA & VEX IR | Java 源码 / Jimple IR |
| **分析引擎** | 双引擎混合：Ghidra High P-Code SSA + angr VEX + Z3 | Soot / FlowDroid（基于 Jimple） |
| **架构支持** | 20+ 种（x86、x64、ARM/AArch64、MIPS、PowerPC、RISC-V 等） | 仅支持 Dalvik |
| **无符号二进制支持** | 支持 — 无需调试符号即可分析 | 不适用（依赖类元数据） |
| **交互界面** | Ghidra 可停靠工作台 + 路径高亮 + Bookmark 审计闭环 | 仅批处理命令行 |
| **CI/CD 模式** | CLI 与 Docker（`SARIF 2.1.0`、JSON、`--baseline` 差分门禁） | CLI 配合 JSON 规则 |
| **开源协议** | Apache 2.0 | Apache 2.0 |

### VulnHunter4Ghidra vs. cwe_checker

| | VulnHunter4Ghidra | cwe_checker |
|---|---|---|
| **分析方法** | High P-Code SSA + VEX 真实数据流污点 + 指针生命周期状态机 | 基于 IR 的启发式模式匹配 |
| **Ghidra 集成** | 原生交互式工作台、单函数右键秒级分析、自定义规则标注 | 仅外部 CLI（调用 Ghidra Headless） |
| **误报抑制** | 自动排除 `.rodata` 常量格式串/命令、安全定长拷贝与 `p = NULL` 消解 | 缺乏跨流常量与边界上下文，误报较高 |
| **符号验证** | 内置 Z3 路径约束可行性验证（`--verify`），自动剪除死分支 | 无 |
| **报告与门禁** | 标准 SARIF 2.1.0 `codeFlows` + `--baseline` 存量基线差分门禁 | JSON / 文本批量输出 |

---

## 支持的漏洞类型

| CWE | 类型 | 默认级别 | 检测机制 |
|---|---|---|---|
| `CWE-78` | OS 命令注入 | Critical | 受污染且非常量的命令参数流入 `system`, `popen`, `exec*`, `WinExec`, `CreateProcessA` |
| `CWE-120` | 缓冲区溢出 | Critical | 受污染拷贝源/长度或超界常量写入栈/堆缓冲区（`strcpy`, `memcpy`, `sprintf`, `fgets`, `recv`, `read`） |
| `CWE-134` | 格式化字符串 | Critical | 受污染且非常量的格式串实参流入 `printf`, `sprintf`, `snprintf`, `fprintf`, `syslog` |
| `CWE-416` | 释放后重用 (UAF) | Critical | VEX/SSA 状态机追踪 `free` 后未重赋值的指针解引用或跨调用传参 |
| `CWE-415` | 双重释放 | Critical | VEX/SSA 状态机追踪同一指针无重赋值的重复 `free`/`cfree`/`HeapFree` |
| `CWE-190` | 整数溢出 | High | 过程内/跨函数受污染整数经算术运算（`Add`/`Mul`/`Shl`）流入 `malloc`/`calloc`/`realloc`/`memcpy` 大小参数 |
| `CWE-476` | 空指针解引用 | Medium | 内存分配返回值（`malloc`/`calloc`/`realloc`）在条件判空前直接解引用或写入 |

## 开发与测试

```bash
# 运行全部 Python 单测、stdio 鉴权协议、SARIF 与真实编译二进制测试（共 71 项）
pytest -v

# 运行 -O0 与 -O2 双优化等级 7-CWE 基准评测
python -m benchmark.run_benchmark --opt all

# 构建 Ghidra 扩展包
gradle buildExtension -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR
```

### 项目结构

```
VulnHunter4Ghidra/
├── src/main/java/vulnhunter4ghidra/
│   ├── VulnHunter4GhidraPlugin.java       # 双引擎混合编排与后台 Task 管理
│   ├── pcode/PCodeTaintAnalyzer.java      # 原生 Ghidra High P-Code SSA 污点与生命周期分析器
│   ├── ui/
│   │   ├── VulnHunterProvider.java        # 可停靠 Findings/Sources/Sinks 交互式工作台
│   │   └── ProgramScanner.java            # Thunk 与 -O2 尾调用元数据提取器
│   ├── highlight/TaintPathHighlighter.java# Listing 与 Decompiler 路径染色服务
│   ├── engine/
│   │   ├── EngineProtocol.java            # 带 Token 鉴权的 JSON-line RPC 协议
│   │   └── EngineManager.java             # 按实例隔离的 stdio Python 进程管理器
│   └── actions/                           # 全量扫描、右键单函数分析与自定义节点标注动作
├── python/vulnhunter4ghidra_engine/
│   ├── models.py                          # Source, Sink, TaintPath, VulnFinding, Confidence 模型
│   ├── rules.py                           # 符号归一化与 TOML/JSON 可扩展规则注册表
│   ├── sources.py / sinks.py              # Source 与 Sink 识别
│   ├── taint.py                           # VEX 寄存器/栈槽与 -O2 尾调用数据流引擎
│   ├── detectors.py                       # 有状态 CWE-415/416/476/190/120 语义检测器
│   ├── verifier.py                        # 有界 Z3 符号路径可行性验证器
│   ├── sarif.py                           # OASIS SARIF 2.1.0 导出与基线指纹加载器
│   ├── engine.py / server.py / cli.py     # 核心编排、stdio/TCP 服务端与独立 CLI
├── rules/embedded_iot.toml                # 嵌入式/IoT 固件扩展规则包示例
├── benchmark/run_benchmark.py             # 7-CWE (-O0 & -O2) 准确率/召回率基准评测套件
├── test/                                  # 71 项单测、IPC、SARIF 与原生二进制集成测试
├── Dockerfile                             # 容器化扫描镜像定义
└── .github/workflows/ci.yml               # GitHub Actions 自动化测试与基准门禁
```

## 开源协议

Apache License 2.0
