# VulnHunter4Ghidra

**面向原生二进制文件的交互式漏洞检测与污点分析工具。**

[English](README.md)

---

VulnHunter4Ghidra 通过追踪用户输入（Source）到危险函数调用（Sink）的数据流，在已编译的二进制文件（ELF、PE、Mach-O）中挖掘潜在漏洞。它既可以作为 Ghidra 插件进行交互式逆向分析，也可以作为独立 CLI 工具集成到 CI/CD 流水线中。

## 核心特性

- **双引擎混合融合架构（Ghidra High P-Code SSA + angr VEX/Z3）** — 同时内置原生 Java 端 Ghidra 反编译器 `HighFunction` SSA 数据流引擎（支持全部 20+ 种 SLEIGH 处理器、裸固件镜像及零 Python 离线模式）与 Python `angr` VEX + Z3 引擎，双引擎交叉印证告警自动升级置信度
- **抗编译器优化（`-O0` 至 `-O2`/`-Os`）污点追踪** — 完整覆盖寄存器、栈缓冲区偏移、跨函数实参与 `-O2` 尾调用优化（Tail-Call `jmp`/`b`）传播链路，自动过滤只读段常量格式串/命令字面量与安全定长拷贝
- **有状态指针生命周期与整数溢出检测器** — 内置针对释放后重用（`CWE-416`，识别 `p = NULL`/重分配消解）、双重释放（`CWE-415`）、未判空解引用（`CWE-476`）、整数溢出流入分配/拷贝长度（`CWE-190`）以及定长栈越界写入（`CWE-120`）的语义状态机
- **Z3 符号可达性验证** — 支持有界符号执行（`--verify`）验证路径约束可满足性，自动剪除互斥死分支（Dead Path）假阳性
- **专业级 Ghidra 逆向工作台** — 可停靠 Findings / Sources / Sinks 表格面板、Taint Path 步进树一键联动跳转、`ColorizingService` 路径染色、后台可取消 `Task` 进度条，以及基于 Ghidra `Bookmark` 的审计状态（Confirmed / False Positive）持久化
- **可扩展规则库** — 支持加载外部 `.toml` / `.json` 规则包（内置 `rules/embedded_iot.toml` 固件规则示例），或直接在 Ghidra 右键标注自定义 Source / Sink / Sanitizer
- **SARIF 2.1.0 与增量基线门禁** — 原生导出带 `codeFlows` 的 OASIS SARIF 2.1.0 报告（无缝对接 GitHub Code Scanning 与 DefectDojo），支持 `--baseline` 存量基线差分与 `--fail-on` 门禁阈值

## 架构设计

```
┌──────────────────────────┐   鉴权 JSON-line stdio 管道  ┌──────────────────────────┐
│   Ghidra 工作台 (Java)   │◄────────────────────────────►│   Python 分析引擎        │
│                          │      按实例隔离，零端口冲突  │   (angr VEX + Z3)        │
│  • VulnHunterProvider UI │                              │  • VEX 数据流污点引擎    │
│  • TaintPathHighlighter  │                              │  • 指针生命周期状态机    │
│  • 后台可取消 Task       │                              │  • Z3 路径可行性验证     │
│  • Bookmark 审计持久化   │                              │  • SARIF 2.1.0 & 规则库  │
└──────────────────────────┘                              └──────────────────────────┘
```

Java 端自动将 Ghidra 程序的加载基址（`getImageBase()`）同步至 Python 引擎，并通过带一次性会话 Token 鉴权的独立 `stdio` 管道通信（彻底消除多实例端口冲突与本地端口未授权访问风险）。引擎基于 VEX IR 执行寄存器/栈数据流传播、生命周期状态机检测及可选的 Z3 路径约束验证。

## 安装指南

### 环境要求

- **Ghidra** 11.x+
- **Python** 3.10+（需安装 angr：`pip install angr`）
- **Java** 17+（用于编译扩展）

### 构建插件

```bash
# 设置 Ghidra 安装路径
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.x

# 构建扩展插件
gradle buildExtension -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR

# 安装：将 dist/*.zip 复制到 $GHIDRA_INSTALL_DIR/Extensions/Ghidra
```

### 配置 Python 引擎

```bash
# 创建包含 angr 的虚拟环境
python3 -m venv .venv
source .venv/bin/activate
pip install angr

# 验证安装
python -c "import angr; print(angr.__version__)"
```

## 使用方法

### Ghidra 插件模式

1. 在 Ghidra 的 CodeBrowser 中打开目标二进制文件
2. 启用插件：**File → Configure → Analysis → VulnHunter4Ghidra**
3. **VulnHunter4Ghidra → Scan Functions** — 扫描所有函数中的污点源（Source）和危险汇聚点（Sink）
4. **VulnHunter4Ghidra → Analyze Taint** — 执行污点分析并展示带 CWE 分类的漏洞结果

插件会自动启动 Python 分析引擎并加载当前打开的二进制文件。

### 独立 CLI 模式

Python 引擎支持脱离 Ghidra 独立运行，方便接入 CI/CD 流水线：

```bash
# 开发模式安装（注册 `vulnhunter` 命令行入口）
pip install -e .

# 快速扫描：识别 Source 与 Sink（可加载自定义固件/业务规则包）
vulnhunter scan ./target_binary --rules rules/embedded_iot.toml

# 完整污点与生命周期分析 + Z3 符号可行性验证
vulnhunter taint ./target_binary --depth 8 --verify

# 生成符合 GitHub Code Scanning / DefectDojo 标准的 SARIF 2.1.0 报告
vulnhunter report ./target_binary --verify --format sarif -o vulnhunter.sarif

# 增量基线门禁：屏蔽存量基线告警，仅在新增 High/Critical 漏洞时返回退出码 1 阻断流水线
vulnhunter report ./target_binary --baseline baseline.sarif --fail-on high --json

# 运行内置 7 类 CWE 准确率/召回率基准评测（Juliet 风格对照组）
python -m benchmark.run_benchmark
```

**退出码说明**（便于 CI 集成）：
| 退出码 | 含义 |
|---|---|
| 0 | 未发现漏洞 |
| 1 | 检测到潜在漏洞 |
| 2 | 分析过程发生错误 |

**JSON 输出示例：**

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

### CI/CD 集成

**GitHub Actions：**

```yaml
- name: Binary Vulnerability Scan
  run: |
    pip install angr
    python -m vulnhunter4ghidra_engine.cli report \
      ./build/output/binary --json > vulnhunter-report.json
    python -m vulnhunter4ghidra_engine.cli report \
      ./build/output/binary  # 检出漏洞时返回退出码 1 并阻断流程
```

**合入前门禁（Pre-merge Gate）：**

```bash
#!/bin/bash
# pre-merge-vuln-check.sh
python -m vulnhunter4ghidra_engine.cli taint "$1" --json \
  | jq -e '.findings | length == 0' > /dev/null
```

**DefectDojo 导入：** 输出的 JSON 包含 CWE 编号、严重级别和文件路径，可直接映射至 DefectDojo 通用告警格式。

---

## 与其他工具对比

### VulnHunter4Ghidra vs. AppShark（字节跳动）

[AppShark](https://github.com/niceas/appshark) 是字节跳动开源的 Android 应用静态分析工具。两者虽然都执行污点分析，但面向的技术栈与分析层面完全不同：

| | VulnHunter4Ghidra | AppShark |
|---|---|---|
| **分析目标** | 原生二进制（ELF、PE、Mach-O、.so） | Android APK（Java/Dalvik 字节码） |
| **分析层次** | 机器码（支持已剥离符号的二进制） | Java 源码 / Jimple IR |
| **分析引擎** | angr + Z3（CFG + 符号执行） | Soot / FlowDroid（基于 Jimple） |
| **架构支持** | x86、x64、ARM、MIPS、PowerPC、RISC-V 等 | 仅支持 Dalvik |
| **无符号二进制支持** | 支持 — 无需调试符号即可分析 | 不适用（依赖类元数据） |
| **Native 代码（.so）** | 支持 — 核心目标 | 不支持 — 无法分析 JNI 原生库 |
| **交互界面** | Ghidra 原生插件，集成反编译器视图 | 仅支持配置驱动的批处理模式 |
| **CI/CD 模式** | 独立 CLI，支持 JSON 输出 | CLI 配合 JSON 规则文件 |
| **CWE 覆盖范围** | 内存破坏、格式化字符串、命令注入、UAF | 隐私泄露、SQL 注入、WebView XSS、Intent 重定向 |
| **开源协议** | Apache 2.0 | Apache 2.0 |

**何时使用 VulnHunter4Ghidra：**

- 审计编译后的 C/C++ 二进制程序、固件、IoT 设备镜像或动态库（`.so`、`.dylib`）
- 在无源码条件下逆向分析已去符号（stripped）的二进制文件
- 针对原生代码排查内存破坏漏洞（缓冲区溢出、UAF、格式化字符串）
- 在构建流水线中集成原生二进制安全门禁扫描

**何时使用 AppShark：**

- 审计 Android Java/Kotlin 应用代码中的隐私数据泄露与 API 误用
- 检测 APK 中的 Intent 重定向、WebView JS 注入或 SQL 注入
- 进行 Android 应用合规扫描

**组合使用：** 对于包含 JNI 原生库的 Android 应用，可用 AppShark 审计 Java 层，同时用 VulnHunter4Ghidra 审计 `.so` 原生库——两者能力互补。

### VulnHunter4Ghidra vs. cwe_checker

[cwe_checker](https://github.com/fkie-cad/cwe_checker) 是一款使用 Ghidra 作为反汇编前端的模式匹配工具：

| | VulnHunter4Ghidra | cwe_checker |
|---|---|---|
| **分析方法** | 数据流污点分析（Source → Sink 路径） | 基于 IR 的模式匹配 |
| **Ghidra 集成** | 原生插件（菜单操作、反编译器视图联动） | 仅外部 CLI（通过 Ghidra Headless 调用） |
| **告警形式** | 带完整调用链的具体污点路径 | CWE 模式匹配结果（无数据流证明） |
| **误报率** | 更低（要求存在真实可达路径） | 较高（缺乏跨流上下文的规则匹配） |
| **符号验证** | 基于 Z3 的可达性验证（规划中） | 无 |
| **交互体验** | 可在 Ghidra 中直接跳转与交互分析 | 仅支持批量文本输出 |

VulnHunter4Ghidra 能给出包含数据流路径依据的深度结果，而 `cwe_checker` 适合快速广度扫描；可以先用 `cwe_checker` 初筛，再用 VulnHunter4Ghidra 进行路径级分析验证。

---

## 支持的漏洞类型

| CWE | 类型 | 严重级别 | Sink 函数 |
|---|---|---|---|
| CWE-120 | 缓冲区溢出 | High | `memcpy`, `strcpy`, `strncpy`, `strcat`, `gets`, `recv`, `read` |
| CWE-134 | 格式化字符串 | High | `printf`, `sprintf`, `fprintf`, `snprintf`, `syslog` |
| CWE-78 | OS 命令注入 | Critical | `system`, `popen`, `execve` |
| CWE-416 | 释放后重用 (UAF) | High | `free`（跟踪释放后的后续解引用） |
| CWE-415 | 双重释放 | High | `free`（重复释放调用检测） |
| CWE-190 | 整数溢出 | Medium | 分配/拷贝函数的长度参数 |
| CWE-476 | 空指针解引用 | Medium | 内存分配未校验返回值 |

## 污点源（Source）类型

| 类型 | 说明 | 示例 |
|---|---|---|
| `FUNC_PARAM` | 导出函数的缓冲区指针参数 | `void parse(char *buf, int len)` |
| `ARGV` | `main()` 函数的命令行参数 | `main(int argc, char **argv)` |
| `RECV` / `READ` | 网络或文件输入函数 | `recv()`, `read()` |
| `FGETS` / `SCANF` | 格式化输入函数 | `fgets()`, `scanf()`, `fscanf()` |
| `STDIN` | 标准输入读取 | `getchar()`, `getline()` |
| `ENV` | 环境变量 | `getenv()` |
| `FILE_READ` | 文件内容读取 | `fread()` |

## 开发与测试

```bash
# 运行 Python 单元测试（59 项）
PYTHONPATH=python python -m pytest test/ -v

# 构建 Java 扩展包
gradle buildExtension -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR

# 开发模式启动引擎服务端
PYTHONPATH=python python -m vulnhunter4ghidra_engine -v
```

### 项目结构

```
VulnHunter4Ghidra/
├── src/main/java/vulnhunter4ghidra/
│   ├── VulnHunter4GhidraPlugin.java    # Ghidra 插件入口
│   ├── engine/
│   │   ├── EngineProtocol.java          # JSON-line 通信协议
│   │   └── EngineManager.java           # Python 进程生命周期管理
│   └── actions/
│       ├── ScanVulnsAction.java         # 函数扫描菜单动作
│       └── AnalyzeTaintAction.java      # 污点分析菜单动作
├── python/vulnhunter4ghidra_engine/
│   ├── protocol.py     # JSON-line 命令/响应封装
│   ├── models.py       # Source, Sink, TaintPath, VulnFinding 模型
│   ├── sources.py      # 污点源识别
│   ├── sinks.py        # 危险汇聚点识别与 CWE 映射
│   ├── taint.py        # 过程内与过程间污点传播分析
│   ├── engine.py       # 核心分析编排
│   ├── server.py       # TCP 服务端（端口 13372）
│   └── cli.py          # 独立命令行工具
└── test/               # 59 项单元测试
```

## 开源协议

Apache License 2.0
