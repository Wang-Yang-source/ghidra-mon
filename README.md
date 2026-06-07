<!--
  GHIDRAI — Terminal Reverse Engineering TUI Toolkit Aggregator
  View this file with `cat README.md` or `less -R README.md` for rainbow colors.
-->
[0;31m ######   ##     ## #### ########  ########     ###    #### [0m
[0;33m##    ##  ##     ##  ##  ##     ## ##     ##   ## ##    ##  [0m
[0;32m##        ##     ##  ##  ##     ## ##     ##  ##   ##   ##  [0m
[0;36m##   #### #########  ##  ##     ## ########  ##     ##  ##  [0m
[0;34m##    ##  ##     ##  ##  ##     ## ##   ##   #########  ##  [0m
[0;35m##    ##  ##     ##  ##  ##     ## ##    ##  ##     ##  ##  [0m
[0;31m ######   ##     ## #### ########  ##     ## ##     ## #### [0m

[0;36m  Terminal Reverse Engineering TUI Toolkit Aggregator[0m
[0;33m  终端逆向工程 TUI 工具合集 · 开源 · 键盘驱动 · 后端可替换[0m
[0;32m  ターミナルリバースエンジニアリング TUI ツールキット[0m
[0;34m  터미널 리버스 엔지니어링 TUI 툴킷 · 오픈소스[0m
[0;35m  Терминальный TUI инструментарий для реверс-инжиниринга[0m
[0;31m  Boîte à outils TUI d'ingénierie inverse pour terminal[0m

---

```ansi
[0;31m ######   ##     ## #### ########  ########     ###    #### [0m
[0;33m##    ##  ##     ##  ##  ##     ## ##     ##   ## ##    ##  [0m
[0;32m##        ##     ##  ##  ##     ## ##     ##  ##   ##   ##  [0m
[0;36m##   #### #########  ##  ##     ## ########  ##     ##  ##  [0m
[0;34m##    ##  ##     ##  ##  ##     ## ##   ##   #########  ##  [0m
[0;35m##    ##  ##     ##  ##  ##     ## ##    ##  ##     ##  ##  [0m
[0;31m ######   ##     ## #### ########  ##     ## ##     ## #### [0m

[0;36m  Terminal Reverse Engineering TUI Toolkit Aggregator[0m
[0;33m  终端逆向工程 TUI 工具合集 · 开源 · 键盘驱动 · 后端可替换[0m
[0;32m  ターミナルリバースエンジニアリング TUI ツールキット[0m
[0;34m  터미널 리버스 엔지니어링 TUI 툴킷 · 오픈소스[0m
[0;35m  Терминальный TUI инструментарий для реверс-инжиниринга[0m
[0;31m  Boîte à outils TUI d'ingénierie inverse pour terminal[0m
```

GhidrAI is a terminal-based AI-assisted reverse engineering workspace.

It does not try to replace Ghidra at the engine level. Instead, it integrates Ghidra and other reverse engineering engines into a fast, keyboard-first TUI workflow, providing project memory, AI-assisted analysis, structured notes, and exportable reverse engineering reports.

GhidrAI 是一个面向 AI 时代的 TUI 逆向工作台。

它不以重写 Ghidra 为第一目标，而是将 Ghidra 及其他逆向工具整合为统一的终端工作流，提供快速分析、反编译结果浏览、函数与字符串索引、AI 辅助理解、项目级记忆和可交付报告导出能力。

项目长期产品记忆和设计哲学记录在 [MEMORY.md](MEMORY.md) 和 [DESIGN.md](DESIGN.md)。

## 设计哲学

- 终端优先：所有核心能力必须能在 Linux CLI/TUI 环境中运行，不能依赖 GUI。
- 工具合集优先：项目中心是统一逆向工作台，不是 Ghidra 自动化、MCP 服务或某个单独工具的包装。
- 开源优先：默认集成开源工具和开源库，避免闭源 SaaS、远程必需服务和不可审计依赖。
- 结构化优先：优先调用 JSON、NDJSON、GDB/MI、API、SQLite 或其他机器可读输出。
- 文本兜底：不得在 UI 层到处写正则解析终端文本；纯文本工具必须通过独立 adapter 隔离。
- 原始输出保留：每个工具的 stdout/stderr 都要能回看，结构化视图和原始视图必须并存。
- 只读默认：分析、扫描、解包、调试 attach、patch 等高风险操作必须区分权限和确认。
- 后端可替换：同一类能力允许多个引擎并存，例如 Ghidra/Rizin 反编译，ROPgadget/ROPper gadget 搜索。

## 核心工作流

```text
┌──────────────┐
│  Target Bin  │
└──────┬───────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│                    Ghidrai TUI Workspace                  │
├──────────┬──────────┬──────────┬─────────┬───────────────┤
│ Overview │ Disasm   │ Decompile│ Xrefs   │ Strings       │
│ Debug    │ ROP      │ Firmware │ Memory  │ Findings/Logs │
└────┬─────┴────┬─────┴────┬─────┴────┬────┴──────┬────────┘
     │          │          │          │           │
     ▼          ▼          ▼          ▼           ▼
  Ghidra     Rizin      Binwalk    ROPgadget    GDB/Frida
  Bridge     JSON       Rust/API   Adapter      MI/NDJSON
```

TUI 层只消费 Ghidrai 的内部事件模型，不直接理解某个工具的奇怪输出格式。

## 工具分层

### P0: 静态分析与反编译核心

| 后端 | 用途 | 集成原则 |
|------|------|----------|
| Ghidra headless/bridge | 高质量反编译、函数、符号、xref、CFG | 作为一个后端引擎接入，不作为产品中心 |
| Rizin/Radare2 | 反汇编、函数列表、xref、字符串、二进制元信息 | 优先使用 `*j` JSON 命令 |
| rz-ghidra | 终端反编译 | 作为 Rizin 反编译后端候选 |

### P1: 二进制手术与漏洞利用辅助

| 后端 | 用途 | 集成原则 |
|------|------|----------|
| checksec | PIE、RELRO、Canary、NX 等保护检测 | 使用自有 Rust ELF 检测，输出统一 SecurityFeature 事件 |
| entropy | 熵分析、壳/压缩/加密初筛 | 使用 Rust 原生 Shannon entropy，输出段级结构化结果和 Finding |
| ROPgadget/ROPper | gadget 搜索、ROP 链辅助 | 当前先用 Rust 原生 x86/x86-64 ELF/PE gadget 扫描；外部 ROPgadget/ROPper 后续作为可替换后端 |
| LIEF | ELF/PE/Mach-O 解析和修改 | 优先走库 API，再封装成 Ghidrai schema |

### P2: 动态分析

| 后端 | 用途 | 集成原则 |
|------|------|----------|
| GDB | 断点、寄存器、栈、内存、单步 | 当前提供 batch metadata 和 GDB/MI metadata 入口；后续调试动作继续走 GDB/MI，不解析彩色 TUI |
| GEF/Pwndbg | 调试增强 | 作为用户可选环境，不把其 ANSI 输出当稳定数据源 |
| Frida | 动态插桩、函数 trace | 使用自定义 JS agent 输出 NDJSON |

### P3: 固件、取证与高级分析

| 后端 | 用途 | 集成原则 |
|------|------|----------|
| Binwalk | 固件签名扫描、解包 | 优先使用 Rust 库/API 或 JSON 路径 |
| Volatility 3 | 内存 dump 取证 | 使用 `--renderer json` |
| Angr | 符号执行 | 独立 worker，强制超时和资源限制 |
| Unicorn | 指令模拟 | 独立 sandbox 任务，输出寄存器/内存 diff |
| CWE_Checker | 二进制 CWE 扫描 | 先报告面板接入，结构化解析逐步补齐 |

## 输出解析原则

所有工具后端必须经过 adapter：

```text
Tool Process stdout/stderr
        │
        ▼
ToolAdapter
  - command building
  - capability probing
  - version detection
  - structured parser
  - raw log capture
  - error classification
        │
        ▼
Ghidrai Event Model
        │
        ▼
TUI Panels / CLI JSON / Logs
```

内部模型包括：

- `Function`
- `Instruction`
- `BasicBlock`
- `Xref`
- `StringHit`
- `Symbol`
- `Section`
- `ImportExport`
- `SecurityFeature`
- `Gadget`
- `FirmwareEntry`
- `MemoryProcess`
- `Finding`
- `ToolLogEvent`

## 当前命令

当前代码仍保留一部分 Ghidra/Revisor 历史命令，后续会逐步重命名和归并到工具合集模型中。

```bash
# 启动 TUI，默认入口
ghidrai tui

# Ghidra 后端：导入和分析
ghidrai analyze ./tests/crackme -p /tmp/ghidra_proj -n crackme
ghidrai bridge -p /tmp/ghidra_proj -n crackme
ghidrai query list_functions

# 工具合集后端：固件/对象解析/二进制体检/熵分析/CWE 风险/内存取证/字符串/反汇编/GDB/ROP/Rizin JSON
ghidrai toolkit binwalk ./firmware.bin
ghidrai toolkit checksec ./tests/crackme
ghidrai toolkit cwe ./tests/crackme
ghidrai toolkit lief ./tests/crackme
ghidrai toolkit strings ./tests/crackme
ghidrai toolkit disasm ./tests/crackme
ghidrai toolkit entropy ./tests/crackme
ghidrai toolkit gdb ./tests/crackme
ghidrai toolkit gdb-mi ./tests/crackme
ghidrai toolkit rop ./tests/crackme
ghidrai toolkit volatility ./memory.dump
ghidrai toolkit all ./tests/crackme --format json
ghidrai toolkit rizin ./tests/crackme --action functions --format json
ghidrai toolkit rizin ./tests/crackme --action disasm --query main
```

## 近期重构方向

- [x] 将 README、CLI help、包描述全部从 Revisor/Ghidra 自动化切换为 Ghidrai 工具合集定位。
- [x] 把 `toolkit` 从附属子命令提升为核心概念。
- [x] 定义 `ToolAdapter` trait 和统一事件模型。
- [x] 将现有 Ghidra bridge 输出映射为普通后端事件。
- [x] 接入 Rizin JSON adapter，形成 Ghidra/Rizin 双静态分析后端。
- [x] 给 Binwalk 和 ROP adapter 增加 fixtures/golden tests。
- [x] 在 TUI 中实现结构化视图和原始输出视图一键切换。

## 项目结构

```text
src/
├── cli.rs              # CLI command definitions
├── handlers.rs         # command dispatch
├── tui.rs              # Ratatui workspace
├── toolkit/            # native CLI toolkit integrations
│   ├── binwalk.rs
│   ├── checksec.rs
│   ├── cwe.rs
│   ├── disasm.rs
│   ├── entropy.rs
│   ├── gdb.rs
│   ├── lief.rs
│   ├── rizin.rs
│   ├── rop.rs
│   ├── strings.rs
│   └── volatility.rs
├── bridge.rs           # Ghidra backend bridge
├── mcp.rs              # optional JSON-RPC/MCP compatibility layer
├── setup.rs            # Ghidra backend installer
├── types.rs            # shared data types
└── RevisorBridge.java  # Ghidra Java bridge backend
```

## License

GPL-3.0-or-later.
