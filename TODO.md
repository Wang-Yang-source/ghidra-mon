<!--
  GHIDRAI — Terminal Reverse Engineering TUI Toolkit Aggregator
  View this file with `cat TODO.md` or `less -R TODO.md` for rainbow colors.
-->
[0;31m ######   ##     ## #### ########  ########     ###    #### [0m
[0;33m##    ##  ##     ##  ##  ##     ## ##     ##   ## ##    ##  [0m
[0;32m##        ##     ##  ##  ##     ## ##     ##  ##   ##   ##  [0m
[0;36m##   #### #########  ##  ##     ## ########  ##     ##  ##  [0m
[0;34m##    ##  ##     ##  ##  ##     ## ##   ##   #########  ##  [0m
[0;35m##    ##  ##     ##  ##  ##     ## ##    ##  ##     ##  ##  [0m
[0;31m ######   ##     ## #### ########  ##     ## ##     ## #### [0m

[0;36m  Ghidrai Roadmap & TODO[0m
[0;33m  路线图与待办事项 · ロードマップ · 로드맵[0m

# Ghidrai 终端逆向 TUI 合集 TODO

目标：打造一个全开源、纯命令行的逆向工程 TUI，把静态分析、反编译、动态调试、二进制修改、固件解包、内存取证和符号执行工作流统一到一个键盘驱动界面中。

## 总体策略

- [x] 统一产品定位：Ghidrai 是终端逆向 TUI 工具合集，不是 Ghidra 自动化工具，也不是 AI/MCP 优先项目。
- [x] 将 Ghidra、Rizin、Binwalk、ROPgadget、GDB、Frida、Volatility、LIEF、Angr、Unicorn 全部视为可替换后端。
- [x] TUI 是产品主界面；CLI 子命令是可脚本化入口；MCP 只是可选兼容层。
- [x] 采用"结构化输出优先，文本解析兜底"的集成策略。
- [x] 优先接入支持 JSON、NDJSON、XML、SQLite、protobuf 或稳定机器可读格式的工具。
- [x] 对只能输出 ANSI/纯文本的工具建立独立 adapter，不让正则解析散落在 TUI 层。checksec 和 ROP adapter 已采用纯 Rust 实现，彻底避开文本解析。
- [x] 所有工具输出先转换成项目内部统一事件模型，再由 TUI 渲染。TUI runner 通过 `ghidrai toolkit` CLI 子进程消费 ToolEvent JSON，控制台命令也走同一路径。
- [x] 保留原始 stdout/stderr 日志，便于排障、复现和回放解析测试。

## 解析架构

- [x] 设计 `ToolAdapter` trait，统一描述命令构造、能力探测、stdout/stderr 流式解析、退出码处理和错误分类。
- [x] 定义统一数据模型：
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
- [ ] 为 `capabilities()` 增加运行时探测：当前实现只返回硬编码能力列表，应在 adapter 初始化时检查外部工具版本、可用参数和输出格式支持。
- [x] 对结构化输出使用 `serde` 强类型反序列化，并把未知字段保存在 `serde_json::Value` 扩展区。
- [x] 对文本输出只做局部、版本绑定的解析，并在 adapter 中标注 `parser_version` 和已验证工具版本。
- [x] 建立"解析失败不崩 TUI"的降级机制：显示原始输出、记录错误、允许用户继续操作。
- [x] 支持流式事件：长任务输出按行或按 JSON event 增量推送到 TUI，而不是等待子进程结束。

## 工具接入优先级

### P0：结构化输出稳定的核心能力

- [x] Rizin/Radare2：优先使用 `-q0`、`cmdj`、`pdfj`、`aflj`、`izzj`、`iSj`、`iij`、`axtj` 等 JSON 命令。
- [x] Ghidra headless/bridge：复用现有 JSON bridge，输出统一映射到内部模型。
- [x] Binwalk：优先接入仓库内 Rust binwalk 库或其 JSON 输出路径，避免解析表格文本。
- [x] Native strings：纯 Rust ASCII/UTF-8 字符串扫描，已接入 `ghidrai toolkit strings`。
- [x] Native disasm：基于 `goblin` + `iced-x86` 的 ELF/PE `.text` 反汇编，已接入 `ghidrai toolkit disasm`。
- [x] Native entropy triage：已接入 `ghidrai toolkit entropy`，基于 Shannon entropy 输出全文件/段级熵分析和 packer/compression Finding。
- [x] Native Volatility-style triage：已接入 `ghidrai toolkit volatility`，对 memory dump/blob 做基础元信息、内嵌 ELF/PE 标记和 IOC 字符串扫描。
- [ ] Volatility 3：后续作为外部 adapter 接 `--renderer json`，与 native memory/blob triage 共存。
- [x] LIEF-style object inspection：先用 Rust `goblin` 接入 `ghidrai toolkit lief`，输出 binary info、sections、symbols、imports、exports；后续如需写操作再接真正 LIEF API。

### P1：文本输出可控但需要 adapter 隔离

- [x] checksec：使用自有 Rust ELF 安全特性检测实现，输出统一 SecurityFeature 事件。
- [ ] ROPgadget/ROPper：当前 ROP adapter 基于 iced-x86 纯 Rust 实现，不依赖外部 ROPgadget 工具。如需接入上游 ROPgadget，需新增一个外部工具 adapter 并用版本锁定文本 parser。
- [x] GDB batch metadata：已接入 `ghidrai toolkit gdb`，通过非交互 batch 命令提取入口点、段和函数符号，解析器版本锁定为 `gdb-batch-v1`。
- [x] GDB/MI metadata：已接入 `ghidrai toolkit gdb-mi`，通过 `--interpreter=mi3` 和 MI stdin 驱动只读文件/符号信息查询，解析器版本锁定为 `gdb-mi-v1`。
- [ ] GDB/MI interactive + GEF/Pwndbg：后续接入断点、寄存器、栈、内存、单步和 attach；优先使用 GDB/MI 或 Python API，不直接解析彩色 TUI 输出。
- [ ] Frida-tools：优先使用自定义 Frida JS agent 输出 NDJSON，而不是解析 `frida-trace` 人类可读日志。

### P2：高级能力，需要任务沙箱和结果缓存

- [ ] Angr：封装成独立 worker，输入起点、目标点、约束和超时，输出 JSON 结果。
- [ ] Unicorn：封装 CPU 模拟任务，输入架构、寄存器、内存映射和代码片段，输出寄存器/内存 diff。
- [x] Native CWE triage：已接入 `ghidrai toolkit cwe`，基于 imports、checksec、strings 汇总 CWE-style `Finding` 事件。
- [ ] CWE_Checker：调研可用输出格式；如果只能文本输出，作为独立外部 adapter 接入并与 native CWE triage 共存。

## 子进程与任务系统

- [x] 建立统一 `ToolProcess` 管理层，负责 spawn、取消、超时、工作目录、环境变量、stdin、stdout、stderr。（见 `adapter/process.rs` 的 `run_tool_process` / `run_tool_process_with_cancel`）
- [ ] 为每个任务生成 `task_id`，TUI 面板根据 `task_id` 订阅状态和事件。当前 `ToolLogEvent` 已有 `task_id` 字段，但 adapter 层未实际填充和传播。
- [ ] 支持后台任务队列：分析、解包、符号执行、ROP 搜索不阻塞 UI。当前 TUI 通过 `tokio::spawn` 异步执行，但没有持久化任务队列或进度跟踪。
- [x] 增加资源限制：`ToolProcessLimits` 已定义超时和最大输出字节数，但目前仅 Rizin adapter 使用，其他 adapter（binwalk/checksec/rop）是纯 Rust 实现不经过此层。
- [x] 对危险操作默认只读：所有 adapter 均标记 `read_only: true`。MCP 工具列表中 `rename_function`、`set_comment` 等标记为 `[Write]` 的操作仅通过 Ghidra bridge 可达，需要明确启动 bridge 才能执行。

## TUI 工作流

- [ ] 顶层 Tab 完整实现：当前已实现 8 个 Tab（Overview `o`、Decompiler `d`、Xrefs `x`、Strings `s`、ROP `r`、Firmware `f`、Findings `g`、Toolkit `t`），计划列表中还剩 3 个未接入：
  - [x] Decompiler（反编译 + 函数列表）
  - [x] Xrefs（调用者/被调用者）
  - [x] Strings（字符串表 + 详情）
  - [x] Toolkit（adapter 说明面板）
  - [x] Overview（二进制摘要 + ASCII 火焰渐变 banner + 格式/架构/段信息）
- [ ] Disasm（交互式反汇编视图，不依赖 Ghidra bridge；CLI 原生 adapter 已接入）
  - [ ] Debug（GDB/Frida 动态调试面板）
  - [x] ROP（gadget 列表面板框架，待接入 adapter 事件流）
  - [x] Firmware（Binwalk 扫描结果面板框架，待接入 adapter 事件流）
  - [ ] Memory（Volatility 内存取证视图）
  - [x] Findings/Logs（独立 Findings 面板 + 严重级过滤侧栏）
  - [ ] Call Graph（函数调用图面板：提供层次化的调用关系结构树与快速跳转，基于 GhidraMCP `generate_call_graph` 思路，重点实现！）
  - [ ] Graph Overview（全局概览图：提供高视角的模块、系统调用与核心函数群组的交互全景图，重点实现！）
- [x] 支持快捷键在函数列表、反汇编、伪代码、引用、日志之间跳转。（`o/d/x/s/r/f/g/t` 切 Tab，`↑↓` 导航，`Enter` 反编译选中函数，`Tab/BackTab` 三区焦点轮换，`v` 切换事件视图）
- [ ] 每个面板显示数据来源工具、命令行、运行耗时和解析状态。当前 `ToolEvent.adapter` 有来源信息，但面板标题未动态展示工具名和耗时。
- [x] 结构化视图和原始输出视图可一键切换。（`v` 键切换 `EventView::Structured` / `EventView::Raw`）
- [ ] 支持把当前函数/地址作为上下文传给其他工具。例如从反汇编选中一条指令后一键跳到 ROP gadget 搜索该地址附近，或从函数列表发送符号到 GDB 断点。

## 新增：TUI 交互特性（已实现但未列入原 TODO）

- [x] Fish-style 命令历史搜索：`↑↓` 按前缀匹配历史命令。
- [x] Fish-style 自动补全：`→` 接受建议，支持根命令 → toolkit 子命令 → query 子命令三级补全。
- [x] Ghost text 预览：输入时显示历史匹配或建议补全的灰色提示。
- [x] 鼠标支持：滚轮导航列表，左键点击函数触发反编译和 xref 查询。
- [x] Bridge 自动发现：TUI 每秒检查 `~/.ghidrai/bridge.pid`，检测到新 bridge 后自动加载符号和字符串。
- [x] MCP JSON-RPC 2.0 兼容层：22 个工具定义，覆盖 Ghidra bridge 全部查询和写入操作。

## 新增：技术债务与改进项

- [x] ROP adapter 已能从 ELF/PE 头自动识别 32/64 位 x86，并按 ELF 可执行 LOAD 段 / PE 可执行 section 输出虚拟地址；ARM 仍待接入。
- [x] checksec adapter 已支持 ELF、PE、Mach-O 基础保护项检测。
- [ ] Rizin adapter 依赖外部 `rizin` 二进制，未做版本检测和降级策略。
- [ ] `ToolProcessLimits` 仅在 Rizin adapter 中使用，binwalk/checksec/rop adapter 不受资源限制保护。
- [ ] TUI 控制台通过 spawn 自身 CLI 执行命令（`current_exe()`），会在 TUI 内递归启动子进程；工具类命令应直接在 TUI 进程内调用 adapter。
- [ ] 无 CI/CD 配置（GitHub Actions / GitLab CI）。
- [ ] CLI `--format pretty` 输出仅打印 `event.message`，未利用 `ToolEvent` 的 `address`、`kind` 等结构化字段做对齐/着色。

## Schema 与测试

- [ ] 为内部 JSON schema 写 fixtures，覆盖 ELF、PE、Mach-O、固件镜像和内存 dump。当前仅有 `tests/crackme`（ELF）一个测试二进制。
- [x] 为每个 adapter 保存真实工具输出样本，做 golden tests。现有测试覆盖：
  - Binwalk: fixture 测试（`third_party/binwalk/tests/inputs/png_malformed.bin`）
  - Checksec: `tests/crackme` ELF fixture
  - Native CWE triage: `tests/crackme` ELF fixture
  - Native entropy triage: `tests/crackme` ELF fixture + entropy math 单元测试
  - LIEF-style object inspection: `tests/crackme` ELF fixture
  - ROP: `tests/crackme` gadget scan
  - Rizin: 内联 JSON 单元测试
  - Native Volatility-style triage: `tests/crackme` blob fixture
  - GDB batch metadata: 内联 batch 输出单元测试
  - GDB/MI metadata: 内联 MI transcript 单元测试
  - Ghidra adapter: 内联 JSON 单元测试
  - Process runner: stdout/stderr/timeout/cancel 测试
  - TUI events: structured/raw view 过滤测试
  - TUI commands: autocomplete/ghost_text 测试
  - MCP tools: 工具列表完整性测试
- [ ] 增加 parser fuzz/容错测试，确保异常输出不会 panic。
- [ ] 增加版本兼容测试：记录工具名、版本、命令、样本输出、期望事件。
- [ ] 对长输出测试 backpressure，确保 TUI 不被 stdout flood 卡死。

## 近期落地顺序

1. [x] 定义内部事件模型和 `ToolAdapter` trait。
2. [x] 接入 Rizin JSON adapter，完成函数列表、反汇编、字符串、xref 四个基础视图。
3. [x] 把现有 Ghidra bridge 输出映射到同一数据模型。
4. [x] 接入 binwalk 固件扫描，优先使用结构化库/API。
5. [ ] 接入 ROPgadget，先提供原始输出面板，再逐步结构化 gadget 列表。（注：当前已有纯 Rust ROP adapter，支持 x86/x86-64 ELF/PE 可执行区域扫描和虚拟地址输出，但仍无链构造、ARM 或外部 ROPgadget 集成）
6. [x] 增加 adapter fixtures 和 golden tests，锁定解析行为。
7. [x] 在 TUI 中加入"结构化/原始输出"双视图和解析错误提示。
8. [ ] 重点实现：Function Call Graph（函数调用图）数据提取与 TUI 可视化呈现。
9. [ ] 重点实现：Graph Overview（全局概览图），提供更宏观的控制流/模块级交互视图。

## 明确不做

- [x] 不在 UI 层写临时正则解析工具输出。
- [x] 不依赖 ANSI 彩色 TUI 文本作为稳定数据源。
- [x] 不把所有工具强行抽象成同一种命令；只统一结果模型和任务生命周期。
- [x] 不默认执行会修改目标文件、系统状态或 attach 进程的操作。所有 adapter 默认只读，写操作仅限 MCP `[Write]` 标记的 bridge 命令。
