# Ghidrai 终端逆向 TUI 合集 TODO

目标：打造一个全开源、纯命令行的逆向工程 TUI，把静态分析、反编译、动态调试、二进制修改、固件解包、内存取证和符号执行工作流统一到一个键盘驱动界面中。

## 总体策略

- [x] 统一产品定位：Ghidrai 是终端逆向 TUI 工具合集，不是 Ghidra 自动化工具，也不是 AI/MCP 优先项目。
- [x] 将 Ghidra、Rizin、Binwalk、ROPgadget、GDB、Frida、Volatility、LIEF、Angr、Unicorn 全部视为可替换后端。
- [x] TUI 是产品主界面；CLI 子命令是可脚本化入口；MCP 只是可选兼容层。
- [x] 采用“结构化输出优先，文本解析兜底”的集成策略。
- [x] 优先接入支持 JSON、NDJSON、XML、SQLite、protobuf 或稳定机器可读格式的工具。
- [ ] 对只能输出 ANSI/纯文本的工具建立独立 adapter，不让正则解析散落在 TUI 层。
- [ ] 所有工具输出先转换成项目内部统一事件模型，再由 TUI 渲染。
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
- [ ] 为每个 adapter 定义 `capabilities()`，运行时检查工具版本、可用参数和是否支持机器可读输出。
- [x] 对结构化输出使用 `serde` 强类型反序列化，并把未知字段保存在 `serde_json::Value` 扩展区。
- [x] 对文本输出只做局部、版本绑定的解析，并在 adapter 中标注 `parser_version` 和已验证工具版本。
- [x] 建立“解析失败不崩 TUI”的降级机制：显示原始输出、记录错误、允许用户继续操作。
- [x] 支持流式事件：长任务输出按行或按 JSON event 增量推送到 TUI，而不是等待子进程结束。

## 工具接入优先级

### P0：结构化输出稳定的核心能力

- [x] Rizin/Radare2：优先使用 `-q0`、`cmdj`、`pdfj`、`aflj`、`izzj`、`iSj`、`iij`、`axtj` 等 JSON 命令。
- [x] Ghidra headless/bridge：复用现有 JSON bridge，输出统一映射到内部模型。
- [x] Binwalk：优先接入仓库内 Rust binwalk 库或其 JSON 输出路径，避免解析表格文本。
- [ ] Volatility 3：优先使用 `--renderer json`。
- [ ] LIEF：优先通过 Rust/Python API 包一层本地 CLI，直接输出项目定义的 JSON schema。

### P1：文本输出可控但需要 adapter 隔离

- [x] checksec：使用自有 Rust ELF 安全特性检测实现，输出统一 SecurityFeature 事件。
- [ ] ROPgadget/ROPper：优先寻找 JSON/脚本 API；没有稳定格式时用版本锁定文本 parser。
- [ ] GDB + GEF/Pwndbg：优先使用 GDB/MI 或 Python API，不直接解析彩色 TUI 输出。
- [ ] Frida-tools：优先使用自定义 Frida JS agent 输出 NDJSON，而不是解析 `frida-trace` 人类可读日志。

### P2：高级能力，需要任务沙箱和结果缓存

- [ ] Angr：封装成独立 worker，输入起点、目标点、约束和超时，输出 JSON 结果。
- [ ] Unicorn：封装 CPU 模拟任务，输入架构、寄存器、内存映射和代码片段，输出寄存器/内存 diff。
- [ ] CWE_Checker：调研可用输出格式；如果只能文本输出，先作为报告面板接入，结构化解析延后。

## 子进程与任务系统

- [x] 建立统一 `ToolProcess` 管理层，负责 spawn、取消、超时、工作目录、环境变量、stdin、stdout、stderr。
- [ ] 为每个任务生成 `task_id`，TUI 面板根据 `task_id` 订阅状态和事件。
- [ ] 支持后台任务队列：分析、解包、符号执行、ROP 搜索不阻塞 UI。
- [ ] 增加资源限制：最大运行时间、最大输出字节数、最大缓存文件大小。
- [ ] 对危险操作默认只读；二进制 patch、文件提取、动态调试 attach 需要明确确认。

## TUI 工作流

- [ ] 顶层 Tab：Overview、Disasm、Decompiler、Xrefs、Strings、Debug、ROP、Firmware、Memory、Findings、Logs。
- [ ] 支持快捷键在函数列表、反汇编、伪代码、引用、日志之间跳转。
- [ ] 每个面板都能显示数据来源工具、命令行、运行耗时和解析状态。
- [x] 结构化视图和原始输出视图可一键切换。
- [ ] 支持把当前函数/地址作为上下文传给其他工具，例如从反汇编跳到 ROP gadget 搜索或 GDB 断点。

## Schema 与测试

- [ ] 为内部 JSON schema 写 fixtures，覆盖 ELF、PE、Mach-O、固件镜像和内存 dump。
- [ ] 为每个 adapter 保存真实工具输出样本，做 golden tests。
- [ ] 增加 parser fuzz/容错测试，确保异常输出不会 panic。
- [ ] 增加版本兼容测试：记录工具名、版本、命令、样本输出、期望事件。
- [ ] 对长输出测试 backpressure，确保 TUI 不被 stdout flood 卡死。

## 近期落地顺序

1. [x] 定义内部事件模型和 `ToolAdapter` trait。
2. [x] 接入 Rizin JSON adapter，完成函数列表、反汇编、字符串、xref 四个基础视图。
3. [x] 把现有 Ghidra bridge 输出映射到同一数据模型。
4. [x] 接入 binwalk 固件扫描，优先使用结构化库/API。
5. [ ] 接入 ROPgadget，先提供原始输出面板，再逐步结构化 gadget 列表。
6. [x] 增加 adapter fixtures 和 golden tests，锁定解析行为。
7. [x] 在 TUI 中加入“结构化/原始输出”双视图和解析错误提示。

## 明确不做

- [x] 不在 UI 层写临时正则解析工具输出。
- [x] 不依赖 ANSI 彩色 TUI 文本作为稳定数据源。
- [x] 不把所有工具强行抽象成同一种命令；只统一结果模型和任务生命周期。
- [ ] 不默认执行会修改目标文件、系统状态或 attach 进程的操作。
