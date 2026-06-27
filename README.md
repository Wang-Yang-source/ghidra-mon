# GhidrAI (v0.8.3)

**Terminal Reverse Engineering TUI Toolkit Aggregator**
*终端逆向工程 TUI 工作台 · 键盘优先与鼠标混用 · 多引擎协同互补*

GhidrAI is a terminal-first reverse engineering workspace and tool aggregator. It bundles local static analysis with Ghidra bridge workflows, MCP tooling, and a catalog for the broader reverse-engineering toolbox.

它将行业标准逆向引擎（Ghidra、Rizin）、反汇编/模拟引擎（Capstone、Unicorn）以及安全审计工具（Binwalk）作为子模块统一编排，形成“快扫描 + 深反编译 + 全景联动”的终端化分析流水线。

本项目的目标是把“多工具并联分析”变成可复用的单点工作流：先用轻量分析拿到快速结论，再以 Ghidra Headless 产出高精度反编译和引用关系，用 TUI 做统一呈现。它不是只做 Ghidra，而是要成为逆向、安全分析、固件分析、动态调试、Android 逆向和取证工具的大合集入口。

项目长期产品记忆和设计哲学记录在 [MEMORY.md](MEMORY.md) 和 [DESIGN.md](DESIGN.md)。

## 一句话项目说明（适合 GitHub 主页）

- **定位**：终端化逆向工程工作台 + MCP 适配层，兼容本地 CLI、TUI 与 MCP 客户端调用。
- **核心亮点**：在 `external` MCP 模式下兼容 `bridge_mcp_ghidra.py` 端点路径，可复用 `bethington/ghidra-mcp` 的工具语义。
- **安装体验**：首次运行涉及 Ghidra Headless 的命令时，默认自动下载并安装 `~/.ghidrai/ghidra`（可通过 `GHIDRA_AUTO_SETUP=0` 关闭）。

## 安装即用

```bash
cargo install --locked ghidrai
gda -h
```

首次执行 `bridge`/`analyze`/`run-script` 等 Ghidra 依赖命令时会触发自动安装。

查看当前工具合集覆盖范围：

```bash
gda catalog
gda catalog --format json
```

目录会区分 `built-in`、`external`、`bundled` 和 `planned` 状态。当前已经内置或接入的能力包括 Ghidra、Rizin、Binwalk、Checksec、LIEF-style parser、strings、disasm、ROP、entropy、CWE、GDB/GDB-MI、Volatility-style triage；规划目录包含 IDA、x64dbg、WinDbg、Frida、JADX、apktool、010 Editor/WinHex/HxD、DIE/PEiD/Exeinfo PE、CFF Explorer/PE-bear、radare2 等看雪常见工具。

## 子模块（Submodules）架构与协同互补的意义

在 `v0.8.1` 中，GhidrAI 全面引入并规范了第三方逆向与模拟引擎的 submodule 架构。它们保存在 `third_party/` 目录下：

```text
third_party/
├── ghidra     # 行业标准反编译器，提供精确的控制流恢复、高阶类型重建与全局交叉引用
├── rizin      # 极速的底层静态分析引擎，适用于瞬间提取符号、Sections 与字符串
├── capstone   # 多架构指令级解码反汇编器，保障 TUI 能够以超低延迟展示精确机器码
├── unicorn    # 多架构 CPU 模拟器，在沙箱中对基本块或函数进行指令级模拟执行
├── binwalk    # 固件包分析与文件系统提取工具，在反编译前进行多层提取
└── ROPgadget  # 专业 ROP 链配件提取器，为漏洞利用开发提供精确定位
```

### 协同互补的逆向工作流

这些子模块并不是简单的堆砌，而是在统一的内部数据模型（ToolEvent Bus）下各展所长，实现**互补协同**：
1. **快慢结合的静态分析**：启动二进制时，TUI 首先使用 `rizin` 和原生 Rust 工具进行秒级粗筛（字符串符号提取、硬防护检测、熵分析）；在此期间，后台静默拉起 `ghidra` 进行深度反编译与全局 XRef 计算。当 Ghidra 结果就绪后，TUI 会将两者的数据无缝融合，使用户同时享有“秒级响应”与“高精度反编译”的体验。
2. **模拟验证静态分析**：当用户在 `Decompiler` 视图中浏览一段复杂的反编译代码并存有疑问时，可一键将该代码段/基本块传入基于 `unicorn` 与 `capstone` 驱动的微型沙箱模拟器，在终端内单步执行并观察寄存器 Diff 变化，以此验证反编译的逻辑，这就是**“以动态模拟验证静态推导”**。
3. **从解包到分析的垂直流**：对于固件文件，由 `binwalk` 子模块完成结构分析与文件系统解包后，解包出来的关键 ELF/PE 二进制将直接被拉入静态分析面板中，无缝链接。

## 设计哲学


GhidrAI 的核心是将强大的逆向分析引擎（尤其是 Ghidra）的能力转化为终端里的可组合命令、面板和工作流。

- **不重写引擎**：不要一开始尝试用 Rust 重写 Ghidra 数百万行的 Java/C++ 代码。相反，把 Ghidra 作为 upstream engine 纳入本项目，通过 headless analyzer 抽取核心数据。
- **快慢结合双路径**：
  - 快速路径：使用原生 Rust 库（如 `goblin`、`memmap2`）进行秒级预分析（ELF/PE解析、字符串、符号表、熵分析）。
  - 深度路径：调用 Ghidra Headless 进行耗时的反编译、交叉引用计算、高级图分析，并在后台运行不阻塞 UI。
- **AI 记忆管理**：所有 AI 结论必须区分 `Fact`（已确认）、`Hypothesis`（假设）和 `Question`（疑问），用户的每一次改名和注释都应沉淀在 `.ghidrai/` 项目记忆中。
- **终端瑞士军刀**：整合 Rizin、Radare2、Binwalk、Capstone 等工具作为特定功能的 adapter 补充。

## 核心功能 (Core Features)

GhidrAI 提供了一个统一的终端 TUI 工作区，整合了多种逆向工程与二进制分析工具。目前它能为你做以下事情：

1. **反编译与静态分析 (Decompilation & Static Analysis)**
   - **Ghidra 头端桥接**：启动 Headless Ghidra，在终端直接列出函数表、一键反编译 C 伪代码、查看并跳转交叉引用（XRefs - Callers / Callees）、获取内存布局和导入/导出表。
   - **Rizin 静态分析**：调用 `rizin` 引擎快速列出函数列表、搜索字符串、提取 sections 结构、导入导出符号及交叉引用。

2. **安全防范审计与 CWE 风险扫描**
   - **Checksec 防护检查**：原生分析 ELF/PE/Mach-O 二进制文件的硬安全机制，如 Canary、NX（DEP）、PIE（ASLR）和 RELRO 是否开启。
   - **CWE 风险静态扫描**：自动Triager，扫描包括：
     - 不安全函数调用（如 `gets`、`strcpy`、`sprintf` 等 CWE-120 缓冲区溢出隐患）。
     - 命令执行调用（CWE-78 注入风险）。
     - 可疑硬编码密匙（CWE-798 凭据泄漏，扫描 "password"、"secret"、"token"、"apikey" 等敏感字符串）。
     - 明文 URL 传输检查（CWE-319 风险）。

3. **固件提取与二进制结构分析**
   - **Binwalk 固件签名分析**：调用内置 binwalk 引擎，扫描固件镜像的已知魔术头字节，发现并定位嵌入的文件系统（SquashFS、YAFFS 等）、压缩包、Bootloader 及加密段。
   - **LIEF 二进制头解析**：瞬间提取 ELF/PE/Mach-O 的文件格式头部元数据、编译架构、节区和依赖动态库。
   - **香农熵 (Entropy) 扫描**：分析文件或特定 Section 的熵值，判定是否存在加壳、压缩或加密数据块。

4. **指令反汇编与 ROP Gadget 构建**
   - **Rust 原生反汇编**：无需外部工具即可针对 x86/x64 的 `.text` 代码段执行高速反汇编。
   - **ROP Gadget 发现引擎**：基于 `iced-x86` 解码指令，自动定位、提取并排重 `ret` 结尾的 ROP 链小配件 (Gadgets)。

5. **内存与调试分析**
   - **GDB 批处理 & GDB/MI 元数据**：基于 Machine Interface 协议交互，获取运行时符号或只读转储元数据。
   - **Volatility 原生 triage**：对内存映像或大型二进制块进行特定模式识别与 IOC 分类。

6. **交互式 TUI 与命令控制台**
   - 支持命令面板（Command Palette），配备 Fish 风格的控制台输入补全和历史建议。
   - 事件日志支持双模式切换：不仅可以在底部看到命令的原始 stdout/stderr 输出，而且在后台运行完毕后，**安全漏洞发现、ROP 机器码、固件签名**等扫描结果将自动映射到对应的 UI 选项卡中，支持使用键盘上下键交互浏览与详细分析。

## 核心架构与工作流

GhidrAI 采用分层调度架构，完全解耦 UI、项目状态与重型分析计算：

```text
GhidrAI TUI
  ↓
Rust Core：项目管理 / TUI 渲染 / 缓存索引 / AI Memory
  ↓
Adapter Layer：Ghidra headless 脚本 / Rizin / Capstone / 原生解析
  ↓
Analysis Engines：反编译、反汇编、符号、字符串、图、调试
```

典型的交互流程：
1. TUI 调用 `goblin` 秒开目标文件，展示基础段、导入导出、字符串。
2. 后台启动 `ghidra headless analyzer` 挂载 `third_party/ghidra`。
3. 自定义 Java/Python script 在后台抽取反编译、调用图、交叉引用，并以 JSON 格式增量流式输出。
4. GhidrAI TUI 实时消费 JSON，将数据呈现到反编译视图、函数调用图等面板中。

## 阶段性交付路线 (MVP)

- **MVP 0：项目合规与引擎纳入**
  - 以 `third_party/ghidra` 形式引入 submodule，保留其开源许可证，搭建基础环境。
- **MVP 1：TUI 框架与操作体系**
  - 构建核心三栏 TUI 面板、命令面板（Command Palette）、日志系统与快捷键绑定。
- **MVP 2：Rust 原生预分析**
  - 不依赖 Ghidra，利用 Rust 原生库实现瞬间的文件格式识别、导出表、基础字符串和熵扫描。
- **MVP 3：Ghidra Headless 数据桥接**
  - 实现从 Ghidra 导出函数列表、反编译代码、交叉引用及 Call Graph 数据，结构化渲染到终端。
- **MVP 4：AI 辅助与项目记忆 (Project Memory)**
  - 实现本地/云端大模型接口对接，保存用户的函数重命名、注释，推断结果，并持久化到 SQLite 和 JSON 缓存中。
- **MVP 5：瑞士军刀扩展适配器**
  - 接入 Rizin、Radare2、GDB、Binwalk 等工具，填补内存取证、固件解包、动态调试等能力拼图。

## 目录结构规划

```text
ghidrai/
├── crates/
│   ├── ghidrai-core/          # Rust 核心：项目、任务、缓存、数据模型
│   ├── ghidrai-tui/           # Ratatui / Crossterm TUI 界面
│   ├── ghidrai-ai/            # AI 总结、命名、项目记忆
│   ├── ghidrai-bridge/        # 外部工具桥接层
│   ├── ghidrai-ghidra/        # Ghidra adapter (Headless 控制器)
│   └── ghidrai-db/            # 索引与持久化
│
├── adapters/
│   ├── ghidra/
│   │   ├── scripts/           # Ghidra 侧的 Java/Python 解析脚本
│   │   └── schema/            # JSON 输出协议定义
│   ├── rizin/
│   └── capstone/
│
├── third_party/
│   ├── ghidra/                # Ghidra 逆向分析引擎 (Java Headless)
│   ├── rizin/                 # Rizin 快速分析框架 (C)
│   ├── capstone/              # Capstone 多架构反汇编引擎 (C)
│   ├── unicorn/               # Unicorn CPU 模拟器引擎 (C)
│   ├── binwalk/               # Binwalk 固件分析框架 (Python/Rust)
│   └── ROPgadget/             # ROPgadget gadget 提取工具 (Python)
│
├── .ghidrai/                  # 运行时项目记忆缓存
│   ├── project.sqlite
│   ├── symbols.json
│   ├── comments.md
│   └── hypotheses.json
│
└── README.md
```

## 当前命令与状态

目前项目仍保留早期的 CLI 工具链入口，后续将逐步重构到 `ghidrai-core` 和 `ghidrai-tui` 的全新架构中。

首次执行涉及 Ghidra Headless 的命令时（如 `bridge`/`analyze`/`run-script`），默认会自动下载并安装到 `~/.ghidrai/ghidra`，以减少手工步骤。若要关闭自动安装，请设置：

```bash
export GHIDRA_AUTO_SETUP=0
```

关闭后再手动安装：

```bash
gda setup
```

## MCP 兼容说明（含 ghidra-mcp 外部后端）

项目支持两种 MCP 运行模式：

- `legacy`（默认）：使用本仓库自带的轻量 MCP 实现，仅暴露可由内建 bridge 直接代理的核心工具。
- `external`：代理运行外部 `bridge_mcp_ghidra.py`（对应 `bethington/ghidra-mcp`）进程，支持完整 `ghidra-mcp` 端点映射。

在 `external` 模式下，`ghidra-mcp` 的 MCP 工具集合会被完整代理，因此可直接服务支持 `ghidra-mcp` 的外部客户端和脚本；`legacy` 则保留兼容性和轻量启动体验。

如果你设置了 `GHIDRA_MCP_COMMAND`，`gda mcp` 在未显式传 `--backend` 时会自动切到 `external`，可以直接走完整能力：

```bash
export GHIDRA_MCP_COMMAND=python3
export GHIDRA_MCP_ARGS='-m tools.bridge --transport stdio'
gda mcp
```

当仅运行 `gda mcp` 且未设置 `GHIDRA_MCP_COMMAND` 时，仍保持 legacy 模式。

当你要“尽量完整对齐 ghidra-mcp”时，建议优先走 `external`：

```bash
GHIDRA_MCP_COMMAND=python3 \
GHIDRA_MCP_ARGS='-m tools.bridge' \
gda mcp --backend external
```

如果你的 `bridge_mcp_ghidra.py` 不是通过 `python3 -m` 启动，也可以直接传完整命令：

```bash
GHIDRA_MCP_COMMAND='python3 bridge_mcp_ghidra.py' \
GHIDRA_MCP_ARGS='--transport stdio' \
gda mcp --backend external
```

辅助变量：

- `GHIDRA_MCP_BACKEND`：环境变量可选，等价于 `--backend`。
- `GHIDRA_MCP_COMMAND`：外部命令（或可解析的 JSON 数组）。
- `GHIDRA_MCP_ARGS`：额外参数（支持普通字符串或 JSON 数组）。

在无 ghidra-mcp 环境时做回归检查：

```bash
./tests/run_mcp_regression.sh external --expected-connect-fail
```

这样当外部后端没安装时会跳过失败，方便 CI/本地快速验证脚本本身。

也可以直接跑覆盖率对账脚本，快速看到还差哪些工具分组：

```bash
python3 tests/compare_mcp_coverage.py
```

如果你有 `ghidra-mcp` 仓库，传入它的 `tests/endpoints.json`：

```bash
python3 tests/compare_mcp_coverage.py --ghidra-endpoints /path/to/ghidra-mcp/tests/endpoints.json
```

如果你不想每次都准备 `ghidra-mcp` 仓库，仓库也提供了本地 `tests/endpoints.json` 快照用于回归对照。
需要自定义时可用环境变量指定：

```bash
export GHIDRA_MCP_ENDPOINTS_PATH=/path/to/ghidra-mcp/tests/endpoints.json
python3 tests/compare_mcp_coverage.py
```

```bash
# 启动 TUI 工作台
gda tui

# 原生预分析工具测试
gda toolkit lief ./tests/crackme
gda toolkit strings ./tests/crackme
gda toolkit entropy ./tests/crackme
```

## License

GPL-3.0-or-later. (注：集成的第三方引擎遵循其原有协议，如 Ghidra 的 Apache-2.0)。
