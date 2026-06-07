# GhidrAI

**Terminal Reverse Engineering TUI Toolkit Aggregator**
*终端逆向工程 TUI 工具合集 · 开源 · 键盘驱动 · 后端可替换*

GhidrAI is a terminal-based AI-assisted reverse engineering workspace.

It does not try to replace Ghidra at the engine level. Instead, it integrates Ghidra and other reverse engineering engines into a fast, keyboard-first TUI workflow, providing project memory, AI-assisted analysis, structured notes, and exportable reverse engineering reports.

GhidrAI 是一个面向 AI 时代的 TUI 逆向工作台。

它不以重写 Ghidra 为第一目标，而是将 Ghidra 及其他逆向工具整合为统一的终端工作流，提供快速分析、反编译结果浏览、函数与字符串索引、AI 辅助理解、项目级记忆和可交付报告导出能力。

项目长期产品记忆和设计哲学记录在 [MEMORY.md](MEMORY.md) 和 [DESIGN.md](DESIGN.md)。

## 设计哲学

GhidrAI 的核心是将强大的逆向分析引擎（尤其是 Ghidra）的能力转化为终端里的可组合命令、面板和工作流。

- **不重写引擎**：不要一开始尝试用 Rust 重写 Ghidra 数百万行的 Java/C++ 代码。相反，把 Ghidra 作为 upstream engine 纳入本项目，通过 headless analyzer 抽取核心数据。
- **快慢结合双路径**：
  - 快速路径：使用原生 Rust 库（如 `goblin`、`memmap2`）进行秒级预分析（ELF/PE解析、字符串、符号表、熵分析）。
  - 深度路径：调用 Ghidra Headless 进行耗时的反编译、交叉引用计算、高级图分析，并在后台运行不阻塞 UI。
- **AI 记忆管理**：所有 AI 结论必须区分 `Fact`（已确认）、`Hypothesis`（假设）和 `Question`（疑问），用户的每一次改名和注释都应沉淀在 `.ghidrai/` 项目记忆中。
- **终端瑞士军刀**：整合 Rizin、Radare2、Binwalk、Capstone 等工具作为特定功能的 adapter 补充。

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
│   └── ghidra/                # Ghidra upstream submodule
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

```bash
# 启动 TUI 工作台
ghidrai tui

# 原生预分析工具测试
ghidrai toolkit lief ./tests/crackme
ghidrai toolkit strings ./tests/crackme
ghidrai toolkit entropy ./tests/crackme
```

## License

GPL-3.0-or-later. (注：集成的第三方引擎遵循其原有协议，如 Ghidra 的 Apache-2.0)。
