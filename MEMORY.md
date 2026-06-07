# Ghidrai Project Memory

Ghidrai = Ghidra + AI + TUI. The project is a terminal-first reverse engineering workbench that makes heavyweight reverse engineering feel fast, readable, and keyboard-native.

## Design Philosophy

- **AI as a managed hypothesis, not an oracle**: Distinguish strictly between facts, AI hypotheses, and open questions. AI explanations and proposed names must not pollute the truth; they require explicit user confirmation to become accepted facts.
- **Project Memory over transient sessions**: The core value is accumulating knowledge. Ghidrai must remember renamed functions, confirmed hypotheses, structural discoveries, and bookmarks so analysis is continuous across restarts.
- First show the forest, then the trees. The default view should be a human-readable binary summary, risk findings, likely language/toolchain, entropy/packer hints, imported capabilities, strings, and decompiled pseudocode. Raw assembly is a drill-down view, not the first thing users see.
- Human-readable output wins. Prefer decompiled C-like views, structured findings, semantic names, xrefs, call graphs, and explanations over walls of hex or assembly.
- Commands are the UI. Use a Vim/IDE-style command palette (`:` / `Ctrl+P`) for navigation and actions instead of deep menu trees.
- Keyboard-first, TUI-native. The terminal workspace should feel closer to `btop` or a tiling editor than to a scrollback log.
- Calm visuals. Use subdued dark themes such as Catppuccin/Ghostty-friendly palettes. Color should encode state: jump targets, danger functions, taint flow, selected variables, constants, and errors. Avoid noisy color.
- Progressive disclosure. Keep the overview simple; expose disassembly, CFG, taint tracking, debug state, symbolic execution, and raw logs only when the user asks for them.

## Architecture Principles

- Rust owns the frontend, orchestration, task lifecycle, event model, cache, and TUI rendering.
- Heavy binary analysis should reuse proven engines instead of being rewritten from scratch.
- Avoid slow stdout scraping for large structured analysis. Prefer direct APIs, structured JSON/NDJSON, memory-mapped files, FFI, or stable library bindings.
- The TUI consumes Ghidrai's internal event model only. Tool-specific formats stay behind adapters.
- Long-running analysis must never block the UI. Use async task orchestration, background workers, cancellation, timeouts, and progressive event streaming.
- Keep the core small. Static analysis, dynamic debugging, firmware analysis, symbolic execution, AI analysis, and patching should behave like pluggable backends.
- Preserve raw output alongside structured views for auditability and debugging.
- Read-only is the default. Any target mutation, attach, patch, or filesystem-impacting operation must be explicit and confirmed.

## Backend Strategy

- Decompilation backend: prioritize the existing Ghidra bridge/headless path for high-quality decompilation, symbols, xrefs, and CFG data.
- Terminal-native decompilation candidate: evaluate `rz-ghidra` through the Rizin adapter as an optional decompiler path, especially when it can provide structured output cleanly.
- Binary/object parsing backend: use Rust-native `goblin` where it is enough; add LIEF or LIEF-backed FFI/bindings when richer ELF/PE/Mach-O parsing or modification is needed.
- Disassembly/gadget scanning: prefer native Rust or structured engine APIs where practical; Capstone/Keystone may be integrated through FFI if they provide better architecture coverage or assembly support.
- Dynamic analysis: start with read-only GDB batch metadata and GDB/MI metadata for entry points, sections, and symbols; use GDB/MI, Frida agents emitting NDJSON, and isolated worker tasks for real debugging. Do not parse colorful debugger TUI output.
- Advanced analysis: Angr, Unicorn, native Volatility-style triage, Volatility 3, Binwalk, native CWE triage, and CWE_Checker are independent adapters/workers with resource limits and structured outputs where available.

## Engine Decision

Do not frame `rz-ghidra` versus LIEF as a single either/or choice. They own different layers:

- Use Ghidra headless/bridge as the default high-quality decompiler and analysis authority.
- Add `rz-ghidra` as the terminal-native Rizin decompiler path when it can return stable structured data; it is a decompilation backend, not the object model.
- Use the LIEF-style lane for ELF/PE/Mach-O object inspection, imports/exports, sections, relocations, patching, and binary surgery.
- Start with Rust-native `goblin` implementations for the LIEF-style read-only subset so Ghidrai works immediately.
- Move hot or richer object-manipulation paths to LIEF through `cxx`/`bindgen` FFI when the Rust-native subset is not enough.
- Keep `toolkit cwe` as an always-available Rust-native first pass for CWE-style findings; add upstream CWE_Checker later as a deeper external analyzer, not a replacement for fast triage.
- Keep `toolkit volatility` as an always-available Rust-native memory/blob triage pass; add upstream Volatility 3 later through JSON renderer plugins for real process/module/registry/memory-forensics workflows.
- Keep `toolkit entropy` as an always-available Rust-native packer/compression/encryption hint pass before heavier deobfuscation or sandbox work.
- Keep `toolkit gdb` as an explicit external debugger metadata pass and `toolkit gdb-mi` as the machine-interface protocol lane; add GDB/MI attach/breakpoint/register/stack workflows later instead of expanding batch text parsing into an interactive debugger.
- Avoid stdout pipes for high-volume internal data. Prefer in-process Rust, memory maps, FFI, structured JSON/NDJSON, or versioned adapters.

## UX Targets

- Main layout: left navigation tree for functions/imports/exports/strings, wide center workspace for decompile/disasm/CFG, side or bottom panels for findings, logs, and task status.
- CFG in terminal should use readable line drawing or braille-style rendering when useful, but clarity beats decoration.
- Hover/context popups should explain registers, addresses, stack values, constants, imports, and suspicious APIs in place.
- Variable and register selection should trigger instant data-flow/taint highlighting across upstream and downstream uses.
- Function Call Graph (CG): A hierarchical, interactive call graph is a high-priority structural view. Users must be able to explore callers and callees rapidly to understand execution paths and business logic.
- AI is part of the rendering pipeline, not just a chat box. It should propose function names, variable names, risk summaries, behavior explanations, and next actions inline.
- AI suggestions must be visually distinct and reversible. Example: render `sub_401100(a1, a2)` with a muted suggestion like `init_network_socket(ip, port)` and allow one-key adoption.

## MCP & Tool Extensibility

- **Swiss-Army-Knife Architecture**: Ghidrai integrates multiple backends (Ghidra, Rizin, Binwalk, Volatility) via adapters. 
- **MCP (Model Context Protocol)**: Expose Ghidrai's structural analysis, mutation capabilities (like renaming functions/variables), and advanced security scanners (e.g., IoT vulnerability checks, emulation, IOC extraction) via an MCP server, turning Ghidrai into an AI-ready reverse engineering infrastructure.

## Product Direction

Ghidrai should feel like a reverse engineer's Swiss army knife in the terminal: fast startup, smooth interaction, pluggable engines, structured results, raw evidence available, and AI assistance woven into the workflow without taking over control.
