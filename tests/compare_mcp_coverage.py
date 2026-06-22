#!/usr/bin/env python3
"""Compare local MCP tool surface with ghidra-mcp endpoint catalog."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
import os


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--legacy-tools", default="src/mcp/tools.rs", help="Path to local tools.rs"
    )
    parser.add_argument(
        "--ghidra-endpoints",
        default=None,
        help="Path to ghidra-mcp tests/endpoints.json",
    )
    parser.add_argument(
        "--top-missing",
        type=int,
        default=30,
        help="How many uncovered upstream tools to list",
    )
    return parser.parse_args()


def iter_local_tool_names(path: str) -> set[str]:
    text = Path(path).read_text(encoding="utf-8")
    local_names = {m.group(1) for m in re.finditer(r'tool\(\s*"([^"]+)"\s*,', text)}

    for endpoint in load_local_upstream_endpoints():
        path = endpoint.get("path")
        if isinstance(path, str) and path:
            local_names.add(f"ghidra_{path.lstrip('/')}")

    return local_names


def local_endpoints_path_candidates() -> list[Path]:
    base_dir = Path(__file__).resolve().parent
    explicit = os.environ.get("GHIDRA_MCP_ENDPOINTS_PATH")
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.append(base_dir / "endpoints.json")
    candidates.append(base_dir / "ghidra-mcp/tests/endpoints.json")
    candidates.append(Path("/tmp/ghidra-mcp-remote/tests/endpoints.json"))
    return candidates


def load_local_upstream_endpoints() -> list[dict[str, object]]:
    for candidate in local_endpoints_path_candidates():
        if not candidate.exists():
            continue
        try:
            obj = json.loads(candidate.read_text(encoding="utf-8"))
            endpoints = obj.get("endpoints")
            if isinstance(endpoints, list):
                return list(endpoints)
        except (OSError, json.JSONDecodeError):
            continue
    return []


def load_upstream_endpoints(path: str | None) -> list[dict[str, object]]:
    base_dir = Path(__file__).resolve().parent
    if path:
        source = Path(path)
    else:
        candidates = [
            base_dir / "ghidra-mcp-remote/tests/endpoints.json",
            Path("/tmp/ghidra-mcp-remote/tests/endpoints.json"),
            base_dir / "endpoints.json",
        ]
        source = next((p for p in candidates if p.exists()), None)
        if source is None:
            raise FileNotFoundError("cannot find ghidra-mcp endpoints.json")

    obj = json.loads(source.read_text(encoding="utf-8"))
    return list(obj.get("endpoints", []))


def main() -> int:
    args = parse_args()

    local_tools = iter_local_tool_names(args.legacy_tools)
    try:
        upstream = load_upstream_endpoints(args.ghidra_endpoints)
    except FileNotFoundError as exc:
        if args.ghidra_endpoints is None:
            print(f"coverage: {exc}; skipping external comparison (not configured)\n")
            return 0
        print(f"coverage: {exc}; pass --ghidra-endpoints to compare against local catalog")
        return 1

    upstream_names = [
        entry["path"].lstrip("/")
        for entry in upstream
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    ]
    upstream_name_set = set(upstream_names)
    covered = []
    missing = []
    missing_by_category: Counter[str] = Counter()

    for entry, name in zip(upstream, upstream_names):
        tool_name = f"ghidra_{name}"
        if tool_name in local_tools:
            covered.append(name)
        else:
            missing.append((name, entry.get("category", "uncategorized"), entry.get("description", "")))
            missing_by_category[entry.get("category", "uncategorized")] += 1

    local_only = sorted(
        name.removeprefix("ghidra_")
        for name in local_tools
        if name.removeprefix("ghidra_") not in upstream_name_set
    )

    total = len(upstream_names)
    print(f"Local MCP tools: {len(local_tools)}")
    print(f"Upstream ghidra-mcp tools: {total}")
    print(f"Directly covered: {len(covered)}")
    print(f"Coverage: {len(covered) / total * 100:.1f}%")
    print()

    print(f"Missing upstream tools: {len(missing)}")
    for name, category, description in missing[: args.top_missing]:
        print(f"- {name} ({category}): {description}")
    if len(missing) > args.top_missing:
        print(f"  ... and {len(missing) - args.top_missing} more")
    print()

    print(f"Legacy-only tools (not in upstream catalog): {len(local_only)}")
    for name in local_only:
        print(f"- {name}")
    if not local_only:
        print("(none)")
    print()

    print("Top missing by category:")
    for category, count in sorted(missing_by_category.items(), key=lambda item: item[1], reverse=True):
        print(f"- {category}: {count}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
