#!/usr/bin/env python3
"""Run MCP regression calls for all known MCP tools.

The tool list is discovered from MCP `tools/list` instead of static source parsing,
which keeps local legacy and external backends aligned with the runtime tool surface.

The goal is "does every tool emit a JSON-RPC compliant response" while the backend is
up. Functional correctness is out-of-scope for heavyweight write tools.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Tuple


REQUEST_TIMEOUT_SECONDS = 120


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--backend", default="legacy", choices=["legacy", "external"], help="MCP backend")
    p.add_argument(
        "--expected-connect-fail",
        action="store_true",
        help="Treat failure to start/connect external backend as non-fatal",
    )
    p.add_argument(
        "--legacy-tools-file",
        default="src/mcp/tools.rs",
        help="(Deprecated) kept for compatibility; runtime tool discovery is now via tools/list",
    )
    p.add_argument(
        "--sample-binary",
        default="tests/complex_benchmark",
        help="Path for sample binary arguments used by legacy/write-headless tests",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=REQUEST_TIMEOUT_SECONDS,
        help="Timeout for each cargo run invocation in seconds",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-tool request/response traces",
    )
    return p.parse_args()


def parse_tool_calls(args: argparse.Namespace) -> List[Tuple[str, Dict[str, Any]]]:
    calls = tool_calls_via_tools_list(args)
    return calls


def tool_calls_via_tools_list(args: argparse.Namespace) -> List[Tuple[str, Dict[str, Any]]]:
    tools_response = fetch_tools_list(args)
    if not tools_response:
        if args.backend == "external" and args.expected_connect_fail:
            return []
    tools = tools_response.get("tools") if isinstance(tools_response, dict) else None
    if not isinstance(tools, list):
        print("[error] malformed tools/list response")
        return []

    calls: List[Tuple[str, Dict[str, Any]]] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue

        name = tool.get("name")
        if not isinstance(name, str) or not name:
            continue

        schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
        properties = schema.get("properties") if isinstance(schema, dict) and isinstance(schema.get("properties"), dict) else {}
        required = schema.get("required") if isinstance(schema.get("required"), list) else []

        args_payload = build_arguments_for_tool(
            name,
            properties,
            required,
            sample_binary=args.sample_binary,
            backend=args.backend,
        )

        calls.append((name, args_payload))

    return calls


def fetch_tools_list(args: argparse.Namespace) -> Dict[str, Any]:
    payload = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    responses = run_backend(args.backend, payload, args)
    tools_obj = locate_tools_response(responses)
    if tools_obj is None:
        return {}
    return tools_obj


def build_arguments_for_tool(
    name: str,
    properties: Dict[str, Any],
    required: List[Any],
    sample_binary: str,
    backend: str,
) -> Dict[str, Any]:
    args: Dict[str, Any] = {}

    for required_key in required:
        if not isinstance(required_key, str):
            continue
        prop = properties.get(required_key)
        if isinstance(prop, dict):
            args[required_key] = placeholder_for_property(required_key, prop, sample_binary)
        else:
            args[required_key] = generic_placeholder(required_key, sample_binary)

    if backend == "legacy":
        legacy_defaults(name, args, sample_binary)

    if backend == "legacy" and "port" not in args:
        args["port"] = 12799

    return args


def legacy_defaults(name: str, args: Dict[str, Any], sample_binary: str) -> None:
    if name == "ghidra_ask_bridge":
        args["command"] = "ping"
        args["args"] = {}
        return

    if "port" not in args:
        args["port"] = 12799

    if name == "ghidra_import_and_analyze":
        args["binary_path"] = sample_binary
        args["project_path"] = "tests"
        args["project_name"] = "ghidra_mcp_smoke"
    elif name == "ghidra_run_script":
        args["project_path"] = "tests"
        args["project_name"] = "ghidra_mcp_smoke"
        args["script_name"] = "noop"

    if "function" in name or name == "ghidra_get_function_signature":
        args.setdefault("function", "main")
    if "address" in name or name == "ghidra_instruction_at":
        args.setdefault("address", "0x401000")

    if "comment" in name:
        args["comment"] = args.get("comment", "smoke check")
    if name == "ghidra_set_comment":
        args["address"] = "0x401000"
    if name == "ghidra_rename_function":
        args["function"] = args.get("function", "main")
        args["new_name"] = "renamed_main"
    if name == "ghidra_set_plate_comment":
        args["function"] = args.get("function", "main")
        args["comment"] = args.get("comment", "plate comment")
    if name in {"ghidra_find_symbols", "ghidra_symbols"}:
        args["query"] = args.get("query", "main")
    if "search" in name:
        args["query"] = args.get("query", "main")
    if "call_graph" in name:
        args["depth"] = args.get("depth", 1)


def run_backend(backend: str, payload: List[Dict[str, Any]], args: argparse.Namespace) -> List[Dict[str, Any]]:
    req_text = "\n".join(json.dumps(obj) for obj in payload) + "\n"
    cmd = ["cargo", "run", "--quiet", "--", "mcp", "--backend", backend]

    try:
        proc = subprocess.run(
            cmd,
            input=req_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=args.timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"[error] cargo run timed out after {args.timeout}s")
        return []

    if proc.returncode != 0 and backend == "external" and args.expected_connect_fail:
        print("[warn] external backend invocation failed (expected)")
        return []

    lines = proc.stdout.splitlines()
    if backend == "external" and not lines:
        # keep error output visible for quick diagnosis when external bridge cannot start
        if proc.stderr:
            print(proc.stderr.strip())

    responses: List[Dict[str, Any]] = []
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            if args.verbose:
                print(f"[debug] skipped non-json line: {line}")
            continue
        if isinstance(obj, dict):
            responses.append(obj)

    return responses


def verify_all_calls(calls: List[Tuple[str, Dict[str, Any]]], responses: List[Dict[str, Any]], args: argparse.Namespace) -> bool:
    by_id: Dict[Any, Dict[str, Any]] = {entry.get("id"): entry for entry in responses if isinstance(entry, dict)}

    expected = len(calls)
    observed = 0
    missing: List[str] = []
    bad: List[str] = []

    for idx, (name, _payload) in enumerate(calls, start=3):
        resp = by_id.get(idx)
        if resp is None:
            missing.append(f"{name}: no response with id={idx}")
            continue

        observed += 1
        has_result = "result" in resp
        has_error = "error" in resp
        if not (has_result or has_error):
            bad.append(f"{name}: id={idx} has neither result nor error")

        if args.verbose:
            if has_result:
                print(f"[ok] {name} (id={idx})")
            else:
                print(f"[err] {name} (id={idx})")

    print(f"observed {observed}/{expected} tool-call responses")
    if missing:
        print("missing responses:")
        for item in missing:
            print(f"  - {item}")
    if bad:
        print("invalid responses:")
        for item in bad:
            print(f"  - {item}")

    return not missing and not bad and expected > 0


def locate_tools_response(outputs: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    for obj in outputs:
        if not isinstance(obj, dict):
            continue
        if obj.get("id") == 2:
            payload = obj.get("result", obj.get("error", {}))
            return payload if isinstance(payload, dict) else None
    return None


def request_payload(calls: List[Tuple[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
    payload = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    for idx, (name, args) in enumerate(calls, start=3):
        payload.append(
            {
                "jsonrpc": "2.0",
                "id": idx,
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": args,
                },
            }
        )
    return payload


def placeholder_for_property(prop_name: str, prop: Dict[str, Any], sample_binary: str) -> Any:
    ptype = prop.get("type")
    if isinstance(ptype, str):
        if ptype == "string":
            return generic_placeholder(prop_name, sample_binary)
        if ptype == "number":
            return 1
        if ptype == "integer":
            return 1
        if ptype == "boolean":
            return False
        if ptype == "array":
            return []
        if ptype == "object":
            return {}

    return generic_placeholder(prop_name, sample_binary)


def generic_placeholder(name: str, sample_binary: str) -> Any:
    lower = name.lower()

    if any(token in lower for token in ["address", "from_address", "to_address", "start", "end", "entry", "pc"]):
        return "0x401000"
    if any(token in lower for token in ["function", "symbol", "routine", "label"]):
        return "main"
    if "query" in lower or "search" in lower:
        return "main"
    if any(token in lower for token in ["binary", "file", "path", "program", "project"]):
        return "tests/complex_benchmark" if sample_binary == "tests/complex_benchmark" else sample_binary
    if any(token in lower for token in ["comment", "text", "message", "cmd", "command"]):
        return "mcp smoke"
    if any(token in lower for token in ["depth", "count", "index", "timeout", "level", "size"]):
        return 1
    if "name" in lower:
        return "smoke_item"
    if "type" in lower:
        return "string"
    return "smoke"


def main() -> int:
    args = parse_args()

    if args.backend == "external":
        if "GHIDRA_MCP_COMMAND" not in os.environ and not args.expected_connect_fail:
            print("GHIDRA_MCP_COMMAND is required unless --expected-connect-fail is set")
            return 2

    calls = parse_tool_calls(args)
    if not calls:
        if args.backend == "external" and args.expected_connect_fail:
            print("external backend unavailable, skip")
            return 0
        print("No tools to test")
        return 1

    print(f"testing {len(calls)} tools on backend={args.backend}")

    payload = request_payload(calls)
    responses = run_backend(args.backend, payload, args)
    if not responses:
        if args.backend == "external" and args.expected_connect_fail:
            print("external backend unavailable, skip")
            return 0
        print("backend did not produce responses")
        return 1

    ok = verify_all_calls(calls, responses, args)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
