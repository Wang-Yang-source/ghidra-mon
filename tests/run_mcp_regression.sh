#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MODE="legacy"
EXPECTED_CONNECT_FAIL=0
TIMEOUT=180

for arg in "$@"; do
    case "$arg" in
        legacy|external)
            MODE="$arg"
            ;;
        --expected-connect-fail)
            EXPECTED_CONNECT_FAIL=1
            ;;
        --timeout=*)
            TIMEOUT="${arg#*=}"
            ;;
        -h|--help)
            echo "usage: $0 [legacy|external] [--timeout=SECONDS] [--expected-connect-fail]" >&2
            echo "  legacy                 run ghidrai built-in MCP backend (default)" >&2
            echo "  external               run external bridge_mcp_ghidra.py backend via env vars" >&2
            echo "  --timeout=SECONDS      cargo run timeout for each regression invocation" >&2
            echo "  --expected-connect-fail tolerate missing external backend (skip external run)." >&2
            exit 0
            ;;
        *)
            echo "usage: $0 [legacy|external] [--timeout=SECONDS] [--expected-connect-fail]" >&2
            exit 1
            ;;
    esac
done

if [[ "$MODE" = "external" && "$EXPECTED_CONNECT_FAIL" -eq 1 && -z "${GHIDRA_MCP_COMMAND:-}" ]]; then
    echo "mcp-regression: GHIDRA_MCP_COMMAND is not set, skip external check" >&2
    echo "mcp-regression: if you want to run external mode now, set GHIDRA_MCP_COMMAND and GHIDRA_MCP_ARGS." >&2
    exit 0
fi

CMD=(python3 tests/mcp_function_regressor.py --backend "$MODE" --sample-binary tests/complex_benchmark --timeout "$TIMEOUT")
if [[ "$EXPECTED_CONNECT_FAIL" -eq 1 ]]; then
    CMD+=(--expected-connect-fail)
fi

if "${CMD[@]}"; then
    echo "mcp-regression completed in $MODE mode"
else
    if [[ "$EXPECTED_CONNECT_FAIL" -eq 1 && "$MODE" == "external" ]]; then
        echo "mcp-regression: external backend failed to launch, skip." >&2
        exit 0
    fi
    exit 1
fi
