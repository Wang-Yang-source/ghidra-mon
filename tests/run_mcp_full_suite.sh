#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MODE="both"
EXPECT_FAIL=0
SAMPLE_BINARY="$ROOT_DIR/tests/complex_benchmark"
TIMEOUT=180
VERBOSE=0

for arg in "$@"; do
    case "$arg" in
        legacy)
            MODE="legacy"
            ;;
        external)
            MODE="external"
            ;;
        both)
            MODE="both"
            ;;
        --expected-connect-fail)
            EXPECT_FAIL=1
            ;;
        --binary=*)
            SAMPLE_BINARY="${arg#*=}"
            ;;
        --timeout=*)
            TIMEOUT="${arg#*=}"
            ;;
        --verbose)
            VERBOSE=1
            ;;
        -h|--help)
            echo "usage: $0 [legacy|external|both] [--expected-connect-fail] [--binary=/path] [--timeout=SECONDS] [--verbose]"
            echo "  legacy    test built-in mcp tools"
            echo "  external  test external ghidra-mcp style backend"
            echo "  both      test both modes (default)"
            exit 0
            ;;
        *)
            echo "usage: $0 [legacy|external|both] [--expected-connect-fail] [--binary=/path] [--timeout=SECONDS] [--verbose]" >&2
            exit 1
            ;;
    esac
done

run_mode() {
    local backend="$1"
    echo "==> mcp_function_regressor backend=$backend"
    local cmd=(python3 tests/mcp_function_regressor.py --backend "$backend" --sample-binary "$SAMPLE_BINARY" --timeout "$TIMEOUT")
    if [[ "$EXPECT_FAIL" -eq 1 ]]; then
        cmd+=(--expected-connect-fail)
    fi
    if [[ "$VERBOSE" -eq 1 ]]; then
        cmd+=(--verbose)
    fi

    "${cmd[@]}"
}

echo "==> compile complex samples"
./tests/build_complex_binary.sh >/tmp/ghidra_complex_build.log 2>&1 || {
    echo "build failed, see /tmp/ghidra_complex_build.log" >&2
    cat /tmp/ghidra_complex_build.log
    exit 1
}

if [[ ! -f "$SAMPLE_BINARY" ]]; then
    echo "complex sample binary still not found after build: $SAMPLE_BINARY" >&2
    exit 1
fi

echo "==> legacy MCP regression"
echo "sample binary: $SAMPLE_BINARY"

case "$MODE" in
    legacy)
        run_mode legacy || true
        ;;
    external)
        if ! run_mode external; then
            if [[ "$EXPECT_FAIL" -eq 1 ]]; then
                echo "external backend unavailable, skip as requested"
            else
                exit 1
            fi
        fi
        ;;
    both)
        run_mode legacy || true
        if ! run_mode external; then
            if [[ "$EXPECT_FAIL" -eq 1 ]]; then
                echo "external backend unavailable, skip as requested"
            else
                exit 1
            fi
        fi
        ;;
    *)
        echo "unknown mode: $MODE" >&2
        exit 1
        ;;
esac

if [[ "$MODE" != "external" && -f "$SAMPLE_BINARY" ]]; then
    ./tests/run_mcp_regression.sh legacy
fi

echo "==> coverage check against ghidra-mcp endpoints"
python3 tests/compare_mcp_coverage.py --top-missing 12

exit 0
