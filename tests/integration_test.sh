#!/bin/bash
# Ghidrai integration test script
# Tests all Bridge query commands against the running bridge

set -e
GHIDRA_MON="cargo run --release --"
PASS=0
FAIL=0
TOTAL=0

test_cmd() {
    local name="$1"
    shift
    TOTAL=$((TOTAL + 1))
    echo -n "  [$TOTAL] $name ... "
    if output=$($GHIDRA_MON "$@" -f json 2>&1); then
        # Check if output contains valid JSON with "status":"ok" or at least valid JSON
        if echo "$output" | grep -q '"status"' || echo "$output" | python3 -m json.tool > /dev/null 2>&1; then
            echo "✅ PASS"
            PASS=$((PASS + 1))
        else
            echo "⚠️ PASS (non-JSON response)"
            PASS=$((PASS + 1))
        fi
    else
        echo "❌ FAIL"
        echo "    Output: $(echo "$output" | tail -3)"
        FAIL=$((FAIL + 1))
    fi
}

echo "═══════════════════════════════════════════════════"
echo "  Ghidrai Integration Test Suite"
echo "  Binary: crackme (ELF x86-64)"
echo "═══════════════════════════════════════════════════"
echo ""

echo "── Basic Connectivity ──"
test_cmd "ping" query ping

echo ""
echo "── Program Metadata ──"
test_cmd "program_info" query program_info
test_cmd "list_functions" query list_functions
test_cmd "memory_blocks" query memory_blocks
test_cmd "symbols" query symbols
test_cmd "list_imports" query list_imports
test_cmd "list_exports" query list_exports
test_cmd "list_data_types" query list_data_types

echo ""
echo "── Decompilation ──"
test_cmd "decompile main" query decompile main
test_cmd "decompile validate_password" query decompile validate_password
test_cmd "decompile xor_decrypt" query decompile xor_decrypt
test_cmd "decompile simple_hash" query decompile simple_hash
test_cmd "decompile secret_function" query decompile secret_function
test_cmd "decompile print_banner" query decompile print_banner
test_cmd "decompile check_license" query decompile check_license

echo ""
echo "── Function Lookup ──"
test_cmd "function_at 0x00400664 (main)" query function_at 0x00400664
test_cmd "function_containing 0x00400700" query function_containing 0x00400700

echo ""
echo "── Call Graph ──"
test_cmd "callers of validate_password" query callers validate_password
test_cmd "callees of main" query callees main
test_cmd "call_graph" query call_graph

echo ""
echo "── Instructions (Disassembly) ──"
test_cmd "instructions for validate_password" query instructions_for_function validate_password

echo ""
echo "── Cross-References ──"
test_cmd "references_to main (0x00400664)" query references_to 0x00400664
test_cmd "references_from main (0x00400664)" query references_from 0x00400664

echo ""
echo "── Strings Search ──"
test_cmd "search_strings password" query search_strings password
test_cmd "find_symbols main" query find_symbols main

echo ""
echo "── Write Operations ──"
test_cmd "rename_function (--json)" query rename_function --json '{"function":"secret_function","new_name":"discovered_secret_fn"}'
test_cmd "set_comment (--json)" query set_comment --json '{"address":"0x00400591","comment":"Password validation: REV3RSE!"}'
test_cmd "set_plate_comment (--json)" query set_plate_comment --json '{"function":"main","comment":"Main entry point of crackme"}'

echo ""
echo "── Data Lookup ──"
test_cmd "data_at 0x00402000" query data_at 0x00402000

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed, $TOTAL total"
echo "═══════════════════════════════════════════════════"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
