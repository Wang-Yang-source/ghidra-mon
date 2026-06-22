#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_GUESS="$ROOT_DIR/tests/guess_game.cpp"
OUT_GUESS="$ROOT_DIR/tests/guess_game"
SRC_COMPLEX="$ROOT_DIR/tests/complex_benchmark.c"
OUT_COMPLEX="$ROOT_DIR/tests/complex_benchmark"

if [[ ! -f "$SRC_GUESS" ]]; then
    echo "missing source file: $SRC_GUESS" >&2
    exit 1
fi

if [[ ! -f "$SRC_COMPLEX" ]]; then
    echo "missing source file: $SRC_COMPLEX" >&2
    exit 1
fi

if command -v g++ >/dev/null 2>&1; then
    CXX_COMPILER="g++"
elif command -v clang++ >/dev/null 2>&1; then
    CXX_COMPILER="clang++"
else
    echo "no C++ compiler found (need g++ or clang++)" >&2
    exit 1
fi

if command -v gcc >/dev/null 2>&1; then
    C_COMPILER="gcc"
elif command -v clang >/dev/null 2>&1; then
    C_COMPILER="clang"
else
    echo "no C compiler found (need gcc or clang)" >&2
    exit 1
fi

if [[ ! -f "$OUT_GUESS" || "$SRC_GUESS" -nt "$OUT_GUESS" ]]; then
    echo "building guess game with $CXX_COMPILER"
    "$CXX_COMPILER" -std=c++17 -g -O0 -fno-omit-frame-pointer "$SRC_GUESS" -o "$OUT_GUESS"
    chmod +x "$OUT_GUESS"
    echo "built: $OUT_GUESS"
else
    echo "guess_game is already up to date: $OUT_GUESS"
fi

if [[ ! -f "$OUT_COMPLEX" || "$SRC_COMPLEX" -nt "$OUT_COMPLEX" ]]; then
    echo "building complex benchmark with $C_COMPILER"
    "$C_COMPILER" -std=c11 -O0 -fno-omit-frame-pointer -g "$SRC_COMPLEX" -o "$OUT_COMPLEX"
    chmod +x "$OUT_COMPLEX"
    echo "built: $OUT_COMPLEX"
else
    echo "complex_benchmark is already up to date: $OUT_COMPLEX"
fi
