#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COVERAGE_DIR="$ROOT_DIR/coverage"

HOST_TRIPLE="$(rustc -vV | awk '/^host: /{print $2}')"
SYSROOT="$(rustc --print sysroot)"
LLVM_BIN="$SYSROOT/lib/rustlib/$HOST_TRIPLE/bin"

export LLVM_PROFILE_FILE="$COVERAGE_DIR/%p-%m.profraw"
export RUSTFLAGS="-C instrument-coverage"

GRCOV_BIN="${GRCOV_BIN:-$HOME/.cargo/bin/grcov}"
if [[ ! -x "$GRCOV_BIN" ]]; then
  echo "grcov not found at $GRCOV_BIN. Install with: cargo install grcov" >&2
  exit 1
fi

mkdir -p "$COVERAGE_DIR"
find "$ROOT_DIR" -name "*.profraw" -delete

cargo test --all-features

"$LLVM_BIN/llvm-profdata" merge -sparse "$COVERAGE_DIR"/*.profraw -o "$COVERAGE_DIR/coverage.profdata"

"$GRCOV_BIN" \
  "$ROOT_DIR" \
  -s "$ROOT_DIR" \
  -t html \
  --binary-path "$ROOT_DIR/target/debug" \
  --llvm \
  --branch \
  --ignore-not-existing \
  --ignore "*/tests/*" \
  --ignore "*/benches/*" \
  --ignore "*/fuzz/*" \
  -o "$COVERAGE_DIR"

echo "Coverage report: $COVERAGE_DIR/index.html"
