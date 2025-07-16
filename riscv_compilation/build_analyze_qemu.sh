#!/usr/bin/env bash
export PATH="/home/arithmic/riscv-linux-toolchain/riscv/bin:$PATH"

set -e

TARGET="riscv64gc-unknown-linux-gnu"
BINARY_NAME="riscv_compilation"
BUILD_DIR="../target/$TARGET/debug"
OUTPUT="$BUILD_DIR/$BINARY_NAME"
TRACE_LOG="trace.log"

echo "✅ Cleaning old build..."
cargo clean

echo "✅ Building DEBUG binary for $TARGET (static)..."
RUSTFLAGS="-C target-feature=+crt-static" \
cargo build --target $TARGET

echo "✅ Verifying binary type:"
file "$OUTPUT"

echo "Running binary with exec"

# To run with run time args
# echo "16" | qemu-riscv64 -d in_asm,exec "$OUTPUT" > "$TRACE_LOG" 2>&1

# To run the program with Command line args
# qemu-riscv64 -d in_asm,exec "$OUTPUT" "10" > "$TRACE_LOG" 2>&1

# echo "✅ Running binary under QEMU with dynamic instruction trace..."
qemu-riscv64 -d in_asm,exec "$OUTPUT" > "$TRACE_LOG" 2>&1

echo "✅ Total disassembled ISA instructions:"
grep '^0x' "$TRACE_LOG" | wc -l

echo "✅ Breakdown by ISA mnemonic:"
echo "--------------------------------------------"
grep '^0x' "$TRACE_LOG" | awk '{print $3}' | sort | uniq -c | sort -nr | awk '{printf "%10s %s\n", $1, $2}'
echo "--------------------------------------------"
