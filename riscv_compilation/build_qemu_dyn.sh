#!/usr/bin/env bash
# This is for programs which gives dynamically linked binaries
# Tried to do it with proper guest rootfs but not yet working
# Our next attempt after this is to use riscv64gc-unknown-linux-musl

set -e

export PATH="/home/arithmic/riscv-linux-toolchain/riscv/bin:$PATH"
export SYSROOT="/home/arithmic/riscv-linux-toolchain/riscv/sysroot"

TARGET="riscv64gc-unknown-linux-gnu"
BINARY_NAME="riscv_compilation"
BUILD_DIR="../target/$TARGET/debug"
OUTPUT="$BUILD_DIR/$BINARY_NAME"
TRACE_LOG="trace.log"
SYSROOT="/home/arithmic/riscv-linux-toolchain/riscv/sysroot"

# echo "✅ Cleaning old build..."
# cargo clean

echo "✅ Building DEBUG binary for $TARGET..."
cargo build --target $TARGET

echo "✅ Verifying binary type:"
file "$OUTPUT"
echo "✅ Verifying ELF interpreter:"
readelf -l "$OUTPUT" | grep interpreter

echo "✅ Running under QEMU with guest sysroot..."
qemu-riscv64 -L "$SYSROOT" -d in_asm,exec "$OUTPUT" > "$TRACE_LOG" 2>&1

echo "✅ Trace log written to $TRACE_LOG"
echo "✅ Total instructions:"
grep '^0x' "$TRACE_LOG" | wc -l

echo "✅ Breakdown by mnemonic:"
grep '^0x' "$TRACE_LOG" | awk '{print $3}' | sort | uniq -c | sort -nr
