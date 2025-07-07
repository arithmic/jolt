#!/bin/bash

# Ensure toolchain is always in PATH
export PATH="/home/arithmic/riscv-linux-toolchain/riscv/bin:$PATH"

echo "Cleaning previous build..."
cargo clean

echo "Building RISC-V 32-bit Rust program..."

# Add RISC-V target if not already installed
rustup target add riscv64gc-unknown-linux-gnu

# Build the project
cargo build --target riscv64gc-unknown-linux-gnu

# Check if build was successful
if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo "Binary location: target/riscv64gc-unknown-linux-gnu/release/riscv_compilation"
else
    echo "Build failed!"
    exit 1
fi