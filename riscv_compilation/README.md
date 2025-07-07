# RISC-V Rust Project

This project is set up to build and analyze a Rust project targeting RISC-V (`riscv32imc-unknown-none-elf`) on macOS.

## Add RISC-V target to Rust:
```rustup target add riscv32imc-unknown-none-elf```

## Make scripts executable:
```chmod +x build.sh analyze.sh```

## RISC-V 32-bit GCC toolchain on macOS
```brew tap riscv-software-src/riscv```
```brew install riscv-tools```

## Check it's working:
```riscv64-unknown-elf-gcc --version```

## Install cargo-binutils
```cargo install cargo-binutils```
```rustup component add llvm-tools-preview```

## Build the project:
```./build.sh```

## Analyze the binary and count instructions:
```./analyze.sh```