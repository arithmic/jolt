## To analyze bytecode
<!-- If you are getting this error, do the following -->
```export OPENSSL_DIR=$HOME/riscv-linux-toolchain/riscv/sysroot/usr```
```export OPENSSL_LIB_DIR=$OPENSSL_DIR/lib```
```export OPENSSL_INCLUDE_DIR=$OPENSSL_DIR/include```

```export PKG_CONFIG_ALLOW_CROSS=1```
```export PKG_CONFIG_SYSROOT_DIR=$HOME/riscv-linux-toolchain/riscv/sysroot```
```export PKG_CONFIG_PATH=$OPENSSL_DIR/lib/pkgconfig```


<!-- # RISC-V Rust Project

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
 -->


