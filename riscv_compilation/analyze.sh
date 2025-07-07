#!/bin/bash

set -e

MODE=${1:-debug}
PACKAGE_NAME=$(grep '^name = ' Cargo.toml | sed 's/name = "\(.*\)"/\1/')
BINARY="../target/riscv64gc-unknown-linux-gnu/$MODE/$PACKAGE_NAME"

if [ ! -f "$BINARY" ]; then
    echo "Binary not found: $BINARY"
    exit 1
fi

echo "Analyzing binary: $BINARY"

# Select objdump
OBJDUMP_CMD=$(command -v riscv32-unknown-elf-objdump || command -v riscv64-unknown-elf-objdump || command -v riscv32-linux-gnu-objdump || command -v riscv64-linux-gnu-objdump || command -v llvm-objdump)
if [ -z "$OBJDUMP_CMD" ]; then
    echo "No RISC-V objdump found"
    exit 1
fi

echo "Using objdump: $OBJDUMP_CMD"

# Get disassembly (only main function)
DISASM=$($OBJDUMP_CMD -d "$BINARY")
DISASM_MAIN=$(echo "$DISASM" | sed -n '/<main>/,/^$/p')
echo "$DISASM_MAIN" > disasm.txt

echo ""
echo "------ Instruction Count ------"

TOTAL=$(echo "$DISASM_MAIN" | grep -E '^\s*[0-9a-f]+:\s+[0-9a-f]+' | wc -l)

# Instruction categories
count_instr() {
    echo "$DISASM_MAIN" | grep -E "\s($1)\s" | wc -l
}

ADD=$(count_instr 'add|addi|addw|addiw')
MUL=$(count_instr 'mul|mulh|mulhu|mulhsu')
DIV=$(count_instr 'div|divu|rem|remu')
LOAD=$(count_instr 'lb|lh|lw|ld|lbu|lhu|lwu')
STORE=$(count_instr 'sb|sh|sw|sd')
BRANCH=$(count_instr 'beq|bne|blt|bge|bltu|bgeu')
JUMP=$(count_instr 'jal|jalr')
MOVE=$(count_instr 'mv|li|lui')
LOGIC=$(echo "$DISASM" | grep -E '\s(xor|xori|or|ori|and|andi)\s' | wc -l)
SHIFT=$(echo "$DISASM" | grep -E '\s(slli|srli|srai|sll|srl|sra)\s' | wc -l)

COMPRESSED=$(echo "$DISASM_MAIN" | grep -E '^\s*[0-9a-f]+:\s+[0-9a-f]{1,4}\s+' | wc -l)

CATEGORIZED=$((ADD + MUL + DIV + LOAD + STORE + BRANCH + JUMP + LOGIC + SHIFT + MOVE))
UNCATEGORIZED=$((TOTAL - CATEGORIZED))

# Report
printf "Total instructions:         %4d\n" "$TOTAL"
printf "  Compressed:               %4d\n" "$COMPRESSED"
printf "  Uncompressed:             %4d\n" "$((TOTAL - COMPRESSED))"
echo "-------------------------------"
printf "  Add:                      %4d\n" "$ADD"
printf "  Mul:                      %4d\n" "$MUL"
printf "  Div/Rem:                  %4d\n" "$DIV"
printf "  Load:                     %4d\n" "$LOAD"
printf "  Store:                    %4d\n" "$STORE"
printf "  Branch:                   %4d\n" "$BRANCH"
printf "  Jump:                     %4d\n" "$JUMP"
printf "  Logic (xor/or/and):       %4d\n" "$LOGIC"
printf "  Shift (sll/srl/sra):      %4d\n" "$SHIFT"
printf "  Move (mv/li/lui):         %4d\n" "$MOVE"
echo "-------------------------------"
printf "Categorized:                %4d\n" "$CATEGORIZED"
printf "Uncategorized:              %4d\n" "$UNCATEGORIZED"

echo ""
echo "First 20 instructions in <main>:"
echo "$DISASM_MAIN" | grep -E '^\s*[0-9a-f]+:\s+[0-9a-f]+' | head -20
