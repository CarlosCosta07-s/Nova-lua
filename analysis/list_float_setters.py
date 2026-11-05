#!/usr/bin/env python3
"""Find short ARM table entries that store a literal float to a global."""

import argparse
import re
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, Cs


CODE_BASE = 0x00100000
TABLE_START = 0x00665F5C
TABLE_END = 0x00666948
PC_LITERAL = re.compile(r"\[pc, #(-?0x[0-9a-f]+|-?\d+)\]")


def read_u32(code: bytes, address: int) -> int:
    return struct.unpack_from("<I", code, address - CODE_BASE)[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("code", type=Path, help="path to raw ExeFS .code")
    args = parser.parse_args()
    code = args.code.read_bytes()
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    rows = []

    for slot in range(TABLE_START, TABLE_END, 4):
        relative = read_u32(code, slot)
        raw_target = (slot + relative) & 0xFFFFFFFF
        if raw_target & 1:
            continue
        target = raw_target
        instructions = list(arm.disasm(code[target - CODE_BASE : target - CODE_BASE + 16], target))
        if len(instructions) < 4:
            continue
        if [i.mnemonic for i in instructions[:4]] != ["ldr", "vldr", "vstr", "bx"]:
            continue
        if instructions[2].op_str != "s0, [r0]" or instructions[3].op_str != "lr":
            continue

        pointer_literal = PC_LITERAL.search(instructions[0].op_str)
        float_literal = PC_LITERAL.search(instructions[1].op_str)
        if pointer_literal is None or float_literal is None:
            continue
        pointer_address = target + 8 + int(pointer_literal.group(1), 0)
        float_address = instructions[1].address + 8 + int(float_literal.group(1), 0)
        global_address = read_u32(code, pointer_address)
        float_bits = read_u32(code, float_address)
        float_value = struct.unpack("<f", struct.pack("<I", float_bits))[0]
        rows.append((target, global_address, float_bits, float_value))

    print(f"matching short float setters: {len(rows)}")
    print(f"unique destinations: {len({row[1] for row in rows})}")
    print(f"unique float bit patterns: {len({row[2] for row in rows})}")
    for target, destination, bits, value in rows:
        print(f"{target:#010x} -> [{destination:#010x}] = {value:.9g} (bits {bits:#010x})")


if __name__ == "__main__":
    main()

