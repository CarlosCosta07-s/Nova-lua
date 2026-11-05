#!/usr/bin/env python3
"""Count initializer entries that call the guard-like Thumb helper.

Requires Capstone. This is a fixed-window heuristic, not a full function
boundary analysis: it scans 0x60 bytes from each relative-table target.
"""

import argparse
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, Cs


CODE_BASE = 0x00100000
TABLE_START = 0x00665F5C
TABLE_END = 0x00666948
WINDOW_SIZE = 0x60
GUARD_HELPER = 0x0030295C


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("code", type=Path, help="path to raw ExeFS .code")
    args = parser.parse_args()
    code = args.code.read_bytes()

    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    matching = []
    total = 0

    for slot in range(TABLE_START, TABLE_END, 4):
        relative = struct.unpack_from("<I", code, slot - CODE_BASE)[0]
        raw_target = (slot + relative) & 0xFFFFFFFF
        target = raw_target & ~1
        mode = thumb if raw_target & 1 else arm
        start = target - CODE_BASE
        instructions = mode.disasm(code[start : start + WINDOW_SIZE], target)
        if any(
            instruction.mnemonic.startswith("bl")
            and instruction.op_str.lstrip("#") == f"{GUARD_HELPER:#x}"
            for instruction in instructions
        ):
            total += 1
            if len(matching) < 12:
                matching.append(target)

    print(f"relative-table entries: {(TABLE_END - TABLE_START) // 4}")
    print(f"entries with a direct call to {GUARD_HELPER:#010x} in first {WINDOW_SIZE:#x} bytes: {total}")
    print("sample targets:", ", ".join(f"{target:#010x}" for target in matching))
    print("Interpretation: fixed-window pattern only; function boundaries are not inferred.")


if __name__ == "__main__":
    main()

