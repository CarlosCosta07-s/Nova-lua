#!/usr/bin/env python3
"""List targets from the relative initializer table reached at 0x00100ef0.

Pass a local, raw ExeFS .code image as the first argument. The ROM itself is
never opened or modified by this script.
"""

import argparse
import struct
from pathlib import Path


CODE_BASE = 0x00100000
TEXT_END = 0x005BA000
TABLE_START = 0x00665F5C
TABLE_END = 0x00666948


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("code", type=Path, help="path to raw ExeFS .code")
    parser.add_argument("--list", action="store_true", help="print all entries")
    args = parser.parse_args()

    code = args.code.read_bytes()
    needed = TABLE_END - CODE_BASE
    if len(code) < needed:
        raise SystemExit(f".code is too short: {len(code):#x} bytes; need {needed:#x}")

    entries = []
    for slot in range(TABLE_START, TABLE_END, 4):
        relative = struct.unpack_from("<I", code, slot - CODE_BASE)[0]
        target = (slot + relative) & 0xFFFFFFFF
        address = target & ~1
        mode = "Thumb" if target & 1 else "ARM"
        if not CODE_BASE <= address < TEXT_END:
            raise SystemExit(f"target outside text at slot {slot:#010x}: {target:#010x}")
        entries.append((slot, relative, target, mode))

    print(f"table: [{TABLE_START:#010x}, {TABLE_END:#010x})")
    print(f"entries: {len(entries)}")
    print(f"unique targets: {len({entry[2] for entry in entries})}")
    for mode in ("ARM", "Thumb"):
        print(f"{mode}: {sum(entry[3] == mode for entry in entries)}")

    if args.list:
        for slot, relative, target, mode in entries:
            print(f"{slot:#010x} + {relative:#010x} -> {target:#010x} ({mode})")
    else:
        for slot, relative, target, mode in entries[:5] + entries[-5:]:
            print(f"{slot:#010x} + {relative:#010x} -> {target:#010x} ({mode})")


if __name__ == "__main__":
    main()

