#!/usr/bin/env python3
"""Scan large binary containers (e.g. packages or dumps) for embedded fake-signed SELFs.

Reads incrementally with seek, never loading the full container into memory.
"""
from __future__ import annotations

import argparse
import os
import re
import struct
import sys
from typing import Optional

from selflib import MODULE_PARAM_MAGIC, PROC_PARAM_MAGIC, SELF_MAGIC, find_param_blocks


def parse_hex_or_int(val: str) -> int:
    try:
        clean = val.strip().lower()
        if clean.startswith("0x"):
            return int(clean[2:], 16)
        return int(clean, 10)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid integer/hex value: '{val}'")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan large binary containers for embedded fake-signed SELFs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s package.pkg
  %(prog)s container.bin --start 0x10000 --align 0x4000
  %(prog)s dump.img --start 0x100000 --end 0x50000000
""",
    )
    parser.add_argument("container", metavar="CONTAINER", help="Path to container file to scan.")
    parser.add_argument(
        "--start",
        type=parse_hex_or_int,
        default=0,
        help="Starting file offset (hex or dec, default: 0).",
    )
    parser.add_argument(
        "--end",
        type=parse_hex_or_int,
        default=None,
        help="Ending file offset (hex or dec, default: container file size).",
    )
    parser.add_argument(
        "--align",
        type=parse_hex_or_int,
        default=0x10000,
        help="Scan alignment boundary in bytes (hex or dec, default: 0x10000 / 64 KiB).",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.container):
        print(f"Error: file '{args.container}' not found.", file=sys.stderr)
        return 1

    file_size = os.path.getsize(args.container)
    start_pos = args.start
    end_pos = file_size if args.end is None else min(file_size, args.end)
    align = max(1, args.align)

    if start_pos >= end_pos:
        print(f"Error: start offset ({start_pos:#x}) is >= end offset ({end_pos:#x}).", file=sys.stderr)
        return 1

    # Round start_pos up to nearest alignment
    if start_pos % align != 0:
        start_pos = ((start_pos + align - 1) // align) * align

    print(f"Scanning '{args.container}' from {start_pos:#x} to {end_pos:#x} (align: {align:#x})...")
    print(f"{'Offset':<14} {'Size':<12} {'Proc SDK':<12} {'Mod SDK':<12} Path / Name")
    print("-" * 80)

    found_count = 0
    pos = start_pos

    try:
        with open(args.container, "rb") as f:
            while pos < end_pos:
                f.seek(pos)
                header = f.read(0x20)
                if len(header) < 0x20:
                    break

                if header[:4] == SELF_MAGIC:
                    self_size = struct.unpack_from("<Q", header, 0x10)[0]
                    if self_size == 0 or pos + self_size > file_size:
                        pos += align
                        continue

                    # Read inspect chunk
                    inspect_len = min(self_size, 2 * 1024 * 1024)
                    f.seek(pos)
                    chunk = f.read(inspect_len)

                    # Find param blocks
                    blocks = find_param_blocks(chunk)
                    proc_sdk = None
                    mod_sdk = None
                    for b in blocks:
                        if b.block_type == "proc" and proc_sdk is None:
                            proc_sdk = b.sdk_version
                        elif b.block_type == "module" and mod_sdk is None:
                            mod_sdk = b.sdk_version

                    # Look for embedded path string (e.g. PATHH marker or filename pattern)
                    path_str = ""
                    pj = chunk.find(b"PATHH")
                    if pj != -1 and pj + 12 < len(chunk):
                        raw_path = chunk[pj + 12 : pj + 12 + 128].split(b"\0")[0]
                        path_str = raw_path.decode("utf-8", errors="replace")

                    if not path_str:
                        # Scan for plausible prx/elf/bin name in first 2MB
                        m = re.search(rb"[A-Za-z0-9_\-\.]{3,64}\.(?:prx|sprx|elf|bin)", chunk[:0x200000])
                        if m:
                            path_str = m.group().decode("utf-8", errors="replace")

                    proc_str = f"{proc_sdk:#010x}" if proc_sdk is not None else "-"
                    mod_str = f"{mod_sdk:#010x}" if mod_sdk is not None else "-"
                    print(f"{pos:#012x}  {self_size:>10}  {proc_str:<12}  {mod_str:<12} {path_str}")
                    found_count += 1

                    # Skip to next aligned boundary after this SELF
                    aligned_next = ((self_size + align - 1) // align) * align
                    pos += max(align, aligned_next)
                    continue

                pos += align

    except OSError as err:
        print(f"Error scanning container: {err}", file=sys.stderr)
        return 1

    print(f"\nScan complete. Found {found_count} SELF binary/binaries.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
