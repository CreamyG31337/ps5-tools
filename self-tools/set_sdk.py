#!/usr/bin/env python3
"""Patch the SDK version in PlayStation fake-signed SELF module and/or process parameter blocks.

Modifies the 32-bit SDK version stored at offset +0xC from the module param magic (0x3C13F4BF)
or proc param magic ('ORBI').
"""
from __future__ import annotations

import argparse
import os
import sys

from selflib import patch_sdk_in_memory


def parse_hex_sdk(val: str) -> int:
    try:
        clean = val.strip().lower()
        if clean.startswith("0x"):
            clean = clean[2:]
        return int(clean, 16)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid hexadecimal SDK value: '{val}' (expected e.g. 04030000 or 0x04030000)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Patch the SDK version in fake-signed SELF module or process parameter blocks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s eboot.bin eboot.patched.bin 04030000
  %(prog)s input.prx output.prx 04030000 --only module
  %(prog)s input.self output.self 04030000 --from 05000033 --force
""",
    )
    parser.add_argument("input", metavar="IN", help="Path to input SELF file.")
    parser.add_argument("output", metavar="OUT", help="Path to write patched SELF file.")
    parser.add_argument(
        "sdk",
        metavar="SDK_HEX",
        type=parse_hex_sdk,
        help="Target SDK version in hex (e.g. 04030000 or 0x04030000).",
    )
    parser.add_argument(
        "--only",
        choices=["module", "proc"],
        default="all",
        help="Only patch specific block type ('module' or 'proc'). Default: patch both.",
    )
    parser.add_argument(
        "--from",
        dest="from_sdk",
        type=parse_hex_sdk,
        default=None,
        help="Only patch blocks currently matching this hex SDK version.",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite output file if it already exists.",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: input file '{args.input}' not found.", file=sys.stderr)
        return 1

    if os.path.exists(args.output) and not args.force:
        print(f"Error: output file '{args.output}' already exists. Use --force to overwrite.", file=sys.stderr)
        return 1

    try:
        with open(args.input, "rb") as f:
            data = bytearray(f.read())
    except OSError as err:
        print(f"Error reading input file '{args.input}': {err}", file=sys.stderr)
        return 1

    modified = patch_sdk_in_memory(
        data=data,
        new_sdk=args.sdk,
        target=args.only,
        old_sdk_filter=args.from_sdk,
    )

    if not modified:
        filter_msg = f" matching filter --from {args.from_sdk:#010x}" if args.from_sdk is not None else ""
        only_msg = f" for type '{args.only}'" if args.only != "all" else ""
        print(f"Error: no valid parameter blocks found{only_msg}{filter_msg} in '{args.input}'.", file=sys.stderr)
        return 1

    for block, old_val in modified:
        print(f"  '{block.block_type}' param at {block.offset:#x}: {old_val:#010x} -> {args.sdk:#010x}")

    try:
        # Avoid creating directories if output is just in current dir
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "wb") as f:
            f.write(data)
    except OSError as err:
        print(f"Error writing output file '{args.output}': {err}", file=sys.stderr)
        return 1

    print(f"Successfully patched {len(modified)} block(s) -> '{args.output}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
