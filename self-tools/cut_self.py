#!/usr/bin/env python3
"""Extract an embedded fake-signed SELF from a container at a specified offset.

Verifies the SELF header magic and reads the exact size specified in the header.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys

from selflib import SELF_MAGIC, SELF_MAGICS


def parse_hex_or_int(val: str) -> int:
    try:
        clean = val.strip().lower()
        if clean.startswith("0x"):
            return int(clean[2:], 16)
        return int(clean, 10)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid offset value: '{val}'")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract an embedded fake-signed SELF from a container file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s package.pkg 0x70000 eboot.bin
  %(prog)s dump.img 0x1a2b0000 plugin.prx --force
""",
    )
    parser.add_argument("container", metavar="CONTAINER", help="Path to container file.")
    parser.add_argument(
        "offset",
        metavar="OFFSET",
        type=parse_hex_or_int,
        help="Byte offset of the SELF within the container (hex or dec).",
    )
    parser.add_argument("output", metavar="OUT", help="Path to write the extracted SELF file.")
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite output file if it already exists.",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.container):
        print(f"Error: container file '{args.container}' not found.", file=sys.stderr)
        return 1

    if os.path.exists(args.output) and not args.force:
        print(f"Error: output file '{args.output}' already exists. Use --force to overwrite.", file=sys.stderr)
        return 1

    container_size = os.path.getsize(args.container)
    if args.offset < 0 or args.offset >= container_size:
        print(
            f"Error: offset {args.offset:#x} is out of bounds (container size: {container_size:#x}).",
            file=sys.stderr,
        )
        return 1

    try:
        with open(args.container, "rb") as f:
            f.seek(args.offset)
            hdr = f.read(0x20)
            if len(hdr) < 0x20:
                print(f"Error: unexpected EOF reading header at offset {args.offset:#x}.", file=sys.stderr)
                return 1

            if hdr[:4] not in SELF_MAGICS:
                print(
                    f"Error: invalid SELF magic at offset {args.offset:#x}: expected {SELF_MAGIC.hex()}, got {hdr[:4].hex()}.",
                    file=sys.stderr,
                )
                return 1

            self_size = struct.unpack_from("<Q", hdr, 0x10)[0]
            if self_size == 0 or args.offset + self_size > container_size:
                print(
                    f"Error: invalid SELF size {self_size} at offset {args.offset:#x} (exceeds container bounds).",
                    file=sys.stderr,
                )
                return 1

            f.seek(args.offset)
            # Read and stream/write in chunks to prevent high memory usage for large files
            out_dir = os.path.dirname(args.output)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)

            hasher = hashlib.sha256()
            remaining = self_size
            chunk_size = 4 * 1024 * 1024  # 4 MiB buffer

            with open(args.output, "wb") as out_f:
                while remaining > 0:
                    read_len = min(remaining, chunk_size)
                    chunk = f.read(read_len)
                    if len(chunk) != read_len:
                        print(
                            f"Error: unexpected EOF while extracting {self_size} bytes (read {self_size - remaining + len(chunk)} bytes).",
                            file=sys.stderr,
                        )
                        return 1
                    out_f.write(chunk)
                    hasher.update(chunk)
                    remaining -= read_len

        sha256_hex = hasher.hexdigest()
        print(f"Extracted {self_size} bytes from {args.offset:#x} -> '{args.output}'")
        print(f"SHA-256: {sha256_hex}")
        return 0

    except OSError as err:
        print(f"Error extracting SELF: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
