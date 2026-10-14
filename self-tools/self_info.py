#!/usr/bin/env python3
"""Display metadata, names, and SDK version information from PlayStation fake-signed SELFs.

Extracts DT_SONAME, DT_SCE_ORIGINAL_FILENAME, DT_SCE_MODULE_INFO, and SDK parameter blocks.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List

from selflib import is_self, parse_self_info


def collect_files(paths: List[str]) -> List[str]:
    """Expand file and directory arguments into a list of file paths."""
    collected: List[str] = []
    known_exts = {".self", ".prx", ".sprx", ".bin", ".elf"}

    for p in paths:
        if os.path.isfile(p):
            collected.append(p)
        elif os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in sorted(files):
                    ext = os.path.splitext(f)[1].lower()
                    if ext in known_exts:
                        collected.append(os.path.join(root, f))
        else:
            print(f"Warning: path '{p}' does not exist.", file=sys.stderr)

    return collected


def process_file(path: str) -> Dict[str, Any]:
    """Inspect a single SELF file and return its metadata dictionary."""
    res: Dict[str, Any] = {
        "path": path,
        "filename": os.path.basename(path),
        "is_self": False,
        "error": None,
    }

    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if not is_self(magic):
                res["error"] = "Not a valid SELF file (magic mismatch)"
                return res

            f.seek(0)
            data = f.read()

        info = parse_self_info(data)
        res.update(
            {
                "is_self": True,
                "file_size": info.file_size,
                "num_segments": info.num_segments,
                "num_program_headers": info.num_ph,
                "soname": info.soname,
                "original_filename": info.orig_filename,
                "module_name": info.module_name,
                "module_sdk": f"{info.module_sdk:#010x}" if info.module_sdk is not None else None,
                "proc_sdk": f"{info.proc_sdk:#010x}" if info.proc_sdk is not None else None,
                "param_blocks": [
                    {
                        "type": b.block_type,
                        "offset": f"{b.offset:#x}",
                        "size": f"{b.size:#x}",
                        "sdk": f"{b.sdk_version:#010x}",
                    }
                    for b in info.param_blocks
                ],
            }
        )
    except Exception as err:
        res["error"] = str(err)

    return res


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect fake-signed SELF files and extract library names and SDK parameter blocks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s eboot.bin
  %(prog)s prx/ modules/
  %(prog)s *.prx --json
""",
    )
    parser.add_argument(
        "targets",
        metavar="FILE_OR_DIR",
        nargs="+",
        help="One or more SELF files or directories to inspect.",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Output results in JSON format.",
    )

    args = parser.parse_args()
    files = collect_files(args.targets)

    if not files:
        print("Error: no input files found to inspect.", file=sys.stderr)
        return 1

    results = [process_file(f) for f in files]

    if args.as_json:
        print(json.dumps(results, indent=2))
        return 0

    # Formatted table output
    headers = ("File", "Module Name", "SONAME", "Mod SDK", "Proc SDK", "Original Filename")
    rows = []
    for r in results:
        fname = r["filename"]
        if not r["is_self"]:
            err_msg = r["error"] or "Invalid SELF"
            rows.append((fname, f"<{err_msg}>", "-", "-", "-", "-"))
            continue

        mod_name = r["module_name"] or "-"
        soname = r["soname"] or "-"
        mod_sdk = r["module_sdk"] or "-"
        proc_sdk = r["proc_sdk"] or "-"
        orig_fn = r["original_filename"] or "-"
        rows.append((fname, mod_name, soname, mod_sdk, proc_sdk, orig_fn))

    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            # Limit very long original paths for terminal width if needed, but display clearly
            col_widths[i] = max(col_widths[i], len(cell))

    # Keep original filename column flexible
    fmt = f"{{:<{col_widths[0]}}}  {{:<{col_widths[1]}}}  {{:<{col_widths[2]}}}  {{:<{col_widths[3]}}}  {{:<{col_widths[4]}}}  {{}}"
    header_line = fmt.format(*headers)
    print(header_line)
    print("-" * len(header_line))
    for row in rows:
        print(fmt.format(*row))

    return 0


if __name__ == "__main__":
    sys.exit(main())
