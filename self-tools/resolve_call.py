#!/usr/bin/env python3
"""Resolve crash backtrace return addresses to imported system functions via the PLT/GOT.

Reconstructs the flat ELF image from a fake-signed SELF, locates the call instruction before
each return address, and resolves targets to their imported NID#lib#module symbol.
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
from typing import Dict, List, Optional

from selflib import (
    DT_JMPREL,
    DT_PLTRELSZ,
    DT_SCE_EXPORT_LIB,
    DT_SCE_EXPORT_MODULE,
    DT_SCE_IMPORT_LIB,
    DT_SCE_NEEDED_LIB,
    DT_STRTAB,
    DT_SYMTAB,
    decode_sony_id,
    get_cstring,
    is_self,
    parse_dynamic_table,
    parse_self_header,
    rebuild_flat_elf,
    vaddr_to_file_offset,
)


def parse_hex(val: str) -> int:
    try:
        clean = val.strip().lower()
        if clean.startswith("0x"):
            clean = clean[2:]
        return int(clean, 16)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid hexadecimal address: '{val}'")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Resolve backtrace return addresses to imported functions (NID#lib#module) via PLT/GOT.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s eboot.bin 0x400000 0x1234567 0x89abcd
  %(prog)s module.prx 0 0x12345 0x12380
""",
    )
    parser.add_argument("self_path", metavar="SELF", help="Path to fake-signed SELF file.")
    parser.add_argument(
        "load_base",
        metavar="LOAD_BASE",
        type=parse_hex,
        help="Runtime base address in hex (e.g. 0x400000 or 0).",
    )
    parser.add_argument(
        "ret_addrs",
        metavar="RET_ADDR",
        nargs="+",
        type=parse_hex,
        help="One or more backtrace return addresses in hex.",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.self_path):
        print(f"Error: file '{args.self_path}' not found.", file=sys.stderr)
        return 1

    try:
        with open(args.self_path, "rb") as f:
            data = f.read()
    except OSError as err:
        print(f"Error reading '{args.self_path}': {err}", file=sys.stderr)
        return 1

    if not is_self(data):
        print(f"Error: '{args.self_path}' is not a valid SELF file.", file=sys.stderr)
        return 1

    try:
        header, entries, elf_off, ph = parse_self_header(data)
        flat_elf = rebuild_flat_elf(data)
        tags, strtab_off = parse_dynamic_table(flat_elf, ph)
    except Exception as err:
        print(f"Error parsing SELF structure: {err}", file=sys.stderr)
        return 1

    if strtab_off is None:
        print("Error: string table (DT_STRTAB) not found in dynamic section.", file=sys.stderr)
        return 1

    def cstr(idx: int) -> str:
        return get_cstring(flat_elf, strtab_off + idx)

    # Build GOT slot -> symbol name table
    got: Dict[int, str] = {}
    if DT_JMPREL in tags and DT_PLTRELSZ in tags and DT_SYMTAB in tags:
        jmprel_va = tags[DT_JMPREL][0]
        pltrelsz = tags[DT_PLTRELSZ][0]
        symtab_va = tags[DT_SYMTAB][0]

        jmprel_off = vaddr_to_file_offset(jmprel_va, ph)
        symtab_off = vaddr_to_file_offset(symtab_va, ph)

        if jmprel_off is not None and symtab_off is not None:
            num_relocs = pltrelsz // 24
            for i in range(num_relocs):
                r_off, r_info, _ = struct.unpack_from("<QQq", flat_elf, jmprel_off + i * 24)
                sym = r_info >> 32
                st_name = struct.unpack_from("<I", flat_elf, symtab_off + sym * 24)[0]
                got[r_off] = cstr(st_name)

    # Module and library dictionary
    # Tag values: (id << 48) | string_offset
    mods: Dict[int, Dict[int, str]] = {}
    lib_tags = (DT_SCE_NEEDED_LIB, DT_SCE_EXPORT_LIB, DT_SCE_IMPORT_LIB, DT_SCE_EXPORT_MODULE)
    for t in lib_tags:
        for v in tags.get(t, []):
            lib_id = (v >> 48) & 0xFFFF
            str_idx = v & 0xFFFFFFFF
            mods.setdefault(t, {})[lib_id] = cstr(str_idx)

    # Resolve each return address
    for ret_addr in args.ret_addrs:
        ret_va = ret_addr - args.load_base
        f_off = vaddr_to_file_offset(ret_va, ph)
        if f_off is None or f_off >= len(flat_elf):
            print(f"{ret_addr:#x}: not inside this module")
            continue

        target = None
        # Direct call: E8 <disp32>
        if f_off >= 5 and flat_elf[f_off - 5] == 0xE8:
            disp = struct.unpack_from("<i", flat_elf, f_off - 4)[0]
            target = ret_va + disp
        # Indirect call via RIP-relative pointer: FF 15 <disp32>
        elif f_off >= 6 and flat_elf[f_off - 6 : f_off - 4] == b"\xff\x15":
            disp = struct.unpack_from("<i", flat_elf, f_off - 4)[0]
            slot = ret_va + disp
            sym_name = got.get(slot, "unknown")
            print(f"{ret_addr:#x}: indirect call via GOT {slot:#x} -> {sym_name}")
            continue

        if target is None:
            raw_bytes = flat_elf[max(0, f_off - 8) : f_off].hex()
            print(f"{ret_addr:#x}: no direct call before it (bytes: {raw_bytes})")
            continue

        target_foff = vaddr_to_file_offset(target, ph)
        if target_foff is None or target_foff + 6 > len(flat_elf):
            print(f"{ret_addr:#x}: call target {target + args.load_base:#x} outside image")
            continue

        stub = flat_elf[target_foff : target_foff + 6]
        # PLT stub: FF 25 <disp32>
        if stub[:2] == b"\xff\x25":
            disp = struct.unpack_from("<i", stub, 2)[0]
            slot = target + 6 + disp
            sym_name = got.get(slot, "unknown")
            parts = sym_name.split("#")
            lib_info = ""
            if len(parts) == 3:
                lid = decode_sony_id(parts[1])
                mid = decode_sony_id(parts[2])
                lib_name = (
                    mods.get(DT_SCE_NEEDED_LIB, {}).get(lid)
                    or mods.get(DT_SCE_EXPORT_LIB, {}).get(lid)
                    or mods.get(DT_SCE_IMPORT_LIB, {}).get(lid)
                    or f"lib_{lid}"
                )
                mod_name = mods.get(DT_SCE_EXPORT_MODULE, {}).get(mid) or f"mod_{mid}"
                lib_info = f" (lib={lib_name}, module={mod_name})"

            print(f"{ret_addr:#x}: call {target + args.load_base:#x} (PLT) -> GOT {slot:#x} -> {sym_name}{lib_info}")
        else:
            print(f"{ret_addr:#x}: call {target + args.load_base:#x} (internal function)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
