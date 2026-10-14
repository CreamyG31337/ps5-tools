"""Shared library for inspecting, parsing, and modifying PlayStation fake-signed SELFs.

Supports Python 3.9+ standard library only.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Dict, List, Optional, Tuple

SELF_MAGIC = b"\x54\x14\xf5\xee"
ELF_MAGIC = b"\x7fELF"

MODULE_PARAM_MAGIC = struct.pack("<I", 0x3C13F4BF)
PROC_PARAM_MAGIC = b"ORBI"

# Dynamic table tags
DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_JMPREL = 0x17

DT_SCE_NEEDED_LIB = 0x6100003D
DT_SCE_ORIGINAL_FILENAME = 0x61000041
DT_SCE_MODULE_INFO = 0x61000043
DT_SCE_EXPORT_LIB = 0x61000045
DT_SCE_IMPORT_LIB = 0x61000047
DT_SCE_EXPORT_MODULE = 0x61000049


@dataclass
class SelfHeader:
    magic: bytes
    version: int
    mode: int
    header_size: int
    meta_size: int
    file_size: int
    num_entries: int
    flags: int


@dataclass
class SelfSegmentEntry:
    props: int
    offset: int
    filesz: int
    memsz: int

    @property
    def is_elf_segment(self) -> bool:
        return bool(self.props & 0x800)

    @property
    def elf_ph_index(self) -> int:
        return (self.props >> 20) & 0xFFF


@dataclass
class ElfProgramHeader:
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int


@dataclass
class ParamBlock:
    block_type: str  # "module" or "proc"
    offset: int  # offset of the magic in the data
    size: int  # 0x20 for module, 0x60 for proc
    sdk_version: int  # 32-bit uint at offset + 0xC


@dataclass
class SelfInfo:
    file_size: int
    num_segments: int
    num_ph: int
    soname: Optional[str]
    orig_filename: Optional[str]
    module_name: Optional[str]
    module_sdk: Optional[int]
    proc_sdk: Optional[int]
    param_blocks: List[ParamBlock]


def is_self(data: bytes) -> bool:
    """Check if the given buffer begins with the SELF magic."""
    return len(data) >= 4 and data[:4] == SELF_MAGIC


def parse_self_header(data: bytes) -> Tuple[SelfHeader, List[SelfSegmentEntry], int, List[ElfProgramHeader]]:
    """Parse SELF header, segment entries, and embedded ELF program headers.

    Returns:
        (SelfHeader, [SelfSegmentEntry], elf_offset, [ElfProgramHeader])
    """
    if len(data) < 0x20:
        raise ValueError("Buffer too small for SELF header")
    if data[:4] != SELF_MAGIC:
        raise ValueError(f"Invalid SELF magic: {data[:4].hex()}")

    version = struct.unpack_from("<I", data, 0x04)[0]
    mode = struct.unpack_from("<H", data, 0x08)[0]
    header_size = struct.unpack_from("<H", data, 0x0A)[0]
    meta_size = struct.unpack_from("<I", data, 0x0C)[0]
    file_size = struct.unpack_from("<Q", data, 0x10)[0]
    num_entries = struct.unpack_from("<H", data, 0x18)[0]
    flags = struct.unpack_from("<H", data, 0x1A)[0]

    header = SelfHeader(
        magic=data[:4],
        version=version,
        mode=mode,
        header_size=header_size,
        meta_size=meta_size,
        file_size=file_size,
        num_entries=num_entries,
        flags=flags,
    )

    entries: List[SelfSegmentEntry] = []
    for i in range(num_entries):
        off = 0x20 + i * 0x20
        if off + 0x20 > len(data):
            raise ValueError("Truncated segment entry table")
        props, o, fs, ms = struct.unpack_from("<QQQQ", data, off)
        entries.append(SelfSegmentEntry(props, o, fs, ms))

    elf_off = 0x20 + num_entries * 0x20
    if elf_off + 0x40 > len(data):
        raise ValueError("Truncated embedded ELF header")
    if data[elf_off : elf_off + 4] != ELF_MAGIC:
        raise ValueError(f"Invalid embedded ELF magic: {data[elf_off:elf_off+4].hex()}")

    phoff = struct.unpack_from("<Q", data, elf_off + 0x20)[0]
    phnum = struct.unpack_from("<H", data, elf_off + 0x38)[0]

    program_headers: List[ElfProgramHeader] = []
    ph_table_off = elf_off + phoff
    for i in range(phnum):
        entry_off = ph_table_off + i * 56
        if entry_off + 56 > len(data):
            raise ValueError("Truncated ELF program header table")
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
            "<IIQQQQQQ", data, entry_off
        )
        program_headers.append(
            ElfProgramHeader(p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align)
        )

    return header, entries, elf_off, program_headers


def read_self_header_from_stream(
    stream: BinaryIO,
) -> Tuple[SelfHeader, List[SelfSegmentEntry], int, List[ElfProgramHeader]]:
    """Read and parse header information directly from a file stream without loading the full file."""
    h_bytes = stream.read(0x20)
    if len(h_bytes) < 0x20:
        raise ValueError("File too small for SELF header")
    if h_bytes[:4] != SELF_MAGIC:
        raise ValueError(f"Invalid SELF magic: {h_bytes[:4].hex()}")

    version = struct.unpack_from("<I", h_bytes, 0x04)[0]
    mode = struct.unpack_from("<H", h_bytes, 0x08)[0]
    header_size = struct.unpack_from("<H", h_bytes, 0x0A)[0]
    meta_size = struct.unpack_from("<I", h_bytes, 0x0C)[0]
    file_size = struct.unpack_from("<Q", h_bytes, 0x10)[0]
    num_entries = struct.unpack_from("<H", h_bytes, 0x18)[0]
    flags = struct.unpack_from("<H", h_bytes, 0x1A)[0]

    header = SelfHeader(
        magic=h_bytes[:4],
        version=version,
        mode=mode,
        header_size=header_size,
        meta_size=meta_size,
        file_size=file_size,
        num_entries=num_entries,
        flags=flags,
    )

    seg_bytes = stream.read(num_entries * 0x20)
    if len(seg_bytes) < num_entries * 0x20:
        raise ValueError("Truncated segment entry table")

    entries: List[SelfSegmentEntry] = []
    for i in range(num_entries):
        props, o, fs, ms = struct.unpack_from("<QQQQ", seg_bytes, i * 0x20)
        entries.append(SelfSegmentEntry(props, o, fs, ms))

    elf_off = 0x20 + num_entries * 0x20
    elf_hdr = stream.read(0x40)
    if len(elf_hdr) < 0x40 or elf_hdr[:4] != ELF_MAGIC:
        raise ValueError("Invalid or truncated embedded ELF header")

    phoff = struct.unpack_from("<Q", elf_hdr, 0x20)[0]
    phnum = struct.unpack_from("<H", elf_hdr, 0x38)[0]

    # Seek to program header table
    stream.seek(elf_off + phoff)
    ph_bytes = stream.read(phnum * 56)
    if len(ph_bytes) < phnum * 56:
        raise ValueError("Truncated ELF program header table")

    program_headers: List[ElfProgramHeader] = []
    for i in range(phnum):
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
            "<IIQQQQQQ", ph_bytes, i * 56
        )
        program_headers.append(
            ElfProgramHeader(p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align)
        )

    return header, entries, elf_off, program_headers


def rebuild_flat_elf(self_data: bytes) -> bytearray:
    """Rebuild a flat ELF image from a fake-signed (unencrypted) SELF."""
    header, entries, elf_off, ph = parse_self_header(self_data)
    if not ph:
        return bytearray()

    total_size = max(p.p_offset + p.p_filesz for p in ph)
    img = bytearray(total_size)

    # Reconstruct ELF headers at offset 0 if space permits
    if len(self_data) >= elf_off:
        header_copy_size = min(len(img), 0x40 + max(p.p_offset for p in ph) if ph else 0x40)
        available = len(self_data) - elf_off
        to_copy = min(available, header_copy_size)
        if to_copy > 0:
            img[:to_copy] = self_data[elf_off : elf_off + to_copy]

    for ent in entries:
        if ent.is_elf_segment:
            idx = ent.elf_ph_index
            if idx < len(ph):
                dst = ph[idx].p_offset
                img[dst : dst + ent.filesz] = self_data[ent.offset : ent.offset + ent.filesz]

    return img


def vaddr_to_file_offset(va: int, program_headers: List[ElfProgramHeader]) -> Optional[int]:
    """Map a virtual address to a flat ELF file offset using PT_LOAD headers."""
    for p in program_headers:
        if p.p_type == 1 and p.p_vaddr <= va < p.p_vaddr + p.p_memsz:
            return p.p_offset + (va - p.p_vaddr)
    return None


def get_cstring(data: bytes, offset: int) -> str:
    """Read a null-terminated C string from data at offset."""
    if offset >= len(data):
        return ""
    end = data.find(b"\0", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def parse_dynamic_table(
    flat_elf: bytes, program_headers: List[ElfProgramHeader]
) -> Tuple[Dict[int, List[int]], Optional[int]]:
    """Parse PT_DYNAMIC segment and locate DT_STRTAB file offset.

    Returns:
        (tags_dict, strtab_file_offset)
    """
    dyn_ph = [p for p in program_headers if p.p_type == 2]
    if not dyn_ph:
        return {}, None
    dyn = dyn_ph[0]

    tags: Dict[int, List[int]] = {}
    dyn_bytes = flat_elf[dyn.p_offset : dyn.p_offset + dyn.p_filesz]
    num_entries = len(dyn_bytes) // 16
    for i in range(num_entries):
        t, v = struct.unpack_from("<qQ", dyn_bytes, i * 16)
        if t == DT_NULL:
            break
        u_tag = t & 0xFFFFFFFFFFFFFFFF
        tags.setdefault(u_tag, []).append(v)

    strtab_offset = None
    if DT_STRTAB in tags and tags[DT_STRTAB]:
        strtab_va = tags[DT_STRTAB][0]
        strtab_offset = vaddr_to_file_offset(strtab_va, program_headers)

    return tags, strtab_offset


def find_param_blocks(data: bytes) -> List[ParamBlock]:
    """Find valid module param and proc param blocks in a buffer.

    Validation rules:
      - Module param: magic 0x3C13F4BF, size u64 at magic-8 == 0x20
      - Proc param: magic 'ORBI', size u64 at magic-8 == 0x60
      - SDK version uint32 at magic+0xC, valid when (sdk >> 24) is in 1..0x1F.
    """
    blocks: List[ParamBlock] = []

    targets = [
        ("module", MODULE_PARAM_MAGIC, 0x20),
        ("proc", PROC_PARAM_MAGIC, 0x60),
    ]

    for block_type, magic, expected_size in targets:
        pos = data.find(magic)
        while pos != -1:
            if pos >= 8 and pos + 0x10 <= len(data):
                size = struct.unpack_from("<Q", data, pos - 8)[0]
                sdk = struct.unpack_from("<I", data, pos + 0xC)[0]
                major = (sdk >> 24) & 0xFF
                if size == expected_size and 1 <= major <= 0x1F:
                    blocks.append(ParamBlock(block_type=block_type, offset=pos, size=size, sdk_version=sdk))
            pos = data.find(magic, pos + 1)

    return blocks


def parse_self_info(self_data: bytes) -> SelfInfo:
    """Extract metadata, dynamic names, and SDK param blocks from a SELF file."""
    header, entries, elf_off, ph = parse_self_header(self_data)
    flat_elf = rebuild_flat_elf(self_data)

    tags, strtab_off = parse_dynamic_table(flat_elf, ph)

    def lookup_str(idx: int) -> Optional[str]:
        if strtab_off is None:
            return None
        return get_cstring(flat_elf, strtab_off + idx)

    soname = lookup_str(tags[DT_SONAME][0]) if DT_SONAME in tags and tags[DT_SONAME] else None
    orig_fn = (
        lookup_str(tags[DT_SCE_ORIGINAL_FILENAME][0])
        if DT_SCE_ORIGINAL_FILENAME in tags and tags[DT_SCE_ORIGINAL_FILENAME]
        else None
    )

    mod_name = None
    if DT_SCE_MODULE_INFO in tags and tags[DT_SCE_MODULE_INFO]:
        raw_val = tags[DT_SCE_MODULE_INFO][0]
        mod_name = lookup_str(raw_val & 0xFFFFFFFF)

    param_blocks = find_param_blocks(self_data)

    mod_sdk = None
    proc_sdk = None
    for b in param_blocks:
        if b.block_type == "module" and mod_sdk is None:
            mod_sdk = b.sdk_version
        elif b.block_type == "proc" and proc_sdk is None:
            proc_sdk = b.sdk_version

    return SelfInfo(
        file_size=header.file_size,
        num_segments=len(entries),
        num_ph=len(ph),
        soname=soname,
        orig_filename=orig_fn,
        module_name=mod_name,
        module_sdk=mod_sdk,
        proc_sdk=proc_sdk,
        param_blocks=param_blocks,
    )


def patch_sdk_in_memory(
    data: bytearray,
    new_sdk: int,
    target: str = "all",
    old_sdk_filter: Optional[int] = None,
) -> List[Tuple[ParamBlock, int]]:
    """Modify SDK version in param blocks within a bytearray.

    Args:
        data: mutable bytearray of the SELF file.
        new_sdk: 32-bit uint new SDK value.
        target: 'all', 'module', or 'proc'.
        old_sdk_filter: if specified, only blocks with this exact SDK are changed.

    Returns:
        List of (ParamBlock, old_sdk_value) for all modified blocks.
    """
    blocks = find_param_blocks(bytes(data))
    modified: List[Tuple[ParamBlock, int]] = []

    for block in blocks:
        if target != "all" and block.block_type != target:
            continue
        if old_sdk_filter is not None and block.sdk_version != old_sdk_filter:
            continue

        struct.pack_into("<I", data, block.offset + 0xC, new_sdk)
        modified.append((block, block.sdk_version))

    return modified


def decode_sony_id(s: str) -> int:
    """Decode a Sony base64 library/module identifier."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    val = 0
    for c in s:
        idx = alphabet.find(c)
        if idx == -1:
            if c == "-":
                idx = 62
            elif c == "_":
                idx = 63
            else:
                continue
        val = (val << 6) | idx
    return val


def format_sdk(sdk: Optional[int]) -> str:
    """Format an SDK integer as 0xXXXXXXXX (e.g. 0x04030000 -> 4.03)."""
    if sdk is None:
        return "None"
    major = (sdk >> 24) & 0xFF
    minor = (sdk >> 16) & 0xFF
    return f"0x{sdk:08x} ({major}.{minor:02x})"
