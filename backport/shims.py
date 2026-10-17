"""What to do with a function the target firmware doesn't export, and the byte patches that do it.

Every entry was found while backporting real games to FW 4.03 and is explained where it is
defined. Add new ones here so every tool picks them up. NIDs are the 11-character Sony NIDs.

Patches are applied to a fake-signed SELF in place: its segments are stored uncompressed, so a
spot in the flat ELF is found in the SELF by its unique surrounding bytes (`put`).
"""
import re
import struct

RET0 = bytes.fromhex("31c0c3")  # xor eax,eax; ret
PAD = b"\xcc"                    # int3, PLT stubs are 16 bytes

# Stand-ins that are better than `return 0`.
KNOWN = {
    # scePadIsRemoteController(handle, bool *out): *out = false; return 0
    "fCWdlnmB1Ks": bytes.fromhex("c6060031c0c3"),
    # sceAgcWriteDataPatchSetAddressOrOffset(cmd, addr): store addr in the packet's dwords 2..3
    # (as emulators implement it). Returning 0 without writing faulted the GPU.
    #   test rdi,rdi; je +4; mov [rdi+8],rsi; xor eax,eax; ret
    "fPSCdQxgpSw": bytes.fromhex("4885ff7404" "48897708" "31c0c3"),
}

# Imports renamed to an older NID of the same function that the target does export. Same
# library, and every NID is 11 characters, so the import string is patched in place.
RENAMES = {
    # sceAgc create-interpolant-mapping: emulators treat dbOl as an SDK alias of pdEV7bI6COI.
    "dbOlWdppb4o": "pdEV7bI6COI",
    # newer sceAgcDcbSetIndexSize(dcb, size, cache, perInstanceObjectId): emits a 3-dword
    # index-type packet. Games seen so far pass 0 as the 4th argument, which the older
    # 3-argument GIIW2J37e70 matches. `return 0` here left the frame without its packet.
    "-KRzWekV120": "GIIW2J37e70",
}

# Futex-style waits from libkernel_sync_on_address, a library FW 4.03 doesn't have (used by
# newer libc and Unity's PS5Util). Their callers re-check the condition, so a wait may return
# early. The import is renamed to libkernel's sceKernelUsleep and the PLT stub becomes
# `mov edi,100; jmp [GOT]`: sleep 100 us, return 0. `return 0` alone would spin and can starve
# the thread that ends the wait. The wakes (q2y-wDIVWZA) just return 0.
USLEEP = "1jfXLRVzisc"
SLEEP_WAITS = {"Hc4CaR6JBL0", "B2n8aDorSH4", "PZQhiiLXRFs"}  # Wait, Wait32, Wait64

# Versioned structs: the caller writes the struct's size into it, newer SDKs pass a bigger
# struct, and the older function rejects it. NID -> (size the game passes, size the target
# accepts). The size is the imm32 of a `mov [mem], imm32` shortly before each call.
STRUCT_SIZES = {
    "-sD02mFDBh4": (0x30, 0x28),  # sceUserServiceGetGamePresets
}


def put(sf, orig, elf, off, new):
    """Write `new` into SELF bytes `sf` at the spot of flat-ELF offset `off`. The spot is found
    in `orig` (the unpatched SELF) by the flat ELF's surrounding bytes, so neighbouring
    patches don't disturb each other. Returns False if no unique match exists."""
    for pre in (16, 32, 64):
        ctx = elf[off - pre:off + max(16, len(new))]
        hits = [m.start() + pre for m in re.finditer(re.escape(ctx), orig)]
        if len(hits) == 1:
            sf[hits[0]:hits[0] + len(new)] = new
            return True
    return False


def rename_import(data, nid, new_nid, new_lib=None):
    """Rename the import string "NID#L#M" in a SELF's string table, optionally also its
    library letter L. Changes it only if it occurs exactly once; returns the match count."""
    assert len(new_nid) == len(nid) == 11
    hits = [m.start() for m in re.finditer(re.escape(b"\x00" + nid.encode() + b"#"), data)]
    if len(hits) == 1:
        o = hits[0] + 1
        data[o:o + 11] = new_nid.encode()
        if new_lib:
            data[o + 12:o + 13] = new_lib.encode()
    return len(hits)


def sleep_stub(stub):
    """16-byte PLT stub `mov edi,100; jmp [GOT]` from the original `jmp [rip+X]` stub."""
    disp = struct.unpack_from("<i", stub, 2)[0] - 5  # the jmp moves 5 bytes later
    return (bytes.fromhex("bf64000000ff25") + struct.pack("<i", disp)).ljust(16, PAD)


def find_size_store(code, size):
    """Offset in `code` (the bytes just before a call) of the imm32 `size` stored by the last
    `mov [mem], imm32` (opcode C7, 3..8 bytes before the imm32), or None."""
    imm = struct.pack("<I", size)
    hits = [m.start() for m in re.finditer(re.escape(imm), code)
            if b"\xc7" in code[max(0, m.start() - 8):m.start() - 2]]
    return hits[-1] if hits else None
