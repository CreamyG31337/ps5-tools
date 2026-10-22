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
    # sceAgc create-interpolant-mapping. Emulators treat dbOl as an SDK alias of pdEV7bI6COI, but a
    # newer libSceAgc exports both as different functions. The rename was fine for an SDK 10 Unity
    # game; an SDK 17 Unity (URP 2D) game rendered its scene magenta with it. Better: put a newer
    # libSceAgc + libSceAgcDriver in the game's fakelib/ and pass --provided-lib for both.
    "dbOlWdppb4o": "pdEV7bI6COI",
    # newer sceAgcDcbSetIndexSize(dcb, size, cache, perInstanceObjectId): emits a 3-dword
    # index-type packet. Games seen so far pass 0 as the 4th argument, which the older
    # 3-argument GIIW2J37e70 matches. `return 0` here left the frame without its packet.
    "-KRzWekV120": "GIIW2J37e70",
    # sceKernelMapNamedFlexibleMemoryInternal(&addr, len, prot, flags, name), used by newer libc's
    # heap. Same arguments as sceKernelMapNamedFlexibleMemory; an SDK 5 libc calls that one at the
    # same spots with flags = 0 (ARG_FIXUPS clears the newer 0x8000). `return 0` left addr NULL.
    "4h6F1LLbTiw": "mL8NDH86iQI",
}

# libkernel_sync_on_address, a library FW 4.03 doesn't have (used by newer libc and Unity's
# PS5Util), is a futex: Wait(addr, expected, uint32 *timeout_us, flags) sleeps while
# *addr == expected; Wake(addr, count) wakes sleepers. FreeBSD's _umtx_op, which libkernel
# exports, does the same. Each import is renamed to _umtx_op and its PLT stub reorders the
# arguments before jumping to it:  _umtx_op(addr, op, value, NULL, uaddr2 = &timespec)
# A timeout can't be converted inside a 16-byte stub (it needs a timespec), so the stubs jump
# to one shared trampoline that backport.py appends to the module's exec segment (umtx_cave):
# every wait, timed or not, sleeps in the kernel until the value changes, a Wake arrives, or
# ~1 second passes — callers that loop on their own deadline then simply re-wait. The older
# paired-stub fallback (umtx_stubs) is kept for modules whose segment can't be grown: an
# untimed wait blocks in the kernel, a timed wait returns 0 at once and its caller polls.
# Checked against the console's own 4.03 libkernel (functions 0x3360/0x33a0/0x33d0 jumping to
# syscall 0x1c6 at 0x380): UMTX_OP_WAIT (2), UMTX_OP_WAIT_UINT (11) and UMTX_OP_WAIT_UINT_PRIVATE
# (15) all pass the timespec pointer in uaddr2 (r8) and set uaddr1 (rcx) = 0.
# History, so nobody repeats it: a 100 us sleep for every wait kept ~50 idle Unity threads
# waking 10,000 times a second, which starved the system UI. Dropping the timeout instead left
# the main thread (frame pacing uses a timed wait nobody wakes) stuck on the splash screen.
UMTX_OP = "04AjkP0jO9U"
UMTX_WAIT, UMTX_WAKE, UMTX_WAIT_UINT = 2, 3, 11
UMTX_SHIMS = {
    "Hc4CaR6JBL0": UMTX_WAIT,       # sceKernelSyncOnAddressWait (64-bit compare)
    "PZQhiiLXRFs": UMTX_WAIT,       # sceKernelSyncOnAddressWait64
    "B2n8aDorSH4": UMTX_WAIT_UINT,  # sceKernelSyncOnAddressWait32
    "q2y-wDIVWZA": UMTX_WAKE,       # sceKernelSyncOnAddressWake(addr, count)
}

# Versioned structs: the caller writes the struct's size into it, newer SDKs pass a bigger
# struct, and the older function rejects it. NID -> (size the game passes, size the target
# accepts). The size is the imm32 of a `mov [mem], imm32` shortly before each call.
STRUCT_SIZES = {
    "-sD02mFDBh4": (0x30, 0x28),  # sceUserServiceGetGamePresets
}


# Imports the target does export but whose older version rejects an argument newer SDKs pass.
# NID -> instructions run in the import's PLT stub before it jumps on (at most 10 bytes).
ARG_FIXUPS = {
    # sceSaveDataMount3(param, result): newer SDKs (Unity's savedata plugin, SDK 10) pass
    # systemBlocks (param+0x18) = -1. The 4.03 client wrapper requires 0 whenever a create bit
    # is set (`cmpq $0,0x18(%rbx); jne` at 0x73e1 in libSceSaveData) and fails with
    # 0x809F0000 before the save service is reached; without create bits it is never checked.
    #   mov qword [rdi+0x18], 0
    "ZP4e7rlzOUk": bytes.fromhex("48c7471800000000"),
    # renamed sceKernelMapNamedFlexibleMemoryInternal (see RENAMES): flags = 0
    #   xor ecx, ecx
    "4h6F1LLbTiw": bytes.fromhex("31c9"),
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


def prefixed_stub(stub, pre):
    """16-byte PLT stub that runs `pre`, then jumps through the stub's own GOT slot. `stub` is
    the original stub, starting with `jmp [rip+X]`; None if it doesn't."""
    if stub[:2] != b"\xff\x25" or len(pre) > 10:
        return None
    disp = struct.unpack_from("<i", stub, 2)[0] - len(pre)  # the jmp ends len(pre) bytes later
    return (pre + b"\xff\x25" + struct.pack("<i", disp)).ljust(16, PAD)


def umtx_stub(stub, op):
    """16-byte PLT stub that calls _umtx_op(rdi, op, rsi, rcx, NULL) through the stub's own GOT
    slot. `stub` is the original stub, starting with `jmp [rip+X]`."""
    if op == UMTX_WAKE:
        pre = bytes.fromhex("89f2")      # mov edx, esi       (count)
    else:
        pre = bytes.fromhex("4889f2")    # mov rdx, rsi       (expected value)
    pre += bytes([0x6A, op, 0x5E])       # push op; pop rsi
    pre += bytes.fromhex("4531c0")       # xor r8d, r8d       (no timeout)
    return prefixed_stub(stub, pre)


def umtx_stubs(stubs):
    """Stand-ins for a module's sync-on-address imports when it imports Wake too.
    `stubs` maps PLT vaddr -> (umtx op, original 16-byte stub). Returns vaddr -> new stub, or
    None if no Wake stub is within short-jump range of every wait stub.

    Wake (hosts the shared tail):       Wait (one per wait import):
       0 mov edx, esi                      0 test rdx, rdx        ; timeout pointer given?
       2 push 3; pop rsi                   3 jnz 13
       5 xor r8d, r8d     <- tail          5 mov rdx, rsi
       8 jmp [GOT]                         8 push op; pop rsi
                                          11 jmp short tail
                                          13 xor eax, eax; ret   ; timed: return at once
    """
    wakes = [va for va, (op, _) in stubs.items() if op == UMTX_WAKE]
    if not wakes:
        return None
    wake = wakes[0]
    tail = wake + 5
    out = {}
    for va, (op, old) in stubs.items():
        if op == UMTX_WAKE:
            disp = struct.unpack_from("<i", old, 2)[0] - 8
            out[va] = (bytes.fromhex("89f2" "6a035e" "4531c0" "ff25") + struct.pack("<i", disp)).ljust(16, PAD)
            continue
        rel = tail - (va + 13)
        if not -128 <= rel <= 127:
            return None
        out[va] = bytes.fromhex("4885d2" "7508" "4889f2") + bytes([0x6A, op, 0x5E, 0xEB, rel & 0xFF]) \
            + bytes.fromhex("31c0c3")
    return out


def umtx_cave(stubs, cave_va):
    """Real timed waits for a module's sync-on-address imports: one shared trampoline
    (hosted at `cave_va`; backport.grow_exec_segment puts it there) plus one PLT stub each.

    Each wait stub becomes `mov eax, op; jmp cave`; wake keeps its umtx_stub. The trampoline
    turns Wait(addr, expected, uint32 *timeout_us, flags) into
    _umtx_op(rdi=addr, rsi=op, rdx=expected, rcx=NULL, r8=&timespec) with the timespec built
    on the stack, every slice capped at 999999 us: a wait with a NULL timeout, or one longer than a
    second, becomes a once-a-second recheck instead of a hot poll or a sleep nobody can
    interrupt. A Wake (or the value changing) still returns the wait immediately.

    `stubs` maps PLT vaddr -> (umtx op, original 16-byte stub); the _umtx_op GOT slot is read
    from the first wait stub, whose import is renamed to _umtx_op anyway. Returns
    ({vaddr: new 16-byte stub}, trampoline bytes), or None if there is no wait import.
    """
    waits = [va for va, (op, _) in stubs.items() if op != UMTX_WAKE]
    wakes = [va for va, (op, _) in stubs.items() if op == UMTX_WAKE]
    if not waits:
        return None
    # the trampoline and the wake stub share one _umtx_op GOT slot: the wake stub's when
    # there is one.
    anchor = wakes[0] if wakes else waits[-1]
    if stubs[anchor][1][:2] != b"\xff\x25":  # need a plain jmp [GOT] stub
        return None
    got = anchor + 6 + struct.unpack_from("<i", stubs[anchor][1], 2)[0]
    head = bytes.fromhex(
        "4885d2"          # test rdx, rdx          ; no timeout pointer?
        "7507"            # jne .timed
        "b93f420f00"      #   mov ecx, 999999      ; -> once-a-second recheck slice
        "eb0f"            #   jmp .body
        "8b0a"            # .timed: mov ecx, [rdx] ; microseconds
        "81f93f420f00"    # cmp ecx, 999999
        "7605"            # jbe .body
        "b93f420f00"      #   mov ecx, 999999      ; cap the slice at ~1 s
    )
    body = bytearray(bytes.fromhex(
        "69c9e8030000"    # .body: imul ecx, ecx, 1000    ; nanoseconds
        "52"              # push rdx                      ; pad: five pushes -> rsp%16==0 at call
        "50"              # push rax                      ; op
        "56"              # push rsi                      ; expected value
        "51"              # push rcx                      ; timespec.tv_nsec
        "6a00"            # push 0                        ; timespec.tv_sec
        "4989e0"          # mov r8, rsp                   ; uaddr2 = &timespec
        "31c9"            # xor ecx, ecx                  ; uaddr1 = NULL
        "488b542410"      # mov rdx, [rsp+0x10]           ; val = expected
        "488b742418"      # mov rsi, [rsp+0x18]           ; op
        "ff1500000000"    # call [rip+X]                  ; _umtx_op through the stub's GOT slot
        "4883c428"        # add rsp, 0x28                 ; unwind the five pushes before ret
        "c3"              # ret
    ))
    struct.pack_into("<i", body, 29, got - (cave_va + len(head) + 33))
    cave = head + bytes(body)
    out = {}
    for va, (op, old) in stubs.items():
        if op == UMTX_WAKE:
            out[va] = umtx_stub(old, UMTX_WAKE)
        else:
            out[va] = (b"\xb8" + struct.pack("<I", op) + b"\xe9" +
                       struct.pack("<i", cave_va - (va + 10))).ljust(16, PAD)
    return out, cave


def find_size_store(code, size):
    """Offset in `code` (the bytes just before a call) of the imm32 `size` stored by the last
    `mov [mem], imm32` (opcode C7, 2..8 bytes before the imm32: `c7 06 imm` for [rsi] up to
    `c7 84 24 disp32 imm` for [rsp+disp32]), or None."""
    imm = struct.pack("<I", size)
    hits = [m.start() for m in re.finditer(re.escape(imm), code)
            if b"\xc7" in code[max(0, m.start() - 8):m.start() - 1]]
    return hits[-1] if hits else None


# SDK 11+ engines can fill the {offset, value} tables of indirect register loads (PM4
# LOAD_SH_REG_INDEX 0x63, LOAD_CONTEXT_REG_INDEX 0x64, and 0x9F) with a {0xFFFFFFFF, 0xFFFFFFFF}
# "no register" placeholder. Newer CP firmware skips it. FW 4.03's writes it, to SH register
# 0x2C00 + 0xFFFFFFFF, and the game dies with
#   GPU Bad packet error:Privilege reg. vmid: game process, opcode:0xc00..... 0 0 0x2bff
#   exception: 0xa0d0c006 (GPU_FAULT_BAD_COMMAND_ASYNC)
# (the opcode named is just the last packet the CP parsed, and varies). Found on Crimson Desert
# (SDK 11.00, BlackSpace engine), whose tables are written by inlined engine code, so the fix
# goes at the choke point: with --pm4-sanitize, every direct call to these submit functions
# goes through pm4_sanitizer's code first, which removes the placeholders from the command
# buffer the descriptor names. Both functions take rdi = descriptor {u64 buffer, u32 dwords}.
PM4_SUBMITS = {
    "UglJIZjGssM": "sceAgcDriverSubmitDcb",
    "AhGvpITrf4M": "sceAgcDriverAgrSubmitDcb",
}


def _asm(prog, base, ext):
    """Two-pass assembler for pm4_sanitizer. Items are raw bytes, ("L", label), or
    (opcode hex, label): "E8"/"E9" call/jmp rel32, or a short jcc/jmp that grows to rel32 when
    the target is out of range. Returns (bytes, {label: vaddr})."""
    long = set()

    def size(k, it):
        if it[0] in ("E8", "E9"):
            return 5
        if k in long:
            return 5 if it[0] == "EB" else 6
        return 2
    while True:
        labels, pc = dict(ext), base
        for k, it in enumerate(prog):
            if isinstance(it, bytes):
                pc += len(it)
            elif it[0] == "L":
                labels[it[1]] = pc
            else:
                pc += size(k, it)
        out, grew = bytearray(), False
        for k, it in enumerate(prog):
            if isinstance(it, bytes):
                out += it
                continue
            if it[0] == "L":
                continue
            n = size(k, it)
            rel = labels[it[1]] - (base + len(out) + n)
            if it[0] in ("E8", "E9"):
                out += bytes.fromhex(it[0]) + struct.pack("<i", rel)
            elif n == 2 and -128 <= rel <= 127:
                out += bytes.fromhex(it[0]) + struct.pack("<b", rel)
            elif n == 2:
                long.add(k)
                grew = True
                out += bytes(2)
            elif it[0] == "EB":
                out += b"\xe9" + struct.pack("<i", rel)
            else:
                out += bytes([0x0F, int(it[0], 16) + 0x10]) + struct.pack("<i", rel)
        if not grew:
            return bytes(out), labels


def pm4_sanitizer(plts, cave_va):
    """Code for `cave_va` that drops the {-1,-1} register-table placeholders (see PM4_SUBMITS)
    before a command buffer is submitted. `plts` are the submit functions' PLT vaddrs; each
    gets a thunk that saves the argument registers, runs the sanitizer on the descriptor in
    rdi, restores them and jumps to the PLT stub. Point the game's calls at the thunks.

    The sanitizer walks the buffer's PM4 packets and follows chained 0x3F jumps (the CHAIN
    bit, up to 8 segments). For every 0x63/0x64/0x9F packet in table form ([3] == 0x80000000)
    it compacts the table in place, dropping entries whose offset is 0xFFFFFFFF, and lowers
    the pair count. A table left empty gets count 0 and address 0, a shape games already
    submit and 4.03 runs. A clean table is not written. The walk stops at a type-0/1 dword
    or an overrun. Returns ({plt vaddr: thunk vaddr}, code bytes)."""
    prog = []
    for k, _ in enumerate(plts):
        prog += [("L", f"t{k}"),
                 b"\x57\x56\x52\x51\x41\x50\x41\x51",       # push rdi, rsi, rdx, rcx, r8, r9
                 ("E8", "san"),
                 b"\x41\x59\x41\x58\x59\x5a\x5e\x5f",       # pop r9, r8, rcx, rdx, rsi, rdi
                 ("E9", f"plt{k}")]
    prog += [
        ("L", "san"),
        b"\x48\x8b\x37",                    # mov rsi, [rdi]        ; segment
        b"\x8b\x4f\x08",                    # mov ecx, [rdi+8]      ; dwords
        b"\x41\xbb\x08\x00\x00\x00",        # mov r11d, 8           ; max segments
        ("L", "seg"),
        b"\x48\x85\xf6", ("74", "done"),    # test rsi, rsi ; jz
        b"\x85\xc9", ("74", "done"),        # test ecx, ecx ; jz
        b"\x4c\x8d\x14\x8e",                # lea r10, [rsi+rcx*4]  ; segment end
        ("L", "pkt"),
        b"\x4c\x39\xd6", ("73", "done"),    # cmp rsi, r10 ; jae
        b"\x8b\x06",                        # mov eax, [rsi]
        b"\x89\xc2", b"\xc1\xea\x1e",       # mov edx, eax ; shr edx, 30
        b"\x83\xfa\x03", ("74", "t3"),      # cmp edx, 3 ; je
        b"\x83\xfa\x02", ("75", "done"),    # cmp edx, 2 ; jne      ; type 0/1: stop
        b"\x48\x83\xc6\x04", ("EB", "pkt"),  # add rsi, 4 ; jmp      ; type-2 filler
        ("L", "t3"),
        b"\x89\xc2", b"\xc1\xea\x10",       # mov edx, eax ; shr edx, 16
        b"\x81\xe2\xff\x3f\x00\x00",        # and edx, 0x3fff
        b"\x83\xc2\x02",                    # add edx, 2
        b"\x4c\x8d\x04\x96",                # lea r8, [rsi+rdx*4]   ; next packet
        b"\x4d\x39\xd0", ("77", "done"),    # cmp r8, r10 ; ja
        b"\x3d\x00\x63\x03\xc0", ("74", "reg"),
        b"\x3d\x00\x64\x03\xc0", ("74", "reg"),
        b"\x3d\x00\x9f\x03\xc0", ("74", "reg"),
        b"\x3d\x00\x3f\x02\xc0", ("74", "jmp"),
        ("L", "next"),
        b"\x4c\x89\xc6", ("EB", "pkt"),     # mov rsi, r8 ; jmp
        ("L", "reg"),
        b"\x81\x7e\x0c\x00\x00\x00\x80", ("75", "next"),  # cmp dword [rsi+12], 0x80000000
        b"\x4c\x8b\x4e\x04",                # mov r9, [rsi+4]       ; table
        b"\x4d\x85\xc9", ("74", "next"),    # test r9, r9
        b"\x8b\x4e\x10",                    # mov ecx, [rsi+16]     ; pairs
        b"\x31\xc0", b"\x31\xd2",           # xor eax, eax (src) ; xor edx, edx (dst)
        ("L", "cl"),
        b"\x39\xc8", ("73", "cdone"),       # cmp eax, ecx ; jae
        b"\x41\x83\x3c\xc1\xff", ("74", "skip"),   # cmp dword [r9+rax*8], -1 ; je
        b"\x39\xd0", ("74", "keep"),        # cmp eax, edx ; je
        b"\x49\x8b\x3c\xc1",                # mov rdi, [r9+rax*8]
        b"\x49\x89\x3c\xd1",                # mov [r9+rdx*8], rdi
        ("L", "keep"), b"\xff\xc2",         # inc edx
        ("L", "skip"), b"\xff\xc0", ("EB", "cl"),  # inc eax ; jmp
        ("L", "cdone"),
        b"\x39\xca", ("74", "next"),        # cmp edx, ecx ; je     ; nothing dropped
        b"\x89\x56\x10",                    # mov [rsi+16], edx
        b"\x85\xd2", ("75", "next"),        # test edx, edx ; jnz
        b"\x48\xc7\x46\x04\x00\x00\x00\x00",  # mov qword [rsi+4], 0 ; empty table: address 0
        ("EB", "next"),
        ("L", "jmp"),
        b"\xf7\x46\x0c\x00\x00\x10\x00", ("74", "next"),  # test dword [rsi+12], CHAIN ; jz
        b"\x48\x8b\x46\x04",                # mov rax, [rsi+4]      ; target
        b"\x8b\x4e\x0c",                    # mov ecx, [rsi+12]
        b"\x81\xe1\xff\xff\x0f\x00",        # and ecx, 0xfffff      ; dwords
        b"\x48\x89\xc6",                    # mov rsi, rax
        b"\x41\xff\xcb", ("75", "seg"),     # dec r11d ; jnz
        ("L", "done"), b"\xc3",
    ]
    code, labels = _asm(prog, cave_va, {f"plt{k}": va for k, va in enumerate(plts)})
    return {va: labels[f"t{k}"] for k, va in enumerate(plts)}, code
