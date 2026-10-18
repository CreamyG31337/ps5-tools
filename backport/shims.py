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
