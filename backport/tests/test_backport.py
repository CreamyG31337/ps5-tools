"""Tests for the backport tools, on a synthetic fake-signed SELF built in memory.

No Sony or game data: the module below is assembled byte by byte. It imports
  -sD02mFDBh4 (sceUserServiceGetGamePresets, exported, called with a struct size of 0x30),
  zzzzzzzzzzz from libFoo (missing on the "target", called -> return 0),
  Hc4CaR6JBL0 (sceKernelSyncOnAddressWait, missing, called -> _umtx_op wait),
  yyyyyyyyyyy from libFoo (missing, never called: no PLT stub),
and has a proc param with SDK 0x10000040.
"""
import os
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
sys.path.insert(0, TOOL)
sys.path.insert(0, os.path.join(TOOL, "..", "self-tools"))
import backport  # noqa: E402
import selflib  # noqa: E402
import shims  # noqa: E402
from elfinfo import Elf  # noqa: E402

TEXT_OFF, TEXT_VA, TEXT_SZ = 0x1000, 0x0, 0x100
DATA_OFF, DATA_VA, DATA_SZ = 0x2000, 0x1000, 0x200
DYNS_OFF, DYNS_VA, DYNS_SZ = 0x3000, 0x2000, 0x400
PLT = {"presets": 0x80, "missing": 0x90, "wait": 0xA0}
GOT = {"presets": 0x1100, "missing": 0x1108, "wait": 0x1110}


def build_module():
    """-> (flat ELF bytes, SELF bytes)"""
    # strings
    strtab = bytearray(b"\x00")

    def add(s):
        o = len(strtab)
        strtab.extend(s.encode() + b"\x00")
        return o

    s_mod = {n: add(n) for n in ("libkernel", "libSceUserService", "libFoo")}
    s_foo_file = add("libFoo.sprx")
    s_sync = add("libkernel_sync_on_address")
    s_self = add("sample")
    syms = ["-sD02mFDBh4#B#B", "zzzzzzzzzzz#C#C", "Hc4CaR6JBL0#D#A", "yyyyyyyyyyy#C#C"]
    s_sym = [add(s) for s in syms]

    # symtab (index 0 is the null symbol), jmprel for the three called imports
    symtab = bytes(24) + b"".join(struct.pack("<IBBHQQ", o, 0x12, 0, 0, 0, 0) for o in s_sym)
    jmprel = b"".join(struct.pack("<QQq", GOT[k], ((i + 1) << 32) | 7, 0)
                      for i, k in enumerate(("presets", "missing", "wait")))
    dyns = bytearray(DYNS_SZ)
    dyns[0:len(strtab)] = strtab
    sym_at, rel_at = 0x100, 0x200
    dyns[sym_at:sym_at + len(symtab)] = symtab
    dyns[rel_at:rel_at + len(jmprel)] = jmprel

    tags = [(5, DYNS_VA), (10, len(strtab)), (6, DYNS_VA + sym_at), (0x6100003F, len(symtab)),
            (0x17, DYNS_VA + rel_at), (2, len(jmprel)), (0x61000043, s_self)]
    for i, n in enumerate(("libkernel", "libSceUserService", "libFoo")):
        if n == "libFoo":
            tags.append((1, s_foo_file))
        tags.append((0x61000045, (i << 48) | s_mod[n]))
        tags.append((0x61000049, (i << 48) | s_mod[n]))
    tags.append((0x61000049, (3 << 48) | s_sync))
    tags.append((0, 0))
    dyn = b"".join(struct.pack("<QQ", t, v) for t, v in tags)
    dyn_at = 0x300
    dyns[dyn_at:dyn_at + len(dyn)] = dyn

    # code: mov dword [rsp+8], 0x30; call presets; call missing; call wait; ret
    text = bytearray(b"\x90" * TEXT_SZ)
    code = bytes.fromhex("c744240830000000")
    for k in ("presets", "missing", "wait"):
        here = len(code) + 0x10
        code += b"\xe8" + struct.pack("<i", PLT[k] - (here + 5))
    code += b"\xc3"
    text[0x10:0x10 + len(code)] = code
    for k, va in PLT.items():  # jmp [rip+X]; push idx; jmp ... (here just padding)
        text[va:va + 6] = b"\xff\x25" + struct.pack("<i", GOT[k] - (va + 6))
        text[va + 6:va + 16] = b"\x68" + bytes([ord(k[0])]) + b"\x00\x00\x00\xe9\x00\x00\x00\x00"

    data = bytearray(DATA_SZ)
    data[0x10:0x10 + 0x60] = struct.pack("<Q4sIII", 0x60, b"ORBI", 5, 0x12090001, 0x10000040).ljust(0x60, b"\x00")

    phs = [(1, 5, TEXT_OFF, TEXT_VA, TEXT_SZ, 0x1000), (1, 6, DATA_OFF, DATA_VA, DATA_SZ, 0x10),
           (1, 0, DYNS_OFF, DYNS_VA, DYNS_SZ, 0x10),
           (2, 6, DYNS_OFF + dyn_at, DYNS_VA + dyn_at, len(dyn), 0x10)]
    ehdr = bytearray(64)
    ehdr[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", ehdr, 0x10, 0xFE18, 0x3E, 1, 0, 64, 0, 0, 64, 56, len(phs), 0, 0, 0)
    phdr = b"".join(struct.pack("<IIQQQQQQ", t, f, o, v, v, s, s, al) for t, f, o, v, s, al in phs)
    flat = bytearray(DYNS_OFF + DYNS_SZ)
    flat[0:64] = ehdr
    flat[64:64 + len(phdr)] = phdr
    flat[TEXT_OFF:TEXT_OFF + TEXT_SZ] = text
    flat[DATA_OFF:DATA_OFF + DATA_SZ] = data
    flat[DYNS_OFF:DYNS_OFF + DYNS_SZ] = dyns

    # SELF: header, one entry per PT_LOAD, then ELF header + phdrs, then segment data
    loads = [(i, p) for i, p in enumerate(phs) if p[0] == 1]
    n = len(loads)
    ehdr_at = 0x20 + 0x20 * n
    body = 0x400
    raw = bytearray(body + sum(p[4] for _, p in loads))
    raw[0:0x20] = struct.pack("<4sIHHIQHH4s", selflib.SELF_MAGIC, 1, 1, 0x20, 0x40, len(raw), n, 2, bytes(4))
    at = body
    for k, (i, p) in enumerate(loads):
        struct.pack_into("<QQQQ", raw, 0x20 + 0x20 * k, 0x800 | (i << 20), at, p[4], p[4])
        raw[at:at + p[4]] = flat[p[2]:p[2] + p[4]]
        at += p[4]
    raw[ehdr_at:ehdr_at + 64] = ehdr
    raw[ehdr_at + 64:ehdr_at + 64 + len(phdr)] = phdr
    return bytes(flat), bytes(raw)


def wr(path, data):
    with open(path, "wb") as f:
        f.write(data)


def write_exports(path):
    rows = [("libSceUserService.sprx", "libSceUserService", "libSceUserService", "-sD02mFDBh4", ""),
            ("libkernel.sprx", "libkernel", "libkernel", shims.UMTX_OP, "_umtx_op"),
            ("libFoo.sprx", "libFoo", "libFoo", "xxxxxxxxxxx", "")]
    with open(path, "w", encoding="utf-8") as f:
        f.write("module_file\tmodule\tlibrary\tnid\tname\n")
        for r in rows:
            f.write("\t".join(r) + "\n")


class TestElfInfo(unittest.TestCase):
    def setUp(self):
        self.flat, self.self_ = build_module()
        self.e = Elf(self.flat)

    def test_selflib_rebuild_matches(self):
        self.assertEqual(bytes(selflib.rebuild_flat_elf(self.self_))[TEXT_OFF:], self.flat[TEXT_OFF:])

    def test_imports_and_libs(self):
        self.assertIn(("Hc4CaR6JBL0", "libkernel"), self.e.imports())
        self.assertIn(("zzzzzzzzzzz", "libFoo"), self.e.imports())
        self.assertEqual(self.e.import_libs()["libkernel"], "A")
        self.assertEqual(self.e.import_libs()["libkernel_sync_on_address"], "D")

    def test_plt_and_calls(self):
        plt = self.e.plt()
        self.assertEqual({v: s[:11] for v, s in plt.items()},
                         {0x80: "-sD02mFDBh4", 0x90: "zzzzzzzzzzz", 0xA0: "Hc4CaR6JBL0"})
        self.assertEqual(sorted(t for _, t in self.e.calls(set(plt))), [0x80, 0x90, 0xA0])


class TestShims(unittest.TestCase):
    def test_rename_import(self):
        d = bytearray(b"\x00abcdefghijk#A#B\x00other")
        self.assertEqual(shims.rename_import(d, "abcdefghijk", "ABCDEFGHIJK", "C"), 1)
        self.assertEqual(bytes(d), b"\x00ABCDEFGHIJK#C#B\x00other")
        dup = bytearray(b"\x00abcdefghijk#A#B\x00abcdefghijk#A#C\x00")
        self.assertEqual(shims.rename_import(dup, "abcdefghijk", "ABCDEFGHIJK"), 2)
        self.assertNotIn(b"ABCDEFGHIJK", dup)  # ambiguous: left alone

    def test_umtx_stub(self):
        stub = b"\xff\x25" + struct.pack("<i", 0x1000)
        for op, pre in ((shims.UMTX_WAIT, "4889f2 6a025e 4531c0"), (shims.UMTX_WAKE, "89f2 6a035e 4531c0")):
            new = shims.umtx_stub(stub, op)
            pre = bytes.fromhex(pre.replace(" ", ""))
            self.assertEqual(len(new), 16)
            self.assertEqual(new[:len(pre)], pre)
            self.assertEqual(new[len(pre):len(pre) + 2], b"\xff\x25")
            # the jmp ends len(pre) bytes later and must still reach the same GOT slot
            disp = struct.unpack_from("<i", new, len(pre) + 2)[0]
            self.assertEqual(len(pre) + 6 + disp, 6 + 0x1000)

    def test_umtx_stubs_paired(self):
        old = lambda got_disp: (b"\xff\x25" + struct.pack("<i", got_disp)).ljust(16, b"\x90")
        out = shims.umtx_stubs({0x100: (shims.UMTX_WAIT, old(0x2000)), 0x110: (shims.UMTX_WAKE, old(0x1ff8))})
        wait, wake = out[0x100], out[0x110]
        self.assertEqual((len(wait), len(wake)), (16, 16))
        self.assertEqual(wait[:5], bytes.fromhex("4885d27508"))        # test rdx,rdx; jnz +8
        self.assertEqual(wait[13:16], shims.RET0)                       # timed: return 0
        self.assertEqual(0x100 + 13 + struct.unpack_from("<b", wait, 12)[0], 0x110 + 5)  # jmp to tail
        self.assertEqual(wake[5:10], bytes.fromhex("4531c0ff25"))       # tail: xor r8d; jmp [GOT]
        self.assertEqual(8 + 6 + struct.unpack_from("<i", wake, 10)[0], 6 + 0x1ff8)  # same GOT slot
        self.assertIsNone(shims.umtx_stubs({0x100: (shims.UMTX_WAIT, old(0))}))  # no wake to share

    def test_umtx_cave(self):
        old = lambda got_disp: (b"\xff\x25" + struct.pack("<i", got_disp)).ljust(16, b"\x90")
        built = shims.umtx_cave({0x100: (shims.UMTX_WAIT, old(0x2000)),
                                 0x110: (shims.UMTX_WAIT_UINT, old(0x1ff8)),
                                 0x120: (shims.UMTX_WAKE, old(0x1ff0))}, 0x800)
        out, cave = built
        wait, wuint, wake = out[0x100], out[0x110], out[0x120]
        self.assertEqual(wait[:5], b"\xb8" + struct.pack("<I", shims.UMTX_WAIT))     # mov eax, op
        self.assertEqual(wuint[:5], b"\xb8" + struct.pack("<I", shims.UMTX_WAIT_UINT))
        for va, stub in ((0x100, wait), (0x110, wuint)):                # jmp cave, 5 bytes in
            self.assertEqual(va + 10 + struct.unpack_from("<i", stub, 6)[0], 0x800)
        self.assertEqual(wake, shims.umtx_stub(old(0x1ff0), shims.UMTX_WAKE))
        # the trampoline: test rdx,rdx; jne/jmp/jbe land on instruction boundaries, the call
        # goes through the first wait stub's GOT slot, and the epilogue unwinds 5 pushes
        self.assertEqual(cave[:3], bytes.fromhex("4885d2"))
        self.assertEqual(cave[3:5], b"\x75\x07")
        self.assertEqual(cave[10:12], b"\xeb\x0f")
        self.assertEqual(cave[20:22], b"\x76\x05")
        self.assertEqual(len(cave), 65)
        got = 0x120 + 6 + 0x1ff0  # the wake stub's GOT slot: duplicate-name JMP_SLOTs
        self.assertEqual(cave[56:60], struct.pack("<i", got - (0x800 + 60)))
        self.assertEqual(cave[60:65], b"\x48\x83\xc4\x28\xc3")
        self.assertIsNone(shims.umtx_cave({0x120: (shims.UMTX_WAKE, old(0x1ff0))}, 0x800))

    def test_prefixed_stub(self):
        stub = b"\xff\x25" + struct.pack("<i", 0x1000)
        pre = shims.ARG_FIXUPS["ZP4e7rlzOUk"]
        new = shims.prefixed_stub(stub, pre)
        self.assertEqual(len(new), 16)
        self.assertEqual(new[:len(pre)], pre)
        self.assertEqual(len(pre) + 6 + struct.unpack_from("<i", new, len(pre) + 2)[0], 6 + 0x1000)
        self.assertIsNone(shims.prefixed_stub(b"\xe9" + bytes(5), pre))   # not jmp [GOT]
        self.assertIsNone(shims.prefixed_stub(stub, bytes(11)))           # no room for the jmp

    def test_find_size_store(self):
        code = bytes.fromhex("90" * 10 + "48c745b030000000" + "488d75b0")
        self.assertEqual(shims.find_size_store(code, 0x30), 14)
        # mov qword [rsi], 0x30: the opcode sits right before the ModRM byte and the imm32
        self.assertEqual(shims.find_size_store(bytes.fromhex("48c70630000000"), 0x30), 3)
        self.assertIsNone(shims.find_size_store(bytes.fromhex("b830000000"), 0x30))  # mov eax, not a store


class TestPatchModule(unittest.TestCase):
    def test_patch(self):
        flat, raw = build_module()
        with tempfile.TemporaryDirectory() as tmp:
            ex = os.path.join(tmp, "exports.tsv")
            write_exports(ex)
            data = bytearray(raw)
            log, missing = backport.patch_module(data, backport.load_exports(ex), set(), 0x04000031, None)
        self.assertEqual(missing, {"zzzzzzzzzzz", "Hc4CaR6JBL0", "yyyyyyyyyyy"})
        out = bytes(selflib.rebuild_flat_elf(bytes(data)))
        e = Elf(out)
        t = TEXT_OFF
        self.assertEqual(out[t + 0x90:t + 0x93], shims.RET0)                       # missing -> return 0
        # wait -> mov eax, UMTX_WAIT; jmp the trampoline grown onto the segment's end
        self.assertEqual(out[t + 0xA0:t + 0xA5], b"\xb8" + struct.pack("<I", shims.UMTX_WAIT))
        cave_va = TEXT_VA + TEXT_SZ
        self.assertEqual(0xA0 + 10 + struct.unpack_from("<i", out, t + 0xA6)[0], cave_va)
        self.assertEqual(out[t + TEXT_SZ:t + TEXT_SZ + 3], bytes.fromhex("4885d2"))  # the trampoline
        self.assertTrue(any("trampoline" in line for line in log))
        self.assertEqual(out[t + 0x80:t + 0x82], b"\xff\x25")                       # exported: untouched
        self.assertEqual(out[t + 0x14:t + 0x18], struct.pack("<I", 0x28))           # struct size fixed
        self.assertIn((shims.UMTX_OP, "libkernel"), e.imports())                    # renamed, lib A
        self.assertNotIn(("Hc4CaR6JBL0", "libkernel"), e.imports())
        self.assertEqual([b.sdk_version for b in selflib.find_param_blocks(bytes(data))], [0x04000031])
        self.assertTrue(any("unused" in line and "yyyyyyyyyyy" in line for line in log))

    def test_arg_fixup(self):
        # an exported import listed in ARG_FIXUPS gets the prefix in its PLT stub
        flat, raw = build_module()
        pre = bytes.fromhex("48c7471800000000")
        saved = shims.ARG_FIXUPS
        shims.ARG_FIXUPS = {"-sD02mFDBh4": pre}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                ex = os.path.join(tmp, "exports.tsv")
                write_exports(ex)
                data = bytearray(raw)
                log, _ = backport.patch_module(data, backport.load_exports(ex), set(), 0x04000031, None)
        finally:
            shims.ARG_FIXUPS = saved
        out = bytes(selflib.rebuild_flat_elf(bytes(data)))
        t = TEXT_OFF + PLT["presets"]
        self.assertEqual(out[t:t + 8], pre)
        self.assertEqual(PLT["presets"] + 14 + struct.unpack_from("<i", out, t + 10)[0], GOT["presets"])
        self.assertTrue(any(line.lstrip().startswith("fixup   -sD02mFDBh4") for line in log))

    def test_arg_fixup_on_renamed_import(self):
        # a missing import that RENAMES maps to an older NID still gets its ARG_FIXUPS prefix
        flat, raw = build_module()
        pre = bytes.fromhex("31c9")
        saved = shims.ARG_FIXUPS, shims.RENAMES
        shims.ARG_FIXUPS, shims.RENAMES = {"zzzzzzzzzzz": pre}, {"zzzzzzzzzzz": "xxxxxxxxxxx"}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                ex = os.path.join(tmp, "exports.tsv")
                write_exports(ex)
                data = bytearray(raw)
                log, _ = backport.patch_module(data, backport.load_exports(ex), set(), 0x04000031, None)
        finally:
            shims.ARG_FIXUPS, shims.RENAMES = saved
        out = bytes(selflib.rebuild_flat_elf(bytes(data)))
        t = TEXT_OFF + PLT["missing"]
        self.assertEqual(out[t:t + 2], pre)
        self.assertEqual(PLT["missing"] + 8 + struct.unpack_from("<i", out, t + 4)[0], GOT["missing"])
        self.assertIn(("xxxxxxxxxxx", "libFoo"), Elf(out).imports())
        self.assertTrue(any(line.lstrip().startswith("renamed zzzzzzzzzzz") for line in log))

    def test_absent_lib(self):
        _, raw = build_module()
        with tempfile.TemporaryDirectory() as tmp:
            ex = os.path.join(tmp, "exports.tsv")
            write_exports(ex)
            exports = backport.load_exports(ex)
        del exports["libFoo"]  # simulate target firmware lacking libFoo entirely
        data = bytearray(raw)
        log, missing = backport.patch_module(data, exports, set(), 0x04000031, None,
                                             absent={"libFoo": "libB"})
        self.assertIn("zzzzzzzzzzz", missing)
        self.assertFalse(any("??" in line and "libFoo" in line for line in log))
        self.assertIn("  absent  libFoo -> libB (1 imports stubbed)", log)
        self.assertTrue(any(line.lstrip().startswith("ret 0   zzzzzzzzzzz") for line in log))
        out = bytes(selflib.rebuild_flat_elf(bytes(data)))
        e = Elf(out)
        self.assertEqual(out[TEXT_OFF + 0x90:TEXT_OFF + 0x93], shims.RET0)
        self.assertEqual(e.modules()[2], "libB")
        self.assertEqual(e.module_files()["libB"], "libB.sprx")
        self.assertIn(("zzzzzzzzzzz", "libB"), e.imports())

    def test_absent_lib_too_long_errors(self):
        _, raw = build_module()
        with self.assertRaises(ValueError):
            backport.patch_module(bytearray(raw), {}, set(), 0x04000031, None,
                                  absent={"libFoo": "libFooTooLong"})

    def test_byte_patch_and_error(self):
        _, raw = build_module()
        with tempfile.TemporaryDirectory() as tmp:
            ex = os.path.join(tmp, "exports.tsv")
            write_exports(ex)
            exports = backport.load_exports(ex)
        data = bytearray(raw)
        # at vaddr 0x10 is c744240830000000; patch first two bytes c744 -> 6690
        log, _ = backport.patch_module(data, exports, set(), 0x04000031, None,
                                       patches=[(0x10, "c744", "6690")])
        out = bytes(selflib.rebuild_flat_elf(bytes(data)))
        self.assertEqual(out[TEXT_OFF + 0x10:TEXT_OFF + 0x12], bytes.fromhex("6690"))
        self.assertIn("  patch   0x10 c744 -> 6690", log)
        # re-applying the same patch reports `already`
        log2, _ = backport.patch_module(data, exports, set(), 0x04000031, None,
                                        patches=[(0x10, "c744", "6690")])
        self.assertTrue(any("already" in line and "0x10" in line for line in log2))
        # wrong OLDHEX errors
        with self.assertRaises(ValueError):
            backport.patch_module(bytearray(raw), exports, set(), 0x04000031, None,
                                  patches=[(0x10, "dead", "6690")])

    def test_patch_file_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            pf = os.path.join(tmp, "patches.txt")
            with open(pf, "w", encoding="utf-8") as f:
                f.write("# comment line\n\n"
                        "eboot.bin:10:c744:6690  # inline comment\n"
                        "sub/mod.prx:0x20:9090:c390\n")
            parsed = backport.load_patches(["eboot.bin:0x18:e8:90"], [pf])
        self.assertEqual(parsed["eboot.bin"], [(0x18, b"\xe8", b"\x90"), (0x10, b"\xc7\x44", b"\x66\x90")])
        self.assertEqual(parsed["sub/mod.prx"], [(0x20, b"\x90\x90", b"\xc3\x90")])

    def test_cli_on_folder(self):
        _, raw = build_module()
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "app0")
            os.makedirs(os.path.join(src, "sce_sys"))
            wr(os.path.join(src, "eboot.bin"), raw)
            wr(os.path.join(src, "sce_sys", "right.sprx"), b"not ours")
            ex = os.path.join(tmp, "exports.tsv")
            write_exports(ex)
            work = os.path.join(tmp, "work")
            r = subprocess.run([sys.executable, os.path.join(TOOL, "backport.py"), src,
                                "--exports", ex, "--out", work], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(os.path.join(work, "overlay", "eboot.bin")))
            self.assertFalse(os.path.exists(os.path.join(work, "overlay", "sce_sys")))
            with open(os.path.join(work, "report.txt"), encoding="utf-8") as f:
                self.assertIn("ret 0", f.read())


class TestDiff(unittest.TestCase):
    def test_diff_names_changes(self):
        _, raw = build_module()
        with tempfile.TemporaryDirectory() as tmp:
            ex = os.path.join(tmp, "exports.tsv")
            write_exports(ex)
            data = bytearray(raw)
            backport.patch_module(data, backport.load_exports(ex), set(), 0x04000031, None)
            a, b = os.path.join(tmp, "a.bin"), os.path.join(tmp, "b.bin")
            wr(a, raw)
            wr(b, data)
            r = subprocess.run([sys.executable, os.path.join(TOOL, "diff_backport.py"), a, b, "--exports", ex],
                               capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("param   proc", r.stdout)
        self.assertIn("plt     0x90 zzzzzzzzzzz", r.stdout)
        self.assertIn("import  Hc4CaR6JBL0#D#A -> 04AjkP0jO9U#A#A", r.stdout)
        self.assertIn("code    0x14", r.stdout)


if __name__ == "__main__":
    unittest.main()
