"""Tests for the backport tools, on a synthetic fake-signed SELF built in memory.

No Sony or game data: the module below is assembled byte by byte. It imports
  -sD02mFDBh4 (sceUserServiceGetGamePresets, exported, called with a struct size of 0x30),
  zzzzzzzzzzz from libFoo (missing on the "target", called -> return 0),
  Hc4CaR6JBL0 (sceKernelSyncOnAddressWait, missing, called -> 100 us sleep),
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

    phs = [(1, 5, TEXT_OFF, TEXT_VA, TEXT_SZ), (1, 6, DATA_OFF, DATA_VA, DATA_SZ),
           (1, 0, DYNS_OFF, DYNS_VA, DYNS_SZ),
           (2, 6, DYNS_OFF + dyn_at, DYNS_VA + dyn_at, len(dyn))]
    ehdr = bytearray(64)
    ehdr[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", ehdr, 0x10, 0xFE18, 0x3E, 1, 0, 64, 0, 0, 64, 56, len(phs), 0, 0, 0)
    phdr = b"".join(struct.pack("<IIQQQQQQ", t, f, o, v, v, s, s, 0x10) for t, f, o, v, s in phs)
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
            ("libkernel.sprx", "libkernel", "libkernel", shims.USLEEP, "sceKernelUsleep"),
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

    def test_sleep_stub(self):
        stub = b"\xff\x25" + struct.pack("<i", 0x1000)
        new = shims.sleep_stub(stub)
        self.assertEqual(len(new), 16)
        self.assertEqual(new[:5], bytes.fromhex("bf64000000"))  # mov edi, 100
        # jmp [rip+X] now ends 5 bytes later, so it must still reach the same GOT slot
        self.assertEqual(5 + 6 + struct.unpack_from("<i", new, 7)[0], 6 + 0x1000)

    def test_find_size_store(self):
        code = bytes.fromhex("90" * 10 + "48c745b030000000" + "488d75b0")
        self.assertEqual(shims.find_size_store(code, 0x30), 14)
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
        self.assertEqual(out[t + 0xA0:t + 0xA5], bytes.fromhex("bf64000000"))      # wait -> sleep
        self.assertEqual(out[t + 0x80:t + 0x82], b"\xff\x25")                       # exported: untouched
        self.assertEqual(out[t + 0x14:t + 0x18], struct.pack("<I", 0x28))           # struct size fixed
        self.assertIn((shims.USLEEP, "libkernel"), e.imports())                     # renamed, lib A
        self.assertNotIn(("Hc4CaR6JBL0", "libkernel"), e.imports())
        self.assertEqual([b.sdk_version for b in selflib.find_param_blocks(bytes(data))], [0x04000031])
        self.assertTrue(any("unused" in line and "yyyyyyyyyyy" in line for line in log))

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
        self.assertIn("import  Hc4CaR6JBL0#D#A -> 1jfXLRVzisc#A#A", r.stdout)
        self.assertIn("code    0x14", r.stdout)


if __name__ == "__main__":
    unittest.main()
