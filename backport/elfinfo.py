"""Read the parts of a flat PS5 ELF that backporting needs: segments, dynamic tags, imported and
exported NIDs, library ids, PLT stubs and direct call sites.

A "flat" ELF is the plain ELF image inside a fake-signed SELF; get one with
`selflib.rebuild_flat_elf` (../self-tools). All functions here take the flat image as bytes.
"""
import re
import struct

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"

DT_NEEDED, DT_PLTRELSZ, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_JMPREL = 1, 2, 5, 6, 10, 0x17
DT_SCE_SYMTABSZ = 0x6100003F
DT_SCE_MODULE_INFO, DT_SCE_NEEDED_MODULE = 0x61000043, 0x61000045
DT_SCE_EXPORT_LIB, DT_SCE_IMPORT_LIB = 0x61000047, 0x61000049


def dec(s):
    """Decode a Sony base64 library/module id ("A" = 0, "B" = 1, ...)."""
    n = 0
    for ch in s:
        n = n * 64 + B64.index(ch)
    return n


class Elf:
    def __init__(self, data):
        self.d = bytes(data)
        n = struct.unpack_from("<H", self.d, 0x38)[0]
        # (type, flags, offset, vaddr, paddr, filesz, memsz, align)
        self.phs = [struct.unpack_from("<IIQQQQQQ", self.d, 0x40 + i * 56) for i in range(n)]
        dyn = [p for p in self.phs if p[0] == 2]
        self.tags = []
        if dyn:
            o = dyn[0][2]
            while o + 16 <= len(self.d):
                t, v = struct.unpack_from("<QQ", self.d, o)
                self.tags.append((t, v))
                o += 16
                if t == 0:
                    break
        self.T = {}
        for t, v in self.tags:
            self.T.setdefault(t, v)
        so = self.v2o(self.T[DT_STRTAB])
        self.strs = self.d[so:so + self.T[DT_STRSZ]]

    def v2o(self, va):
        """Virtual address -> file offset (PT_LOAD segments only), or None."""
        for p in self.phs:
            if p[0] == 1 and p[3] <= va < p[3] + max(p[5], 1):
                return p[2] + va - p[3]
        return None

    def s(self, off):
        return self.strs[off:self.strs.index(b"\x00", off)].decode("latin1")

    def text(self):
        """(file offset, vaddr, size) of the executable PT_LOAD."""
        p = [p for p in self.phs if p[0] == 1 and p[1] & 1][0]
        return p[2], p[3], p[5]

    def symbols(self):
        """(name, shndx, value) for every dynamic symbol."""
        syo = self.v2o(self.T[DT_SYMTAB])
        out = []
        for i in range(1, self.T.get(DT_SCE_SYMTABSZ, 0) // 24):
            nm, _, _, shn, val, _ = struct.unpack_from("<IBBHQQ", self.d, syo + i * 24)
            out.append((self.s(nm), shn, val))
        return out

    def modules(self):
        """Needed-module id -> module name."""
        return {(v >> 48) & 0xFFFF: self.s(v & 0xFFFFFFFF)
                for t, v in self.tags if t == DT_SCE_NEEDED_MODULE}

    def module_files(self):
        """Needed-module name -> DT_NEEDED file name (the NEEDED tag precedes its module tag)."""
        files, last = {}, None
        for t, v in self.tags:
            if t == DT_NEEDED:
                last = self.s(v)
            elif t == DT_SCE_NEEDED_MODULE and last:
                files[self.s(v & 0xFFFFFFFF)] = last
        return files

    def import_libs(self):
        """Imported library name -> its one-letter id in import names (NID#lib#module)."""
        return {self.s(v & 0xFFFFFFFF): B64[v >> 48] for t, v in self.tags if t == DT_SCE_IMPORT_LIB}

    def module_name(self):
        v = self.T.get(DT_SCE_MODULE_INFO)
        return self.s(v & 0xFFFFFFFF) if v is not None else None

    def imports(self):
        """[(nid, module name)] of every imported function."""
        mods = self.modules()
        out = []
        for name, shn, _ in self.symbols():
            if not shn and name.count("#") == 2:
                nid, _, mod = name.split("#")
                out.append((nid, mods.get(dec(mod), "?")))
        return out

    def exports(self):
        """[(library name, nid)] of every exported function."""
        libs = {(v >> 48) & 0xFFFF: self.s(v & 0xFFFFFFFF)
                for t, v in self.tags if t == DT_SCE_EXPORT_LIB}
        out = []
        for name, shn, _ in self.symbols():
            if shn and name.count("#") == 2:
                nid, lib, _ = name.split("#")
                out.append((libs.get(dec(lib), lib), nid))
        return out

    def plt(self):
        """PLT stub vaddr -> imported symbol name ("NID#L#M"), from `jmp [rip+X]` to GOT slots."""
        syo = self.v2o(self.T[DT_SYMTAB])
        jo = self.v2o(self.T[DT_JMPREL])
        got = {}
        for i in range(self.T.get(DT_PLTRELSZ, 0) // 24):
            off, info, _ = struct.unpack_from("<QQq", self.d, jo + i * 24)
            nm = struct.unpack_from("<I", self.d, syo + (info >> 32) * 24)[0]
            got[off] = self.s(nm)
        t0, tva, tsz = self.text()
        seg = self.d[t0:t0 + tsz]
        stubs = {}
        for m in re.finditer(rb"\xff\x25", seg):
            i = m.start()
            slot = tva + i + 6 + struct.unpack_from("<i", seg, i + 2)[0]
            if slot in got:
                stubs[tva + i] = got[slot]
        return stubs

    def calls(self, targets):
        """[(call-site vaddr, target vaddr)] of every `call rel32` to one of `targets`."""
        t0, tva, tsz = self.text()
        seg = self.d[t0:t0 + tsz]
        out = []
        for m in re.finditer(rb"\xe8", seg):
            i = m.start()
            if i + 5 > len(seg):
                break
            tgt = tva + i + 5 + struct.unpack_from("<i", seg, i + 1)[0]
            if tgt in targets:
                out.append((tva + i, tgt))
        return out
