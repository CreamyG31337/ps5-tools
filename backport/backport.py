"""Backport a PS5 game's executables to an older firmware: one command from an untouched dump
to an overlay folder.

    python backport.py SOURCE --exports exports.tsv --out WORK [--sdk 0x04000031]
                       [--nids nids.csv] [--replace INNER=LOCAL ...] [--only REGEX]
                       [--absent-lib NAME=SUBSTITUTE ...] [--provided-lib NAME ...]
                       [--patch INNER:VADDR:OLDHEX:NEWHEX ...] [--patch-file FILE ...]
                       [--pm4-sanitize]

SOURCE is either an app0 folder dump (eboot.bin, sce_module/, ...) or a fake package .pkg.
A .pkg is read with ProsperoPkgTool (see pkgtool/README.md), which also decodes
Kraken-compressed packages. exports.tsv comes from fw_exports.py, made from the target
firmware's own system libraries.

For eboot.bin and every .prx/.sprx (sce_sys/ is skipped, it's Sony-signed):
1. Lower the module/proc param SDK version to --sdk if it is higher. The loader refuses
   modules built for a newer SDK than the firmware.
2. Lower known struct sizes the older function rejects (shims.STRUCT_SIZES), and fix up
   arguments an exported function's older version rejects in its PLT stub (shims.ARG_FIXUPS).
3. List imports the target firmware doesn't export. Modules the game ships itself are skipped.
   Each missing import that has a PLT stub gets a stand-in: an older NID of the same function
   (RENAMES), FreeBSD's _umtx_op for futex waits/wakes (UMTX_SHIMS), a known shim (KNOWN), or else
   `return 0`. Imports with no PLT stub are never called and are left alone.
Results go to WORK/overlay/ (same paths as app0) and WORK/report.txt, which names every
stubbed function: a `return 0` is a guess, so that list is where to look when something breaks.
--absent-lib NAME=SUBSTITUTE stubs every called import of a library the target firmware lacks
entirely and points the module's dependency on NAME at SUBSTITUTE in place. --provided-lib NAME
treats NAME like a module the game ships: use it when a newer build of a system library goes
into the game's fakelib/ (e.g. libSceAgc), so its imports get no stand-ins. --patch (or
--patch-file) applies per-module byte changes at flat-ELF virtual addresses. --replace
INNER=LOCAL copies a hand-made file into the overlay instead. --pm4-sanitize is for games
whose GPU commands use the "no register" placeholder older firmware rejects ("GPU Bad packet
error:Privilege reg ... 0x2bff"): see shims.PM4_SUBMITS.

The overlay is what a backport loader (e.g. ShadowMountPlus's backports folder) lays over the
installed game. Input files must be fake-signed SELFs (fpkg/dump), not retail-encrypted ones.
"""
import argparse
import csv
import os
import re
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "self-tools"))
import selflib  # noqa: E402
import shims  # noqa: E402
from elfinfo import Elf  # noqa: E402

EXEC = re.compile(r"(^|/)eboot\.bin$|\.s?prx$", re.I)
SKIP = re.compile(r"^sce_sys/", re.I)
PPT = os.path.join(HERE, "pkgtool", "ppt.ps1")


class PatchError(ValueError):
    pass


def load_exports(path):
    """module name -> set of exported NIDs."""
    out = {}
    with open(path, encoding="utf-8") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            out.setdefault(r["module"], set()).add(r["nid"])
    return out


def load_names(path, nids):
    names = {}
    if path and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            for r in csv.DictReader(f):
                if r["nid"] in nids:
                    names[r["nid"]] = r["name"]
    return names


def parse_absent(specs):
    """Parse ['NAME=SUBSTITUTE', ...] or {NAME: SUBSTITUTE} -> {NAME: SUBSTITUTE}."""
    items = specs.items() if isinstance(specs, dict) else (
        s.split("=", 1) if "=" in s else (s, "") for s in (specs or ())
    )
    out = {}
    for name, sub in items:
        if not name or not sub:
            raise PatchError(f"invalid --absent-lib {name}={sub}: expected NAME=SUBSTITUTE")
        if len(sub) > len(name):
            raise PatchError(f"absent-lib {name}={sub}: substitute {sub!r} is longer than {name!r}")
        out[name] = sub
    return out


def parse_patch_spec(spec):
    """Parse 'INNER:VADDR:OLDHEX:NEWHEX' -> (inner, vaddr, old_bytes, new_bytes)."""
    parts = spec.strip().rsplit(":", 3)
    if len(parts) != 4 or not parts[0]:
        raise PatchError(f"invalid patch spec {spec!r}: expected INNER:VADDR:OLDHEX:NEWHEX")
    inner, va_s, old_s, new_s = parts
    try:
        va = int(va_s, 16)
        old = bytes.fromhex(old_s)
        new = bytes.fromhex(new_s)
    except ValueError as ex:
        raise PatchError(f"invalid patch spec {spec!r}: {ex}") from ex
    if not old or len(old) != len(new):
        raise PatchError(f"invalid patch spec {spec!r}: old and new hex must have equal non-zero length")
    return inner.replace("\\", "/"), va, old, new


def load_patches(specs=(), files=()):
    """Parse --patch specs and --patch-file files -> {inner: [(vaddr, old_bytes, new_bytes), ...]}."""
    out = {}
    all_specs = list(specs or ())
    for path in files or ():
        with open(path, encoding="utf-8") as f:
            for line in f:
                s = line.split("#", 1)[0].strip()
                if s:
                    all_specs.append(s)
    for s in all_specs:
        inner, va, old, new = parse_patch_spec(s)
        out.setdefault(inner, []).append((va, old, new))
    return out


def rewrite_absent_lib(data, orig, elf_b, e, name, sub):
    """Rewrite the dynamic string table entries that name `name` as a needed module to `sub`."""
    so = e.v2o(e.T[5])
    rewrites = {}
    # if the module already needs `sub`, reuse that file name (e.g. libSceAjm.native.prx), so
    # the loader doesn't pull in a second build of the same library
    sub_fn, last_needed = None, None
    for t, v in e.tags:
        if t == 1:
            last_needed = v
        elif t == 0x61000045:
            if e.s(v & 0xFFFFFFFF) == sub and last_needed is not None:
                sub_fn = e.s(last_needed)
            last_needed = None
    last_needed = None
    for t, v in e.tags:
        if t == 1:
            last_needed = v
        elif t == 0x61000045:
            off = v & 0xFFFFFFFF
            if e.s(off) == name:
                rewrites[off] = (name, sub)
                if last_needed is not None:
                    old_fn = e.s(last_needed)
                    new_fn = sub_fn if sub_fn and len(sub_fn) <= len(old_fn) else \
                        sub + os.path.splitext(old_fn)[1]
                    rewrites[last_needed] = (old_fn, new_fn)
            last_needed = None
        elif t == 0x61000049 and e.s(v & 0xFFFFFFFF) == name:
            rewrites[v & 0xFFFFFFFF] = (name, sub)
    if not rewrites:
        raise PatchError(f"absent-lib {name}: needed module entry not found")
    for off, (old_s, new_s) in rewrites.items():
        if len(new_s) > len(old_s):
            raise PatchError(f"absent-lib {name}={sub}: {new_s!r} is longer than {old_s!r}")
        raw_hits = len(re.findall(re.escape(b"\x00" + old_s.encode("latin1") + b"\x00"), orig))
        padded = new_s.encode("latin1").ljust(len(old_s), b"\x00")
        if raw_hits != 1 or not shims.put(data, orig, elf_b, so + off, padded):
            raise PatchError(f"absent-lib {name}: string {old_s!r} not uniquely patchable in SELF")


def ppt(*args):
    r = subprocess.run(["pwsh", "-NoProfile", "-File", PPT, *args], capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"ProsperoPkgTool {args[0]} failed:\n{r.stdout}{r.stderr}")
    return r.stdout


def collect(source, orig, only):
    """Copy (folder) or extract (.pkg) the executables into `orig`; returns inner paths."""
    keep = lambda p: EXEC.search(p) and not SKIP.search(p) and (not only or re.search(only, p))
    files = []
    if os.path.isdir(source):
        for dp, _, fs in os.walk(source):
            for f in fs:
                rel = os.path.relpath(os.path.join(dp, f), source).replace(os.sep, "/")
                if keep(rel):
                    files.append(rel)
                    dst = os.path.join(orig, *rel.split("/"))
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copyfile(os.path.join(dp, f), dst)
        return files
    for line in ppt("img_file_list", source).splitlines():
        m = re.match(r"file\s+\d+\s+/uroot/(.+)$", line.strip())
        if m and keep(m[1]):
            files.append(m[1])
    for rel in files:
        dst = os.path.join(orig, *rel.split("/"))
        if not os.path.exists(dst):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            ppt("img_extract", f"{source}:/uroot/{rel}", dst)
            print(f"  extracted {rel}")
    return files


def exec_cave_va(data, e, size):
    """Vaddr where grow_exec_segment can put a trampoline: the end of the executable
    segment, which stays inside the segment's last (already mapped) page. None if that page
    has no room or the segment/entry layout is unusual."""
    hdr, ents, _, phs = selflib.parse_self_header(bytes(data))
    ex = [i for i, p in enumerate(phs) if p.p_type == 1 and p.p_flags & 1]
    if len(ex) != 1 or sum(1 for t in ents if t.is_elf_segment and t.elf_ph_index == ex[0]) != 1:
        return None
    p = phs[ex[0]]
    page_end = (p.p_vaddr + p.p_filesz + p.p_align - 1) & ~(p.p_align - 1)
    if p.p_filesz != p.p_memsz or p.p_vaddr + p.p_filesz + size > page_end:
        return None
    return p.p_vaddr + p.p_filesz


def grow_exec_segment(data, extra):
    """Append `extra` to the executable segment, at the vaddr exec_cave_va returned (call
    this after every PLT stub patch is already in `data`). A fake-signed SELF stores its
    segments as plain blobs: the whole patched segment moves to the end of the file with
    `extra` as its new tail, and the segment entry plus the embedded program header
    (p_filesz, p_memsz) grow to cover it. Nothing moves in memory: the extra bytes stay
    inside the segment's last page."""
    hdr, ents, elf_off, phs = selflib.parse_self_header(bytes(data))
    ex = [i for i, p in enumerate(phs) if p.p_type == 1 and p.p_flags & 1]
    k = [j for j, t in enumerate(ents) if t.is_elf_segment and t.elf_ph_index == ex[0]]
    if len(ex) != 1 or len(k) != 1:
        return False
    i, j = ex[0], k[0]
    ent, p = ents[j], phs[i]
    at = (len(data) + 0xF) & ~0xF
    data.extend(b"\x00" * (at + ent.filesz + len(extra) - len(data)))
    data[at:at + ent.filesz] = data[ent.offset:ent.offset + ent.filesz]
    data[at + ent.filesz:at + ent.filesz + len(extra)] = extra
    struct.pack_into("<QQQ", data, 0x20 + j * 0x20 + 8, at, ent.filesz + len(extra),
                     ent.memsz + len(extra))
    ph_at = elf_off + struct.unpack_from("<Q", data, elf_off + 0x20)[0] + i * 56
    struct.pack_into("<QQ", data, ph_at + 32, p.p_filesz + len(extra), p.p_memsz + len(extra))
    struct.pack_into("<Q", data, 0x10, len(data))
    return True


def patch_module(data, exports, shipped, sdk, names_db, absent=None, patches=(), pm4=False):
    """Patch one fake-signed SELF in place. Returns (log lines, missing NIDs)."""
    absent = parse_absent(absent)
    orig = bytes(data)
    elf_b = bytes(selflib.rebuild_flat_elf(orig))
    e = Elf(elf_b)
    log = []
    for blk in selflib.find_param_blocks(orig):
        if blk.sdk_version and blk.sdk_version > sdk:
            struct.pack_into("<I", data, blk.offset + 0xC, sdk)
            log.append(f"  {blk.block_type} param SDK {blk.sdk_version:#010x} -> {sdk:#010x}")

    plt = e.plt()
    by_nid = {}
    for va, sym in plt.items():
        by_nid.setdefault(sym[:11], va)
    calls = e.calls(set(plt))
    ncalls = {}
    for site, tgt in calls:
        nid = plt[tgt][:11]
        ncalls[nid] = ncalls.get(nid, 0) + 1
        if nid in shims.STRUCT_SIZES:
            old, new = shims.STRUCT_SIZES[nid]
            off = e.v2o(site)
            at = shims.find_size_store(elf_b[off - 64:off], old)
            if at is None:
                log.append(f"  ?? {nid} call at {site:#x}: struct size {old:#x} not found, not patched")
            elif shims.put(data, orig, elf_b, off - 64 + at, struct.pack("<I", new)):
                log.append(f"  struct  {nid} call at {site:#x}: size {old:#x} -> {new:#x}")

    imps = e.imports()
    missing = set()
    absent_nids = set()
    for nid, mod in imps:
        if mod not in shipped:
            if mod in absent:
                missing.add(nid)
                absent_nids.add(nid)
            elif mod in exports and nid not in exports[mod]:
                missing.add(nid)
    unknown = sorted({m for _, m in imps if m not in shipped and m not in exports and m not in absent})
    if unknown:
        log.append(f"  ?? modules not in the exports table, not checked: {', '.join(unknown)}")
    present_mods = set(e.modules().values()) | {m for _, m in imps}
    for mod in sorted(m for m in absent if m not in shipped and m in present_mods):
        rewrite_absent_lib(data, orig, elf_b, e, mod, absent[mod])
        k = sum(1 for n, m in imps if m == mod and n in by_nid)
        log.append(f"  absent  {mod} -> {absent[mod]} ({k} imports stubbed)")
    for nid, pre in sorted(shims.ARG_FIXUPS.items()):
        renamed = nid in shims.RENAMES and nid not in absent_nids
        if (nid in missing and not renamed) or nid not in by_nid:
            continue
        off = e.v2o(by_nid[nid])
        stub = shims.prefixed_stub(elf_b[off:off + 6], pre)
        if stub and shims.put(data, orig, elf_b, off, stub):
            log.append(f"  fixup   {nid} (PLT {by_nid[nid]:#x}, {ncalls.get(nid, 0)} direct calls): "
                       f"{pre.hex()} before the call")
        else:
            log.append(f"  ?? {nid}: argument fixup not applied (PLT stub not patchable)")
    names = load_names(names_db, missing)
    libs = e.import_libs()
    # futex stand-ins: a shared trampoline appended to the exec segment gives every wait a
    # real kernel timeout (shims.umtx_cave); the paired-stub layout is the fallback
    umtx, cave, tramp = {}, None, 0
    if "libkernel" in libs:
        stubs = {by_nid[n]: (shims.UMTX_SHIMS[n], elf_b[e.v2o(by_nid[n]):e.v2o(by_nid[n]) + 16])
                 for n in missing if n in shims.UMTX_SHIMS and n not in absent_nids and n in by_nid}
        if any(op != shims.UMTX_WAKE for op, _ in stubs.values()):
            tramp = len(shims.umtx_cave(stubs, 0)[1])
    # --pm4-sanitize: the game's calls to the command-buffer submit functions go through
    # shims.pm4_sanitizer first; its code shares the grown exec segment with the trampoline
    pm4_sites = sorted((s, t) for s, t in calls if pm4 and plt[t][:11] in shims.PM4_SUBMITS)
    pm4_plts = sorted({t for _, t in pm4_sites})
    pm4_len = len(shims.pm4_sanitizer(pm4_plts, 0)[1]) if pm4_sites else 0
    if pm4_len:
        cave = exec_cave_va(data, e, tramp + 15 + pm4_len)
        if cave is None:
            log.append("  !! pm4 sanitizer: no room at the end of the exec segment, NOT applied")
            pm4_sites = []
    if cave is None and tramp:
        cave = exec_cave_va(data, e, tramp)
    if "libkernel" in libs:
        if tramp and cave is not None:
            umtx = shims.umtx_cave(stubs, cave)[0]
        else:
            umtx = shims.umtx_stubs(stubs) or {}
    tail = shims.umtx_cave(stubs, cave)[1] if tramp and cave is not None else b""
    if pm4_sites:
        pm4_va = (cave + len(tail) + 0xF) & ~0xF
        thunks, pm4_code = shims.pm4_sanitizer(pm4_plts, pm4_va)
        tail = tail.ljust(pm4_va - cave, shims.PAD) + pm4_code
        for site, tgt in pm4_sites:
            new = b"\xe8" + struct.pack("<i", thunks[tgt] - (site + 5))
            if shims.put(data, orig, elf_b, e.v2o(site), new):
                log.append(f"  pm4     call {shims.PM4_SUBMITS[plt[tgt][:11]]} at {site:#x} -> "
                           f"sanitizer {thunks[tgt]:#x}")
            else:
                log.append(f"  !!      pm4: call at {site:#x} has no unique spot in the SELF, NOT redirected")
    for nid in sorted(missing):
        label = f"{nid} {names.get(nid, '(unnamed)')}"
        if nid not in absent_nids and nid in shims.RENAMES and \
                shims.rename_import(data, nid, shims.RENAMES[nid]) == 1:
            log.append(f"  renamed {label} -> {shims.RENAMES[nid]}")
            continue
        if nid not in by_nid:
            log.append(f"  unused  {label} (no PLT stub, never called)")
            continue
        off = e.v2o(by_nid[nid])
        where = f"(PLT {by_nid[nid]:#x}, {ncalls.get(nid, 0)} direct calls)"
        if nid not in absent_nids and nid in shims.UMTX_SHIMS and "libkernel" in libs:
            stub = umtx.get(by_nid[nid]) or shims.umtx_stub(elf_b[off:off + 6], shims.UMTX_SHIMS[nid])
            if stub and shims.rename_import(data, nid, shims.UMTX_OP, libs["libkernel"]) == 1 and \
                    shims.put(data, orig, elf_b, off, stub):
                if shims.UMTX_SHIMS[nid] == shims.UMTX_WAKE:
                    kind = ""
                elif tramp and cave is not None:
                    kind = ", trampoline wait"
                else:
                    kind = ", timed waits return at once" if by_nid[nid] in umtx else ", timeout dropped"
                log.append(f"  umtx    {label} {where}{kind}")
                continue
        new = shims.KNOWN.get(nid, shims.RET0).ljust(16, shims.PAD)
        if shims.put(data, orig, elf_b, off, new):
            log.append(f"  {'shim' if nid in shims.KNOWN else 'ret 0':7} {label} {where}")
        else:
            log.append(f"  !!      {label}: no unique spot in the SELF, NOT patched")
    for item in patches or ():
        if isinstance(item, str):
            _, va, old, new = parse_patch_spec(item if item.count(":") >= 3 else f"_:{item}")
        else:
            va, old, new = item[-3:]
            va = int(va, 16) if isinstance(va, str) else int(va)
            old = bytes.fromhex(old) if isinstance(old, str) else bytes(old)
            new = bytes.fromhex(new) if isinstance(new, str) else bytes(new)
        if not old or len(old) != len(new):
            raise PatchError(f"patch at {va:#x}: old and new hex must have equal non-zero length")
        off = e.v2o(va)
        if off is None or off + len(old) > len(elf_b):
            raise PatchError(f"patch at {va:#x}: address not in a loadable segment")
        cur = elf_b[off:off + len(old)]
        if cur == new:
            log.append(f"  already {va:#x} {old.hex()} -> {new.hex()}")
        elif cur != old:
            raise PatchError(f"patch at {va:#x}: expected {old.hex()}, found {cur.hex()}")
        elif not shims.put(data, orig, elf_b, off, new):
            raise PatchError(f"patch at {va:#x}: no unique spot in the SELF")
        else:
            log.append(f"  patch   {va:#x} {old.hex()} -> {new.hex()}")
    if tail:
        # the stubs are in; move the patched segment to the end of the file with the
        # trampoline / sanitizer as its tail (exec_cave_va already checked this cannot fail)
        assert grow_exec_segment(data, tail)
        if tramp:
            log.append(f"  umtx trampoline at {cave:#x} (exec segment grown): "
                       "timed waits sleep in the kernel, ~1 s recheck slices")
        if pm4_sites:
            log.append(f"  pm4 sanitizer at {pm4_va:#x} ({len(pm4_code)} bytes, exec segment grown): "
                       "drops {-1,-1} register-table placeholders before each submit")
    return log, missing


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source", help="app0 folder dump or .pkg")
    ap.add_argument("--exports", required=True, help="target firmware's exports.tsv (fw_exports.py)")
    ap.add_argument("--out", required=True, help="work folder")
    ap.add_argument("--sdk", type=lambda s: int(s, 0), default=0x04000031,
                    help="SDK version to set (default 0x04000031, FW 4.00)")
    ap.add_argument("--nids", help="NID database CSV (nid,name) for readable reports")
    ap.add_argument("--replace", nargs="*", default=[], metavar="INNER=LOCAL")
    ap.add_argument("--only", help="regex on the inner path: only these modules")
    ap.add_argument("--absent-lib", action="append", default=[], metavar="NAME=SUBSTITUTE",
                    help="stub imports of absent library NAME and point its module dependency at SUBSTITUTE")
    ap.add_argument("--provided-lib", action="append", default=[], metavar="NAME",
                    help="library the game gets from elsewhere (e.g. a newer build in its fakelib/), so "
                         "its imports aren't checked against the target firmware")
    ap.add_argument("--patch", action="append", default=[], metavar="INNER:VADDR:OLDHEX:NEWHEX",
                    help="patch bytes at flat-ELF hex VADDR in module INNER")
    ap.add_argument("--patch-file", action="append", default=[], metavar="FILE",
                    help="file of INNER:VADDR:OLDHEX:NEWHEX patch specs (# comments allowed)")
    ap.add_argument("--pm4-sanitize", action="store_true",
                    help="route command-buffer submits through code that drops the {-1,-1} register-table "
                         "placeholders older GPU firmware writes to register 0x2bff (see shims.PM4_SUBMITS)")
    a = ap.parse_args()
    try:
        absent = parse_absent(a.absent_lib)
        patches = load_patches(a.patch, a.patch_file)
    except PatchError as ex:
        sys.exit(str(ex))
    exports = load_exports(a.exports)
    orig, overlay = os.path.join(a.out, "orig"), os.path.join(a.out, "overlay")

    inner = collect(a.source, orig, a.only)
    paths = {i: os.path.join(orig, *i.split("/")) for i in inner}
    shipped = set()
    for p in paths.values():
        try:
            shipped.add(selflib.parse_self_info(open(p, "rb").read()).module_name)
        except Exception:
            pass
    shipped.discard(None)
    shipped |= set(a.provided_lib)
    replace = dict(r.split("=", 1) for r in a.replace)
    report, total = [f"game's own modules: {', '.join(sorted(shipped))}"], 0
    for i in sorted(set(inner) | set(replace)):
        dst = os.path.join(overlay, *i.split("/"))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if i in replace:
            shutil.copyfile(replace[i], dst)
            report.append(f"== {i}: copied from {replace[i]}")
            continue
        data = bytearray(open(paths[i], "rb").read())
        try:
            log, missing = patch_module(data, exports, shipped, a.sdk, a.nids,
                                        absent=absent, patches=patches.get(i, ()), pm4=a.pm4_sanitize)
        except PatchError as ex:
            sys.exit(f"{i}: {ex}")
        except Exception as ex:  # e.g. retail-encrypted
            shutil.copyfile(paths[i], dst)
            report.append(f"== {i}: not patched, copied as-is ({type(ex).__name__}: {ex})")
            continue
        total += len(missing)
        with open(dst, "wb") as f:
            f.write(data)
        report.append(f"== {i}: {len(missing)} imports missing on the target")
        report += log
    text = "\n".join(report)
    print(text)
    with open(os.path.join(a.out, "report.txt"), "w", encoding="utf-8") as f:
        f.write(text + "\n")
    print(f"== {len(inner)} modules, {total} missing imports; overlay in {overlay}")


if __name__ == "__main__":
    main()
