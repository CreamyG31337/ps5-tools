"""Backport a PS5 game's executables to an older firmware: one command from an untouched dump
to an overlay folder.

    python backport.py SOURCE --exports exports.tsv --out WORK [--sdk 0x04000031]
                       [--nids nids.csv] [--replace INNER=LOCAL ...] [--only REGEX]

SOURCE is either an app0 folder dump (eboot.bin, sce_module/, ...) or a fake package .pkg.
A .pkg is read with ProsperoPkgTool (see pkgtool/README.md), which also decodes
Kraken-compressed packages. exports.tsv comes from fw_exports.py, made from the target
firmware's own system libraries.

For eboot.bin and every .prx/.sprx (sce_sys/ is skipped, it's Sony-signed):
1. Lower the module/proc param SDK version to --sdk if it is higher. The loader refuses
   modules built for a newer SDK than the firmware.
2. Lower known struct sizes the older function rejects (shims.STRUCT_SIZES).
3. List imports the target firmware doesn't export. Modules the game ships itself are skipped.
   Each missing import that has a PLT stub gets a stand-in: an older NID of the same function
   (RENAMES), a 100 us sleep for futex waits (SLEEP_WAITS), a known shim (KNOWN), or else
   `return 0`. Imports with no PLT stub are never called and are left alone.
Results go to WORK/overlay/ (same paths as app0) and WORK/report.txt, which names every
stubbed function: a `return 0` is a guess, so that list is where to look when something breaks.
--replace INNER=LOCAL copies a hand-made file into the overlay instead.

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


def patch_module(data, exports, shipped, sdk, names_db):
    """Patch one fake-signed SELF in place. Returns (log lines, missing NIDs)."""
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

    missing = set()
    for nid, mod in e.imports():
        if mod not in shipped and mod in exports and nid not in exports[mod]:
            missing.add(nid)
    unknown = sorted({m for _, m in e.imports() if m not in shipped and m not in exports})
    if unknown:
        log.append(f"  ?? modules not in the exports table, not checked: {', '.join(unknown)}")
    names = load_names(names_db, missing)
    libs = e.import_libs()
    for nid in sorted(missing):
        label = f"{nid} {names.get(nid, '(unnamed)')}"
        if nid in shims.RENAMES and shims.rename_import(data, nid, shims.RENAMES[nid]) == 1:
            log.append(f"  renamed {label} -> {shims.RENAMES[nid]}")
            continue
        if nid not in by_nid:
            log.append(f"  unused  {label} (no PLT stub, never called)")
            continue
        off = e.v2o(by_nid[nid])
        where = f"(PLT {by_nid[nid]:#x}, {ncalls.get(nid, 0)} direct calls)"
        if nid in shims.SLEEP_WAITS and "libkernel" in libs:
            stub = shims.sleep_stub(elf_b[off:off + 6])
            if shims.rename_import(data, nid, shims.USLEEP, libs["libkernel"]) == 1 and \
                    shims.put(data, orig, elf_b, off, stub):
                log.append(f"  usleep  {label} {where}")
                continue
        new = shims.KNOWN.get(nid, shims.RET0).ljust(16, shims.PAD)
        if shims.put(data, orig, elf_b, off, new):
            log.append(f"  {'shim' if nid in shims.KNOWN else 'ret 0':7} {label} {where}")
        else:
            log.append(f"  !!      {label}: no unique spot in the SELF, NOT patched")
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
    a = ap.parse_args()
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
            log, missing = patch_module(data, exports, shipped, a.sdk, a.nids)
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
