"""Show what someone else's backport changed: compare an untouched module with the released one.

    python diff_backport.py ORIGINAL RELEASED [--nids nids.csv] [--exports exports.tsv]

Both are fake-signed SELFs (or flat ELFs) of the same build. Only bytes the loader uses are
compared (PT_LOAD segments); a SELF doesn't store the other segments, so differences there are
artifacts of rebuilding the flat image. Each changed run is labelled:
  param      a proc/module param field (SDK version and its neighbour)
  plt        a PLT stub replaced by a shim (the import is named)
  import     an import string renamed (old NID -> new NID)
  code       instructions; the next call after it is named, which usually tells what for
  data       anything else
This is how to learn the fixes a release made by hand, so they can go into shims.py and be
applied to an untouched dump instead of relying on someone's prebuilt files.
"""
import argparse
import csv
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "self-tools"))
import selflib  # noqa: E402
from elfinfo import Elf  # noqa: E402


def flat(path):
    d = open(path, "rb").read()
    return d if d[:4] == b"\x7fELF" else bytes(selflib.rebuild_flat_elf(d))


def runs(a, b, lo, hi, gap=8):
    """Changed byte ranges in [lo, hi), merging runs closer than `gap`."""
    out, i = [], lo
    while i < hi:
        if a[i] != b[i]:
            j = i + 1
            while j < hi and (a[j] != b[j] or any(a[k] != b[k] for k in range(j, min(j + gap, hi)))):
                j += 1
            out.append((i, j))
            i = j
        else:
            i += 1
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("original")
    ap.add_argument("released")
    ap.add_argument("--nids", help="NID database CSV (nid,name) for names")
    ap.add_argument("--exports", help="target firmware exports.tsv: marks imports it lacks")
    a = ap.parse_args()
    A, B = flat(a.original), flat(a.released)
    if len(A) != len(B):
        print(f"note: flat sizes differ ({len(A):#x} vs {len(B):#x}); comparing the common part")
    ea, eb = Elf(A), Elf(B)
    names = {}
    if a.nids:
        with open(a.nids, encoding="utf-8", errors="replace") as f:
            names = {r["nid"]: r["name"] for r in csv.DictReader(f)}
    nm = lambda sym: f"{sym[:11]} {names.get(sym[:11], '')}".rstrip()
    plt = ea.plt()
    strtab = ea.v2o(ea.T[5]), ea.v2o(ea.T[5]) + ea.T[10]
    params = [(blk.offset - 8, blk.offset - 8 + blk.size, blk.block_type)
              for blk in selflib.find_param_blocks(A)]
    t0, tva, tsz = ea.text()

    for p in ea.phs:
        if p[0] != 1:
            continue
        lo, hi = p[2], min(p[2] + p[5], len(A), len(B))
        for s, e in runs(A, B, lo, hi):
            va = p[3] + s - p[2]
            old, new = A[s:e].hex(), B[s:e].hex()
            par = [x for x in params if x[0] <= s < x[1]]
            stub = [v for v in plt if v <= va < v + 16]
            if par:
                f0 = (s - par[0][0]) & ~3
                vals = [(f0 + k, struct.unpack_from("<I", A, par[0][0] + f0 + k)[0],
                         struct.unpack_from("<I", B, par[0][0] + f0 + k)[0])
                        for k in range(0, (e - par[0][0]) - f0, 4)]
                for off, x, y in vals:
                    if x != y:
                        print(f"param   {par[0][2]} +{off:#x}: {x:#010x} -> {y:#010x}")
            elif stub:
                shim = B[s:e].rstrip(b"\xcc").hex()
                print(f"plt     {stub[0]:#x} {nm(plt[stub[0]])}: stub -> {shim}")
            elif strtab[0] <= s < strtab[1]:
                s0 = A.rfind(b"\x00", 0, s) + 1
                was = A[s0:A.index(b"\x00", s)].decode("latin1")
                now = B[s0:B.index(b"\x00", s)].decode("latin1")
                print(f"import  {was} -> {now}")
            elif t0 <= s < t0 + tsz:
                nxt = [(site, tgt) for site, tgt in ea.calls(set(plt)) if va <= site < va + 96]
                why = f" (before call to {nm(plt[nxt[0][1]])} at {nxt[0][0]:#x})" if nxt else ""
                print(f"code    {va:#x} {e - s} bytes: {old[:48]} -> {new[:48]}{why}")
            else:
                print(f"data    {va:#x} {e - s} bytes: {old[:48]} -> {new[:48]}")

    ia, ib = set(ea.imports()), set(eb.imports())
    for nid, mod in sorted(ib - ia):
        print(f"import  added {nid} {names.get(nid, '')} from {mod}")
    if a.exports:
        have = {}
        with open(a.exports, encoding="utf-8") as f:
            for r in csv.DictReader(f, delimiter="\t"):
                have.setdefault(r["module"], set()).add(r["nid"])
        stubs = {s[:11]: v for v, s in eb.plt().items()}
        orig_stubs = {s[:11]: v for v, s in plt.items()}
        left = [(n, m) for n, m in sorted(ib) if m in have and n not in have[m]
                and n in stubs and B[eb.v2o(stubs[n]):eb.v2o(stubs[n]) + 6] ==
                A[ea.v2o(orig_stubs[n]):ea.v2o(orig_stubs[n]) + 6]]
        for nid, mod in left:
            print(f"missing {nid} {names.get(nid, '')} ({mod}): still imported, its PLT stub untouched (crashes if called)")


if __name__ == "__main__":
    main()
