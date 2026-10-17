"""Build the table of every function a firmware exports, from its decrypted system libraries.

    python fw_exports.py LIBDIR --out exports.tsv [--nids nids.csv]

LIBDIR is a copy of the console's /system/common/lib and /system/priv/lib (subfolders are
searched). Download them over a jailbroken console's FTP server that decrypts on download
(e.g. ftpsrv); encrypted files are skipped and counted. The table is what `audit.py` and
`backport.py` check imports against, so build it once per target firmware.

Output columns: module_file  module  library  nid  name. Names come from an NID database CSV
with `nid` and `name` columns (e.g. the one in github.com/claimore22/ps5rs) if given.
"""
import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf  # noqa: E402


def load_names(path):
    names = {}
    if path:
        with open(path, encoding="utf-8", errors="replace") as f:
            for r in csv.DictReader(f):
                names.setdefault(r["nid"], r["name"])
    return names


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("libdir")
    ap.add_argument("--out", required=True)
    ap.add_argument("--nids", help="NID database CSV (nid,name columns) for function names")
    a = ap.parse_args()
    names = load_names(a.nids)
    rows, skipped = [], 0
    for dp, _, fs in os.walk(a.libdir):
        for f in sorted(fs):
            p = os.path.join(dp, f)
            data = open(p, "rb").read()
            if data[:4] != b"\x7fELF":
                skipped += 1
                continue
            try:
                e = Elf(data)
            except Exception:
                skipped += 1
                continue
            rel = os.path.relpath(p, a.libdir).replace(os.sep, "/")
            mod = e.module_name() or "?"
            for lib, nid in e.exports():
                rows.append((rel, mod, lib, nid, names.get(nid, "")))
    with open(a.out, "w", encoding="utf-8", newline="") as f:
        f.write("module_file\tmodule\tlibrary\tnid\tname\n")
        for r in sorted(rows):
            f.write("\t".join(r) + "\n")
    mods = len({r[0] for r in rows})
    print(f"{len(rows)} exports from {mods} modules -> {a.out} ({skipped} files skipped: not decrypted ELFs)")


if __name__ == "__main__":
    main()
