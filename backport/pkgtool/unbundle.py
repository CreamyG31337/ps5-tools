"""Pull the assemblies out of a .NET single-file app (bundle format v2..v6), so a library inside
it can be used on its own. Used here for PS5 PKG Tool, whose package reader (ProsperoPkgTool)
has a command line but no launcher.

    python -I unbundle.py "PATH\\TO\\PS5 PKG Tool.exe" [OUTDIR]

OUTDIR defaults to .\\unbundled next to this script. oo2core_9_win64.dll (the Kraken decoder)
ships beside the exe in the release zip; it is copied too when found there.
"""
import os
import shutil
import struct
import sys
import zlib

# SHA-256 of ".net core bundle", which the host stores right after the bundle header offset
SIG = bytes.fromhex("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae")


def rstr(d, p):
    """.NET 7-bit length-prefixed UTF-8 string at p -> (string, next offset)."""
    n = s = 0
    while True:
        b = d[p]
        p += 1
        n |= (b & 0x7F) << s
        s += 7
        if b < 0x80:
            break
    return d[p:p + n].decode(), p + n


def unbundle(d, out):
    i = d.find(SIG)
    if i < 8:
        raise ValueError("not a .NET single-file bundle")
    hdr = struct.unpack_from("<q", d, i - 8)[0]
    major, minor, count = struct.unpack_from("<IIi", d, hdr)
    _, p = rstr(d, hdr + 12)
    if major >= 2:
        p += 8 * 4 + 8  # deps.json and runtimeconfig.json locations, flags
    names = []
    for _ in range(count):
        off, size = struct.unpack_from("<qq", d, p)
        p += 16
        csize = 0
        if major >= 6:
            csize = struct.unpack_from("<q", d, p)[0]
            p += 8
        p += 1  # file type
        path, p = rstr(d, p)
        blob = d[off:off + (csize or size)]
        if csize:
            blob = zlib.decompress(blob, -15)
        dst = os.path.join(out, path)
        if os.path.commonpath([os.path.abspath(dst), os.path.abspath(out)]) != os.path.abspath(out):
            raise ValueError(f"bundle path escapes the output folder: {path}")
        os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
        with open(dst, "wb") as f:
            f.write(blob)
        names.append(path)
    return major, minor, names


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    exe = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "unbundled")
    with open(exe, "rb") as f:
        major, minor, names = unbundle(f.read(), out)
    print(f"bundle v{major}.{minor}: {len(names)} files -> {out}")
    oodle = os.path.join(os.path.dirname(os.path.abspath(exe)), "oo2core_9_win64.dll")
    if os.path.exists(oodle):
        shutil.copy(oodle, out)
        print("copied oo2core_9_win64.dll")
    else:
        print("oo2core_9_win64.dll not next to the exe: copy it into the output folder by hand")


if __name__ == "__main__":
    main()
