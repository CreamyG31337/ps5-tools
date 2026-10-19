# backport

Tools to make a PS5 game built with a newer SDK run on an older firmware, starting from the
untouched game files. **Start with [RECIPE.md](RECIPE.md)**: it's the whole process, with a
worked example.

| Tool | What it does |
|---|---|
| `backport.py SOURCE --exports T --out W` | The pipeline: from an app0 folder or `.pkg` to an overlay folder plus a report. Lowers SDK versions, fixes known struct sizes, gives every called missing function a stand-in, redirects absent libraries (`--absent-lib`) and applies per-module byte patches (`--patch`, `--patch-file`) |
| `fw_exports.py LIBDIR --out T` | Builds the target firmware's export table from its decrypted system libraries |
| `diff_backport.py ORIGINAL RELEASED` | Shows what someone else's backport changed by hand, labelled, so it can be turned into a rule |
| `shims.py` | Every known fix (renames, shims, sleeps, struct sizes) and why. Add new ones here |
| `elfinfo.py` | Reading imports, exports, library ids, PLT stubs and call sites from a flat PS5 ELF |
| `pkgtool/` | Command-line access to PS5 PKG Tool's package reader (Kraken/NAPS packages). See its README |

Python 3.9+, standard library only. Uses `../self-tools/selflib.py`. `.pkg` input also needs
PowerShell 7 and the package reader from `pkgtool/` (Windows).

These tools ship no Sony or game files and decrypt nothing. You need your own console, your own
dumps, and your own copy of the target firmware's system libraries.

## Tests

```
python -m unittest discover -s tests
```

The tests build a small synthetic module in memory; no game or system files are needed.
