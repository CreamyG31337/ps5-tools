# Recipe: backport a PS5 game to an older firmware, from an untouched dump

This is the whole process, starting from the game exactly as published: no prebuilt
"backport" files from anyone else. It was worked out on a Unity game built with SDK 10.00 and
made to run on FW 4.03. The tools default to 4.03 (`--sdk 0x04000031`), but nothing in the
method is specific to it.

**What a backport is.** Each game executable (`eboot.bin`, every `.prx`/`.sprx`) records the
SDK it was built with, and imports system functions by NID. An older firmware refuses modules
from a newer SDK, and lacks some of the functions. A backport lowers the recorded SDK, then
deals with every missing function and changed interface. The game's data files stay as they
are. Only the executables are replaced, through an overlay folder that a loader (e.g.
ShadowMountPlus's `/data/homebrew/backports/<TITLE_ID>/`) lays over the installed game.

## What you need

- A jailbroken console on the target firmware, with fake-package support (kstuff), an ELF
  loader, an FTP server that decrypts system files on download (ftpsrv), and a backport
  overlay loader (ShadowMountPlus).
- The game's original **fake package** (`.pkg`) or a **folder dump** of its `app0`, with
  fake-signed (decrypted) executables. The base game must also be installed on the console:
  the overlay only replaces executables.
- PC: Python 3.9+. For `.pkg` input also PowerShell 7 and the package reader set up as in
  [`pkgtool/README.md`](pkgtool/README.md) (Windows).
- Optional, for readable reports: an NID database CSV with `nid` and `name` columns, e.g.
  `nids.csv` from [claimore22/ps5rs](https://github.com/claimore22/ps5rs).
- Optional, for diagnosis: a kernel log server payload (klogsrv) and a root shell.

## 1. Build the target firmware's function table (once per firmware)

Download `/system/common/lib/` and `/system/priv/lib/` from the console over ftpsrv. It
decrypts as it sends, so the files arrive as plain ELFs. These are Sony's files: keep them to
yourself. Then:

```
python fw_exports.py syslibs\ --out fw403-exports.tsv --nids nids.csv
```

That gives one row per exported NID (about 24,000 on 4.03). Everything below checks imports
against this table, offline.

## 2. Run the backport

```
python backport.py game.pkg --exports fw403-exports.tsv --nids nids.csv --out work\
```

(or a folder: `python backport.py D:\dumps\GAME-app0 ...`). For every executable it:

1. lowers the module/process param SDK version to `--sdk`;
2. fixes known struct-size changes before calls (`shims.STRUCT_SIZES`), and arguments an
   exported function's older version rejects (`shims.ARG_FIXUPS`, run in the PLT stub);
3. finds imports the target doesn't export (skipping libraries the game ships itself) and
   gives each called one a stand-in: an older NID of the same function (`RENAMES`), a
   real futex wait/wake through FreeBSD's `_umtx_op` for the sync-on-address functions
   (`UMTX_SHIMS` — each stub jumps to a trampoline appended to the module's exec segment,
   which converts the microsecond timeout into the timespec `_umtx_op` takes, so timed
   waits sleep in the kernel too), a known shim (`KNOWN`), or `return 0`.

The output is `work\overlay\` (same paths as app0) and `work\report.txt`. **Read the report.**
Every `ret 0` line is a guess, and the first place to look when something misbehaves. Lines
with `??` or `!!` need attention.

Don't skip any module. Unity games load their plugins (`Media/Plugins/*.prx`: audio engines,
save data, PSN) by name at run time, through P/Invoke. If a plugin is refused, the C# code
gets an exception, initialization stops, and the game renders a black screen at full frame
rate without crashing. The tool processes every `.prx` it finds, plugins included.

## 3. Install and test

Copy `work\overlay\` to `/data/homebrew/backports/<TITLE_ID>/` keeping the paths, and launch the
game. Start a kernel log capture first, so a failure leaves evidence.

**Never read files from a running game's mount over FTP** (`/mnt/sandbox/pfsmnt/<TITLE>-app0`).
Reading it, or listing it during launch or shutdown, has hung the FTP server, blocked the
unmount and rebooted the console. Get files from the package or dump on the PC instead.

## 4. When it doesn't work

| Symptom (kernel log / behaviour) | Meaning | What to do |
|---|---|---|
| loader rejects the module, SDK version | a module still has a newer SDK | check `report.txt` covered it; a module outside app0 paths? |
| `PRX_NOT_RESOLVED_FUNCTION` crash | a missing function was called that has no PLT stub in the scanned module (dlsym, or a module not processed) | map the crash address to the import; add a stand-in |
| runs, black screen, no crash | usually a refused plugin (Unity: `element_lookup() error=2` lines for `Plugins/...`) | make sure every `.prx` was processed and uploaded |
| a feature fails after `ret 0` | the stand-in needs real behaviour (an out-parameter, a handle) | write a `KNOWN` shim in `shims.py` |
| a call returns an error with valid arguments | interface change: a bigger struct, a new argument | add a `STRUCT_SIZES` entry, or a shim |
| a call fails with a generic parameter error and the service never logs the request | the older client library rejects a newer-SDK default before sending (e.g. Mount3's systemBlocks = -1) | find the check in the target's library; add an `ARG_FIXUPS` entry |
| hang in a wait | a missing wait/wake pair | see `UMTX_SHIMS` |
| whole console laggy, system UI "no heart beat" in the log | game threads busy-polling (e.g. a wait stubbed to return at once or sleep briefly) | dump the threads; give the wait a real blocking stand-in |

To see what a thread is doing, a debugger that can read registers and stacks of all threads
(ptrace `PT_GETLWPLIST`/`PT_GETREGS`) helps a lot. Check the obvious first: "stuck" may be a
game running fine behind a black screen.

## 5. Learn from an existing backport, don't depend on it

If someone released a backport of the same game version, compare it with your untouched files
to see what they changed by hand:

```
python diff_backport.py original\eboot.bin released\eboot.bin --nids nids.csv --exports fw403-exports.tsv
```

It labels each change (param field, PLT shim, import rename, code, data). For code changes it
also names the next call, which usually tells what for. It then lists missing functions the
release left alone. Turn each lesson into a general rule in `shims.py`, so it applies to the
untouched dump and to the next game.

What this found on the worked example: the release changed the SDK version and a neighbouring
param field, replaced one PLT stub (scePadIsRemoteController), and changed a struct size from
0x30 to 0x28 before a call to `sceUserServiceGetGamePresets`. It left 8 missing functions
unhandled, so it couldn't have run on stock 4.03 by itself. The param field turned out not to
matter. The other two are now in `shims.py`.

## Worked example (FW 4.03, Unity game, SDK 10.00)

`backport.py` on the original package handled 11 modules: eboot, libc, the IL2CPP module,
PS5Util, 6 plugins and one Sony library the game ships. It found 17 missing functions:
- **eboot (9):** two PS5 Pro checks, two VRR calls and an HTTP/2 setter → `return 0`;
  two GPU functions renamed to their older NIDs; two shims.
- **libc and PS5Util (6):** `sceKernelSyncOnAddressWait`/`Wake` and related functions → real
  futex waits and wakes through `_umtx_op`, with a small trampoline appended to each module's
  exec segment converting the microsecond timeout into the timespec `_umtx_op` takes. Untimed
  waits and waits longer than a second recheck once a second; everything else sleeps in the
  kernel until the value changes or a `Wake` arrives.
- **audio plugin (1):** a 3D-latency setter → `return 0`.

It also fixed one struct size. The game ran with nothing else. It logs that the temporary-data
mount (`/temp0`) fails, which turned out to be harmless.

Saving did not work at first: every `sceSaveDataMount3` returned 0x809F0000 and the save
service never logged the request. The save plugin (Unity savedata, SDK 10) passes
systemBlocks = -1, and the 4.03 client wrapper requires 0 when creating a save. It checks this
before sending anything. The SDK version was ruled out first: the same failure happened with
the whole overlay at 0x04030000. `ARG_FIXUPS` now zeroes the field in Mount3's PLT stub, and
saving and Continue work.
