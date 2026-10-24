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
| `PRX_SCE_MODULE_LOAD_ERROR` on launch, `?? modules not in the exports table` in the report | the module imports a system library the target firmware doesn't have at all | pass `--absent-lib NAME=SUBSTITUTE` |
| menus and UI draw fine, but the game scene is covered in magenta (Unity's error colour) or flickering blocks | GPU-side stand-ins don't match the newer SDK: the `sceAgcCreateInterpolantMapping` rename in `RENAMES` broke an SDK 17 Unity game | put a newer `libSceAgc.sprx` + `libSceAgcDriver.sprx` (SDK already lowered) in the game's `fakelib/` and rerun with `--provided-lib libSceAgc --provided-lib libSceAgcDriver` |
| `GPU Bad packet error:Privilege reg ... opcode:0xc0...... 0 0 0x2bff`, then `0xa0d0c006 (GPU_FAULT_BAD_COMMAND_ASYNC)`, a minute or so in (the opcode varies) | the game's register tables hold the newer SDK's `{-1,-1}` "no register" placeholder, which the older GPU firmware writes to register 0x2bff | rerun with `--pm4-sanitize` (below) |
| no sound at all; `sceAudioOut2PortCreate` returns `0x8026800e`; report says `?? audio: Wwise picks a 7.1.4 output` | the game asks for a 12-channel (7.1.4) output, and 4.03 opens only 1, 2 or 8 channels | rerun with `--audio-71` (Wwise); for other engines, find where the port's channel count is chosen and make it 8 |
| music plays, but positional sounds (wind, footsteps) drop out with headphones; `sceAcmBatchStartBuffers` returns `0x81940006`; report says `?? audio: uses sceAcm_Panner` | with headphones, the game switches to object (3D) audio, and 4.03's kernel rejects its ACM panner batches | keep the game out of headphone mode: find where it reads the headphone bit of `sceAudioOut2GetSpeakerInfo` and clear it (`--patch`) |
| installed as a `.pkg`, the game opens a message like "There may be a problem with the game installation. Please reinstall." and quits (`Returned from main with non-zero`, `0xa0020002`); report says `?? playgo:`. The same dump ran from a folder | the game asks PlayGo where each chunk of its data is, and 4.03's PlayGo answers some of a newer package's chunks with `0x80b20023` | rerun with `--playgo-local` (below) |

**`--provided-lib NAME` (repeatable).** Treats `NAME` as a library the game brings itself, so its
imports are not checked and get no stand-ins. Use it when a newer build of a system library goes into
the game's `fakelib/`, which ShadowMountPlus mounts over the system libraries. The graphics library is the
main case: with a newer `libSceAgc` and `libSceAgcDriver` there, every AGC function resolves natively
instead of through renames and guesses.

**`--absent-lib NAME=SUBSTITUTE` (repeatable).** When a module imports a library that does not
exist on the target firmware (e.g. `libScePsml`), `backport.py` otherwise reports it under `??`
and leaves it alone, so the loader fails to find the module. With `--absent-lib
libScePsml=libSceAjm`, every import of `NAME` that has a PLT stub gets a `KNOWN` shim or
`return 0`, and the dynamic string table entries that name `NAME` as a needed module are
rewritten in place (padded with NULs, so `SUBSTITUTE` must be no longer than `NAME`) to point
at `SUBSTITUTE`, a library the target does have.

**`--patch INNER:VADDR:OLDHEX:NEWHEX` and `--patch-file FILE` (repeatable).** Applies a known
per-module byte change at flat-ELF virtual address `VADDR` in module `INNER` (e.g.
`eboot.bin:123400:cd41:6690` to NOP an assertion trap after a call the older firmware rejects).
`backport.py` checks that the flat ELF has `OLDHEX` at `VADDR` (or `NEWHEX`, reported as
`already`) before patching the SELF in place. `--patch-file` reads one spec per line (`#`
comments allowed) so game-specific patch lists can be kept outside the repo.

**`--pm4-sanitize`.** Some SDK 11+ engines leave a `{0xFFFFFFFF, 0xFFFFFFFF}` placeholder in
the tables of indirect register loads (PM4 `0x63`/`0x64`/`0x9F`). Newer GPU firmware skips it;
4.03's writes it to SH register `0x2C00 + 0xFFFFFFFF = 0x2BFF` and kills the game with
"Privilege reg ... 0x2bff". The tables are filled by inlined engine code, so there is no single
instruction to patch. With this flag every direct call to `sceAgcDriverSubmitDcb` /
`sceAgcDriverAgrSubmitDcb` is pointed at a small routine appended to the exec segment (like the
umtx trampoline). It walks the command buffer, follows chained jumps, drops the placeholder
entries and lowers each table's count before the real submit. The report lists each redirected
call (`pm4     call ...`). Found on Crimson Desert (SDK 11.00), where it stopped the fault; see
`shims.PM4_SUBMITS`. It only touches direct `call`s: a game that submits through a function
pointer, or through other submit functions, needs those added.

**Audio: `?? audio:` report lines and `--audio-71`.** Audio failures happen inside functions the
target exports, so the import check can't see them. `backport.py` flags the two known cases instead.
A game that imports `sceAudioOut2PortCreate` and contains Wwise's 7.1 / 7.1.4 channel-config switch is
reported. `--audio-71` makes that switch always choose 7.1, so Wwise mixes 8 channels and the port opens.
Patching only the port's channel count is not enough: the mix stays 12-channel and crackles. A game
that imports `sceAcm_Panner` gets a warning about headphone dropouts, which needs a game-specific
patch. When a game is silent or drops sounds, log what every audio call returns with a debugger before
guessing. Most of these calls return an error code, not a crash.

**PlayGo: `?? playgo:` report lines and `--playgo-local`.** A game installed as a package can ask
`scePlayGoGetLocus` which chunks of its data are on the drive before it opens them. For a newer package,
4.03's PlayGo can answer with `0x80b20023` instead of "local". The game then decides its installation
is broken, shows its own "please reinstall" message and exits. A third-party backport of the same game
fails the same way, because the check is in the game's own startup. Run from a folder, PlayGo isn't
involved, which is why the same dump can work there. `--playgo-local` replaces the import's PLT stub with
12 bytes that mark every requested chunk as local (3) and return 0. That is true for a fake package,
which installs in full. Found on Crimson Desert (Enhanced, SDK 11.00), where the error came from chunk
group `packages/0030`. The report lists every game that imports the function, including games that run
fine, so only use the flag when the game reports a broken install.

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
