# pkgtool: read PS5 fake packages from the command line

`backport.py` can take a `.pkg` directly. It reads the package with **ProsperoPkgTool**, the
reader inside [PS5 PKG Tool](https://github.com/pearlxcore/PS5PKGTool) by pearlxcore. Version
1.3.0 (2026-10-11) decodes Kraken-compressed (NAPS) packages and packages with a plaintext
outer PFS, which older readers such as LibProsperoPKG 2.5 can't.

PS5 PKG Tool is a Windows GUI, but its reader has a full command line (`img_file_list`,
`img_extract`, `img_verify`, ...) with no launcher. It's packed into the exe as a .NET
single-file bundle. Nothing from it is redistributed here. Get it yourself and unpack it:

1. Download `PS5PKGTool-v1.3.0.zip` from the project's releases and extract it.
2. `python -I unbundle.py "<extracted>\PS5 PKG Tool.exe"`. This fills `unbundled\` beside the
   script and copies `oo2core_9_win64.dll` from the exe's folder.
3. Test it: `pwsh ppt.ps1 img_file_list game.pkg`

Requires PowerShell 7 (`pwsh`, which brings the .NET runtime). The release is Windows x64 only,
because of the Oodle DLL.

Examples:
```
pwsh ppt.ps1 img_file_list game.pkg
pwsh ppt.ps1 img_extract game.pkg out\                               # everything
pwsh ppt.ps1 img_extract "game.pkg:/uroot/Media/Plugins" out\         # a folder (flattened)
pwsh ppt.ps1 img_extract "game.pkg:/uroot/eboot.bin" out\eboot.bin    # one file
```
Inner paths start with `/uroot/`. Extracting a folder puts its files directly into `out\`.

Retail (encrypted) packages need their image keys and are out of scope.
