# self-tools

A lightweight, dependency-free Python toolkit for inspecting, extracting, analyzing, and patching PlayStation fake-signed (decrypted / unencrypted) SELF binaries.

Written in standard Python 3.9+ with zero external dependencies.

---

## Important Limitation

> [!IMPORTANT]
> These tools operate exclusively on **fake-signed, decrypted, or plaintext SELF binaries** (magic `54 14 F5 EE`). Standard retail encrypted SELFs require console hardware keys and must be decrypted before these tools can process them.

---

## SDK Version Encoding

The SDK version is a little-endian 32-bit value whose hex digits read as the version:
- `0x04030000` = Firmware / SDK **4.03**
- `0x04500000` = Firmware / SDK **4.50**
- `0x05000033` = Firmware / SDK **5.00**
- `0x05500000` = Firmware / SDK **5.50**

The major version corresponds to `(sdk >> 24) & 0xFF`, the minor version to `(sdk >> 16) & 0xFF`, and maintenance/build revisions to the lower 16 bits.

Parameter blocks in SELFs:
- **Module Param:** Identified by magic `0x3C13F4BF`, preceded by a 64-bit block size (`0x20` or `0x60`). The 32-bit SDK version is at offset `+0xC` from the magic.
- **Process Param:** Identified by ASCII magic `ORBI`, preceded by a 64-bit block size (`0x20` or `0x60`). The 32-bit SDK version is at offset `+0xC` from the magic.

---

## Tools Overview

### 1. `selflib.py` (Core Library)
Shared module providing parsing and manipulation routines:
- Parses SELF headers, segment tables, and embedded ELF64 program headers.
- Rebuilds flat ELF images in memory from segment tables.
- Translates virtual addresses to flat file offsets via `PT_LOAD` segments.
- Parses `PT_DYNAMIC` tables to resolve `DT_SONAME`, `DT_SCE_ORIGINAL_FILENAME`, and `DT_SCE_MODULE_INFO`.
- Locates and validates module and process parameter blocks.
- Resolves GOT relocations (`DT_JMPREL`) and decodes Sony base64 NID library/module identifiers.

---

### 2. `set_sdk.py`
Patches the SDK version in module and/or process parameter blocks within a fake-signed SELF.

```text
usage: set_sdk.py [-h] [--only {module,proc}] [--from FROM_SDK] [-f]
                  IN OUT SDK_HEX
```

#### Arguments
- `IN`: Path to input SELF file.
- `OUT`: Path to write the patched SELF file.
- `SDK_HEX`: Target SDK version in hexadecimal (e.g. `04030000` or `0x04030000`).
- `--only {module,proc}`: Restrict modifications to only module params or only proc params.
- `--from FROM_SDK`: Only patch blocks currently matching this hex SDK version.
- `-f`, `--force`: Overwrite the destination file if it already exists.

#### Examples
```bash
# Patch all parameter blocks down to 4.03
python set_sdk.py eboot.bin eboot.patched.bin 04030000

# Patch only module parameter blocks in a PRX
python set_sdk.py sample.prx sample.patched.prx 04030000 --only module

# Overwrite output and only patch if current version is 5.00
python set_sdk.py input.self output.self 04030000 --from 05000033 --force
```

---

### 3. `self_info.py`
Inspects one or more SELF files or directories and extracts module metadata, internal names, original build paths, and SDK versions.

```text
usage: self_info.py [-h] [--json] FILE_OR_DIR [FILE_OR_DIR ...]
```

#### Arguments
- `FILE_OR_DIR`: One or more SELF files or directories to inspect recursively.
- `--json`: Output full metadata in machine-readable JSON format.

#### Examples
```bash
# Inspect a single executable
python self_info.py eboot.bin

# Inspect all modules in a directory
python self_info.py modules/ prx/

# Export module information to JSON
python self_info.py modules/*.prx --json > modules.json
```

---

### 4. `resolve_call.py`
Resolves crash backtrace return addresses to imported system functions via the PLT and GOT.

```text
usage: resolve_call.py [-h] SELF LOAD_BASE RET_ADDR [RET_ADDR ...]
```

#### Arguments
- `SELF`: Path to the executable SELF file.
- `LOAD_BASE`: Runtime base address in hex (e.g. `0x400000` or `0`).
- `RET_ADDR`: One or more return addresses from a crash backtrace.

#### Examples
```bash
# Resolve backtrace addresses from a crash log
python resolve_call.py eboot.bin 0x400000 0x1234567 0x89abcd
```

---

### 5. `find_selfs.py`
Scans large binary containers (e.g. packages, uncompressed disc images, or memory dumps) for embedded fake-signed SELFs.

```text
usage: find_selfs.py [-h] [--start START] [--end END] [--align ALIGN]
                     CONTAINER
```

#### Arguments
- `CONTAINER`: Container file to scan.
- `--start START`: Starting file offset (default: `0`).
- `--end END`: Ending file offset (default: container file size).
- `--align ALIGN`: Scan alignment boundary (default: `0x10000` / 64 KiB).

#### Examples
```bash
# Scan a package for embedded binaries
python find_selfs.py package.pkg

# Scan specific offset range with 16 KiB alignment
python find_selfs.py dump.img --start 0x10000 --align 0x4000
```

---

### 6. `cut_self.py`
Extracts an embedded fake-signed SELF from a container file at a specified offset, verifying header magic and exact segment bounds.

```text
usage: cut_self.py [-h] [-f] CONTAINER OFFSET OUT
```

#### Arguments
- `CONTAINER`: Container file to extract from.
- `OFFSET`: Byte offset of the SELF within the container (hex or decimal).
- `OUT`: Output destination file.
- `-f`, `--force`: Overwrite output file if it exists.

#### Examples
```bash
# Extract an eboot at offset 0x70000
python cut_self.py package.pkg 0x70000 eboot.bin

# Extract a module from an offset with force overwrite
python cut_self.py package.pkg 0x1a2b0000 module.prx --force
```

---

## Running Unit Tests

A comprehensive unit test suite is included in `tests/`. All tests use synthetic in-memory SELFs and require no external files or packages.

Run the test suite from the `self-tools` folder:
```bash
python -m unittest discover -s tests
```
