"""Unit tests for selflib and self-tools CLI scripts.

Uses only the Python standard library and synthetic in-memory SELFs.
Contains no external dependencies and no proprietary or game-specific data.
"""
from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import unittest

# Ensure tools directory is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import selflib


def build_synthetic_self(
    module_sdk: int = 0x05000033,
    proc_sdk: int = 0x05000033,
    soname: str = "sample_plugin.prx",
    orig_filename: str = "src/plugins/sample_plugin.prx",
    module_name: str = "sample_module",
) -> bytes:
    """Construct a minimal synthetic fake-signed SELF file in memory."""
    # 1. String table
    soname_b = soname.encode("utf-8") + b"\0"
    orig_b = orig_filename.encode("utf-8") + b"\0"
    mod_b = module_name.encode("utf-8") + b"\0"

    strtab = b"\x00" + soname_b + orig_b + mod_b
    soname_idx = 1
    orig_idx = 1 + len(soname_b)
    mod_idx = orig_idx + len(orig_b)

    # 2. Dynamic table
    strtab_vaddr = 0x1100
    dyn_vaddr = 0x1200
    dyn_entries = [
        (selflib.DT_STRTAB, strtab_vaddr),
        (selflib.DT_SONAME, soname_idx),
        (selflib.DT_SCE_ORIGINAL_FILENAME, orig_idx),
        (selflib.DT_SCE_MODULE_INFO, mod_idx),
        (selflib.DT_NULL, 0),
    ]
    dyn_bytes = b"".join(struct.pack("<qQ", t, v) for t, v in dyn_entries)

    # 3. Param blocks:
    # module param: size u64 = 0x20, magic 0x3C13F4BF, pad 8, sdk u32
    mod_param = struct.pack("<QI8sI", 0x20, 0x3C13F4BF, b"\x00" * 8, module_sdk) + b"\x00" * 12
    # proc param: size u64 = 0x60, magic 'ORBI', pad 8, sdk u32
    proc_param = struct.pack("<Q4s8sI", 0x60, b"ORBI", b"\x00" * 8, proc_sdk) + b"\x00" * 76

    payload = bytearray(0x1000)
    payload[0 : len(mod_param)] = mod_param
    payload[0x40 : 0x40 + len(proc_param)] = proc_param
    payload[0x100 : 0x100 + len(strtab)] = strtab
    payload[0x200 : 0x200 + len(dyn_bytes)] = dyn_bytes

    elf_hdr = bytearray(64)
    elf_hdr[:4] = b"\x7fELF"
    elf_hdr[4] = 2  # 64-bit
    elf_hdr[5] = 1  # little-endian
    elf_hdr[6] = 1  # version
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        elf_hdr,
        0x10,
        2,  # ET_EXEC
        0x3E,  # EM_X86_64
        1,  # EV_CURRENT
        0x1000,  # e_entry
        64,  # e_phoff
        0,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        2,  # e_phnum
        0,
        0,
        0,
    )

    ph0 = struct.pack("<IIQQQQQQ", 1, 7, 0x1000, 0x1000, 0x1000, len(payload), len(payload), 0x1000)
    ph1 = struct.pack("<IIQQQQQQ", 2, 6, 0x1200, 0x1200, 0x1200, len(dyn_bytes), len(dyn_bytes), 8)
    ph_table = ph0 + ph1

    seg_offset = 0x200
    self_size = seg_offset + len(payload)

    self_hdr = struct.pack(
        "<4sIHHIQHH4s",
        selflib.SELF_MAGIC,
        1,  # version
        1,  # mode
        0x20,  # header_size
        0x40,  # meta_size
        self_size,  # file_size
        1,  # num_entries
        2,  # flags
        b"\x00" * 4,
    )

    seg_entry = struct.pack("<QQQQ", 0x800, seg_offset, len(payload), len(payload))

    raw = bytearray(self_size)
    raw[0:0x20] = self_hdr
    raw[0x20:0x40] = seg_entry
    raw[0x40:0x80] = elf_hdr
    raw[0x80 : 0x80 + len(ph_table)] = ph_table
    raw[seg_offset : seg_offset + len(payload)] = payload

    return bytes(raw)


class TestSelfLib(unittest.TestCase):
    def setUp(self):
        self.synthetic_self = build_synthetic_self(
            module_sdk=0x05000033,
            proc_sdk=0x05000033,
            soname="sample_plugin.prx",
            orig_filename="src/plugins/sample_plugin.prx",
            module_name="sample_module",
        )

    def test_parse_self_info(self):
        """Test parsing header, segment table, dynamic names, and SDK param blocks."""
        info = selflib.parse_self_info(self.synthetic_self)
        self.assertEqual(info.file_size, len(self.synthetic_self))
        self.assertEqual(info.soname, "sample_plugin.prx")
        self.assertEqual(info.orig_filename, "src/plugins/sample_plugin.prx")
        self.assertEqual(info.module_name, "sample_module")
        self.assertEqual(info.module_sdk, 0x05000033)
        self.assertEqual(info.proc_sdk, 0x05000033)

    def test_ps4_magic_same_layout(self):
        """A PS5 SELF carrying the PS4 magic parses the same and keeps its magic when patched."""
        ps4 = selflib.PS4_SELF_MAGIC + self.synthetic_self[4:]
        self.assertTrue(selflib.is_self(ps4))
        info = selflib.parse_self_info(ps4)
        self.assertEqual(info.module_name, "sample_module")
        self.assertEqual(selflib.rebuild_flat_elf(ps4), selflib.rebuild_flat_elf(self.synthetic_self))
        self.assertFalse(selflib.is_self(b"\x00\x00\x00\x00" + self.synthetic_self[4:]))
        self.assertEqual(len(info.param_blocks), 2)

        types = {b.block_type for b in info.param_blocks}
        self.assertEqual(types, {"module", "proc"})

    def test_patch_sdk_in_memory(self):
        """Test patching SDK in memory and verify exact byte modifications."""
        data = bytearray(self.synthetic_self)
        new_sdk = 0x04030000

        # Patch only module param
        modified = selflib.patch_sdk_in_memory(data, new_sdk=new_sdk, target="module")
        self.assertEqual(len(modified), 1)
        mod_block, old_val = modified[0]
        self.assertEqual(mod_block.block_type, "module")
        self.assertEqual(old_val, 0x05000033)

        # Check byte difference against original
        diff_offsets = [i for i in range(len(data)) if data[i] != self.synthetic_self[i]]
        param_sdk_off = mod_block.offset + 0xC
        # In 0x05000033 -> 0x04030000:
        # byte 0: 0x33 -> 0x00 (diff)
        # byte 1: 0x00 -> 0x00 (same)
        # byte 2: 0x00 -> 0x03 (diff)
        # byte 3: 0x05 -> 0x04 (diff)
        # All differences must fall precisely within [param_sdk_off, param_sdk_off+4)
        for offset in diff_offsets:
            self.assertTrue(param_sdk_off <= offset < param_sdk_off + 4)

        # Re-parse and verify
        reparsed = selflib.parse_self_info(bytes(data))
        self.assertEqual(reparsed.module_sdk, new_sdk)
        self.assertEqual(reparsed.proc_sdk, 0x05000033)

    def test_set_sdk_cli(self):
        """Test set_sdk.py CLI script execution."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            in_file = os.path.join(tmp_dir, "input.self")
            out_file = os.path.join(tmp_dir, "output.self")
            with open(in_file, "wb") as f:
                f.write(self.synthetic_self)

            script_path = os.path.join(BASE_DIR, "set_sdk.py")
            cmd = [sys.executable, script_path, in_file, out_file, "04030000"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("Successfully patched", res.stdout)

            with open(out_file, "rb") as f:
                patched_data = f.read()

            info = selflib.parse_self_info(patched_data)
            self.assertEqual(info.module_sdk, 0x04030000)
            self.assertEqual(info.proc_sdk, 0x04030000)

            # Test refusal to overwrite without --force
            res_fail = subprocess.run(cmd, capture_output=True, text=True)
            self.assertNotEqual(res_fail.returncode, 0)
            self.assertIn("already exists", res_fail.stderr)

            # Test with --force
            res_force = subprocess.run(cmd + ["--force"], capture_output=True, text=True)
            self.assertEqual(res_force.returncode, 0)

    def test_self_info_cli(self):
        """Test self_info.py CLI with text and --json flags."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            in_file = os.path.join(tmp_dir, "test.prx")
            with open(in_file, "wb") as f:
                f.write(self.synthetic_self)

            script_path = os.path.join(BASE_DIR, "self_info.py")
            # Text output
            res_txt = subprocess.run([sys.executable, script_path, in_file], capture_output=True, text=True)
            self.assertEqual(res_txt.returncode, 0)
            self.assertIn("sample_module", res_txt.stdout)

            # JSON output
            res_json = subprocess.run([sys.executable, script_path, in_file, "--json"], capture_output=True, text=True)
            self.assertEqual(res_json.returncode, 0)
            self.assertIn('"module_name": "sample_module"', res_json.stdout)
            self.assertIn('"module_sdk": "0x05000033"', res_json.stdout)

    def test_find_and_cut_self(self):
        """Test find_selfs.py and cut_self.py on a container holding a SELF at offset 0x20000."""
        target_offset = 0x20000
        container_size = target_offset + len(self.synthetic_self) + 0x10000

        container_data = bytearray(container_size)
        # Fill padding with identifiable pattern
        container_data[:target_offset] = b"\xAA" * target_offset
        container_data[target_offset : target_offset + len(self.synthetic_self)] = self.synthetic_self
        container_data[target_offset + len(self.synthetic_self) :] = b"\xBB" * 0x10000

        with tempfile.TemporaryDirectory() as tmp_dir:
            container_path = os.path.join(tmp_dir, "container.bin")
            with open(container_path, "wb") as f:
                f.write(container_data)

            # 1. Test find_selfs.py
            find_script = os.path.join(BASE_DIR, "find_selfs.py")
            cmd_find = [sys.executable, find_script, container_path, "--align", "0x10000"]
            res_find = subprocess.run(cmd_find, capture_output=True, text=True)
            self.assertEqual(res_find.returncode, 0, res_find.stderr)
            self.assertIn(f"{target_offset:#012x}", res_find.stdout)
            self.assertIn("0x05000033", res_find.stdout)

            # 2. Test cut_self.py
            cut_script = os.path.join(BASE_DIR, "cut_self.py")
            extracted_path = os.path.join(tmp_dir, "extracted.self")
            cmd_cut = [sys.executable, cut_script, container_path, f"{target_offset:#x}", extracted_path]
            res_cut = subprocess.run(cmd_cut, capture_output=True, text=True)
            self.assertEqual(res_cut.returncode, 0, res_cut.stderr)

            # Verify extracted bytes match original synthetic SELF exactly
            with open(extracted_path, "rb") as f:
                extracted_data = f.read()

            self.assertEqual(len(extracted_data), len(self.synthetic_self))
            self.assertEqual(extracted_data, self.synthetic_self)
            self.assertEqual(hashlib.sha256(extracted_data).hexdigest(), hashlib.sha256(self.synthetic_self).hexdigest())

    def test_cli_help(self):
        """Verify each tool responds successfully to --help."""
        scripts = [
            "set_sdk.py",
            "self_info.py",
            "resolve_call.py",
            "find_selfs.py",
            "cut_self.py",
        ]
        for s in scripts:
            script_path = os.path.join(BASE_DIR, s)
            res = subprocess.run([sys.executable, script_path, "--help"], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"{s} failed --help: {res.stderr}")
            self.assertIn("usage:", res.stdout.lower())


if __name__ == "__main__":
    unittest.main()
