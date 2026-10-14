#!/usr/bin/env python3
"""
Unit and integration tests for ps5_orphan_scan.py.

Uses Python stdlib unittest. Validates:
1. Unix ls -l parsing fallback
2. .rif license extraction
3. Firmware version string parsing
4. Recursive directory size calculation (ignoring directory entry sizes like 65536)
5. Extracted game folder detection under /data, /mnt/usb*, /mnt/ext*
6. Severity downgrades (empty DLC stub -> LOW, NPXS system placeholders -> INFO, homebrew without pkg/rif -> INFO)
7. bgft task file and size listing
8. Disk usage table clutter suppression (0 B system apps hidden unless --all)
9. Suggested manual cleanup section generation with warning line
10. Full offline scan against a mock console root.
"""

import importlib.util
import json
import os
import shutil
import sqlite3
import tempfile
import unittest

script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ps5_orphan_scan.py")
spec = importlib.util.spec_from_file_location("ps5_orphan_scan", script_path)
orphan_scan_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(orphan_scan_mod)

FileInfo = orphan_scan_mod.FileInfo
LocalConsoleFS = orphan_scan_mod.LocalConsoleFS
OrphanScanner = orphan_scan_mod.OrphanScanner
format_size = orphan_scan_mod.format_size
is_homebrew_title = orphan_scan_mod.is_homebrew_title
is_system_npxs_title = orphan_scan_mod.is_system_npxs_title
parse_app_json = orphan_scan_mod.parse_app_json
parse_fw_string = orphan_scan_mod.parse_fw_string
parse_param_json = orphan_scan_mod.parse_param_json
parse_rif_content = orphan_scan_mod.parse_rif_content
parse_unix_list_line = orphan_scan_mod.parse_unix_list_line


class TestParsing(unittest.TestCase):
    """Test string, listing, and file parsing routines."""

    def test_parse_unix_list_line_file(self):
        line = "-rwxrwx--- 1 0 0 62849024 Oct 12 05:33 app.pkg"
        info = parse_unix_list_line(line, "/user/app/ITEM00001")
        self.assertIsNotNone(info)
        self.assertEqual(info.name, "app.pkg")
        self.assertEqual(info.path, "/user/app/ITEM00001/app.pkg")
        self.assertFalse(info.is_dir)
        self.assertEqual(info.size, 62849024)

    def test_parse_unix_list_line_directory(self):
        line = "drwxr-xr-x 2 0 0 65536 Oct 12 06:50 user"
        info = parse_unix_list_line(line, "/")
        self.assertIsNotNone(info)
        self.assertEqual(info.name, "user")
        self.assertEqual(info.path, "/user")
        self.assertTrue(info.is_dir)

    def test_parse_unix_list_line_dots(self):
        self.assertIsNone(parse_unix_list_line("drwxrwxrwx 1 0 0 16384 Dec 31 17:00 .", "/"))
        self.assertIsNone(parse_unix_list_line("drwxrwxrwx 1 0 0 16384 Dec 31 17:00 ..", "/"))
        self.assertIsNone(parse_unix_list_line("total 12345", "/"))
        self.assertIsNone(parse_unix_list_line("", "/"))

    def test_parse_unix_list_line_spaces(self):
        line = "-rwxrwx--- 1 0 0 123456 Dec 31 2024 some name with spaces.pkg"
        info = parse_unix_list_line(line, "/data")
        self.assertIsNotNone(info)
        self.assertEqual(info.name, "some name with spaces.pkg")
        self.assertEqual(info.path, "/data/some name with spaces.pkg")
        self.assertEqual(info.size, 123456)

    def test_parse_unix_list_line_symlink(self):
        line = "lrwxrwxrwx 1 0 0 15 Oct 12 06:50 link_app -> ../other/app"
        info = parse_unix_list_line(line, "/user")
        self.assertIsNotNone(info)
        self.assertEqual(info.name, "link_app")
        self.assertEqual(info.path, "/user/link_app")

    def test_parse_dos_list_line(self):
        line_dir = "05-14-21  12:30AM  <DIR>  appmeta"
        info_dir = parse_unix_list_line(line_dir, "/user")
        self.assertIsNotNone(info_dir)
        self.assertEqual(info_dir.name, "appmeta")
        self.assertTrue(info_dir.is_dir)

        line_file = "05-14-21  12:30AM  1048576  game.pkg"
        info_file = parse_unix_list_line(line_file, "/data")
        self.assertIsNotNone(info_file)
        self.assertEqual(info_file.name, "game.pkg")
        self.assertFalse(info_file.is_dir)
        self.assertEqual(info_file.size, 1048576)

    def test_parse_fw_string(self):
        fw_int = parse_fw_string("4.03")
        self.assertEqual(fw_int, 0x0403000000000000)

        fw_int_5 = parse_fw_string("5.00")
        self.assertGreater(fw_int_5, fw_int)

        fw_hex = parse_fw_string("0x0403000000000000")
        self.assertEqual(fw_hex, 0x0403000000000000)

    def test_parse_rif_content(self):
        # Sample fake rif data with Content ID embedded
        raw = b"rifa" + b"X" * 16 + b"UP9000-CUSA00359_00-UNTILDAWN0000001" + b"Y" * 16
        cid, tid = parse_rif_content(raw, "some_license.rif")
        self.assertEqual(cid, "UP9000-CUSA00359_00-UNTILDAWN0000001")
        self.assertEqual(tid, "CUSA00359")

        # Filename only
        cid2, tid2 = parse_rif_content(b"", "fakeIV0002-ITEM00001_00.rif")
        self.assertEqual(tid2, "ITEM00001")


class TestReviewerFixes(unittest.TestCase):
    """Specific unit tests targeting the reviewer findings in TASK-orphan-scan-fixes.md."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ps5_test_fixes_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_recursive_directory_size_excludes_dir_entry_sizes(self):
        """Item 1: Sizes must recurse into subdirectories and must NOT count a directory's own size (e.g. 65536)."""
        bp_dir = os.path.join(self.test_dir, "data", "homebrew", "backports", "PPSA00001")
        os.makedirs(os.path.join(bp_dir, "fakelib"), exist_ok=True)
        os.makedirs(os.path.join(bp_dir, "prx"), exist_ok=True)

        with open(os.path.join(bp_dir, "eboot.bin"), "wb") as f:
            f.write(b"E" * 1000)
        with open(os.path.join(bp_dir, "fakelib", "lib.sprx"), "wb") as f:
            f.write(b"F" * 2000)
        with open(os.path.join(bp_dir, "prx", "game.prx"), "wb") as f:
            f.write(b"P" * 3000)

        fs = LocalConsoleFS(self.test_dir)
        total_size, all_files = fs.get_dir_tree("/data/homebrew/backports/PPSA00001")

        # Exactly 1000 + 2000 + 3000 = 6000 bytes
        self.assertEqual(total_size, 6000)
        self.assertEqual(len(all_files), 3)

    def test_extracted_game_folder_detection(self):
        """Item 2: Any dir in /data, /mnt/usb*, /mnt/ext* starting with Title ID is detected as extracted game."""
        data_dir = os.path.join(self.test_dir, "data", "PPSA00002-app0")
        os.makedirs(data_dir, exist_ok=True)
        # Create a file inside it
        with open(os.path.join(data_dir, "game.dat"), "wb") as f:
            f.write(b"D" * 5000)

        fs = LocalConsoleFS(self.test_dir)
        scanner = OrphanScanner(fs=fs, console_fw="4.03")
        scanner.build_inventory()
        scanner.run_checks()

        self.assertIn("PPSA00002", scanner.inventory)
        self.assertEqual(scanner.inventory["PPSA00002"].total_size_bytes, 5000)

        c12_findings = [f for f in scanner.findings if f.check_id == 12]
        self.assertEqual(len(c12_findings), 1)
        self.assertEqual(c12_findings[0].title_id, "PPSA00002")
        self.assertEqual(c12_findings[0].severity, "MEDIUM")  # <= 1 GB is MEDIUM

    def test_empty_dlc_stub_downgraded_to_low(self):
        """Item 3a: Empty /user/appmeta/addcont/<TID> is reported as LOW severity leftover DLC metadata stub."""
        stub_dir = os.path.join(self.test_dir, "user", "appmeta", "addcont", "PPSA00001")
        os.makedirs(stub_dir, exist_ok=True)

        fs = LocalConsoleFS(self.test_dir)
        scanner = OrphanScanner(fs=fs, console_fw="4.03")
        scanner.build_inventory()
        scanner.run_checks()

        c4_findings = [f for f in scanner.findings if f.check_id == 4 and f.title_id == "PPSA00001"]
        self.assertEqual(len(c4_findings), 1)
        self.assertEqual(c4_findings[0].severity, "LOW")
        self.assertIn("metadata stub (empty)", c4_findings[0].explanation.lower())

    def test_npxs_system_placeholder_downgraded_to_info(self):
        """Item 3b: NPXS40172 with 0-byte app.pkg, no appmeta, and no app.db row reported at most INFO."""
        app_dir = os.path.join(self.test_dir, "user", "app", "NPXS40172")
        os.makedirs(app_dir, exist_ok=True)
        with open(os.path.join(app_dir, "app.pkg"), "wb") as f:
            pass  # 0-byte

        fs = LocalConsoleFS(self.test_dir)
        scanner = OrphanScanner(fs=fs, console_fw="4.03")
        scanner.build_inventory()
        scanner.run_checks()

        npxs_findings = [f for f in scanner.findings if f.title_id == "NPXS40172"]
        self.assertTrue(len(npxs_findings) > 0)
        for f in npxs_findings:
            self.assertEqual(f.severity, "INFO")

    def test_homebrew_without_pkg_or_rif_reported_as_info(self):
        """Item 3c: Homebrew without app.pkg (FAKE10101) or without .rif reported as INFO."""
        # FAKE10101 with only sce_sys
        fake_dir = os.path.join(self.test_dir, "user", "app", "FAKE10101", "sce_sys")
        os.makedirs(fake_dir, exist_ok=True)
        with open(os.path.join(fake_dir, "param.sfo"), "wb") as f:
            f.write(b"param")

        fs = LocalConsoleFS(self.test_dir)
        scanner = OrphanScanner(fs=fs, console_fw="4.03")
        scanner.build_inventory()
        scanner.run_checks()

        fake_findings = [f for f in scanner.findings if f.title_id == "FAKE10101"]
        for f in fake_findings:
            if f.check_id in (3, 6):
                self.assertEqual(f.severity, "INFO")

    def test_bgft_tasks_list_files_and_sizes(self):
        """Item 3d: bgft tasks list the files and their sizes in each task dir, severity MEDIUM."""
        task_dir = os.path.join(self.test_dir, "user", "bgft", "task", "00000001")
        os.makedirs(task_dir, exist_ok=True)
        with open(os.path.join(task_dir, "d0.pdb"), "wb") as f:
            f.write(b"D" * 911)
        with open(os.path.join(task_dir, "f0.pdb"), "wb") as f:
            pass

        fs = LocalConsoleFS(self.test_dir)
        scanner = OrphanScanner(fs=fs, console_fw="4.03")
        scanner.build_inventory()
        scanner.run_checks()

        task_findings = [f for f in scanner.findings if f.check_id == 7]
        self.assertEqual(len(task_findings), 1)
        self.assertEqual(task_findings[0].severity, "MEDIUM")
        self.assertIn("d0.pdb", task_findings[0].explanation)
        self.assertIn("f0.pdb", task_findings[0].explanation)

    def test_disk_usage_table_clutter_and_all_flag(self):
        """Item 4: Hide 0 B non-homebrew NPXS system apps with no findings unless show_all=True."""
        db_path = os.path.join(self.test_dir, "system_data", "priv", "mms", "app.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("CREATE TABLE tbl_contentinfo (titleId TEXT, titleName TEXT, metaDataPath TEXT)")
        c.execute("INSERT INTO tbl_contentinfo VALUES ('NPXS40032', 'PlayStation Now', '/system_ex/apps/NPXS40032')")
        conn.commit()
        conn.close()

        fs = LocalConsoleFS(self.test_dir)
        scanner = OrphanScanner(fs=fs, console_fw="4.03")
        scanner.build_inventory()
        scanner.run_checks()

        rep_default = scanner.generate_report(show_all=False)
        self.assertNotIn("NPXS40032", rep_default)
        self.assertIn("Hidden", rep_default)

        rep_all = scanner.generate_report(show_all=True)
        self.assertIn("NPXS40032", rep_all)

    def test_suggested_manual_cleanup_section(self):
        """Item 5: Suggested manual cleanup section includes console paths, space saved, and warning."""
        # Create an extracted dump folder
        data_dir = os.path.join(self.test_dir, "data", "PPSA00002-app0")
        os.makedirs(data_dir, exist_ok=True)
        with open(os.path.join(data_dir, "file.bin"), "wb") as f:
            f.write(b"X" * 1024)

        fs = LocalConsoleFS(self.test_dir)
        scanner = OrphanScanner(fs=fs, console_fw="4.03")
        scanner.build_inventory()
        scanner.run_checks()

        report = scanner.generate_report()
        self.assertIn("SUGGESTED MANUAL CLEANUP", report)
        self.assertIn("WARNING: Do NOT delete anything under /user/app", report)
        self.assertIn("/data/PPSA00002-app0", report)

        suggestions = scanner.get_manual_cleanup_suggestions()
        self.assertTrue(len(suggestions) > 0)
        self.assertEqual(suggestions[0]["path"], "/data/PPSA00002-app0")


class TestOfflineScan(unittest.TestCase):
    """Test full scanner functionality against a complete mock local filesystem."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ps5_test_root_")

        def make_file(rel_path: str, content: bytes = b""):
            full = os.path.join(self.test_dir, rel_path.lstrip("/\\"))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as f:
                f.write(content)
            return full

        self.make_file = make_file

        # Setup mock app.db
        db_path = os.path.join(self.test_dir, "system_data", "priv", "mms", "app.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute(
            """
            CREATE TABLE tbl_contentinfo (
                titleId TEXT PRIMARY KEY,
                contentId TEXT,
                titleName TEXT,
                metaDataPath TEXT
            )
            """
        )
        c.execute(
            "INSERT INTO tbl_contentinfo VALUES (?, ?, ?, ?)",
            ("CLEAN0001", "UP0001-CLEAN0001_00-CLEAN00000000001", "Clean Title", "/user/appmeta/CLEAN0001"),
        )
        c.execute(
            "INSERT INTO tbl_contentinfo VALUES (?, ?, ?, ?)",
            ("DBNOR0001", "UP0001-DBNOR0001_00-DBONLY00000000001", "DB Only Title", "/user/appmeta/DBNOR0001"),
        )
        conn.commit()
        conn.close()

        # Clean title files
        make_file("user/app/CLEAN0001/app.pkg", b"P" * (5 * 1024 * 1024))
        clean_param = json.dumps({
            "titleId": "CLEAN0001",
            "titleName": "Clean Title",
            "requiredSystemSoftwareVersion": "0x0300000000000000",
        }).encode("utf-8")
        make_file("user/appmeta/CLEAN0001/param.json", clean_param)
        make_file("user/appmeta/CLEAN0001/icon0.png", b"icon_data")

        # Check 1: app content with no appmeta (ORPH10001)
        make_file("user/app/ORPH10001/app.pkg", b"P" * (2 * 1024 * 1024))

        # Check 2: appmeta with no app content (ORPH20001)
        orph2_param = json.dumps({"titleId": "ORPH20001", "titleName": "Dead Registration"}).encode("utf-8")
        make_file("user/appmeta/ORPH20001/param.json", orph2_param)

        # Check 3: app dir with 0-byte app.pkg, missing app.pkg, and temp files
        make_file("user/app/ORPH30001/app.pkg", b"")
        make_file("user/appmeta/ORPH30001/param.json", b"{}")

        make_file("user/app/ORPH30002/some_other_file.bin", b"123")
        make_file("user/appmeta/ORPH30002/param.json", b"{}")

        make_file("user/app/ORPH30003/app.pkg", b"TINY_PKG")
        make_file("user/appmeta/ORPH30003/param.json", b"{}")

        make_file("user/app/ORPH30004/app.pkg", b"P" * (2 * 1024 * 1024))
        make_file("user/app/ORPH30004/install_payload.part", b"partial_data")
        make_file("user/appmeta/ORPH30004/param.json", b"{}")

        # Check 4: patch and DLC without base app
        make_file("user/patch/ORPH40001/patch.pkg", b"patch_data")
        make_file("user/addcont/ORPH40002/dlc.pkg", b"dlc_data")
        # Empty DLC stub
        os.makedirs(os.path.join(self.test_dir, "user", "appmeta", "addcont", "ORPH40003"), exist_ok=True)

        # Check 5: license .rif not matching installed title
        rif_data = b"rifa" + b"UP9000-ORPH50001_00-TEST000000000001"
        make_file("user/license/fakeUP9000-ORPH50001_00.rif", rif_data)
        make_file("user/license/fake_unmapped_junk.rif", b"junk_bytes_with_no_id")

        # Check 6: installed fpkg with no license (ORPH60001)
        make_file("user/app/ORPH60001/app.pkg", b"P" * (2 * 1024 * 1024))
        make_file("user/app/ORPH60001/app.json", json.dumps({"fake": True}).encode("utf-8"))
        make_file("user/appmeta/ORPH60001/param.json", json.dumps({"titleId": "ORPH60001", "titleName": "FPKG No License"}).encode("utf-8"))

        # Check 7: leftover entries in bgft/task
        make_file("user/bgft/task/00000099/task.pdb", b"task_data")

        # Check 8: backport folder for uninstalled title & installed title needing backport
        make_file("data/homebrew/backports/ORPH80001/eboot.bin", b"backport_bin")
        make_file("user/app/ORPH80002/app.pkg", b"P" * (2 * 1024 * 1024))
        orph8_param = json.dumps({
            "titleId": "ORPH80002",
            "titleName": "Requires High FW",
            "requiredSystemSoftwareVersion": "0x0500000000000000",
        }).encode("utf-8")
        make_file("user/appmeta/ORPH80002/param.json", orph8_param)

        # Check 9: app.db discrepancies
        make_file("user/app/DISK90001/app.pkg", b"P" * (2 * 1024 * 1024))
        make_file("user/appmeta/DISK90001/param.json", json.dumps({"titleId": "DISK90001", "titleName": "Not In DB"}).encode("utf-8"))

        # Check 10: stray .pkg files
        make_file("data/stray_package.pkg", b"P" * 1024)
        make_file("mnt/usb0/stray_usb.pkg", b"P" * 2048)

        # Check 12: extracted game folder
        make_file("data/ORPH99999-app0/dump.bin", b"D" * 2048)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_full_offline_scan_all_checks(self):
        fs = LocalConsoleFS(self.test_dir)
        scanner = OrphanScanner(fs=fs, console_fw="4.03")
        scanner.build_inventory()
        scanner.run_checks()

        check_findings = {}
        for f in scanner.findings:
            check_findings.setdefault(f.check_id, []).append(f)

        self.assertIn(1, check_findings, "Check 1 did not fire")
        self.assertIn(2, check_findings, "Check 2 did not fire")
        self.assertIn(3, check_findings, "Check 3 did not fire")
        self.assertIn(4, check_findings, "Check 4 did not fire")
        self.assertIn(5, check_findings, "Check 5 did not fire")
        self.assertIn(6, check_findings, "Check 6 did not fire")
        self.assertIn(7, check_findings, "Check 7 did not fire")
        self.assertIn(8, check_findings, "Check 8 did not fire")
        self.assertIn(9, check_findings, "Check 9 did not fire")
        self.assertIn(10, check_findings, "Check 10 did not fire")
        self.assertIn(12, check_findings, "Check 12 did not fire")

        # Check 11: Disk space usage calculation
        self.assertIn("CLEAN0001", scanner.inventory)
        clean_inv = scanner.inventory["CLEAN0001"]
        self.assertGreater(clean_inv.total_size_bytes, 5 * 1024 * 1024)

        clean_findings = [f for f in scanner.findings if f.title_id == "CLEAN0001"]
        self.assertEqual(len(clean_findings), 0)

        # Report & JSON validation
        report = scanner.generate_report()
        self.assertIn("SUMMARY", report)
        self.assertIn("DISK SPACE USAGE PER TITLE", report)
        self.assertIn("SUGGESTED MANUAL CLEANUP", report)

        json_data = scanner.to_json()
        self.assertIn("findings", json_data)
        self.assertIn("inventory", json_data)
        self.assertIn("manual_cleanup_suggestions", json_data)
        self.assertEqual(len(json_data["findings"]), len(scanner.findings))

    def test_no_console_fw_skips_backport_needed_check(self):
        fs = LocalConsoleFS(self.test_dir)
        scanner = OrphanScanner(fs=fs)
        scanner.build_inventory()
        scanner.run_checks()

        c8_tids = {f.title_id for f in scanner.findings if f.check_id == 8}
        self.assertIn("ORPH80001", c8_tids)  # orphaned backport folder still reported
        self.assertNotIn("ORPH80002", c8_tids)  # needs-newer-FW check skipped
        self.assertIn("backport check skipped", scanner.generate_report())


if __name__ == "__main__":
    unittest.main()
