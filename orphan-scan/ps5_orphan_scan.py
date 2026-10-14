#!/usr/bin/env python3
"""
PS5 Orphaned Content Scanner (Read-Only)

Connects to a PS5 FTP server (e.g. the ftpsrv payload, port 2121, anonymous) or inspects a local offline
directory tree to find orphaned game files, incomplete installs, dead registrations,
stray packages, and app.db discrepancies.

Strictly read-only: does not modify or delete anything on the console.
Stdlib only (ftplib, sqlite3, json, argparse, socket, tempfile, os, sys, re).
"""

import argparse
import datetime
import ftplib
import io
import json
import os
import re
import socket
import sqlite3
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from typing import Dict, Generator, List, Optional, Set, Tuple

# Regex pattern for Unix ls -l format output from FTP LIST
UNIX_LIST_PATTERN = re.compile(
    r"^([bcdlps-][rwxstST-]{9})\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+([A-Za-z]{3}\s+\d+\s+[\d:]{4,5})\s+(.*)$"
)

# Fallback pattern for Windows/DOS style FTP directory listings
DOS_LIST_PATTERN = re.compile(
    r"^(\d{2}-\d{2}-\d{2,4}\s+\d{2}:\d{2}(?:[AP]M)?)\s+(<DIR>|\d+)\s+(.*)$"
)

# Sony Content ID pattern: e.g. UP9000-CUSA00359_00-UNTILDAWN0000001 or IV0002-ITEM00001_00-STOREUPD00000000
CONTENT_ID_PATTERN = re.compile(
    r"(?:[A-Z]{2}[0-9]{4}|[A-Z0-9]{6})-([A-Z0-9]{9})_[0-9]{2}-[A-Z0-9_]{16}"
)
CONTENT_ID_BYTES_PATTERN = re.compile(
    rb"(?:[A-Z]{2}[0-9]{4}|[A-Z0-9]{6})-([A-Z0-9]{9})_[0-9]{2}-[A-Z0-9_]{16}"
)

# Title ID patterns
TITLE_ID_PATTERN = re.compile(r"^[A-Z]{4}\d{5}$")
TITLE_ID_PREFIX_PATTERN = re.compile(r"^([A-Z]{4}\d{5})")
TITLE_ID_EXT_PATTERN = re.compile(r"[A-Z]{4}\d{5}")
TITLE_ID_EXT_BYTES_PATTERN = re.compile(rb"[A-Z]{4}\d{5}")

# Temp / partial file name indicators
TEMP_EXTENSIONS = {".tmp", ".part", "~"}
TEMP_KEYWORDS = ("temp", "partial", "download")


@dataclass
class FileInfo:
    name: str
    path: str
    is_dir: bool
    size: int
    mtime: Optional[str] = None


@dataclass
class Finding:
    check_id: int
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title_id: Optional[str]
    path: Optional[str]
    explanation: str
    details: Dict = field(default_factory=dict)


@dataclass
class TitleData:
    title_id: str
    title_name: Optional[str] = None
    content_id: Optional[str] = None
    app_paths: List[str] = field(default_factory=list)
    appmeta_paths: List[str] = field(default_factory=list)
    patch_paths: List[str] = field(default_factory=list)
    addcont_paths: List[str] = field(default_factory=list)
    backport_paths: List[str] = field(default_factory=list)
    extracted_paths: List[Tuple[str, int]] = field(default_factory=list)
    license_files: List[str] = field(default_factory=list)
    is_fpkg: bool = False
    required_fw: Optional[int] = None
    app_files: List[FileInfo] = field(default_factory=list)
    temp_files: List[FileInfo] = field(default_factory=list)
    total_size_bytes: int = 0
    in_app_db: bool = False
    app_db_metadata_path: Optional[str] = None


def format_size(bytes_val: int) -> str:
    """Format bytes into human-readable string."""
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.2f} KB"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.2f} MB"
    else:
        return f"{bytes_val / (1024 * 1024 * 1024):.2f} GB"


def parse_unix_list_line(line: str, parent_path: str = "") -> Optional[FileInfo]:
    """Parse a single line from Unix ls -l style FTP LIST output."""
    line = line.strip()
    if not line or line.startswith("total "):
        return None

    # Try Unix ls -l format
    m = UNIX_LIST_PATTERN.match(line)
    if m:
        perms = m.group(1)
        size = int(m.group(5))
        mtime = m.group(6)
        name = m.group(7).strip()
        is_dir = perms.startswith("d")
        if perms.startswith("l") and " -> " in name:
            name = name.split(" -> ", 1)[0].strip()
        if name in (".", ".."):
            return None
        full_path = f"{parent_path.rstrip('/')}/{name}" if parent_path else name
        return FileInfo(name=name, path=full_path, is_dir=is_dir, size=size, mtime=mtime)

    # Try DOS / Windows format
    m_dos = DOS_LIST_PATTERN.match(line)
    if m_dos:
        mtime = m_dos.group(1)
        dir_or_size = m_dos.group(2)
        name = m_dos.group(3).strip()
        if name in (".", ".."):
            return None
        is_dir = dir_or_size.upper() == "<DIR>"
        size = 0 if is_dir else int(dir_or_size)
        full_path = f"{parent_path.rstrip('/')}/{name}" if parent_path else name
        return FileInfo(name=name, path=full_path, is_dir=is_dir, size=size, mtime=mtime)

    return None


class ConsoleFS:
    """Abstract interface for reading console filesystem."""

    def list_dir(self, path: str) -> List[FileInfo]:
        raise NotImplementedError

    def read_bytes(self, path: str) -> Optional[bytes]:
        raise NotImplementedError

    def download_file(self, remote_path: str, local_dest: str) -> bool:
        raise NotImplementedError

    def exists(self, path: str) -> bool:
        raise NotImplementedError

    def is_dir(self, path: str) -> bool:
        raise NotImplementedError

    def walk(
        self, root: str, max_depth: int = 6, skip_prefixes: Tuple[str, ...] = ()
    ) -> Generator[Tuple[str, List[FileInfo], List[FileInfo]], None, None]:
        raise NotImplementedError

    def get_dir_tree(
        self, path: str, max_depth: int = 10
    ) -> Tuple[int, List[FileInfo]]:
        """Recursively traverse directory to calculate total size and list files.

        Only regular files are counted towards total size. Directory entries'
        own listing sizes (e.g. 65536 on PS5) are explicitly ignored.
        """
        queue = [(path, 0)]
        total_size = 0
        all_files: List[FileInfo] = []
        while queue:
            curr_path, depth = queue.pop(0)
            if depth > max_depth:
                continue
            entries = self.list_dir(curr_path)
            for entry in entries:
                if entry.is_dir:
                    queue.append((entry.path, depth + 1))
                else:
                    total_size += entry.size
                    all_files.append(entry)
        return total_size, all_files

    def close(self) -> None:
        pass


class LocalConsoleFS(ConsoleFS):
    """ConsoleFS implementation that reads a local directory tree (offline mode)."""

    def __init__(self, root_dir: str):
        self.root_dir = os.path.abspath(root_dir)

    def _to_local_path(self, virtual_path: str) -> str:
        clean = virtual_path.lstrip("/\\").replace("/", os.sep).replace("\\", os.sep)
        return os.path.join(self.root_dir, clean)

    def list_dir(self, path: str) -> List[FileInfo]:
        local_path = self._to_local_path(path)
        if not os.path.exists(local_path) or not os.path.isdir(local_path):
            return []
        items = []
        try:
            with os.scandir(local_path) as it:
                for entry in it:
                    if entry.name in (".", ".."):
                        continue
                    is_dir = entry.is_dir()
                    try:
                        stat = entry.stat()
                        size = stat.st_size if not is_dir else 0
                    except OSError:
                        size = 0
                    virtual_child = f"{path.rstrip('/')}/{entry.name}"
                    items.append(
                        FileInfo(
                            name=entry.name,
                            path=virtual_child,
                            is_dir=is_dir,
                            size=size,
                        )
                    )
        except OSError:
            return []
        return items

    def read_bytes(self, path: str) -> Optional[bytes]:
        local_path = self._to_local_path(path)
        if not os.path.exists(local_path) or os.path.isdir(local_path):
            return None
        try:
            with open(local_path, "rb") as f:
                return f.read()
        except OSError:
            return None

    def download_file(self, remote_path: str, local_dest: str) -> bool:
        local_path = self._to_local_path(remote_path)
        if not os.path.exists(local_path) or os.path.isdir(local_path):
            return False
        try:
            import shutil

            shutil.copyfile(local_path, local_dest)
            return True
        except OSError:
            return False

    def exists(self, path: str) -> bool:
        local_path = self._to_local_path(path)
        return os.path.exists(local_path)

    def is_dir(self, path: str) -> bool:
        local_path = self._to_local_path(path)
        return os.path.isdir(local_path)

    def walk(
        self, root: str, max_depth: int = 6, skip_prefixes: Tuple[str, ...] = ()
    ) -> Generator[Tuple[str, List[FileInfo], List[FileInfo]], None, None]:
        queue = [(root, 0)]
        while queue:
            current_path, depth = queue.pop(0)
            if depth > max_depth:
                continue
            entries = self.list_dir(current_path)
            dirs = [e for e in entries if e.is_dir]
            files = [e for e in entries if not e.is_dir]
            yield current_path, dirs, files
            for d in dirs:
                child_path = f"{current_path.rstrip('/')}/{d.name}"
                if any(child_path.startswith(prefix) for prefix in skip_prefixes):
                    continue
                queue.append((child_path, depth + 1))


class FTPConsoleFS(ConsoleFS):
    """ConsoleFS implementation that connects to PS5 FTP server (ftpsrv).

    Strictly read-only. Never issues DELE, RMD, STOR, RNFR/RNTO, MKD, or SITE.
    """

    def __init__(self, host: str, port: int = 2121, timeout: int = 30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.ftp: Optional[ftplib.FTP] = None
        self.use_mlsd = True
        self.connect()

    def connect(self) -> None:
        """Establish connection to FTP server."""
        if self.ftp:
            try:
                self.ftp.close()
            except Exception:
                pass
        self.ftp = ftplib.FTP()
        self.ftp.connect(self.host, self.port, timeout=self.timeout)
        self.ftp.login()
        # Ensure binary mode as default
        self.ftp.voidcmd("TYPE I")

    def _execute_with_retry(self, fn, *args, **kwargs):
        """Execute FTP command, reconnecting once on connection failure."""
        try:
            return fn(*args, **kwargs)
        except (
            socket.error,
            socket.timeout,
            EOFError,
            ConnectionResetError,
            ftplib.error_temp,
        ) as err:
            try:
                self.connect()
                return fn(*args, **kwargs)
            except Exception:
                raise err

    def list_dir(self, path: str) -> List[FileInfo]:
        """List files in directory using MLSD or LIST fallback."""
        if not path.startswith("/"):
            path = "/" + path

        # Try MLSD if not previously disabled
        if self.use_mlsd:
            try:
                items: List[FileInfo] = []

                def _mlsd():
                    for name, facts in self.ftp.mlsd(path):
                        if name in (".", ".."):
                            continue
                        is_dir = facts.get("type") in ("dir", "cdir", "pdir")
                        size = int(facts.get("size", 0))
                        mtime = facts.get("modify")
                        child_path = f"{path.rstrip('/')}/{name}"
                        items.append(
                            FileInfo(
                                name=name,
                                path=child_path,
                                is_dir=is_dir,
                                size=size,
                                mtime=mtime,
                            )
                        )
                    return items

                return self._execute_with_retry(_mlsd)
            except ftplib.error_perm as e:
                resp = str(e)
                if "502" in resp or "not recognized" in resp.lower():
                    self.use_mlsd = False
                elif "550" in resp:
                    return []
                else:
                    self.use_mlsd = False
            except Exception:
                self.use_mlsd = False

        # Fallback to LIST
        lines: List[str] = []

        def _list():
            lines.clear()
            self.ftp.retrlines(f"LIST {path}", lines.append)

        try:
            self._execute_with_retry(_list)
        except ftplib.error_perm as e:
            if "550" in str(e):
                return []
            raise e
        except Exception:
            return []

        results = []
        for line in lines:
            parsed = parse_unix_list_line(line, parent_path=path)
            if parsed:
                results.append(parsed)
        return results

    def read_bytes(self, path: str) -> Optional[bytes]:
        """Download small file directly into memory."""
        buf = io.BytesIO()

        def _retr():
            self.ftp.retrbinary(f"RETR {path}", buf.write)

        try:
            self._execute_with_retry(_retr)
            return buf.getvalue()
        except ftplib.error_perm as e:
            if "550" in str(e):
                return None
            raise e
        except Exception:
            return None

    def download_file(self, remote_path: str, local_dest: str) -> bool:
        """Download a file over FTP into a local file path."""

        def _download():
            with open(local_dest, "wb") as f:
                self.ftp.retrbinary(f"RETR {remote_path}", f.write)

        try:
            self._execute_with_retry(_download)
            return True
        except ftplib.error_perm as e:
            if "550" in str(e):
                return False
            raise e
        except Exception:
            return False

    def exists(self, path: str) -> bool:
        parent = os.path.dirname(path.rstrip("/")) or "/"
        base = os.path.basename(path.rstrip("/"))
        entries = self.list_dir(parent)
        return any(e.name == base for e in entries)

    def is_dir(self, path: str) -> bool:
        parent = os.path.dirname(path.rstrip("/")) or "/"
        base = os.path.basename(path.rstrip("/"))
        entries = self.list_dir(parent)
        for e in entries:
            if e.name == base:
                return e.is_dir
        return False

    def walk(
        self, root: str, max_depth: int = 6, skip_prefixes: Tuple[str, ...] = ()
    ) -> Generator[Tuple[str, List[FileInfo], List[FileInfo]], None, None]:
        queue = [(root, 0)]
        while queue:
            current_path, depth = queue.pop(0)
            if depth > max_depth:
                continue
            entries = self.list_dir(current_path)
            dirs = [e for e in entries if e.is_dir]
            files = [e for e in entries if not e.is_dir]
            yield current_path, dirs, files
            for d in dirs:
                child_path = f"{current_path.rstrip('/')}/{d.name}"
                if any(child_path.startswith(prefix) for prefix in skip_prefixes):
                    continue
                queue.append((child_path, depth + 1))

    def close(self) -> None:
        if self.ftp:
            try:
                self.ftp.quit()
            except Exception:
                try:
                    self.ftp.close()
                except Exception:
                    pass
            self.ftp = None


def parse_param_json(data_bytes: bytes) -> Dict:
    """Extract metadata from param.json."""
    try:
        data = json.loads(data_bytes.decode("utf-8", errors="ignore"))
    except Exception:
        return {}

    title_id = data.get("titleId")
    content_id = data.get("contentId")
    title_name = data.get("titleName")

    # If titleName not at top level, check localizedParameters
    if not title_name:
        loc_params = data.get("localizedParameters", {})
        if isinstance(loc_params, dict):
            default_lang = loc_params.get("defaultLanguage", "en-US")
            if default_lang in loc_params and isinstance(loc_params[default_lang], dict):
                title_name = loc_params[default_lang].get("titleName")
            if not title_name:
                for lang_key in ("en-US", "en"):
                    if lang_key in loc_params and isinstance(loc_params[lang_key], dict):
                        title_name = loc_params[lang_key].get("titleName")
                        break
            if not title_name:
                for val in loc_params.values():
                    if isinstance(val, dict) and val.get("titleName"):
                        title_name = val.get("titleName")
                        break

    req_fw_raw = data.get("requiredSystemSoftwareVersion")
    req_fw = None
    if req_fw_raw is not None:
        try:
            if isinstance(req_fw_raw, str):
                req_fw = int(req_fw_raw, 16 if req_fw_raw.startswith("0x") else 10)
            elif isinstance(req_fw_raw, int):
                req_fw = req_fw_raw
        except Exception:
            pass

    return {
        "title_id": title_id,
        "content_id": content_id,
        "title_name": title_name,
        "required_fw": req_fw,
    }


def parse_app_json(data_bytes: bytes) -> Dict:
    """Extract metadata from app.json."""
    try:
        data = json.loads(data_bytes.decode("utf-8", errors="ignore"))
    except Exception:
        return {}
    is_fake = bool(data.get("fake", False))
    pieces = data.get("pieces", [])
    if not is_fake and isinstance(pieces, list):
        for piece in pieces:
            if isinstance(piece, dict):
                url = piece.get("url", "").lower()
                if "/mnt/" in url or "usb" in url or (url and "playstation.net" not in url):
                    is_fake = True
                    break
    return {
        "fake": is_fake,
        "original_file_size": data.get("originalFileSize", 0),
    }


def parse_rif_content(data_bytes: bytes, filename: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract (content_id, title_id) from .rif file bytes and filename."""
    content_id = None
    title_id = None

    # Search in binary data for Content ID pattern
    match = CONTENT_ID_BYTES_PATTERN.search(data_bytes)
    if match:
        try:
            content_id = match.group(0).decode("ascii", errors="ignore")
            title_id = match.group(1).decode("ascii", errors="ignore")
        except Exception:
            pass

    # If no Title ID yet, search filename
    if not title_id:
        m_cid = CONTENT_ID_PATTERN.search(filename)
        if m_cid:
            content_id = m_cid.group(0)
            title_id = m_cid.group(1)
        else:
            m_tid = TITLE_ID_EXT_PATTERN.search(filename)
            if m_tid:
                title_id = m_tid.group(0)

    # If still no Title ID, search binary data for any Title ID pattern
    if not title_id:
        m_tid_bytes = TITLE_ID_EXT_BYTES_PATTERN.search(data_bytes)
        if m_tid_bytes:
            try:
                title_id = m_tid_bytes.group(0).decode("ascii", errors="ignore")
            except Exception:
                pass

    return content_id, title_id


def parse_fw_string(fw_str: str) -> int:
    """Convert a firmware version string like '4.03' to integer 0x0403000000000000."""
    clean = fw_str.strip().lower()
    if clean.startswith("0x"):
        return int(clean, 16)
    parts = clean.split(".")
    major = int(parts[0]) if len(parts) > 0 else 0
    minor = int(parts[1]) if len(parts) > 1 else 0
    patch = int(parts[2]) if len(parts) > 2 else 0
    return (major << 56) | (minor << 48) | (patch << 40)


def is_homebrew_title(
    tid: str,
    title_name: Optional[str] = None,
    content_id: Optional[str] = None,
) -> bool:
    """Determine whether a title represents homebrew rather than an official retail or system app."""
    if title_name and title_name.startswith("★"):
        return True
    if (
        tid.startswith("FAKE")
        or tid.startswith("ITEM")
        or tid.startswith("IDLE")
        or tid.startswith("MOUU")
    ):
        return True
    if content_id and (
        content_id.startswith("IV0002-") or content_id.startswith("IV0001-")
    ):
        return True
    return False


def is_system_npxs_title(
    tid: str,
    title_name: Optional[str] = None,
    content_id: Optional[str] = None,
) -> bool:
    """Check if title is a Sony system app (NPXS) and not a homebrew reusing an NPXS ID."""
    if not tid.startswith("NPXS"):
        return False
    if title_name and title_name.startswith("★"):
        return False
    return True


class OrphanScanner:
    """Performs the full inventory and runs all orphaned-content checks."""

    def __init__(
        self,
        fs: ConsoleFS,
        console_fw: Optional[str] = None,
        min_pkg_size: int = 1048576,  # 1 MB
        max_depth: int = 6,
    ):
        self.fs = fs
        # Without a firmware version, the "needs a backport" check (check 8, side B) is skipped.
        self.console_fw_str = console_fw
        self.console_fw_int = parse_fw_string(console_fw) if console_fw else None
        self.min_pkg_size = min_pkg_size
        self.max_depth = max_depth

        self.inventory: Dict[str, TitleData] = {}
        self.findings: List[Finding] = []
        self.app_db_titles: Dict[str, Dict] = {}
        self.app_db_path: Optional[str] = None
        self.app_db_error: Optional[str] = None
        self.stray_pkgs: List[FileInfo] = []
        self.bgft_tasks: List[Tuple[FileInfo, int, List[FileInfo]]] = []  # (entry, size, files)
        self.extracted_folders: List[Dict] = []
        self.license_inventory: List[Dict] = []
        self.roots_scanned: List[str] = []

    def _get_or_create_title(self, tid: str) -> TitleData:
        if tid not in self.inventory:
            self.inventory[tid] = TitleData(title_id=tid)
        return self.inventory[tid]

    def scan_app_db(self) -> None:
        """Download app.db to a local temp file and inspect registered titles."""
        candidate_paths = [
            "/system_data/priv/mms/app.db",
            "/system_data/priv/mwcache/Sony/app.db",
        ]

        temp_db = os.path.join(tempfile.gettempdir(), f"ps5_app_scan_{os.getpid()}.db")
        downloaded_path = None

        for cand in candidate_paths:
            if self.fs.download_file(cand, temp_db):
                downloaded_path = cand
                break

        if not downloaded_path:
            self.app_db_error = (
                f"Could not download app.db from any candidate path: {candidate_paths}"
            )
            return

        self.app_db_path = downloaded_path
        try:
            conn = sqlite3.connect(temp_db)
            c = conn.cursor()
            tables = [
                row[0]
                for row in c.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]

            # Primary table: tbl_contentinfo
            if "tbl_contentinfo" in tables:
                cols = [
                    col[1]
                    for col in c.execute("PRAGMA table_info(tbl_contentinfo)").fetchall()
                ]
                has_metapath = "metaDataPath" in cols
                has_name = "titleName" in cols
                has_cid = "contentId" in cols
                query = "SELECT titleId"
                if has_name:
                    query += ", titleName"
                if has_metapath:
                    query += ", metaDataPath"
                if has_cid:
                    query += ", contentId"
                query += " FROM tbl_contentinfo"

                for row in c.execute(query).fetchall():
                    tid = row[0]
                    idx = 1
                    tname = None
                    mpath = None
                    cid = None
                    if has_name:
                        tname = row[idx]
                        idx += 1
                    if has_metapath:
                        mpath = row[idx]
                        idx += 1
                    if has_cid:
                        cid = row[idx]
                        idx += 1

                    if tid:
                        self.app_db_titles[tid] = {
                            "title_name": tname,
                            "metadata_path": mpath,
                            "content_id": cid,
                        }

            # Secondary tables: tbl_appbrowse_*
            for t in tables:
                if t.startswith("tbl_appbrowse_") or "appbrowse" in t.lower():
                    cols = [
                        col[1]
                        for col in c.execute(f"PRAGMA table_info({t})").fetchall()
                    ]
                    tid_col = next(
                        (col for col in cols if col.lower() in ("titleid", "title_id")),
                        None,
                    )
                    if tid_col:
                        for row in c.execute(f"SELECT {tid_col} FROM {t}").fetchall():
                            tid = row[0]
                            if tid and tid not in self.app_db_titles:
                                self.app_db_titles[tid] = {
                                    "title_name": None,
                                    "metadata_path": None,
                                    "content_id": None,
                                }

            conn.close()
        except Exception as e:
            self.app_db_error = f"Failed to parse app.db ({downloaded_path}): {e}"
        finally:
            if os.path.exists(temp_db):
                try:
                    os.unlink(temp_db)
                except Exception:
                    pass

        # Update inventory titles known in app.db
        for tid, db_info in self.app_db_titles.items():
            tdata = self._get_or_create_title(tid)
            tdata.in_app_db = True
            tdata.app_db_metadata_path = db_info.get("metadata_path")
            if not tdata.title_name and db_info.get("title_name"):
                tdata.title_name = db_info.get("title_name")
            if not tdata.content_id and db_info.get("content_id"):
                tdata.content_id = db_info.get("content_id")

    def build_inventory(self) -> None:
        """Scan console directories and build comprehensive inventory."""
        # 1. Download and read app.db first
        self.scan_app_db()

        # 2. Check for extended storage prefixes
        prefixes = [""]
        for ext_candidate in (
            "/mnt/ext0",
            "/mnt/ext1",
            "/mnt/ext2",
            "/mnt/m2",
            "/mnt/ext0/user",
            "/mnt/ext1/user",
        ):
            if self.fs.exists(ext_candidate):
                if ext_candidate.endswith("/user"):
                    prefix = ext_candidate[:-5]
                else:
                    prefix = ext_candidate
                if prefix not in prefixes:
                    prefixes.append(prefix)

        # 3. Scan user content roots
        for prefix in prefixes:
            app_root = f"{prefix}/user/app"
            appmeta_root = f"{prefix}/user/appmeta"
            patch_root = f"{prefix}/user/patch"
            addcont_root = f"{prefix}/user/addcont"

            # Scan /user/app/<TID>/
            if self.fs.exists(app_root):
                self.roots_scanned.append(app_root)
                for entry in self.fs.list_dir(app_root):
                    if not entry.is_dir:
                        continue
                    tid = entry.name
                    tdata = self._get_or_create_title(tid)
                    tdata.app_paths.append(entry.path)

                    # List files recursively in app dir
                    app_size, all_app_files = self.fs.get_dir_tree(entry.path)
                    tdata.total_size_bytes += app_size
                    tdata.app_files.extend(all_app_files)

                    for f in all_app_files:
                        lower_name = f.name.lower()
                        # Check for temp / partial files (skip subdirectories)
                        if not f.is_dir and (
                            any(lower_name.endswith(ext) for ext in TEMP_EXTENSIONS)
                            or any(kw in lower_name for kw in TEMP_KEYWORDS)
                        ):
                            tdata.temp_files.append(f)

                        # Check app.json
                        if f.name == "app.json":
                            json_bytes = self.fs.read_bytes(f.path)
                            if json_bytes:
                                aj_info = parse_app_json(json_bytes)
                                if aj_info.get("fake"):
                                    tdata.is_fpkg = True

                        # Check param.json in app dir if present
                        if f.name == "param.json" and not tdata.title_name:
                            p_bytes = self.fs.read_bytes(f.path)
                            if p_bytes:
                                p_info = parse_param_json(p_bytes)
                                if p_info.get("title_name"):
                                    tdata.title_name = p_info["title_name"]
                                if p_info.get("required_fw"):
                                    tdata.required_fw = p_info["required_fw"]

            # Scan /user/appmeta/<TID>/
            if self.fs.exists(appmeta_root):
                self.roots_scanned.append(appmeta_root)
                for entry in self.fs.list_dir(appmeta_root):
                    if not entry.is_dir:
                        continue
                    if entry.name in ("push_resource", "addcont", "lost+found"):
                        # Special subdirectories
                        if entry.name == "push_resource":
                            for sub in self.fs.list_dir(entry.path):
                                if sub.is_dir and TITLE_ID_PATTERN.match(sub.name):
                                    tdata = self._get_or_create_title(sub.name)
                                    tdata.appmeta_paths.append(sub.path)
                                    sub_size, _ = self.fs.get_dir_tree(sub.path)
                                    tdata.total_size_bytes += sub_size
                        continue

                    tid = entry.name
                    tdata = self._get_or_create_title(tid)
                    tdata.appmeta_paths.append(entry.path)

                    meta_size, meta_files = self.fs.get_dir_tree(entry.path)
                    tdata.total_size_bytes += meta_size

                    # Check param.json in appmeta
                    for mf in meta_files:
                        if mf.name == "param.json":
                            p_bytes = self.fs.read_bytes(mf.path)
                            if p_bytes:
                                p_info = parse_param_json(p_bytes)
                                if p_info.get("title_name") and not tdata.title_name:
                                    tdata.title_name = p_info["title_name"]
                                if p_info.get("content_id"):
                                    tdata.content_id = p_info["content_id"]
                                if p_info.get("required_fw"):
                                    tdata.required_fw = p_info["required_fw"]

            # Scan /user/patch/<TID>/
            if self.fs.exists(patch_root):
                self.roots_scanned.append(patch_root)
                for entry in self.fs.list_dir(patch_root):
                    if entry.is_dir and entry.name not in ("lost+found", ".", ".."):
                        tid = entry.name
                        tdata = self._get_or_create_title(tid)
                        tdata.patch_paths.append(entry.path)
                        patch_size, _ = self.fs.get_dir_tree(entry.path)
                        tdata.total_size_bytes += patch_size

            # Scan /user/addcont/<TID>/
            if self.fs.exists(addcont_root):
                self.roots_scanned.append(addcont_root)
                for entry in self.fs.list_dir(addcont_root):
                    if entry.is_dir and entry.name not in ("lost+found", ".", ".."):
                        tid = entry.name
                        tdata = self._get_or_create_title(tid)
                        tdata.addcont_paths.append(entry.path)
                        addcont_size, _ = self.fs.get_dir_tree(entry.path)
                        tdata.total_size_bytes += addcont_size

        # Also check /user/appmeta/addcont/<TID> if it exists
        if self.fs.exists("/user/appmeta/addcont"):
            for entry in self.fs.list_dir("/user/appmeta/addcont"):
                if entry.is_dir and TITLE_ID_PATTERN.match(entry.name):
                    tdata = self._get_or_create_title(entry.name)
                    if entry.path not in tdata.addcont_paths:
                        tdata.addcont_paths.append(entry.path)
                        stub_size, _ = self.fs.get_dir_tree(entry.path)
                        tdata.total_size_bytes += stub_size

        # 4. Scan /data/homebrew/backports/<TID>/
        backports_root = "/data/homebrew/backports"
        if self.fs.exists(backports_root):
            self.roots_scanned.append(backports_root)
            for entry in self.fs.list_dir(backports_root):
                if entry.is_dir and entry.name not in (".", ".."):
                    tid = entry.name
                    tdata = self._get_or_create_title(tid)
                    tdata.backport_paths.append(entry.path)
                    bp_size, _ = self.fs.get_dir_tree(entry.path)
                    tdata.total_size_bytes += bp_size

        # 5. Scan extracted game folders in /data, /mnt/usb*, /mnt/ext*
        extracted_roots = ["/data"]
        for i in range(8):
            extracted_roots.append(f"/mnt/usb{i}")
            extracted_roots.append(f"/mnt/ext{i}")

        for ex_root in extracted_roots:
            if not self.fs.exists(ex_root):
                continue
            for entry in self.fs.list_dir(ex_root):
                if not entry.is_dir:
                    continue
                # Skip known system or homebrew utility directories
                if entry.path in (
                    "/data/homebrew",
                    "/data/shadowmount",
                    "/data/etaHEN",
                    "/data/itemzflow",
                ):
                    continue
                m_tid = TITLE_ID_PREFIX_PATTERN.match(entry.name)
                if m_tid:
                    tid = m_tid.group(1)
                    folder_size, folder_files = self.fs.get_dir_tree(entry.path)
                    tdata = self._get_or_create_title(tid)
                    tdata.extracted_paths.append((entry.path, folder_size))
                    tdata.total_size_bytes += folder_size
                    self.extracted_folders.append(
                        {
                            "path": entry.path,
                            "title_id": tid,
                            "size": folder_size,
                            "files_count": len(folder_files),
                        }
                    )

        # 6. Scan /user/license/
        license_roots = ["/user/license"]
        for p in prefixes:
            if p and f"{p}/user/license" not in license_roots:
                license_roots.append(f"{p}/user/license")

        for l_root in license_roots:
            if self.fs.exists(l_root):
                self.roots_scanned.append(l_root)
                for entry in self.fs.list_dir(l_root):
                    if entry.is_dir:
                        continue
                    if entry.name.lower().endswith(".rif"):
                        data_bytes = self.fs.read_bytes(entry.path) or b""
                        cid, tid = parse_rif_content(data_bytes, entry.name)
                        lic_info = {
                            "filename": entry.name,
                            "path": entry.path,
                            "size": entry.size,
                            "content_id": cid,
                            "title_id": tid,
                        }
                        self.license_inventory.append(lic_info)
                        if tid:
                            tdata = self._get_or_create_title(tid)
                            tdata.license_files.append(entry.path)
                            if entry.name.lower().startswith("fake"):
                                tdata.is_fpkg = True

        # 7. Scan /user/bgft/task/ (record files and sizes)
        bgft_root = "/user/bgft/task"
        if self.fs.exists(bgft_root):
            self.roots_scanned.append(bgft_root)
            for entry in self.fs.list_dir(bgft_root):
                if entry.name not in (".", "..") and entry.is_dir:
                    task_size, task_files = self.fs.get_dir_tree(entry.path)
                    self.bgft_tasks.append((entry, task_size, task_files))

        # 8. Check if any title is homebrew / backported
        for tid, tdata in self.inventory.items():
            if is_homebrew_title(tid, tdata.title_name, tdata.content_id):
                tdata.is_fpkg = True
            if tdata.backport_paths:
                tdata.is_fpkg = True

    def run_checks(self) -> None:
        """Run all checks against the inventory."""
        self.findings.clear()

        # Check 1: app content with no appmeta
        for tid, tdata in self.inventory.items():
            if tdata.app_paths and not tdata.appmeta_paths:
                # If app.db points metaDataPath to sce_sys inside app and it exists, skip
                has_internal_meta = False
                if tdata.app_db_metadata_path and self.fs.exists(
                    tdata.app_db_metadata_path
                ):
                    has_internal_meta = True

                if not has_internal_meta:
                    if is_system_npxs_title(tid, tdata.title_name, tdata.content_id):
                        # System apps without appmeta are normal placeholders
                        sev = "INFO"
                        exp = f"System app {tid} in {tdata.app_paths[0]} has no appmeta (system placeholder)"
                    else:
                        sev = "HIGH"
                        exp = f"App content in {tdata.app_paths[0]} has no appmeta registration in /user/appmeta/{tid} (incomplete install / missing icon)"

                    self.findings.append(
                        Finding(
                            check_id=1,
                            severity=sev,
                            title_id=tid,
                            path=tdata.app_paths[0],
                            explanation=exp,
                            details={"app_paths": tdata.app_paths},
                        )
                    )

        # Check 2: appmeta with no app content
        for tid, tdata in self.inventory.items():
            if tdata.appmeta_paths and not tdata.app_paths:
                self.findings.append(
                    Finding(
                        check_id=2,
                        severity="MEDIUM",
                        title_id=tid,
                        path=tdata.appmeta_paths[0],
                        explanation=f"Appmeta registration in {tdata.appmeta_paths[0]} has no installed app content in /user/app/{tid} (dead registration)",
                        details={"appmeta_paths": tdata.appmeta_paths},
                    )
                )

        # Check 3: app dir with no app.pkg, 0-byte or suspiciously small app.pkg, or temp/partial files
        for tid, tdata in self.inventory.items():
            for app_p in tdata.app_paths:
                pkg_files = [f for f in tdata.app_files if f.path.startswith(app_p) and f.name == "app.pkg"]
                is_homebrew = is_homebrew_title(tid, tdata.title_name, tdata.content_id)
                is_npxs_sys = is_system_npxs_title(tid, tdata.title_name, tdata.content_id)

                if not pkg_files:
                    # Missing app.pkg
                    if is_homebrew:
                        self.findings.append(
                            Finding(
                                check_id=3,
                                severity="INFO",
                                title_id=tid,
                                path=app_p,
                                explanation=f"Homebrew app {tid} ({tdata.title_name or 'unknown'}) in {app_p} has no app.pkg (normal if it launches via sce_sys/ShadowMount+)",
                                details={"app_path": app_p},
                            )
                        )
                    elif is_npxs_sys:
                        self.findings.append(
                            Finding(
                                check_id=3,
                                severity="INFO",
                                title_id=tid,
                                path=app_p,
                                explanation=f"System app {tid} in {app_p} contains no app.pkg (system placeholder)",
                                details={"app_path": app_p},
                            )
                        )
                    else:
                        self.findings.append(
                            Finding(
                                check_id=3,
                                severity="HIGH",
                                title_id=tid,
                                path=app_p,
                                explanation=f"App directory {app_p} contains no app.pkg",
                                details={"app_path": app_p},
                            )
                        )
                else:
                    for pkg in pkg_files:
                        if pkg.size == 0:
                            if is_npxs_sys:
                                self.findings.append(
                                    Finding(
                                        check_id=3,
                                        severity="INFO",
                                        title_id=tid,
                                        path=pkg.path,
                                        explanation=f"System app {tid} in {pkg.path} has 0-byte app.pkg (system placeholder)",
                                        details={"size": pkg.size},
                                    )
                                )
                            else:
                                self.findings.append(
                                    Finding(
                                        check_id=3,
                                        severity="HIGH",
                                        title_id=tid,
                                        path=pkg.path,
                                        explanation=f"0-byte app.pkg found in {pkg.path}",
                                        details={"size": pkg.size},
                                    )
                                )
                        elif pkg.size < self.min_pkg_size:
                            if is_npxs_sys or is_homebrew:
                                self.findings.append(
                                    Finding(
                                        check_id=3,
                                        severity="INFO",
                                        title_id=tid,
                                        path=pkg.path,
                                        explanation=f"Small app.pkg in {pkg.path} ({format_size(pkg.size)}, homebrew/system)",
                                        details={"size": pkg.size},
                                    )
                                )
                            else:
                                self.findings.append(
                                    Finding(
                                        check_id=3,
                                        severity="HIGH",
                                        title_id=tid,
                                        path=pkg.path,
                                        explanation=f"Suspiciously small app.pkg in {pkg.path} ({format_size(pkg.size)} < {format_size(self.min_pkg_size)})",
                                        details={"size": pkg.size},
                                    )
                                )

                # Temp / partial files in app dir
                app_temp_files = [f for f in tdata.temp_files if f.path.startswith(app_p)]
                for tf in app_temp_files:
                    self.findings.append(
                        Finding(
                            check_id=3,
                            severity="HIGH",
                            title_id=tid,
                            path=tf.path,
                            explanation=f"Temporary or partial file found in {app_p}: {tf.name} ({format_size(tf.size)})",
                            details={"file": tf.name, "size": tf.size},
                        )
                    )

        # Check 4: a DLC (addcont) or patch whose base app is not installed (the corruption trigger)
        for tid, tdata in self.inventory.items():
            if not tdata.app_paths:
                if tdata.patch_paths:
                    for p in tdata.patch_paths:
                        self.findings.append(
                            Finding(
                                check_id=4,
                                severity="CRITICAL",
                                title_id=tid,
                                path=p,
                                explanation=f"Patch in {p} exists for {tid}, but base app /user/app/{tid} is not installed (corruption trigger)",
                                details={"patch_path": p},
                            )
                        )
                if tdata.addcont_paths:
                    for p in tdata.addcont_paths:
                        if "/user/appmeta/addcont" in p:
                            stub_size, stub_files = self.fs.get_dir_tree(p)
                            if stub_size == 0 and len(stub_files) == 0:
                                self.findings.append(
                                    Finding(
                                        check_id=4,
                                        severity="LOW",
                                        title_id=tid,
                                        path=p,
                                        explanation=f"Leftover DLC metadata stub (empty) in {p} for uninstalled title {tid}",
                                        details={"addcont_path": p, "empty": True},
                                    )
                                )
                            else:
                                self.findings.append(
                                    Finding(
                                        check_id=4,
                                        severity="CRITICAL",
                                        title_id=tid,
                                        path=p,
                                        explanation=f"DLC metadata in {p} exists for {tid}, but base app /user/app/{tid} is not installed (corruption trigger)",
                                        details={"addcont_path": p},
                                    )
                                )
                        else:
                            self.findings.append(
                                Finding(
                                    check_id=4,
                                    severity="CRITICAL",
                                    title_id=tid,
                                    path=p,
                                    explanation=f"DLC (addcont) in {p} exists for {tid}, but base app /user/app/{tid} is not installed (corruption trigger)",
                                    details={"addcont_path": p},
                                )
                            )

        # Check 5: a license .rif that doesn't match an installed title
        for lic in self.license_inventory:
            target_tid = lic.get("title_id")
            if not target_tid:
                self.findings.append(
                    Finding(
                        check_id=5,
                        severity="MEDIUM",
                        title_id=None,
                        path=lic["path"],
                        explanation=f"License file {lic['path']} could not be mapped to any known title ID (unmapped license)",
                        details=lic,
                    )
                )
            else:
                tdata = self.inventory.get(target_tid)
                if not tdata or not tdata.app_paths:
                    self.findings.append(
                        Finding(
                            check_id=5,
                            severity="MEDIUM",
                            title_id=target_tid,
                            path=lic["path"],
                            explanation=f"License file {lic['path']} maps to title {target_tid}, but base app /user/app/{target_tid} is not installed",
                            details=lic,
                        )
                    )

        # Check 6: an installed fpkg with no license
        for tid, tdata in self.inventory.items():
            if tdata.app_paths and tdata.is_fpkg:
                if not tdata.license_files:
                    is_homebrew = is_homebrew_title(tid, tdata.title_name, tdata.content_id)
                    if is_homebrew:
                        self.findings.append(
                            Finding(
                                check_id=6,
                                severity="INFO",
                                title_id=tid,
                                path=tdata.app_paths[0],
                                explanation=f"Homebrew app {tid} ({tdata.title_name or 'unknown'}) has no license .rif (normal if it launches without license)",
                                details={"title_name": tdata.title_name},
                            )
                        )
                    else:
                        self.findings.append(
                            Finding(
                                check_id=6,
                                severity="HIGH",
                                title_id=tid,
                                path=tdata.app_paths[0],
                                explanation=f"Installed fpkg {tid} ({tdata.title_name or 'unknown'}) has no license .rif in /user/license/",
                                details={"title_name": tdata.title_name},
                            )
                        )

        # Check 7: any leftover entries in bgft/task (list files and sizes)
        for task_entry, task_size, task_files in self.bgft_tasks:
            files_desc = (
                ", ".join(f"{f.name} ({format_size(f.size)})" for f in task_files)
                if task_files
                else "empty"
            )
            self.findings.append(
                Finding(
                    check_id=7,
                    severity="MEDIUM",
                    title_id=None,
                    path=task_entry.path,
                    explanation=f"Leftover background download/install task in {task_entry.path} [{files_desc}]",
                    details={
                        "task_entry": task_entry.name,
                        "size": task_size,
                        "files": [f.name for f in task_files],
                    },
                )
            )

        # Check 8: a backport folder whose title is not installed, or an installed title that needs one
        # Side A: backport without installed title
        for tid, tdata in self.inventory.items():
            if tdata.backport_paths and not tdata.app_paths:
                self.findings.append(
                    Finding(
                        check_id=8,
                        severity="LOW",
                        title_id=tid,
                        path=tdata.backport_paths[0],
                        explanation=f"Backport folder exists in {tdata.backport_paths[0]}, but title {tid} is not installed",
                        details={"backport_paths": tdata.backport_paths},
                    )
                )
            # Side B: installed title needing backport
            if tdata.app_paths and tdata.required_fw and self.console_fw_int is not None:
                if tdata.required_fw > self.console_fw_int and not tdata.backport_paths:
                    self.findings.append(
                        Finding(
                            check_id=8,
                            severity="LOW",
                            title_id=tid,
                            path=tdata.app_paths[0],
                            explanation=f"Installed title {tid} ({tdata.title_name or 'unknown'}) requires FW > {self.console_fw_str} (0x{tdata.required_fw:016x}) but has no backport in /data/homebrew/backports/{tid}",
                            details={
                                "required_fw": hex(tdata.required_fw),
                                "console_fw": hex(self.console_fw_int),
                            },
                        )
                    )

        # Check 9: app.db rows with no files on disk, and files on disk with no app.db row
        if not self.app_db_error:
            # Side A: app.db rows with no files on disk
            for tid, db_info in self.app_db_titles.items():
                if is_system_npxs_title(tid, db_info.get("title_name"), db_info.get("content_id")):
                    continue

                tdata = self.inventory.get(tid)
                has_files = False
                if tdata and (tdata.app_paths or tdata.appmeta_paths):
                    has_files = True
                elif db_info.get("metadata_path") and self.fs.exists(
                    db_info["metadata_path"]
                ):
                    has_files = True

                if not has_files:
                    tname = db_info.get("title_name") or "unknown"
                    self.findings.append(
                        Finding(
                            check_id=9,
                            severity="MEDIUM",
                            title_id=tid,
                            path=db_info.get("metadata_path"),
                            explanation=f"app.db row exists for {tid} ({tname}), but no files found on disk",
                            details={"db_entry": db_info},
                        )
                    )

            # Side B: files on disk with no app.db row
            for tid, tdata in self.inventory.items():
                if (tdata.app_paths or tdata.appmeta_paths) and not tdata.in_app_db:
                    primary_path = tdata.app_paths[0] if tdata.app_paths else tdata.appmeta_paths[0]
                    if is_system_npxs_title(tid, tdata.title_name, tdata.content_id):
                        sev = "INFO"
                        exp = f"System app {tid} found on disk, but not registered in app.db (normal placeholder)"
                    else:
                        sev = "MEDIUM"
                        exp = f"Files found on disk for {tid} ({tdata.title_name or 'unknown'}), but title is not registered in app.db"

                    self.findings.append(
                        Finding(
                            check_id=9,
                            severity=sev,
                            title_id=tid,
                            path=primary_path,
                            explanation=exp,
                            details={
                                "app_paths": tdata.app_paths,
                                "appmeta_paths": tdata.appmeta_paths,
                            },
                        )
                    )

        # Check 10: stray .pkg files anywhere
        self.scan_stray_pkgs()
        for spkg in self.stray_pkgs:
            self.findings.append(
                Finding(
                    check_id=10,
                    severity="LOW",
                    title_id=None,
                    path=spkg.path,
                    explanation=f"Stray PKG file found outside installed content paths: {spkg.path} ({format_size(spkg.size)})",
                    details={"size": spkg.size},
                )
            )

        # Check 12: Extracted game folders in /data, /mnt/usb*, /mnt/ext*
        for ex_info in self.extracted_folders:
            p = ex_info["path"]
            tid = ex_info["title_id"]
            sz = ex_info["size"]
            tdata = self.inventory[tid]
            is_installed = bool(tdata.app_paths)

            if not is_installed:
                # Severity HIGH when over 1 GB, otherwise MEDIUM
                sev = "HIGH" if sz > 1024 * 1024 * 1024 else "MEDIUM"
                self.findings.append(
                    Finding(
                        check_id=12,
                        severity=sev,
                        title_id=tid,
                        path=p,
                        explanation=f"Extracted game folder {p} ({format_size(sz)}) found for uninstalled title {tid}",
                        details=ex_info,
                    )
                )
            else:
                self.findings.append(
                    Finding(
                        check_id=12,
                        severity="INFO",
                        title_id=tid,
                        path=p,
                        explanation=f"Extracted game folder {p} ({format_size(sz)}) found for installed title {tid}",
                        details=ex_info,
                    )
                )

    def scan_stray_pkgs(self) -> None:
        """Walk specified roots to locate stray .pkg files."""
        walk_roots = [
            "/data",
            "/user/data",
            "/user/download",
        ]
        # /user/home/*/
        if self.fs.exists("/user/home"):
            for udir in self.fs.list_dir("/user/home"):
                if udir.is_dir and udir.name not in (".", ".."):
                    walk_roots.append(udir.path)

        # /mnt/usb0..7
        for i in range(8):
            usb_p = f"/mnt/usb{i}"
            if self.fs.exists(usb_p):
                walk_roots.append(usb_p)

        # /mnt/ext*
        for i in range(8):
            ext_p = f"/mnt/ext{i}"
            if self.fs.exists(ext_p):
                walk_roots.append(ext_p)

        skip_prefixes = (
            "/system",
            "/system_data",
            "/system_ex",
            "/system_tmp",
            "/dev",
            "/proc",
            "/mnt/sandbox",
        )

        for root in walk_roots:
            if not self.fs.exists(root):
                continue
            for dirpath, dirs, files in self.fs.walk(
                root, max_depth=self.max_depth, skip_prefixes=skip_prefixes
            ):
                for f in files:
                    if f.name.lower().endswith(".pkg"):
                        p = f.path
                        if (
                            "/user/app/" in p
                            or "/user/patch/" in p
                            or "/user/addcont/" in p
                        ):
                            continue
                        self.stray_pkgs.append(f)

    def get_manual_cleanup_suggestions(self) -> List[Dict]:
        """Build list of manual cleanup suggestions for findings at LOW severity or above."""
        suggestions = []
        seen_paths = set()

        for f in self.findings:
            if f.severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                continue

            path = f.path
            if not path or path in seen_paths:
                continue

            reclaimable = 0
            action = ""

            if f.check_id == 12:  # Extracted game folder
                reclaimable = f.details.get("size", 0)
                action = "Safe to delete extracted dump folder over FTP if backup is not needed."
            elif f.check_id == 4:  # DLC / Patch
                if "stub" in f.explanation.lower() or "empty" in f.explanation.lower():
                    reclaimable = 0
                    action = "Delete empty DLC metadata stub folder over FTP."
                else:
                    reclaimable = (
                        self.fs.get_dir_tree(path)[0] if self.fs.exists(path) else 0
                    )
                    action = "Delete orphaned patch/DLC folder over FTP (base game not installed)."
            elif f.check_id == 7:  # bgft task
                reclaimable = f.details.get("size", 0)
                action = "Delete leftover background download task folder over FTP."
            elif f.check_id == 8:  # backport folder
                reclaimable = (
                    self.fs.get_dir_tree(path)[0] if self.fs.exists(path) else 0
                )
                action = "Delete backport folder over FTP if not planning to install base game soon; otherwise keep."
            elif f.check_id == 2:  # dead appmeta
                reclaimable = (
                    self.fs.get_dir_tree(path)[0] if self.fs.exists(path) else 0
                )
                action = "Verify title is not on console dashboard; delete dead appmeta folder over FTP."
            elif f.check_id == 5:  # license .rif
                reclaimable = f.details.get("size", 0)
                action = "Delete orphaned license file over FTP."
            elif f.check_id == 10:  # stray pkg
                reclaimable = f.details.get("size", 0)
                action = "Delete stray package installer over FTP."
            elif f.check_id == 3:  # temp file
                reclaimable = f.details.get("size", 0)
                action = "Delete temporary/partial file over FTP."
            elif f.check_id == 9:  # disk files not in app.db
                reclaimable = (
                    self.fs.get_dir_tree(path)[0] if self.fs.exists(path) else 0
                )
                action = "Verify title is not on dashboard; delete unregistered files over FTP."
            else:
                reclaimable = 0
                action = "Manual inspection recommended before removing."

            seen_paths.add(path)
            suggestions.append(
                {
                    "path": path,
                    "title_id": f.title_id,
                    "severity": f.severity,
                    "check_id": f.check_id,
                    "explanation": f.explanation,
                    "reclaimable_bytes": reclaimable,
                    "reclaimable_formatted": format_size(reclaimable),
                    "action": action,
                }
            )

        return suggestions

    def generate_report(self, show_all: bool = False) -> str:
        """Generate human-readable text report."""
        lines = []
        lines.append("=" * 72)
        lines.append(" PS5 ORPHANED CONTENT SCANNER REPORT (READ-ONLY)")
        lines.append(f" Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f" Console FW Target: {self.console_fw_str or 'not set (backport check skipped)'}")
        if self.app_db_path:
            lines.append(f" app.db: {self.app_db_path} ({len(self.app_db_titles)} titles registered)")
        elif self.app_db_error:
            lines.append(f" app.db: FAILED ({self.app_db_error})")
        lines.append("=" * 72)
        lines.append("")

        # Severity breakdown
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        total_findings = len(self.findings)
        lines.append(f"SUMMARY: {total_findings} finding(s) detected.")
        lines.append(
            f"  CRITICAL: {counts['CRITICAL']} | HIGH: {counts['HIGH']} | "
            f"MEDIUM: {counts['MEDIUM']} | LOW: {counts['LOW']} | INFO: {counts['INFO']}"
        )
        lines.append("-" * 72)
        lines.append("")

        # Group findings by severity
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev_findings = [f for f in self.findings if f.severity == sev]
            if sev_findings:
                lines.append(f"[{sev}] ({len(sev_findings)} issue{'s' if len(sev_findings) != 1 else ''})")
                for sf in sev_findings:
                    tid_prefix = f"[{sf.title_id}] " if sf.title_id else ""
                    lines.append(f"  * (Check {sf.check_id}) {tid_prefix}{sf.explanation}")
                lines.append("")

        if total_findings == 0:
            lines.append("  All checks passed. No orphaned files or database discrepancies found.")
            lines.append("")

        # Check 11: Disk space usage per title
        lines.append("=" * 72)
        lines.append(" DISK SPACE USAGE PER TITLE (Check 11)")
        lines.append("=" * 72)
        lines.append(f"{'Title ID':<12} {'Size':<12} {'Status':<16} {'Title Name'}")
        lines.append("-" * 72)

        sorted_titles = sorted(
            self.inventory.values(), key=lambda t: t.total_size_bytes, reverse=True
        )

        hidden_count = 0
        for t in sorted_titles:
            # Check 4 clutter rule: hide 0 B, system (NPXS non-homebrew), with no findings
            is_npxs_sys = is_system_npxs_title(t.title_id, t.title_name, t.content_id)
            t_findings = [f for f in self.findings if f.title_id == t.title_id]
            has_actionable = any(f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") for f in t_findings)

            if not show_all and t.total_size_bytes == 0 and is_npxs_sys and not has_actionable:
                hidden_count += 1
                continue

            # Determine orphan / status label
            if any(f.severity in ("CRITICAL", "HIGH") for f in t_findings):
                status = "ORPHAN / BROKEN"
            elif any(f.severity == "MEDIUM" for f in t_findings):
                status = "WARNING"
            elif any(f.severity == "LOW" for f in t_findings):
                status = "NOTICE"
            elif not t.app_paths and not t.appmeta_paths:
                status = "UNINSTALLED"
            else:
                status = "CLEAN"

            tname = t.title_name or "(unknown)"
            size_str = format_size(t.total_size_bytes)
            lines.append(f"{t.title_id:<12} {size_str:<12} {status:<16} {tname}")

        lines.append("-" * 72)
        if hidden_count > 0:
            lines.append(f"(Hidden {hidden_count} 0 B system titles with no findings; pass --all to show all)")
            lines.append("-" * 72)

        total_disk = sum(t.total_size_bytes for t in self.inventory.values())
        lines.append(f"Total Disk Space Accounted For: {format_size(total_disk)}")
        lines.append("=" * 72)

        # Suggested manual cleanup section
        lines.append("")
        lines.append("=" * 72)
        lines.append(" SUGGESTED MANUAL CLEANUP")
        lines.append("=" * 72)
        lines.append(" NOTE: The scanner is strictly read-only and deletes nothing.")
        lines.append(" All cleanup actions must be performed manually over FTP.")
        lines.append("")
        lines.append(" WARNING: Do NOT delete anything under /user/app, /user/appmeta, or")
        lines.append(" /system_data without first checking that the title is really gone")
        lines.append(" from the dashboard. Deleting a registered title's files while it is")
        lines.append(" still registered triggers an app.db rebuild (README gotcha 5).")
        lines.append("-" * 72)

        cleanup_items = self.get_manual_cleanup_suggestions()
        if cleanup_items:
            lines.append(" Recommended manual cleanup actions (findings at LOW or above):")
            lines.append("")
            total_reclaimable = 0
            for idx, item in enumerate(cleanup_items, 1):
                total_reclaimable += item["reclaimable_bytes"]
                tid_str = f" [{item['title_id']}]" if item["title_id"] else ""
                lines.append(f" {idx}. [{item['severity']}]{tid_str} {item['explanation']}")
                lines.append(f"    Console Path: {item['path']}")
                lines.append(f"    Reclaimable:  {item['reclaimable_formatted']}")
                lines.append(f"    Action:       {item['action']}")
                lines.append("")
            lines.append("-" * 72)
            lines.append(f" Total Potential Space Reclaimable: {format_size(total_reclaimable)}")
        else:
            lines.append(" No manual cleanup needed. All checks clean.")
        lines.append("=" * 72)

        return "\n".join(lines)

    def to_json(self) -> Dict:
        """Export scan results as structured dictionary."""
        cleanup_items = self.get_manual_cleanup_suggestions()
        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "console_fw": self.console_fw_str,
            "app_db": {
                "path": self.app_db_path,
                "error": self.app_db_error,
                "registered_count": len(self.app_db_titles),
            },
            "findings_count": len(self.findings),
            "findings": [asdict(f) for f in self.findings],
            "inventory": {
                tid: {
                    "title_id": t.title_id,
                    "title_name": t.title_name,
                    "content_id": t.content_id,
                    "app_paths": t.app_paths,
                    "appmeta_paths": t.appmeta_paths,
                    "patch_paths": t.patch_paths,
                    "addcont_paths": t.addcont_paths,
                    "backport_paths": t.backport_paths,
                    "extracted_paths": [p[0] for p in t.extracted_paths],
                    "license_files": t.license_files,
                    "is_fpkg": t.is_fpkg,
                    "total_size_bytes": t.total_size_bytes,
                    "total_size_formatted": format_size(t.total_size_bytes),
                    "in_app_db": t.in_app_db,
                    "temp_files": [f.path for f in t.temp_files],
                }
                for tid, t in self.inventory.items()
            },
            "extracted_folders": self.extracted_folders,
            "stray_pkgs": [
                {"path": spkg.path, "size": spkg.size, "size_formatted": format_size(spkg.size)}
                for spkg in self.stray_pkgs
            ],
            "bgft_tasks": [
                {
                    "path": t[0].path,
                    "size": t[1],
                    "size_formatted": format_size(t[1]),
                    "files": [f.name for f in t[2]],
                }
                for t in self.bgft_tasks
            ],
            "manual_cleanup_suggestions": cleanup_items,
        }


def read_default_ip() -> Optional[str]:
    """Read the default PS5 IP from $PS5_IP, else from ps5-ip.txt (current dir or next to this script)."""
    env_ip = os.environ.get("PS5_IP", "").strip()
    if env_ip:
        return env_ip
    for cand in ("ps5-ip.txt", os.path.join(os.path.dirname(__file__), "ps5-ip.txt")):
        if os.path.exists(cand):
            try:
                with open(cand, "r", encoding="utf-8") as f:
                    ip = f.read().strip()
                    if ip:
                        return ip
            except Exception:
                pass
    return None


def check_tcp_reachable(host: str, port: int = 2121, timeout: float = 3.0) -> bool:
    """Check TCP reachability to host:port with a timeout."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def main():
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr and hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="PS5 Orphaned Content Scanner (Read-Only)"
    )
    parser.add_argument(
        "--ip",
        help="PS5 IP address (default: $PS5_IP, else ps5-ip.txt)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=2121,
        help="PS5 FTP port (default: 2121)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Command timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--offline",
        help="Run analysis against a local directory tree instead of live FTP",
    )
    parser.add_argument(
        "--console-fw",
        help="Console firmware version, e.g. 4.03. Enables the check for installed titles "
        "that need a newer firmware and have no backport (default: check skipped)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=6,
        help="Max recursion depth for stray pkg scan (default: 6)",
    )
    parser.add_argument(
        "--min-pkg-size",
        type=int,
        default=1048576,
        help="Minimum expected app.pkg size in bytes (default: 1048576 = 1MB)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Show all titles in disk usage table, including 0 B system apps with no findings",
    )
    parser.add_argument(
        "--json",
        dest="json_out",
        help="Path to write JSON scan report",
    )

    args = parser.parse_args()

    # Determine filesystem backend
    fs: Optional[ConsoleFS] = None
    if args.offline:
        if not os.path.exists(args.offline) or not os.path.isdir(args.offline):
            print(f"Error: Offline directory does not exist: {args.offline}", file=sys.stderr)
            sys.exit(2)
        fs = LocalConsoleFS(args.offline)
    else:
        ip = args.ip or read_default_ip()
        if not ip:
            print(
                "Error: No PS5 IP specified. Use --ip <address>, set PS5_IP, or create ps5-ip.txt.",
                file=sys.stderr,
            )
            sys.exit(2)

        # Reachability check
        if not check_tcp_reachable(ip, args.port, timeout=3.0):
            print(
                f"Error: Console at {ip}:{args.port} is unreachable (TCP connect timeout).",
                file=sys.stderr,
            )
            sys.exit(2)

        try:
            fs = FTPConsoleFS(host=ip, port=args.port, timeout=args.timeout)
        except Exception as e:
            print(f"Error connecting to FTP server {ip}:{args.port}: {e}", file=sys.stderr)
            sys.exit(2)

    try:
        scanner = OrphanScanner(
            fs=fs,
            console_fw=args.console_fw,
            min_pkg_size=args.min_pkg_size,
            max_depth=args.max_depth,
        )

        scanner.build_inventory()
        scanner.run_checks()

        # Output text report
        report_text = scanner.generate_report(show_all=args.all)
        print(report_text)

        # Output JSON if requested
        if args.json_out:
            out_dir = os.path.dirname(args.json_out)
            if out_dir and not os.path.exists(out_dir):
                os.makedirs(out_dir, exist_ok=True)
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(scanner.to_json(), f, indent=2)
            print(f"\n[+] JSON report saved to: {args.json_out}")

        # Exit code: 0 if clean, 1 if findings
        if len(scanner.findings) > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    finally:
        fs.close()


if __name__ == "__main__":
    main()
