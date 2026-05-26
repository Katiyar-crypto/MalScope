"""
MalScope - ZIP Handler
Handles password-protected and plain ZIP files.
Extracts contents and routes to correct analyzer.
"""

import zipfile
import os
import tempfile
import shutil
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass, field


# Common malware sample passwords used by security repos
# (MalwareBazaar, VirusTotal, ANY.RUN, Hybrid Analysis, etc.)
COMMON_MALWARE_PASSWORDS = [
    b"infected",
    b"Infected",
    b"INFECTED",
    b"malware",
    b"Malware",
    b"virus",
    b"Virus",
    b"password",
    b"1234",
    b"admin",
    b"sample",
    b"sandbox",
    b"analysis",
    b"infected123",
    b"mal",
    b"evil",
    b"danger",
    b"threat",
    b"test",
    b"abc",
    b"abc123",
    b"P@ssw0rd",
    b"hackthebox",
    b"tryhackme",
    b"security",
    b"csirt",
    b"dfir",
    b"reverse",
    b"re",
    b"pwned",
    b"exploit",
    b"payload",
    b"0",
    b"1",
]


@dataclass
class ZipExtractResult:
    success: bool = False
    is_encrypted: bool = False
    password_found: Optional[str] = None
    password_tried: bool = False
    extracted_files: List[str] = field(default_factory=list)
    primary_file: Optional[str] = None   # Main file to analyze (exe, pyc, etc.)
    output_dir: str = ""
    file_list: List[str] = field(default_factory=list)
    error: str = ""
    needs_password: bool = False
    warnings: List[str] = field(default_factory=list)


class ZipHandler:
    """Handles zip extraction including password-protected malware samples"""

    MAX_FILES = 2000
    MAX_UNCOMPRESSED_SIZE = 250 * 1024 * 1024
    MAX_MEMBER_SIZE = 100 * 1024 * 1024
    MAX_DEPTH = 12

    # Priority order for which file to analyze first
    ANALYSIS_PRIORITY = [
        ".pyc", ".pyo",           # Python bytecode (highest)
        ".exe",                    # PE executable
        ".dll",                    # PE DLL
        ".so", ".elf",            # Linux binary
        ".apk", ".dex",           # Android
        ".jar", ".class",         # Java
        ".js", ".ps1", ".vbs",   # Scripts
        ".bat", ".cmd", ".sh",
        ".pdf", ".docx", ".xlsx",
        ".wasm",
    ]

    def is_zip(self, filepath: str) -> bool:
        try:
            with open(filepath, "rb") as f:
                return f.read(4) in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
        except Exception:
            return False

    def is_encrypted(self, filepath: str) -> bool:
        try:
            with zipfile.ZipFile(filepath) as zf:
                for info in zf.infolist():
                    if info.flag_bits & 0x1:
                        return True
            return False
        except Exception:
            return False

    def extract(self, filepath: str, password: Optional[str] = None,
                output_dir: Optional[str] = None) -> ZipExtractResult:
        result = ZipExtractResult()

        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix="malscope_zip_")
        result.output_dir = output_dir

        try:
            with zipfile.ZipFile(filepath) as zf:
                result.file_list = zf.namelist()
                result.is_encrypted = self.is_encrypted(filepath)
                uses_aes = self._uses_winzip_aes(zf)

                # Determine passwords to try
                passwords_to_try: List[Optional[bytes]] = [None]  # Try no password first

                if result.is_encrypted:
                    result.needs_password = True
                    if password:
                        # User-provided password goes first
                        passwords_to_try = [password.encode() if isinstance(password, str) else password]
                        passwords_to_try.extend(COMMON_MALWARE_PASSWORDS)
                    else:
                        passwords_to_try.extend(COMMON_MALWARE_PASSWORDS)

                    # Also try filename as password (SHA256 hashes)
                    fname_stem = Path(filepath).stem
                    if len(fname_stem) in (32, 40, 64):  # MD5, SHA1, SHA256
                        passwords_to_try.insert(1, fname_stem.encode())
                        passwords_to_try.insert(2, fname_stem[:8].encode())

                safety_error = self._validate_archive(zf)
                if safety_error:
                    result.error = safety_error
                    return result

                if uses_aes:
                    try:
                        import pyzipper
                    except ImportError:
                        result.error = (
                            "ZIP uses WinZip AES encryption (compression method 99), "
                            "which Python's built-in zipfile cannot decrypt.\n"
                            "Install pyzipper or run: pip install -r requirements.txt"
                        )
                        result.needs_password = True
                        return result
                    return self._extract_with_pyzipper(
                        filepath,
                        output_dir,
                        passwords_to_try,
                        result,
                        pyzipper,
                    )

                # Try extraction
                extracted = False
                for pwd in passwords_to_try:
                    try:
                        result.warnings = self._safe_extract_all(zf, output_dir, pwd=pwd)
                        result.password_found = pwd.decode("utf-8", errors="replace") if pwd else None
                        result.password_tried = True
                        extracted = True
                        break
                    except (RuntimeError, zipfile.BadZipFile):
                        continue
                    except Exception:
                        continue

                if not extracted:
                    result.error = (
                        "ZIP is password-protected and no common password worked.\n"
                        "Please provide the password manually in the ZIP Password field."
                    )
                    result.needs_password = True
                    return result

        except zipfile.BadZipFile as e:
            result.error = f"Invalid or corrupted ZIP file: {e}"
            return result
        except Exception as e:
            result.error = f"ZIP extraction failed: {e}"
            return result

        # Collect extracted files
        for root, dirs, files in os.walk(output_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                result.extracted_files.append(fpath)

        # Pick primary file to analyze (by priority)
        result.primary_file = self._pick_primary(result.extracted_files)
        result.success = True
        return result

    def _finalize_extraction(self, result: ZipExtractResult) -> ZipExtractResult:
        for root, dirs, files in os.walk(result.output_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                result.extracted_files.append(fpath)

        result.primary_file = self._pick_primary(result.extracted_files)
        result.success = True
        return result

    def _validate_archive(self, zf: zipfile.ZipFile) -> str:
        members = zf.infolist()
        if len(members) > self.MAX_FILES:
            return f"ZIP has too many files ({len(members)} > {self.MAX_FILES})."

        total_size = 0
        for info in members:
            name = info.filename.replace("\\", "/")
            if not name or name.endswith("/"):
                continue
            if Path(name).is_absolute() or ".." in Path(name).parts:
                return f"Unsafe ZIP path blocked: {info.filename}"
            if len([p for p in Path(name).parts if p not in ("", ".")]) > self.MAX_DEPTH:
                return f"ZIP nesting too deep: {info.filename}"
            if info.file_size > self.MAX_MEMBER_SIZE:
                return f"ZIP member too large: {info.filename} ({info.file_size:,} bytes)."
            total_size += info.file_size

        if total_size > self.MAX_UNCOMPRESSED_SIZE:
            return f"ZIP uncompressed size too large ({total_size:,} bytes)."
        return ""

    def _uses_winzip_aes(self, zf: zipfile.ZipFile) -> bool:
        return any(info.compress_type == 99 for info in zf.infolist())

    def _safe_extract_all(self, zf: zipfile.ZipFile, output_dir: str,
                          pwd: Optional[bytes] = None) -> List[str]:
        warnings = []
        base = Path(output_dir).resolve()
        base.mkdir(parents=True, exist_ok=True)

        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            if not name or name.endswith("/"):
                continue

            target = (base / name).resolve()
            try:
                target.relative_to(base)
            except ValueError:
                raise RuntimeError(f"Unsafe ZIP path blocked: {info.filename}")

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r", pwd=pwd) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)

            if info.flag_bits & 0x800:
                warnings.append(f"UTF-8 filename: {info.filename}")

        return warnings

    def _extract_with_pyzipper(self, filepath: str, output_dir: str,
                               passwords_to_try: List[Optional[bytes]],
                               result: ZipExtractResult, pyzipper) -> ZipExtractResult:
        extracted = False
        for pwd in passwords_to_try:
            try:
                with pyzipper.AESZipFile(filepath) as zf:
                    if pwd:
                        zf.setpassword(pwd)
                    result.warnings = self._safe_extract_all(zf, output_dir, pwd=None)
                    result.password_found = pwd.decode("utf-8", errors="replace") if pwd else None
                    result.password_tried = True
                    extracted = True
                    break
            except (RuntimeError, zipfile.BadZipFile, NotImplementedError, ValueError):
                continue
            except Exception:
                continue

        if not extracted:
            result.error = (
                "ZIP uses WinZip AES encryption and no common password worked.\n"
                "Please provide the password manually in the ZIP Password field."
            )
            result.needs_password = True
            return result

        return self._finalize_extraction(result)

    def _pick_primary(self, files: List[str]) -> Optional[str]:
        """Pick the most interesting file to analyze"""
        for ext in self.ANALYSIS_PRIORITY:
            for f in files:
                if f.lower().endswith(ext):
                    return f
        # Fallback: largest file
        if files:
            return max(files, key=lambda f: os.path.getsize(f))
        return None

    def get_file_list_summary(self, filepath: str) -> List[dict]:
        """Get list of files in zip without extracting"""
        result = []
        try:
            with zipfile.ZipFile(filepath) as zf:
                for info in zf.infolist():
                    result.append({
                        "name": info.filename,
                        "size": info.file_size,
                        "compressed": info.compress_size,
                        "encrypted": bool(info.flag_bits & 0x1),
                        "method": info.compress_type,
                    })
        except Exception:
            pass
        return result
