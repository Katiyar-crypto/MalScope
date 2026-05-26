"""
MalScope - PyInstaller Unpacker
Extracts .pyc files from PyInstaller-packed executables
"""

import os
import struct
import zlib
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class UnpackResult:
    success: bool = False
    is_pyinstaller: bool = False
    extracted_files: List[str] = field(default_factory=list)
    pyc_files: List[str] = field(default_factory=list)
    output_dir: str = ""
    error: str = ""
    python_version: str = ""
    metadata: Dict = field(default_factory=dict)


class PyInstallerUnpacker:
    """Extracts embedded Python files from PyInstaller executables"""

    # PyInstaller magic bytes
    PYINST_MAGIC = b"MEI\014\013\012\013\016"
    PYINST20_MAGIC = b"MEIXXXXXX"

    # CArchive item types
    PKG_ITEM_BINARY = b"b"
    PKG_ITEM_DEPENDENCY = b"d"
    PKG_ITEM_PYZ = b"z"
    PKG_ITEM_ZIPFILE = b"Z"
    PKG_ITEM_PYPACKAGE = b"M"
    PKG_ITEM_PYMODULE = b"m"
    PKG_ITEM_PYSOURCE = b"s"
    PKG_ITEM_DATA = b"x"
    PKG_ITEM_RUNTIME_OPTION = b"o"
    PKG_ITEM_SPLASH = b"l"

    def detect_pyinstaller(self, filepath: str) -> bool:
        """Check if a file is a PyInstaller executable"""
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            return self.PYINST_MAGIC in data or self.PYINST20_MAGIC in data
        except Exception:
            return False

    def unpack(self, filepath: str, output_dir: Optional[str] = None) -> UnpackResult:
        """Main unpacking entry point"""
        result = UnpackResult()

        if not os.path.exists(filepath):
            result.error = f"File not found: {filepath}"
            return result

        # Detect PyInstaller
        result.is_pyinstaller = self.detect_pyinstaller(filepath)
        if not result.is_pyinstaller:
            result.error = "File does not appear to be a PyInstaller executable"
            return result

        # Setup output dir
        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix="malscope_unpack_")
        os.makedirs(output_dir, exist_ok=True)
        result.output_dir = output_dir

        # Try pyinstxtractor first
        success = self._try_pyinstxtractor(filepath, output_dir, result)
        if not success:
            success = self._manual_extract(filepath, output_dir, result)

        if success:
            result.success = True
            result.pyc_files = [
                f for f in result.extracted_files
                if f.endswith(".pyc") or f.endswith(".pyc.encrypted")
            ]

        return result

    def _try_pyinstxtractor(self, filepath: str, output_dir: str, result: UnpackResult) -> bool:
        """Try using pyinstxtractor library"""
        try:
            import pyinstxtractor
            old_dir = os.getcwd()
            os.chdir(output_dir)
            try:
                arch = pyinstxtractor.PyInstArchive(filepath)
                if arch.open():
                    if arch.checkFile():
                        if arch.getCArchiveInfo():
                            arch.parseTOC()
                            arch.extractFiles()
                            arch.close()

                            # Collect extracted files
                            for root, dirs, files in os.walk(output_dir):
                                for fname in files:
                                    fpath = os.path.join(root, fname)
                                    result.extracted_files.append(fpath)

                            result.python_version = getattr(arch, "pyver", "Unknown")
                            return True
            finally:
                os.chdir(old_dir)
        except ImportError:
            pass
        except Exception as e:
            result.error = f"pyinstxtractor error: {e}"

        return False

    def _manual_extract(self, filepath: str, output_dir: str, result: UnpackResult) -> bool:
        """Manual extraction fallback"""
        try:
            with open(filepath, "rb") as f:
                data = f.read()

            # Find PyInstaller overlay
            magic_pos = data.rfind(self.PYINST_MAGIC)
            if magic_pos == -1:
                magic_pos = data.rfind(self.PYINST20_MAGIC)
            if magic_pos == -1:
                result.error = "Could not find PyInstaller archive magic"
                return False

            # Parse CArchive TOC
            overlay_start = magic_pos
            pkg_data = data[overlay_start:]

            # Try to find and decompress zlib-compressed entries
            extracted = self._find_zlib_payloads(data, output_dir)
            result.extracted_files.extend(extracted)

            return len(extracted) > 0
        except Exception as e:
            result.error = f"Manual extraction failed: {e}"
            return False

    def _find_zlib_payloads(self, data: bytes, output_dir: str) -> List[str]:
        """Find and decompress zlib-compressed payloads"""
        extracted = []
        pos = 0
        idx = 0

        while pos < len(data):
            # Look for zlib magic bytes
            zlib_magic = data.find(b"\x78\x9c", pos)
            if zlib_magic == -1:
                zlib_magic = data.find(b"\x78\xda", pos)
            if zlib_magic == -1:
                break

            for size in [1024, 4096, 16384, 65536, 262144, 1048576]:
                try:
                    chunk = data[zlib_magic:zlib_magic + size]
                    decompressed = zlib.decompress(chunk)
                    if len(decompressed) > 100:
                        fname = os.path.join(output_dir, f"payload_{idx}.bin")
                        with open(fname, "wb") as f:
                            f.write(decompressed)

                        # Check if it's a .pyc
                        if decompressed[:4] in [b"\x55\x0d\x0d\x0a", b"\x16\x0d\x0d\x0a",
                                                  b"\x33\x0d\x0d\x0a", b"\x61\x0d\x0d\x0a"]:
                            pyc_name = fname.replace(".bin", ".pyc")
                            os.rename(fname, pyc_name)
                            extracted.append(pyc_name)
                        else:
                            extracted.append(fname)
                        idx += 1
                        break
                except Exception:
                    continue

            pos = zlib_magic + 2

        return extracted

    def get_entry_point(self, output_dir: str) -> Optional[str]:
        """Try to identify the main entry point script"""
        candidates = ["__main__", "main", "entry_point", "app"]
        for root, dirs, files in os.walk(output_dir):
            for fname in files:
                stem = Path(fname).stem.lower()
                if stem in candidates and fname.endswith(".pyc"):
                    return os.path.join(root, fname)
        # Fallback: return first .pyc
        for root, dirs, files in os.walk(output_dir):
            for fname in files:
                if fname.endswith(".pyc"):
                    return os.path.join(root, fname)
        return None
