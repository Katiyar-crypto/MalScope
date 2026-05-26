"""
MalScope - Universal Decompiler Engine
Supports: .pyc, .exe (PyInstaller), ELF, PE, .class (Java),
          .apk (Android), .wasm, .dll, .so, scripts (.js, .ps1, .vbs, .bat),
          documents (.pdf, .docx, .xlsm), and more.
"""

import os
import sys
import struct
import subprocess
import tempfile
import hashlib
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple


@dataclass
class UniversalResult:
    success: bool = False
    file_type: str = "Unknown"
    file_category: str = "Unknown"
    language: str = "Unknown"
    architecture: str = ""
    bits: int = 0
    source_code: str = ""
    disassembly: str = ""
    strings: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    sections: List[Dict] = field(default_factory=list)
    headers: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)
    error: str = ""
    warnings: List[str] = field(default_factory=list)
    backend_used: str = ""
    md5: str = ""
    sha256: str = ""
    file_size: int = 0
    entropy: float = 0.0
    # For tab display
    tabs: Dict[str, str] = field(default_factory=dict)
    needs_password: bool = False   # ZIP needs password


# ─────────────────────────────────────────────────────────────────────────────
# File type detection
# ─────────────────────────────────────────────────────────────────────────────

MAGIC_SIGNATURES = {
    b"\x4d\x5a": "PE",                          # MZ - Windows PE
    b"\x7fELF": "ELF",                           # Linux/Unix ELF
    b"\xca\xfe\xba\xbe": "MachO_FAT",           # Mach-O Fat
    b"\xce\xfa\xed\xfe": "MachO_32",            # Mach-O 32-bit
    b"\xcf\xfa\xed\xfe": "MachO_64",            # Mach-O 64-bit
    b"\xfe\xed\xfa\xce": "MachO_32_BE",
    b"\xfe\xed\xfa\xcf": "MachO_64_BE",
    b"\x00asm": "WASM",                          # WebAssembly
    b"PK\x03\x04": "ZIP",                        # ZIP / APK / JAR / DOCX
    b"PK\x05\x06": "ZIP_EMPTY",
    b"\xd0\xcf\x11\xe0": "OLE2",                # Office 97-2003 / XLS / DOC
    b"%PDF": "PDF",
    b"CAFEBABE": "Java_CLASS",
    b"\xac\xed": "Java_SERIALIZED",
    b"dex\n": "DEX",                             # Android DEX
    b"CDEX": "CDEX",                             # Compact DEX
    b"\x1f\x8b": "GZIP",
    b"BZh": "BZIP2",
    b"\xfd7zXZ": "XZ",
    b"Rar!": "RAR",
    b"7z\xbc\xaf\x27\x1c": "7ZIP",
    b"\x0d\x0d\x0a": "PYC",                     # Python .pyc (older)
}

EXTENSION_MAP = {
    ".pyc": ("Python Bytecode", "Python"),
    ".pyo": ("Python Bytecode", "Python"),
    ".py":  ("Python Script",   "Python"),
    ".exe": ("PE Executable",   "Native/Python"),
    ".dll": ("PE DLL",          "Native"),
    ".so":  ("ELF Shared Lib",  "Native"),
    ".elf": ("ELF Binary",      "Native"),
    ".class": ("Java Class",    "Java"),
    ".jar": ("Java Archive",    "Java"),
    ".apk": ("Android Package", "Java/Dalvik"),
    ".dex": ("Dalvik Bytecode", "Java/Dalvik"),
    ".wasm": ("WebAssembly",    "WASM"),
    ".js":  ("JavaScript",      "JavaScript"),
    ".ts":  ("TypeScript",      "JavaScript"),
    ".ps1": ("PowerShell",      "PowerShell"),
    ".psm1": ("PowerShell Module", "PowerShell"),
    ".vbs": ("VBScript",        "VBScript"),
    ".bat": ("Batch Script",    "Batch"),
    ".cmd": ("Batch Script",    "Batch"),
    ".sh":  ("Shell Script",    "Bash"),
    ".rb":  ("Ruby Script",     "Ruby"),
    ".pl":  ("Perl Script",     "Perl"),
    ".php": ("PHP Script",      "PHP"),
    ".lua": ("Lua Script",      "Lua"),
    ".go":  ("Go Source",       "Go"),
    ".rs":  ("Rust Source",     "Rust"),
    ".pdf": ("PDF Document",    "PDF"),
    ".docx": ("Word Document",  "Office"),
    ".xlsx": ("Excel Document", "Office"),
    ".xlsm": ("Excel Macro",    "Office/VBA"),
    ".doc":  ("Word 97 Doc",    "Office"),
    ".xls":  ("Excel 97",       "Office"),
    ".pptx": ("PowerPoint",     "Office"),
    ".vba":  ("VBA Script",     "VBA"),
}


def detect_file_type(filepath: str) -> Tuple[str, str, str]:
    """Returns (file_type, category, language)"""
    ext = Path(filepath).suffix.lower()
    try:
        with open(filepath, "rb") as f:
            header = f.read(16)

        # Check magic bytes
        for sig, ftype in MAGIC_SIGNATURES.items():
            if header[:len(sig)] == sig:
                # Refine ZIP-based formats by extension
                if ftype == "ZIP":
                    if ext == ".apk": return "APK", "Android", "Java/Dalvik"
                    if ext == ".jar": return "JAR", "Java", "Java"
                    if ext in (".docx", ".docm"): return "DOCX", "Office", "Office/VBA"
                    if ext in (".xlsx", ".xlsm"): return "XLSX", "Office", "Office/VBA"
                    if ext == ".pptx": return "PPTX", "Office", "Office"
                    return "ZIP", "Archive", "N/A"
                if ftype == "PE":
                    if ext == ".dll": return "PE DLL", "Native", "Native"
                    return "PE EXE", "Native", "Native/Python"
                if ftype in ("ELF",):
                    if ext == ".so": return "ELF Shared", "Native", "Native"
                    return "ELF", "Native", "Native"
                # PYC magic check (3rd/4th bytes are 0x0d 0x0a)
                if header[2:4] == b"\r\n":
                    if ext in (".pyc", ".pyo"):
                        return "PYC", "Python", "Python"
                return ftype, "Binary", "Native"

        # Fallback to extension
        if ext in EXTENSION_MAP:
            ft, lang = EXTENSION_MAP[ext]
            cat = "Script" if lang in ("Python","JavaScript","PowerShell","Bash","Ruby","Perl","PHP","VBScript","Batch") else "Binary"
            return ft, cat, lang

        # Try reading as text
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read(512)
            if text.startswith("#!/"):
                return "Shell Script", "Script", "Bash/Shell"
            if "<?php" in text:
                return "PHP Script", "Script", "PHP"
            if "function " in text or "var " in text or "const " in text:
                return "JavaScript", "Script", "JavaScript"
        except Exception:
            pass

        return "Unknown Binary", "Unknown", "Unknown"
    except Exception as e:
        return "Unknown", "Unknown", "Unknown"


def compute_hashes(filepath: str) -> Tuple[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha256.update(chunk)
    except Exception:
        pass
    return md5.hexdigest(), sha256.hexdigest()


def shannon_entropy(filepath: str) -> float:
    import math
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        if not data: return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        entropy = 0.0
        n = len(data)
        for count in freq.values():
            p = count / n
            entropy -= p * math.log2(p)
        return round(entropy, 4)
    except Exception:
        return 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Individual format handlers
# ─────────────────────────────────────────────────────────────────────────────

class PEAnalyzer:
    """PE/EXE/DLL analyzer using pefile"""

    def analyze(self, filepath: str, result: UniversalResult):
        result.file_category = "Native Binary"
        try:
            import pefile
            pe = pefile.PE(filepath)

            # Machine / arch
            machine = pe.FILE_HEADER.Machine
            arch_map = {0x14c: "x86", 0x8664: "x64", 0xaa64: "ARM64", 0x1c0: "ARM"}
            result.architecture = arch_map.get(machine, f"0x{machine:04x}")
            result.bits = 64 if machine == 0x8664 else 32

            # Headers
            result.headers = {
                "TimeDateStamp": pe.FILE_HEADER.TimeDateStamp,
                "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
                "Characteristics": hex(pe.FILE_HEADER.Characteristics),
                "ImageBase": hex(pe.OPTIONAL_HEADER.ImageBase),
                "EntryPoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "SizeOfImage": pe.OPTIONAL_HEADER.SizeOfImage,
                "Subsystem": pe.OPTIONAL_HEADER.Subsystem,
            }

            # Sections
            for section in pe.sections:
                try:
                    name = section.Name.decode("utf-8", errors="replace").strip("\x00")
                    result.sections.append({
                        "name": name,
                        "vaddr": hex(section.VirtualAddress),
                        "vsize": section.Misc_VirtualSize,
                        "rsize": section.SizeOfRawData,
                        "characteristics": hex(section.Characteristics),
                    })
                except Exception:
                    pass

            # Imports
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode("utf-8", errors="replace")
                    for imp in entry.imports:
                        name = imp.name.decode("utf-8", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                        result.imports.append(f"{dll}::{name}")

            # Exports
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        result.exports.append(exp.name.decode("utf-8", errors="replace"))

            # Strings
            result.strings = self._extract_strings(filepath)

            # Check PyInstaller
            with open(filepath, "rb") as f:
                raw = f.read()
            if b"MEI\014\013\012\013\016" in raw or b"PyInstaller" in raw:
                result.metadata["pyinstaller"] = True
                result.warnings.append("PyInstaller bundle detected — use PyInstaller tab to extract .pyc files")

            result.success = True
            result.backend_used = "pefile"
            result.tabs["PE Headers"] = self._format_headers(result)
            result.tabs["Sections"] = self._format_sections(result)
            result.tabs["Imports"] = "\n".join(result.imports[:500])
            result.tabs["Exports"] = "\n".join(result.exports[:200])
            result.tabs["Strings"] = "\n".join(result.strings[:300])

            # Disassembly with capstone
            self._disassemble(pe, result)

        except ImportError:
            self._analyze_pe_fallback(filepath, result)
        except Exception as e:
            result.error = f"PE analysis failed: {e}"

    def _analyze_pe_fallback(self, filepath: str, result: UniversalResult):
        try:
            with open(filepath, "rb") as f:
                data = f.read()

            if data[:2] != b"MZ":
                raise ValueError("Missing MZ header")

            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                raise ValueError("Missing PE signature")

            coff = pe_offset + 4
            machine, sections_count, timestamp, sym_ptr, sym_count, opt_size, characteristics = struct.unpack_from(
                "<HHIIIHH", data, coff
            )
            arch_map = {0x14c: "x86", 0x8664: "x64", 0xaa64: "ARM64", 0x1c0: "ARM"}
            result.architecture = arch_map.get(machine, f"0x{machine:04x}")
            result.bits = 64 if machine in (0x8664, 0xaa64) else 32

            optional_offset = coff + 20
            optional_magic = struct.unpack_from("<H", data, optional_offset)[0] if opt_size >= 2 else 0
            entry_point = struct.unpack_from("<I", data, optional_offset + 16)[0] if opt_size >= 20 else 0
            image_base_offset = optional_offset + (24 if optional_magic == 0x20B else 28)
            if optional_magic == 0x20B and len(data) >= image_base_offset + 8:
                image_base = struct.unpack_from("<Q", data, image_base_offset)[0]
            elif len(data) >= image_base_offset + 4:
                image_base = struct.unpack_from("<I", data, image_base_offset)[0]
            else:
                image_base = 0

            result.headers = {
                "Machine": hex(machine),
                "Architecture": result.architecture,
                "Bits": result.bits,
                "TimeDateStamp": timestamp,
                "NumberOfSections": sections_count,
                "Characteristics": hex(characteristics),
                "OptionalMagic": hex(optional_magic),
                "ImageBase": hex(image_base),
                "EntryPoint": hex(entry_point),
                "SymbolTablePointer": sym_ptr,
                "SymbolCount": sym_count,
            }

            section_offset = optional_offset + opt_size
            for i in range(sections_count):
                off = section_offset + (i * 40)
                if off + 40 > len(data):
                    break
                name = data[off:off + 8].rstrip(b"\x00").decode("utf-8", errors="replace")
                vsize, vaddr, rsize, raw_ptr, reloc_ptr, line_ptr, reloc_count, line_count, chars = struct.unpack_from(
                    "<IIIIIIHHI", data, off + 8
                )
                result.sections.append({
                    "name": name,
                    "vaddr": hex(vaddr),
                    "vsize": vsize,
                    "rsize": rsize,
                    "raw_ptr": raw_ptr,
                    "characteristics": hex(chars),
                })

            result.strings = self._extract_strings(filepath)
            result.imports = self._guess_imports_from_strings(result.strings)
            result.success = True
            result.backend_used = "stdlib PE fallback"
            result.warnings.append("pefile not installed - using limited built-in PE parser")
            result.tabs["PE Headers"] = self._format_headers(result)
            result.tabs["Sections"] = self._format_sections(result)
            result.tabs["Imports"] = "\n".join(result.imports[:500])
            result.tabs["Strings"] = "\n".join(result.strings[:300])
        except Exception as e:
            result.error = f"PE fallback analysis failed: {e}"

    def _guess_imports_from_strings(self, strings: List[str]) -> List[str]:
        dlls = []
        apis = []
        for s in strings:
            low = s.lower()
            if low.endswith((".dll", ".ocx", ".drv")) and len(s) < 80:
                dlls.append(s)
            elif re.match(r"^[A-Za-z_][A-Za-z0-9_]{3,}$", s) and any(
                token in s for token in ("Create", "Get", "Set", "Reg", "Crypt", "Win", "Load", "Open", "Read", "Write")
            ):
                apis.append(s)
        return sorted(set(dlls + apis))[:1000]

    def _extract_strings(self, filepath: str, min_len: int = 6) -> List[str]:
        strings = []
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
            strings = [m.decode("ascii") for m in re.findall(pattern, data)]
        except Exception:
            pass
        return strings[:1000]

    def _disassemble(self, pe, result: UniversalResult):
        try:
            import capstone
            arch_map = {
                0x14c: (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
                0x8664: (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
                0xaa64: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            }
            machine = pe.FILE_HEADER.Machine
            if machine not in arch_map:
                return
            arch, mode = arch_map[machine]
            md = capstone.Cs(arch, mode)
            md.detail = False

            # Get .text section
            text_section = None
            for s in pe.sections:
                name = s.Name.decode("utf-8", errors="replace").strip("\x00")
                if name in (".text", "CODE", ".code"):
                    text_section = s
                    break

            if not text_section:
                return

            code = text_section.get_data()[:16384]  # First 16KB
            base = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress

            lines = [f"; .text section disassembly (first {len(code)} bytes)", f"; Base: 0x{base:08x}", ""]
            count = 0
            for instr in md.disasm(code, base):
                lines.append(f"  0x{instr.address:08x}:  {instr.mnemonic:<12} {instr.op_str}")
                count += 1
                if count >= 500:
                    lines.append(f"  ; ... ({count} instructions shown, truncated)")
                    break

            result.disassembly = "\n".join(lines)
            result.tabs["Disassembly"] = result.disassembly
        except ImportError:
            result.warnings.append("capstone not installed — no disassembly. Run: pip install capstone")
        except Exception as e:
            result.warnings.append(f"Disassembly failed: {e}")

    def _format_headers(self, result: UniversalResult) -> str:
        lines = ["PE File Headers", "=" * 40]
        for k, v in result.headers.items():
            lines.append(f"  {k:<30} {v}")
        return "\n".join(lines)

    def _format_sections(self, result: UniversalResult) -> str:
        lines = ["Sections", "=" * 60,
                 f"  {'Name':<12} {'VAddr':<12} {'VSize':<10} {'RSize':<10} {'Chars'}"]
        lines.append("-" * 60)
        for s in result.sections:
            lines.append(f"  {s['name']:<12} {s['vaddr']:<12} {s['vsize']:<10} {s['rsize']:<10} {s['characteristics']}")
        return "\n".join(lines)


class ELFAnalyzer:
    """ELF binary analyzer using pyelftools"""

    def analyze(self, filepath: str, result: UniversalResult):
        result.file_category = "Native Binary"
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.sections import SymbolTableSection
            from elftools.elf.dynamic import DynamicSection

            with open(filepath, "rb") as f:
                elf = ELFFile(f)

                result.architecture = elf.get_machine_arch()
                result.bits = elf.elfclass
                result.headers = {
                    "Type": elf.header.e_type,
                    "Machine": elf.header.e_machine,
                    "Entry Point": hex(elf.header.e_entry),
                    "Sections": elf.num_sections(),
                    "Segments": elf.num_segments(),
                    "OS/ABI": elf.header.e_ident["EI_OSABI"],
                    "Endianness": elf.little_endian and "Little" or "Big",
                }

                # Sections
                for section in elf.iter_sections():
                    result.sections.append({
                        "name": section.name,
                        "type": section["sh_type"],
                        "addr": hex(section["sh_addr"]),
                        "size": section["sh_size"],
                        "flags": hex(section["sh_flags"]),
                    })

                # Symbols / imports
                for section in elf.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for sym in section.iter_symbols():
                            if sym.name:
                                result.imports.append(sym.name)

                # Dynamic deps
                for section in elf.iter_sections():
                    if isinstance(section, DynamicSection):
                        for tag in section.iter_tags():
                            if tag.entry.d_tag == "DT_NEEDED":
                                result.metadata.setdefault("needed_libs", []).append(tag.needed)

                # Disassemble with capstone
                text = elf.get_section_by_name(".text")
                if text:
                    self._disassemble_elf(text, elf, result)

            result.strings = self._extract_strings(filepath)
            result.success = True
            result.backend_used = "pyelftools + capstone"
            result.tabs["ELF Headers"] = self._format_headers(result)
            result.tabs["Sections"] = self._format_sections(result)
            result.tabs["Symbols"] = "\n".join(result.imports[:300])
            result.tabs["Strings"] = "\n".join(result.strings[:300])
            if result.disassembly:
                result.tabs["Disassembly"] = result.disassembly

        except ImportError:
            result.error = "pyelftools not installed. Run: pip install pyelftools"
        except Exception as e:
            result.error = f"ELF analysis failed: {e}"

    def _disassemble_elf(self, text_section, elf, result: UniversalResult):
        try:
            import capstone
            arch_map = {
                "x64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
                "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
                "AArch64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
                "ARM": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            }
            arch_name = elf.get_machine_arch()
            if arch_name not in arch_map:
                return
            arch, mode = arch_map[arch_name]
            md = capstone.Cs(arch, mode)
            code = text_section.data()[:16384]
            base = text_section["sh_addr"]
            lines = [f"; .text section ({len(code)} bytes, base 0x{base:x})", ""]
            count = 0
            for instr in md.disasm(code, base):
                lines.append(f"  0x{instr.address:08x}:  {instr.mnemonic:<12} {instr.op_str}")
                count += 1
                if count >= 500:
                    lines.append("  ; ... truncated")
                    break
            result.disassembly = "\n".join(lines)
        except Exception:
            pass

    def _extract_strings(self, filepath: str) -> List[str]:
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            return [m.decode("ascii") for m in re.findall(rb"[\x20-\x7e]{6,}", data)][:500]
        except Exception:
            return []

    def _format_headers(self, result: UniversalResult) -> str:
        lines = ["ELF Headers", "=" * 40]
        for k, v in result.headers.items():
            lines.append(f"  {k:<25} {v}")
        return "\n".join(lines)

    def _format_sections(self, result: UniversalResult) -> str:
        lines = ["ELF Sections", "=" * 60,
                 f"  {'Name':<20} {'Type':<20} {'Addr':<14} {'Size'}"]
        lines.append("-" * 60)
        for s in result.sections:
            lines.append(f"  {s['name']:<20} {s['type']:<20} {s['addr']:<14} {s['size']}")
        return "\n".join(lines)


class JavaClassAnalyzer:
    """Java .class file analyzer"""

    def analyze(self, filepath: str, result: UniversalResult):
        result.file_category = "Java Bytecode"
        result.language = "Java"

        try:
            with open(filepath, "rb") as f:
                data = f.read()

            if data[:4] != b"\xca\xfe\xba\xbe":
                result.error = "Not a valid Java .class file"
                return

            minor = struct.unpack(">H", data[4:6])[0]
            major = struct.unpack(">H", data[6:8])[0]
            java_ver = {
                52: "Java 8", 53: "Java 9", 54: "Java 10", 55: "Java 11",
                56: "Java 12", 57: "Java 13", 58: "Java 14", 59: "Java 15",
                60: "Java 16", 61: "Java 17", 62: "Java 18", 63: "Java 19",
                64: "Java 20", 65: "Java 21",
            }.get(major, f"Class version {major}.{minor}")

            result.headers = {
                "Magic": "0xCAFEBABE",
                "Class Version": f"{major}.{minor}",
                "Java Version": java_ver,
            }
            result.metadata["java_version"] = java_ver

            # Try javap
            javap = self._try_javap(filepath)
            if javap:
                result.source_code = javap
                result.backend_used = "javap"
            else:
                result.source_code = f"# Java class file ({java_ver})\n# Install JDK and ensure 'javap' is in PATH for disassembly\n"
                result.backend_used = "header-only"

            # Extract strings from class file
            result.strings = self._extract_utf8_strings(data)
            result.success = True
            result.tabs["Disassembly"] = result.source_code
            result.tabs["Strings"] = "\n".join(result.strings[:300])
            result.tabs["Headers"] = self._format_headers(result)

        except Exception as e:
            result.error = f"Java class analysis failed: {e}"

    def _try_javap(self, filepath: str) -> Optional[str]:
        try:
            r = subprocess.run(
                ["javap", "-c", "-p", "-verbose", filepath],
                capture_output=True, text=True, timeout=15
            )
            if r.returncode == 0 and r.stdout:
                return r.stdout
        except Exception:
            pass
        return None

    def _extract_utf8_strings(self, data: bytes) -> List[str]:
        strings = []
        i = 0
        while i < len(data) - 3:
            if data[i] == 0x01:  # CONSTANT_Utf8
                length = struct.unpack(">H", data[i+1:i+3])[0]
                if 3 <= length <= 200:
                    try:
                        s = data[i+3:i+3+length].decode("utf-8", errors="strict")
                        if all(32 <= ord(c) < 127 for c in s):
                            strings.append(s)
                    except Exception:
                        pass
                i += 3 + length
            else:
                i += 1
        return strings[:300]

    def _format_headers(self, result: UniversalResult) -> str:
        lines = ["Java Class Headers", "=" * 40]
        for k, v in result.headers.items():
            lines.append(f"  {k:<25} {v}")
        return "\n".join(lines)


class AndroidAPKAnalyzer:
    """APK / DEX analyzer"""

    def analyze(self, filepath: str, result: UniversalResult):
        result.file_category = "Android Package"
        result.language = "Java/Dalvik"

        try:
            import zipfile
            strings_found = []
            classes_found = []
            permissions = []
            manifest_content = ""

            with zipfile.ZipFile(filepath, "r") as zf:
                names = zf.namelist()

                # Manifest
                if "AndroidManifest.xml" in names:
                    raw = zf.read("AndroidManifest.xml")
                    manifest_content = self._parse_binary_xml(raw)
                    result.tabs["AndroidManifest"] = manifest_content

                    # Extract permissions from raw text
                    perms = re.findall(r"android\.permission\.\w+", manifest_content)
                    permissions = sorted(set(perms))

                # DEX files
                dex_files = [n for n in names if n.endswith(".dex")]
                for dex in dex_files[:3]:
                    with zf.open(dex) as f:
                        dex_data = f.read()
                    strs = self._extract_dex_strings(dex_data)
                    strings_found.extend(strs)
                    classes_found.extend(self._extract_dex_classes(dex_data))

                # List all files
                result.sections = [{"name": n, "size": zf.getinfo(n).file_size} for n in names]

            result.imports = permissions
            result.strings = list(set(strings_found))[:500]
            result.metadata = {
                "dex_files": len(dex_files),
                "total_files": len(names),
                "permissions": permissions,
            }
            result.headers = {
                "Format": "APK (ZIP-based)",
                "DEX Files": len(dex_files),
                "Total Files": len(names),
                "Permissions": len(permissions),
            }

            result.source_code = self._format_apk_summary(result, classes_found, manifest_content)
            result.success = True
            result.backend_used = "zipfile + DEX parser"
            result.tabs["Summary"] = result.source_code
            result.tabs["Permissions"] = "\n".join(permissions)
            result.tabs["File List"] = "\n".join(n for n in names)
            result.tabs["Strings"] = "\n".join(result.strings[:300])

        except Exception as e:
            result.error = f"APK analysis failed: {e}"

    def _parse_binary_xml(self, data: bytes) -> str:
        """Basic binary XML string extraction"""
        strings = re.findall(rb"[\x20-\x7e]{4,}", data)
        return "\n".join(s.decode("ascii", errors="replace") for s in strings[:200])

    def _extract_dex_strings(self, data: bytes) -> List[str]:
        return [m.decode("ascii", errors="replace") for m in re.findall(rb"[\x20-\x7e]{5,}", data)][:300]

    def _extract_dex_classes(self, data: bytes) -> List[str]:
        classes = re.findall(rb"L([a-zA-Z][a-zA-Z0-9/$_]{2,60});", data)
        return [c.decode("ascii", errors="replace").replace("/", ".") for c in classes][:200]

    def _format_apk_summary(self, result, classes, manifest) -> str:
        lines = [
            "# APK Analysis Summary",
            f"# DEX files: {result.metadata.get('dex_files', 0)}",
            f"# Total files: {result.metadata.get('total_files', 0)}",
            f"# Permissions: {len(result.imports)}",
            "",
            "## Permissions Declared:",
        ]
        for p in result.imports[:30]:
            lines.append(f"  - {p}")
        lines += ["", "## Classes Found (sample):"]
        for c in classes[:50]:
            lines.append(f"  - {c}")
        return "\n".join(lines)


class WASMAnalyzer:
    """WebAssembly analyzer"""

    def analyze(self, filepath: str, result: UniversalResult):
        result.file_category = "WebAssembly"
        result.language = "WASM"

        try:
            with open(filepath, "rb") as f:
                data = f.read()

            if data[:4] != b"\x00asm":
                result.error = "Not a valid WASM file"
                return

            version = struct.unpack("<I", data[4:8])[0]
            result.headers = {"Magic": "0x00 0x61 0x73 0x6d", "Version": version}

            sections, pos = [], 8
            section_names = {
                0: "Custom", 1: "Type", 2: "Import", 3: "Function",
                4: "Table", 5: "Memory", 6: "Global", 7: "Export",
                8: "Start", 9: "Element", 10: "Code", 11: "Data",
            }

            while pos < len(data):
                try:
                    sec_id = data[pos]; pos += 1
                    size, n = self._read_leb128(data, pos); pos += n
                    sec_name = section_names.get(sec_id, f"Unknown({sec_id})")
                    sections.append({"id": sec_id, "name": sec_name, "size": size})
                    pos += size
                except Exception:
                    break

            result.sections = sections
            result.strings = [m.decode("ascii", errors="replace") for m in re.findall(rb"[\x20-\x7e]{4,}", data)][:200]
            result.source_code = self._format_summary(result, sections)
            result.success = True
            result.backend_used = "built-in WASM parser"
            result.tabs["WASM Sections"] = result.source_code
            result.tabs["Strings"] = "\n".join(result.strings)

        except Exception as e:
            result.error = f"WASM analysis failed: {e}"

    def _read_leb128(self, data: bytes, pos: int) -> Tuple[int, int]:
        result = 0; shift = 0; n = 0
        while True:
            byte = data[pos + n]; n += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0: break
            shift += 7
        return result, n

    def _format_summary(self, result, sections) -> str:
        lines = ["# WebAssembly Module", f"# Version: {result.headers.get('Version', '?')}", "",
                 "## Sections:"]
        for s in sections:
            lines.append(f"  [{s['id']:2d}] {s['name']:<15} size={s['size']} bytes")
        return "\n".join(lines)


class ScriptAnalyzer:
    """Analyzer for script files: JS, PS1, VBS, BAT, SH, PHP, etc."""

    def analyze(self, filepath: str, result: UniversalResult):
        result.file_category = "Script"
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            result.source_code = content
            result.strings = re.findall(r'"([^"]{4,})"', content) + re.findall(r"'([^']{4,})'", content)

            ext = Path(filepath).suffix.lower()
            if ext == ".js":
                result.language = "JavaScript"
                result.tabs["Source"] = content
                self._analyze_js(content, result)
            elif ext in (".ps1", ".psm1"):
                result.language = "PowerShell"
                result.tabs["Source"] = content
                self._analyze_powershell(content, result)
            elif ext in (".vbs", ".vbe"):
                result.language = "VBScript"
                result.tabs["Source"] = content
            elif ext in (".bat", ".cmd"):
                result.language = "Batch"
                result.tabs["Source"] = content
            elif ext == ".sh":
                result.language = "Bash/Shell"
                result.tabs["Source"] = content
            elif ext == ".php":
                result.language = "PHP"
                result.tabs["Source"] = content
            elif ext == ".rb":
                result.language = "Ruby"
                result.tabs["Source"] = content

            result.success = True
            result.backend_used = "text reader"

        except Exception as e:
            result.error = f"Script analysis failed: {e}"

    def _analyze_js(self, content: str, result: UniversalResult):
        urls = re.findall(r'https?://[^\s\'"<>]+', content)
        evals = re.findall(r'eval\s*\(', content)
        if urls:
            result.imports.extend(urls[:20])
        if len(evals) > 0:
            result.warnings.append(f"eval() used {len(evals)} times — possible obfuscation")

    def _analyze_powershell(self, content: str, result: UniversalResult):
        if "EncodedCommand" in content or "-enc" in content.lower():
            result.warnings.append("Encoded PowerShell command detected")
        if "IEX" in content or "Invoke-Expression" in content:
            result.warnings.append("Invoke-Expression detected — dynamic execution")
        if "DownloadString" in content or "DownloadFile" in content:
            result.warnings.append("Network download function detected")


class OfficeAnalyzer:
    """Office document analyzer: DOCX, XLSX, XLSM, DOC, XLS"""

    def analyze(self, filepath: str, result: UniversalResult):
        result.file_category = "Office Document"
        ext = Path(filepath).suffix.lower()

        if ext in (".docx", ".xlsx", ".xlsm", ".pptx", ".docm"):
            self._analyze_ooxml(filepath, result)
        elif ext in (".doc", ".xls", ".xla"):
            self._analyze_ole(filepath, result)
        else:
            self._analyze_ooxml(filepath, result)

    def _analyze_ooxml(self, filepath: str, result: UniversalResult):
        try:
            import zipfile
            with zipfile.ZipFile(filepath, "r") as zf:
                names = zf.namelist()
                content_parts = []
                vba_code = []

                for name in names:
                    if name.endswith(".xml"):
                        try:
                            xml = zf.read(name).decode("utf-8", errors="replace")
                            text = re.sub(r"<[^>]+>", " ", xml)
                            text = re.sub(r"\s+", " ", text).strip()
                            if len(text) > 20:
                                content_parts.append(f"[{name}]\n{text[:2000]}")
                        except Exception:
                            pass
                    if "vba" in name.lower() or name.endswith(".bin"):
                        try:
                            raw = zf.read(name)
                            vba_strings = re.findall(rb"[\x20-\x7e]{6,}", raw)
                            vba_code.extend([s.decode("ascii", errors="replace") for s in vba_strings[:50]])
                        except Exception:
                            pass

                result.source_code = "\n\n".join(content_parts[:10])
                result.strings = vba_code
                result.sections = [{"name": n} for n in names]
                result.metadata = {"files_in_archive": len(names), "has_vba": bool(vba_code)}
                result.success = True
                result.backend_used = "zipfile (OOXML)"
                result.tabs["Document Content"] = result.source_code
                result.tabs["File Structure"] = "\n".join(names)
                if vba_code:
                    result.tabs["VBA Strings"] = "\n".join(vba_code)
                    result.warnings.append("VBA/macro content found — review for malicious code")
        except Exception as e:
            result.error = f"OOXML analysis failed: {e}"

    def _analyze_ole(self, filepath: str, result: UniversalResult):
        try:
            import olefile
            ole = olefile.OleFileIO(filepath)
            streams = ole.listdir()
            result.sections = [{"name": "/".join(s)} for s in streams]

            vba_streams = [s for s in streams if any("vba" in p.lower() for p in s)]
            vba_content = []
            for stream in vba_streams[:5]:
                try:
                    data = ole.openstream(stream).read()
                    strings = re.findall(rb"[\x20-\x7e]{6,}", data)
                    vba_content.extend([s.decode("ascii", errors="replace") for s in strings[:30]])
                except Exception:
                    pass

            result.strings = vba_content
            result.success = True
            result.backend_used = "olefile"
            result.tabs["OLE Streams"] = "\n".join("/".join(s) for s in streams)
            if vba_content:
                result.tabs["VBA Content"] = "\n".join(vba_content)
                result.warnings.append("VBA macro content found")
        except ImportError:
            result.error = "olefile not installed. Run: pip install olefile"
        except Exception as e:
            result.error = f"OLE analysis failed: {e}"


class PDFAnalyzer:
    """PDF document analyzer"""

    def analyze(self, filepath: str, result: UniversalResult):
        result.file_category = "PDF Document"
        result.language = "PDF"

        try:
            with open(filepath, "rb") as f:
                data = f.read()

            # Version
            ver_match = re.search(rb"%PDF-(\d+\.\d+)", data)
            version = ver_match.group(1).decode() if ver_match else "Unknown"

            # Count objects
            objects = len(re.findall(rb"\d+ \d+ obj", data))

            # Check for JavaScript
            has_js = b"/JavaScript" in data or b"/JS" in data
            has_launch = b"/Launch" in data
            has_form = b"/AcroForm" in data
            has_openaction = b"/OpenAction" in data

            # Extract readable strings
            strings = [m.decode("ascii", errors="replace") for m in re.findall(rb"[\x20-\x7e]{8,}", data)]

            result.headers = {
                "PDF Version": version,
                "Object Count": objects,
                "Has JavaScript": has_js,
                "Has Launch Action": has_launch,
                "Has AcroForm": has_form,
                "Has OpenAction": has_openaction,
            }
            result.strings = strings[:300]

            if has_js:
                result.warnings.append("JavaScript embedded in PDF — potential malicious action")
            if has_launch:
                result.warnings.append("/Launch action found — can execute files")
            if has_openaction:
                result.warnings.append("/OpenAction found — executes on open")

            # Extract JS content
            js_blocks = re.findall(rb"/JS\s*\(([^)]+)\)", data)
            js_content = "\n".join(b.decode("ascii", errors="replace") for b in js_blocks[:10])

            summary = self._format_summary(result, js_content)
            result.source_code = summary
            result.success = True
            result.backend_used = "built-in PDF parser"
            result.tabs["PDF Summary"] = summary
            result.tabs["Strings"] = "\n".join(result.strings[:200])
            if js_content:
                result.tabs["JavaScript"] = js_content

        except Exception as e:
            result.error = f"PDF analysis failed: {e}"

    def _format_summary(self, result, js_content) -> str:
        lines = ["# PDF Analysis Report", ""]
        for k, v in result.headers.items():
            lines.append(f"  {k:<30} {v}")
        if result.warnings:
            lines += ["", "## Warnings:"]
            for w in result.warnings:
                lines.append(f"  ⚠ {w}")
        if js_content:
            lines += ["", "## Embedded JavaScript:"]
            lines.append(js_content[:2000])
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Main dispatcher
# ─────────────────────────────────────────────────────────────────────────────

class UniversalDecompiler:
    """Main entry point — dispatches to the right analyzer"""

    def analyze(self, filepath: str, zip_password: str = None) -> UniversalResult:
        result = UniversalResult()
        result.file_size = os.path.getsize(filepath)
        result.md5, result.sha256 = compute_hashes(filepath)
        result.entropy = shannon_entropy(filepath)

        file_type, category, language = detect_file_type(filepath)
        result.file_type = file_type
        result.file_category = category
        result.language = language

        ext = Path(filepath).suffix.lower()

        # ── ZIP files (including password-protected malware samples) ──────────
        # Must be checked BEFORE extension-based dispatch since .exe/.apk inside
        # zip need to be extracted first
        if file_type in ("ZIP", "ZIP_EMPTY") or ext == ".zip":
            self._analyze_zip(filepath, result, password=zip_password)
            return result

        # Dispatch
        if file_type in ("PYC",) or ext in (".pyc", ".pyo"):
            from core.decompiler import PycDecompiler
            dec = PycDecompiler()
            r = dec.decompile(filepath)
            result.source_code = r.source_code
            result.language = f"Python {r.python_version}"
            result.backend_used = r.backend_used
            result.success = r.success
            result.error = r.error
            result.imports = r.imports
            result.strings = r.strings
            result.tabs["Source"] = r.source_code
            result.tabs["Pseudo-Source"] = r.pseudo_source
            result.metadata = {"python_version": r.python_version, "magic": r.magic_number}

        elif file_type in ("PE EXE", "PE DLL"):
            analyzer = PEAnalyzer()
            analyzer.analyze(filepath, result)

        elif file_type in ("ELF", "ELF Shared"):
            analyzer = ELFAnalyzer()
            analyzer.analyze(filepath, result)

        elif file_type == "APK":
            analyzer = AndroidAPKAnalyzer()
            analyzer.analyze(filepath, result)

        elif file_type in ("JAR",) or ext == ".jar":
            result.file_type = "JAR"
            self._analyze_jar(filepath, result)

        elif file_type == "Java_CLASS" or ext == ".class":
            analyzer = JavaClassAnalyzer()
            analyzer.analyze(filepath, result)

        elif file_type == "WASM" or ext == ".wasm":
            analyzer = WASMAnalyzer()
            analyzer.analyze(filepath, result)

        elif file_type == "PDF" or ext == ".pdf":
            analyzer = PDFAnalyzer()
            analyzer.analyze(filepath, result)

        elif file_type in ("DOCX", "XLSX", "PPTX") or ext in (".docx", ".xlsx", ".xlsm", ".pptx", ".docm"):
            analyzer = OfficeAnalyzer()
            analyzer.analyze(filepath, result)

        elif file_type in ("OLE2",) or ext in (".doc", ".xls", ".xla"):
            analyzer = OfficeAnalyzer()
            analyzer.analyze(filepath, result)

        elif ext in (".js", ".ts", ".ps1", ".psm1", ".vbs", ".bat", ".cmd", ".sh", ".rb", ".pl", ".php", ".lua", ".py"):
            analyzer = ScriptAnalyzer()
            analyzer.analyze(filepath, result)

        elif file_type in ("MachO_32", "MachO_64", "MachO_FAT"):
            self._analyze_macho(filepath, result)

        elif file_type == "DEX" or ext == ".dex":
            self._analyze_dex(filepath, result)

        else:
            # Generic binary fallback
            self._generic_analyze(filepath, result)

        # Always add metadata tab
        result.tabs["File Info"] = self._format_file_info(filepath, result)
        return result

    def _analyze_zip(self, filepath: str, result: UniversalResult,
                      password: str = None):
        """Handle ZIP files - extract, detect contents, route to right analyzer"""
        from core.zip_handler import ZipHandler
        result.file_type = "ZIP Archive"
        result.file_category = "Archive"

        handler = ZipHandler()
        file_list = handler.get_file_list_summary(filepath)
        is_enc = handler.is_encrypted(filepath)

        # Show file list immediately
        file_list_text = "ZIP Archive Contents\n" + "=" * 50 + "\n"
        file_list_text += f"Encrypted: {'Yes ⚠' if is_enc else 'No'}\n\n"
        for f in file_list:
            enc_tag = "🔒 " if f["encrypted"] else "   "
            file_list_text += (
                f"{enc_tag}{f['name']:<50} "
                f"{f['size']:>10,} bytes\n"
            )
        result.tabs["ZIP Contents"] = file_list_text

        # Attempt extraction
        extract = handler.extract(filepath, password=password)

        if not extract.success:
            result.success = False
            result.error = extract.error
            result.needs_password = extract.needs_password

            # Still show file list even if extraction failed
            result.source_code = (
                file_list_text + "\n\n" +
                "❌ " + extract.error + "\n\n" +
                "💡 Tip: Enter the ZIP password in the field above and click Re-analyze."
            )
            result.tabs["Error"] = result.source_code
            result.file_type = f"ZIP Archive ({'Encrypted 🔒' if is_enc else 'Plain'})"
            result.language = f"{len(file_list)} files inside"
            result.backend_used = "zip_handler"
            return

        # Extraction succeeded
        pwd_msg = " (password accepted)" if extract.password_found else ""
        result.metadata["zip_password_used"] = bool(extract.password_found)
        result.metadata["extracted_files"] = len(extract.extracted_files)
        result.metadata["output_dir"] = extract.output_dir

        result.tabs["ZIP Contents"] = (
            file_list_text +
            f"\n✅ Extracted successfully{pwd_msg}\n" +
            f"Primary file: {Path(extract.primary_file).name if extract.primary_file else 'None'}\n"
        )

        if not extract.primary_file:
            result.success = True
            result.source_code = file_list_text + "\nNo analyzable file found inside ZIP."
            return

        # ── Recursively analyze the primary extracted file ──────────────────
        primary = extract.primary_file
        primary_ext = Path(primary).suffix.lower()
        primary_name = Path(primary).name

        result.file_type = f"ZIP → {primary_name}"
        result.language = f"Extracted: {primary_name}"
        result.backend_used = f"zip_handler + {primary_ext} analyzer"

        # Run full analysis on the extracted file
        sub_result = UniversalDecompiler().analyze(primary)

        # Merge sub_result tabs into our result
        for tab_name, tab_content in sub_result.tabs.items():
            result.tabs[tab_name] = tab_content

        # Copy all important fields
        result.source_code = sub_result.source_code
        result.disassembly = sub_result.disassembly
        result.strings = sub_result.strings
        result.imports = sub_result.imports
        result.exports = sub_result.exports
        result.sections = sub_result.sections
        result.headers = sub_result.headers
        result.architecture = sub_result.architecture
        result.bits = sub_result.bits
        result.warnings = (
            sub_result.warnings
            + extract.warnings
            + (["ZIP was encrypted" + pwd_msg] if extract.password_found else [])
        )
        result.success = sub_result.success
        result.error = sub_result.error
        result.entropy = sub_result.entropy
        result.file_category = sub_result.file_category

        # Add extraction summary tab
        summary = [
            f"ZIP Extraction Summary",
            "=" * 40,
            f"  ZIP file       : {Path(filepath).name}",
            f"  Encrypted      : {'Yes' if is_enc else 'No'}",
            f"  Password found : {extract.password_found or 'N/A'}",
            f"  Files inside   : {len(extract.extracted_files)}",
            f"  Analyzed file  : {primary_name}",
            f"  File type      : {sub_result.file_type}",
            f"  Architecture   : {sub_result.architecture or 'N/A'}",
            "",
            "All other tabs show analysis of the extracted file.",
        ]
        result.tabs["Extraction Info"] = "\n".join(summary)

    def _analyze_jar(self, filepath: str, result: UniversalResult):
        import zipfile
        try:
            with zipfile.ZipFile(filepath, "r") as zf:
                names = zf.namelist()
                classes = [n for n in names if n.endswith(".class")]
                result.sections = [{"name": n} for n in names]
                result.headers = {"Classes": len(classes), "Total Files": len(names)}
                result.source_code = f"# JAR Archive\n# {len(classes)} .class files\n# {len(names)} total files\n\n"
                result.source_code += "\n".join(f"  {n}" for n in names[:100])
                result.success = True
                result.backend_used = "zipfile"
                result.tabs["JAR Contents"] = result.source_code
        except Exception as e:
            result.error = f"JAR analysis failed: {e}"

    def _analyze_dex(self, filepath: str, result: UniversalResult):
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            strings = [m.decode("ascii", errors="replace") for m in re.findall(rb"[\x20-\x7e]{5,}", data)]
            classes = [s for s in strings if s.startswith("L") and "/" in s and s.endswith(";")]
            result.strings = strings[:300]
            result.imports = classes[:200]
            result.source_code = f"# Dalvik DEX Bytecode\n# Version: {data[4:8].decode('ascii', errors='replace')}\n\n"
            result.source_code += "## Classes:\n" + "\n".join(classes[:100])
            result.success = True
            result.backend_used = "built-in DEX parser"
            result.tabs["DEX Classes"] = result.source_code
        except Exception as e:
            result.error = f"DEX analysis failed: {e}"

    def _analyze_macho(self, filepath: str, result: UniversalResult):
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            result.strings = [m.decode("ascii") for m in re.findall(rb"[\x20-\x7e]{6,}", data)][:300]
            result.source_code = f"# Mach-O Binary ({result.file_type})\n# Size: {result.file_size} bytes\n"
            self._try_otool(filepath, result)
            result.success = True
            result.backend_used = "built-in Mach-O parser"
            result.tabs["Mach-O Info"] = result.source_code
        except Exception as e:
            result.error = f"Mach-O analysis failed: {e}"

    def _try_otool(self, filepath: str, result: UniversalResult):
        try:
            r = subprocess.run(["otool", "-l", filepath], capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                result.disassembly = r.stdout[:5000]
                result.tabs["otool"] = result.disassembly
        except Exception:
            pass

    def _generic_analyze(self, filepath: str, result: UniversalResult):
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            result.strings = [m.decode("ascii") for m in re.findall(rb"[\x20-\x7e]{6,}", data)][:300]
            result.source_code = f"# Unknown file type\n# Size: {len(data)} bytes\n# Entropy: {result.entropy}\n\n"
            result.source_code += "## Extracted Strings:\n" + "\n".join(result.strings[:100])
            result.success = True
            result.backend_used = "generic string extractor"
            result.tabs["Strings"] = "\n".join(result.strings)
        except Exception as e:
            result.error = f"Generic analysis failed: {e}"

    def _format_file_info(self, filepath: str, result: UniversalResult) -> str:
        lines = [
            "File Information",
            "=" * 50,
            f"  Path         : {filepath}",
            f"  Type         : {result.file_type}",
            f"  Category     : {result.file_category}",
            f"  Language     : {result.language}",
            f"  Architecture : {result.architecture or 'N/A'}",
            f"  Bits         : {result.bits or 'N/A'}",
            f"  Size         : {result.file_size:,} bytes",
            f"  Entropy      : {result.entropy} / 8.0",
            f"  MD5          : {result.md5}",
            f"  SHA256       : {result.sha256}",
            f"  Backend      : {result.backend_used}",
        ]
        if result.warnings:
            lines += ["", "  Warnings:"]
            for w in result.warnings:
                lines.append(f"    ⚠  {w}")
        return "\n".join(lines)
