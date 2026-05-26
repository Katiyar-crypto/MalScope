"""
MalScope - Background Worker Threads
Keeps UI responsive during analysis
"""

import os
import sys
import traceback
from pathlib import Path
from typing import Dict, Any

from PyQt6.QtCore import QThread, pyqtSignal

sys.path.insert(0, str(Path(__file__).parent.parent))


class AnalysisWorker(QThread):
    """Runs full static analysis in background"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, filepath: str, zip_password: str = None):
        super().__init__()
        self.filepath = filepath
        self.zip_password = zip_password

    def run(self):
        try:
            result = {}
            filepath = self.filepath
            ext = Path(filepath).suffix.lower()
            try:
                from utils.dependency_checker import check_dependencies
                result["dependency_health"] = check_dependencies()
            except Exception:
                result["dependency_health"] = {}

            # ── Step 1: Determine if this is a universal file type ──────────────
            is_pyc = ext in (".pyc", ".pyo")
            is_exe = ext in (".exe", ".bin")

            # For non-pyc/exe files — route to universal decompiler
            if not is_pyc and not is_exe:
                self.progress.emit(f"Detecting file type...")
                from core.universal_decompiler import UniversalDecompiler, detect_file_type
                file_type, category, language = detect_file_type(filepath)

                if file_type not in ("PYC",):
                    self.progress.emit(f"Analyzing {file_type} file...")
                    ud = UniversalDecompiler()
                    ur = ud.analyze(filepath, zip_password=self.zip_password)
                    result["universal"] = {
                        "file_type": ur.file_type,
                        "needs_password": ur.needs_password,
                        "file_category": ur.file_category,
                        "language": ur.language,
                        "architecture": ur.architecture,
                        "bits": ur.bits,
                        "source_code": ur.source_code,
                        "disassembly": ur.disassembly,
                        "strings": ur.strings,
                        "imports": ur.imports,
                        "exports": ur.exports,
                        "sections": ur.sections,
                        "headers": ur.headers,
                        "metadata": ur.metadata,
                        "tabs": ur.tabs,
                        "warnings": ur.warnings,
                        "success": ur.success,
                        "error": ur.error,
                        "backend_used": ur.backend_used,
                        "md5": ur.md5,
                        "sha256": ur.sha256,
                        "file_size": ur.file_size,
                        "entropy": ur.entropy,
                    }

                    # Still run malware detection on strings + source
                    self.progress.emit("Analyzing malware behavior...")
                    from core.malware_detector import MalwareDetector
                    detector = MalwareDetector()
                    combined_text = " ".join([
                        ur.source_code,
                        " ".join(ur.strings),
                        " ".join(ur.imports),
                    ])
                    behavior = detector.analyze(
                        source_code=combined_text,
                        opcodes=[],
                        names=ur.imports,
                        constants=ur.strings,
                        strings=ur.strings,
                    )
                    result["behavior"] = self._behavior_to_dict(behavior)
                    result["decompile"] = {
                        "success": ur.success,
                        "source_code": ur.source_code,
                        "error": ur.error,
                        "backend_used": ur.backend_used,
                        "python_version": ur.language,
                        "magic_number": 0,
                        "imports": ur.imports,
                        "strings": ur.strings,
                        "pseudo_source": "",
                        "opcode_summary": {},
                        "entropy": {"average_constant_entropy": ur.entropy},
                    }
                    result["code_objects"] = []
                    result["opcodes"] = []
                    result["cfg_dot"] = ""
                    result["cfg_stats"] = {}
                    self.progress.emit("Running YARA scan...")
                    result["yara"] = self._run_yara(filepath, ur.source_code)
                    self.progress.emit("Analysis complete")
                    self.finished.emit(result)
                    return

            # ── Step 2: PyInstaller unpacking for .exe ───────────────────────────
            if is_exe:
                self.progress.emit("Detecting PyInstaller packaging...")
                from core.unpacker import PyInstallerUnpacker
                unpacker = PyInstallerUnpacker()
                if unpacker.detect_pyinstaller(filepath):
                    self.progress.emit("Unpacking PyInstaller executable...")
                    unpack_result = unpacker.unpack(filepath)
                    result["unpack"] = {
                        "success": unpack_result.success,
                        "extracted": len(unpack_result.extracted_files),
                        "pyc_files": unpack_result.pyc_files,
                        "output_dir": unpack_result.output_dir,
                    }
                    if unpack_result.pyc_files:
                        entry = unpacker.get_entry_point(unpack_result.output_dir)
                        if entry:
                            filepath = entry
                            self.progress.emit(f"Analyzing extracted: {Path(entry).name}")
                else:
                    # Not PyInstaller — route to PE analyzer
                    self.progress.emit("Analyzing PE binary...")
                    from core.universal_decompiler import UniversalDecompiler
                    ud = UniversalDecompiler()
                    ur = ud.analyze(filepath, zip_password=self.zip_password)
                    result["universal"] = {"file_type": ur.file_type, "tabs": ur.tabs,
                                           "source_code": ur.source_code, "success": ur.success,
                                           "backend_used": ur.backend_used, "strings": ur.strings,
                                           "imports": ur.imports, "entropy": ur.entropy,
                                           "md5": ur.md5, "sha256": ur.sha256}
                    result["decompile"] = {"success": ur.success, "source_code": ur.source_code,
                                           "error": ur.error, "backend_used": ur.backend_used,
                                           "python_version": "Native", "magic_number": 0,
                                           "imports": ur.imports, "strings": ur.strings,
                                           "pseudo_source": "", "opcode_summary": {}, "entropy": {}}
                    result["code_objects"] = []
                    result["opcodes"] = []
                    result["cfg_dot"] = ""
                    result["cfg_stats"] = {}
                    from core.malware_detector import MalwareDetector
                    behavior = MalwareDetector().analyze("", [], ur.imports, ur.strings, ur.strings)
                    result["behavior"] = self._behavior_to_dict(behavior)
                    self.progress.emit("Running YARA scan...")
                    result["yara"] = self._run_yara(filepath, ur.source_code)
                    self.progress.emit("Analysis complete")
                    self.finished.emit(result)
                    return

            # ── Step 3: Decompile .pyc ───────────────────────────────────────────
            self.progress.emit("Decompiling bytecode...")
            from core.decompiler import PycDecompiler
            decompiler = PycDecompiler()
            decompile_result = decompiler.decompile(filepath)

            # ── BUG FIX: Reuse the already-parsed code object from decompiler ────
            # Instead of re-reading the file with a broken header skip,
            # we extract the code object here using the same correct header logic.
            code_obj = None
            try:
                import struct, marshal
                with open(filepath, "rb") as f:
                    magic_raw = f.read(4)
                    magic = struct.unpack("<H", magic_raw[:2])[0]
                    # Correct header skip: 16 bytes for 3.8+, 12 for 3.3-3.7, 8 for older
                    if magic >= 3400:
                        f.read(12)  # flags(4) + mtime(4) + size(4)
                    else:
                        f.read(8)
                    code_obj = marshal.loads(f.read())
            except Exception as ce:
                result["cfg_dot"] = ""
                result["cfg_stats"] = {}
                result["cfg_error"] = f"Could not load code object: {ce}"

            result["decompile"] = {
                "success": decompile_result.success,
                "source_code": decompile_result.source_code,
                "error": decompile_result.error,
                "backend_used": decompile_result.backend_used,
                "python_version": decompile_result.python_version,
                "magic_number": decompile_result.magic_number,
                "imports": decompile_result.imports,
                "strings": decompile_result.strings,
                "pseudo_source": decompile_result.pseudo_source,
                "opcode_summary": decompile_result.opcode_summary,
                "entropy": decompile_result.entropy,
            }
            result["code_objects"] = decompile_result.co_objects
            result["opcodes"] = decompile_result.opcodes

            # ── Step 4: Behavior detection ───────────────────────────────────────
            # BUG FIX: Also pass strings/names from bytecode, not just source_code
            self.progress.emit("Analyzing malware behavior...")
            from core.malware_detector import MalwareDetector
            detector = MalwareDetector()
            behavior = detector.analyze(
                source_code=decompile_result.source_code,
                opcodes=decompile_result.opcodes,
                names=decompile_result.names,
                constants=decompile_result.constants,
                strings=decompile_result.strings,   # ← FIX: pass extracted strings
            )
            result["behavior"] = self._behavior_to_dict(behavior)

            # ── Step 5: CFG Generation ───────────────────────────────────────────
            # BUG FIX: Use the code_obj we already loaded above, not re-reading the file
            self.progress.emit("Generating Control Flow Graph...")
            if code_obj and "cfg_dot" not in result:
                try:
                    from core.cfg_generator import CFGGenerator
                    cfg_gen = CFGGenerator()
                    blocks = cfg_gen.build_cfg(code_obj)
                    dot_source = cfg_gen.to_dot(blocks, Path(filepath).stem)
                    stats = cfg_gen.get_cfg_summary(blocks)
                    result["cfg_dot"] = dot_source
                    result["cfg_stats"] = stats
                    result["cfg_error"] = ""
                except Exception as e:
                    result["cfg_dot"] = ""
                    result["cfg_stats"] = {}
                    result["cfg_error"] = f"{type(e).__name__}: {e}"

            # ── Step 6: YARA scanning ────────────────────────────────────────────
            self.progress.emit("Running YARA scan...")
            result["yara"] = self._run_yara(filepath, decompile_result.source_code or "")

            self.progress.emit("Analysis complete")
            self.finished.emit(result)

        except Exception as e:
            self.error.emit(f"{type(e).__name__}: {e}\n{traceback.format_exc()}")

    def _behavior_to_dict(self, behavior) -> dict:
        return {
            "threat_score": behavior.threat_score,
            "confidence_score": behavior.confidence_score,
            "summary": behavior.summary,
            "indicators": [
                {
                    "category": ind.category,
                    "severity": ind.severity,
                    "description": ind.description,
                    "evidence": ind.evidence,
                    "mitre_id": ind.mitre_id,
                    "mitre_technique": ind.mitre_technique,
                }
                for ind in behavior.indicators
            ],
            "iocs": behavior.iocs,
            "malware_families": behavior.malware_families,
            "obfuscation_detected": behavior.obfuscation_detected,
            "observed_facts": behavior.observed_facts,
            "ai_hypotheses": behavior.ai_hypotheses,
        }

    def _run_yara(self, filepath: str, source_code: str = "") -> dict:
        from core.yara_scanner import YARAScanner

        scanner = YARAScanner()
        yara_result = None

        if filepath and os.path.exists(filepath):
            yara_result = scanner.scan_file(filepath)

        if source_code and (not yara_result or not yara_result.matches):
            source_result = scanner.scan_source(source_code)
            if not yara_result or source_result.matches or not yara_result.success:
                yara_result = source_result

        if yara_result is None:
            yara_result = scanner.scan_source(source_code or "")

        return {
            "success": yara_result.success,
            "yara_available": yara_result.yara_available,
            "matches": [self._yara_match_to_dict(m) for m in yara_result.matches],
            "error": yara_result.error,
            "scan_time_ms": yara_result.scan_time_ms,
            "rules_loaded": yara_result.rules_loaded,
            "engine": getattr(yara_result, "engine", "yara-python"),
        }

    def _yara_match_to_dict(self, match) -> dict:
        return {
            "rule_name": match.rule_name,
            "namespace": match.namespace,
            "tags": match.tags,
            "meta": match.meta,
            "strings": [self._format_yara_string(s) for s in match.strings],
            "severity": match.severity,
        }

    def _format_yara_string(self, item):
        try:
            offset, ident, data = item
            if isinstance(data, bytes):
                data = data.decode("utf-8", errors="replace")
            return (offset, ident, str(data))
        except Exception:
            return (0, "", str(item))


class AIWorker(QThread):
    """Runs AI analysis in background"""
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, source_code: str, behavior: dict, api_key: str,
                 mode: str = "analyze", provider: str = "Claude (Anthropic)",
                 ollama_model: str = "llama3", analysis_context: dict = None):
        super().__init__()
        self.source_code = source_code
        self.behavior = behavior
        self.api_key = api_key
        self.mode = mode
        self.provider = provider          # ← FIX: actually used now
        self.ollama_model = ollama_model
        self.analysis_context = analysis_context or {}

    def run(self):
        try:
            from ai.claude_analyzer import ClaudeAnalyzer

            # BUG FIX: Pass provider selection properly so Anthropic is used when chosen
            provider_l = (self.provider or "").lower()
            anthropic_key = self.api_key if (
                ("anthropic" in provider_l or "claude" in provider_l) and
                self.api_key.startswith("sk-ant-")
            ) else None

            openai_key = self.api_key if (
                "openai" in provider_l and
                self.api_key.startswith("sk-") and
                not self.api_key.startswith("sk-ant-")
            ) else None

            hf_key = self.api_key if (
                "huggingface" in provider_l and
                self.api_key.startswith("hf_")
            ) else None

            # BUG FIX: If provider is Ollama, don't pass API key at all
            ollama_model = self.ollama_model if "ollama" in provider_l else None

            analyzer = ClaudeAnalyzer(
                api_key=anthropic_key,
                openai_api_key=openai_key,
                huggingface_api_key=hf_key,
                ollama_model=ollama_model,
                preferred_provider=self.provider,   # ← new param to enforce priority
            )

            context = {
                "threat_score": self.behavior.get("threat_score", 0),
                "indicators": self.behavior.get("indicators", []),
                "obfuscation": self.behavior.get("obfuscation_detected", []),
                "iocs": self.behavior.get("iocs", {}),
            }
            context.update(self.analysis_context)

            if self.mode == "analyze":
                result = analyzer.analyze_code(self.source_code, context)
            elif self.mode == "deobfuscate":
                result = analyzer.deobfuscate(self.source_code)
            elif self.mode == "yara":
                result = analyzer.generate_yara_rule(self.source_code)
            elif self.mode == "summary":
                result = analyzer.summarize_report(
                    indicators=self.behavior.get("indicators", []),
                    iocs=self.behavior.get("iocs", {}),
                    obfuscation=self.behavior.get("obfuscation_detected", []),
                    malware_families=self.behavior.get("malware_families", []),
                    threat_score=self.behavior.get("threat_score", 0),
                )
            else:
                result = analyzer.analyze_code(self.source_code, context)

            if result.success:
                output = result.analysis
                if result.tokens_used:
                    output += f"\n\n---\n*Tokens: {result.tokens_used} | Model: {result.model}*"
                self.finished.emit(output)
            else:
                self.error.emit(result.error)

        except Exception as e:
            self.error.emit(f"{type(e).__name__}: {e}")
