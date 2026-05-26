"""
MalScope - Core Decompiler Module
Handles .pyc decompilation using multiple backends
"""

import dis
import marshal
import struct
import sys
import os
import tempfile
import importlib.util
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple


class DecompilerResult:
    def __init__(self):
        self.success: bool = False
        self.source_code: str = ""
        self.error: str = ""
        self.backend_used: str = ""
        self.python_version: str = ""
        self.magic_number: int = 0
        self.opcodes: List[Dict] = []
        self.constants: List[Any] = []
        self.structured_constants: List[Dict] = []
        self.names: List[str] = []
        self.imports: List[str] = []
        self.strings: List[str] = []
        self.pseudo_source: str = ""
        self.opcode_summary: Dict[str, Any] = {}
        self.entropy: Dict[str, Any] = {}
        self.co_objects: List[Any] = []


class PycDecompiler:
    """Multi-backend Python bytecode decompiler"""

    MAGIC_TO_VERSION = {
        # Python 3.4
        3310: "3.4", 3320: "3.4", 3330: "3.4", 3340: "3.4", 3350: "3.4",
        # Python 3.5
        3360: "3.5", 3361: "3.5", 3370: "3.5", 3371: "3.5",
        3372: "3.5", 3373: "3.5", 3375: "3.5", 3376: "3.5",
        3377: "3.5", 3378: "3.5", 3379: "3.5",
        # Python 3.6
        3379: "3.6", 3390: "3.6", 3391: "3.6", 3392: "3.6",
        3393: "3.6", 3394: "3.6", 3400: "3.6", 3401: "3.6",
        # Python 3.7
        3394: "3.7", 3400: "3.7", 3401: "3.7", 3410: "3.7",
        3411: "3.7", 3412: "3.7", 3413: "3.7",
        # Python 3.8
        3400: "3.8", 3401: "3.8", 3410: "3.8", 3411: "3.8",
        3412: "3.8", 3413: "3.8",
        3900: "3.8", 3901: "3.8",
        # Python 3.9
        3950: "3.9", 3951: "3.9", 3952: "3.9", 3953: "3.9",
        3954: "3.9", 3955: "3.9", 3956: "3.9",
        # Python 3.10
        3970: "3.10", 3971: "3.10", 3972: "3.10", 3973: "3.10",
        3974: "3.10", 3975: "3.10", 3976: "3.10",
        4000: "3.10", 4010: "3.10", 4050: "3.10",
        # Python 3.11  ← vault.pyc magic 3495 is here
        3450: "3.11", 3451: "3.11", 3452: "3.11", 3453: "3.11",
        3454: "3.11", 3455: "3.11", 3456: "3.11", 3457: "3.11",
        3458: "3.11", 3459: "3.11", 3460: "3.11", 3461: "3.11",
        3462: "3.11", 3463: "3.11", 3464: "3.11", 3465: "3.11",
        3466: "3.11", 3467: "3.11", 3468: "3.11", 3469: "3.11",
        3470: "3.11", 3471: "3.11", 3472: "3.11", 3473: "3.11",
        3474: "3.11", 3475: "3.11", 3476: "3.11", 3477: "3.11",
        3478: "3.11", 3479: "3.11", 3480: "3.11", 3481: "3.11",
        3482: "3.11", 3483: "3.11", 3484: "3.11", 3485: "3.11",
        3486: "3.11", 3487: "3.11", 3488: "3.11", 3489: "3.11",
        3490: "3.11", 3491: "3.11", 3492: "3.11", 3493: "3.11",
        3494: "3.11", 3495: "3.11", 3496: "3.11", 3497: "3.11",
        3498: "3.11", 3499: "3.11",
        4100: "3.11", 4101: "3.11", 4102: "3.11",
        # Python 3.12
        4200: "3.12", 4201: "3.12", 4202: "3.12", 4203: "3.12",
        # Python 3.13
        4300: "3.13", 4301: "3.13",
    }

    def __init__(self):
        self._check_backends()

    def _check_backends(self):
        """Check which decompilation backends are available"""
        self.backends = {}

        try:
            import uncompyle6
            self.backends["uncompyle6"] = True
        except ImportError:
            self.backends["uncompyle6"] = False

        try:
            import decompyle3
            self.backends["decompyle3"] = True
        except ImportError:
            self.backends["decompyle3"] = False

        self.backends["dis"] = True  # Always available

    def get_available_backends(self) -> List[str]:
        return [k for k, v in self.backends.items() if v]

    def read_pyc_header(self, filepath: str) -> Tuple[int, Optional[bytes]]:
        """Read .pyc magic number and extract bytecode.

        Header layout:
          Python 3.0-3.2 : magic(4) + mtime(4)              =  8 bytes
          Python 3.3-3.7 : magic(4) + mtime(4) + size(4)    = 12 bytes
          Python 3.8+    : magic(4) + flags(4) + mtime(4) + size(4) = 16 bytes
          Python 3.11 magic range 3450-3499 also uses 16-byte header.
        """
        with open(filepath, "rb") as f:
            magic_raw = f.read(4)
            magic = struct.unpack("<H", magic_raw[:2])[0]

            # Python 3.8+ AND Python 3.11 magic 3450-3499 both use 16-byte header
            if magic >= 3400:
                f.read(12)  # flags(4) + mtime(4) + size(4)
            else:
                f.read(8)   # mtime(4) + size(4)

            bytecode = f.read()
        return magic, bytecode

    def get_python_version_from_magic(self, magic: int) -> str:
        """Resolve magic number to Python version string.
        Falls back to range-based lookup for edge-case magic numbers."""
        if magic in self.MAGIC_TO_VERSION:
            return self.MAGIC_TO_VERSION[magic]
        if magic == 3627:
            return "3.14"
        # Range-based fallback
        ranges = [
            (3000, 3099, "3.0"), (3100, 3199, "3.1"), (3200, 3299, "3.2"),
            (3300, 3399, "3.3/3.4"), (3400, 3449, "3.6/3.7"),
            (3450, 3499, "3.11"),   # vault.pyc 3495 lands here
            (3500, 3599, "3.7"),    (3600, 3699, "3.14"),
            (3900, 3919, "3.8"),    (3950, 3969, "3.9"),
            (3970, 3999, "3.10"),   (4000, 4099, "3.10"),
            (4100, 4199, "3.11"),   (4200, 4299, "3.12"),
            (4300, 4399, "3.13"),
        ]
        for lo, hi, ver in ranges:
            if lo <= magic <= hi:
                return ver
        return f"Unknown (magic={magic})"

    def get_python_version_tuple(self, version_str: str) -> Tuple[int, int]:
        try:
            parts = version_str.split(".")
            return (int(parts[0]), int(parts[1]))
        except Exception:
            return (sys.version_info.major, sys.version_info.minor)

    def _load_xdis_opcode_module(self, python_version: str):
        try:
            import xdis.bytecode as xb
            from xdis.bytecode import PythonImplementation
            version_tuple = self.get_python_version_tuple(python_version)
            return xb.get_opcode_module(version_tuple, PythonImplementation.CPython)
        except Exception:
            return None

    def get_xdis_instructions(self, code_object, python_version: str):
        try:
            opc = self._load_xdis_opcode_module(python_version)
            if not opc:
                return []
            import xdis.bytecode as xb
            bc = xb.Bytecode(code_object, opc=opc)
            return list(bc)
        except Exception:
            return []

    def normalize_opcode_name(self, opname: str) -> str:
        if not opname:
            return "UNKNOWN"
        if opname.startswith("<") and opname.endswith(">"):
            return "UNKNOWN"
        if opname.startswith("COMPARE_OP"):
            return "COMPARE_OP"
        if opname.endswith("_GEN"):
            return opname[: -4]
        if opname in {"LOAD_FAST_BORROW", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_NAME", "LOAD_ATTR"}:
            return "LOAD"
        if opname in {"STORE_NAME", "STORE_FAST", "STORE_ATTR", "STORE_GLOBAL"}:
            return "STORE"
        return opname

    def get_opcode_semantics(self, opname: str, argval: Any = None) -> Dict[str, Any]:
        semantics = {
            "comparison": False,
            "generator_behavior": False,
            "loop_behavior": False,
            "call_behavior": False,
            "import_behavior": False,
            "dynamic_execution": False,
            "exception_behavior": False,
            "store_behavior": False,
            "load_behavior": False,
            "adaptive_opcode": False,
        }

        if opname.startswith("COMPARE_OP") or opname in {"IS_OP", "CONTAINS_OP"}:
            semantics["comparison"] = True
        if opname in {
            "YIELD_VALUE", "YIELD_FROM", "GET_AITER", "GET_ANEXT",
            "FOR_ITER", "FOR_ITER_GEN", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT",
            "SETUP_LOOP",
        }:
            semantics["generator_behavior"] = True
            semantics["loop_behavior"] = True
        if opname in {
            "CALL_FUNCTION", "CALL_METHOD", "CALL_FUNCTION_KW", "CALL_FUNCTION_EX",
            "CALL_METHOD_KW", "CALL_INTRINSIC_1", "CALL", "PRECALL",
        }:
            semantics["call_behavior"] = True
        if opname in {"IMPORT_NAME", "IMPORT_FROM"}:
            semantics["import_behavior"] = True
        if opname in {"EXEC_STMT", "EXEC_FUNCTION", "LOAD_BUILD_CLASS"}:
            semantics["dynamic_execution"] = True
        if opname in {"RAISE_VARARGS", "SETUP_FINALLY", "POP_EXCEPT", "POP_JUMP_IF_EXCEPTION"}:
            semantics["exception_behavior"] = True
        if opname in {"STORE_NAME", "STORE_FAST", "STORE_ATTR", "STORE_GLOBAL"}:
            semantics["store_behavior"] = True
        if opname in {"LOAD_CONST", "LOAD_UNBOUND", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_NAME", "LOAD_ATTR"}:
            semantics["load_behavior"] = True
        if opname in {"RESUME", "CACHE", "PUSH_NULL", "PRECALL", "COPY_FREE_VARS"}:
            semantics["adaptive_opcode"] = True

        if argval and isinstance(argval, str) and argval in {"eval", "exec", "compile", "execfile", "__import__"}:
            semantics["dynamic_execution"] = True

        return semantics

    def get_string_constants(self, code_object, path: str = "root") -> List[Dict[str, str]]:
        strings = []
        try:
            for idx, const in enumerate(code_object.co_consts):
                current_path = f"{path}/{idx}"
                if isinstance(const, str):
                    strings.append({"path": current_path, "value": const})
                elif isinstance(const, bytes):
                    try:
                        strings.append({"path": current_path, "value": const.decode("utf-8", errors="ignore")})
                    except Exception:
                        strings.append({"path": current_path, "value": repr(const)})
                elif isinstance(const, (tuple, list, set)):
                    for item in const:
                        if isinstance(item, str):
                            strings.append({"path": current_path, "value": item})
                elif isinstance(const, dict):
                    for item in list(const.keys()) + list(const.values()):
                        if isinstance(item, str):
                            strings.append({"path": current_path, "value": item})
                elif hasattr(const, "co_code"):
                    strings.extend(self.get_string_constants(const, path=f"{current_path}/{const.co_name}"))
        except Exception:
            pass
        return strings

    def get_opcode_module(self, python_version: str):
        module = self._load_xdis_opcode_module(python_version)
        return module

    def get_opcodes(self, code_object, python_version: str = "") -> List[Dict]:
        opcodes = []
        try:
            instructions = self.get_xdis_instructions(code_object, python_version)
            if not instructions:
                instructions = list(dis.get_instructions(code_object))

            for instr in instructions:
                opname = getattr(instr, "opname", str(instr))
                opcode = getattr(instr, "opcode", None)
                arg = getattr(instr, "arg", None)
                argval = getattr(instr, "argval", None)
                semantic = self.get_opcode_semantics(opname, argval)
                opcodes.append({
                    "offset": getattr(instr, "offset", None),
                    "opname": opname,
                    "normalized_opname": self.normalize_opcode_name(opname),
                    "opcode": opcode,
                    "arg": arg,
                    "argval": str(argval),
                    "argrepr": getattr(instr, "argrepr", ""),
                    "is_jump_target": getattr(instr, "is_jump_target", False),
                    "semantics": semantic,
                })

            for const in code_object.co_consts:
                if hasattr(const, "co_code"):
                    opcodes.extend(self.get_opcodes(const, python_version))
        except Exception:
            pass
        return opcodes

    def get_imports(self, code_object) -> List[str]:
        imports = []
        try:
            for instr in dis.get_instructions(code_object):
                if instr.opname in {"IMPORT_NAME", "IMPORT_FROM"} and instr.argval:
                    imports.append(str(instr.argval))
            for const in code_object.co_consts:
                if hasattr(const, "co_code"):
                    imports.extend(self.get_imports(const))
        except Exception:
            pass
        return sorted(set(imports))

    def get_opcode_summary(self, code_object, python_version: str = "") -> Dict[str, Any]:
        summary = {
            "instruction_count": 0,
            "call_count": 0,
            "branch_count": 0,
            "load_count": 0,
            "store_count": 0,
            "jump_targets": 0,
            "function_count": 0,
            "loop_count": 0,
            "comparison_count": 0,
            "generator_count": 0,
            "dynamic_execution_count": 0,
            "adaptive_opcode_count": 0,
            "has_comparison": False,
            "has_generator_behavior": False,
            "has_dynamic_execution": False,
            "has_imports": False,
            "has_exception_handling": False,
            "semantic_flags": {},
        }
        try:
            instructions = self.get_xdis_instructions(code_object, python_version)
            if not instructions:
                instructions = list(dis.get_instructions(code_object))

            for instr in instructions:
                opname = getattr(instr, "opname", str(instr))
                semantic = self.get_opcode_semantics(opname, getattr(instr, "argval", None))
                summary["instruction_count"] += 1
                if semantic["call_behavior"]:
                    summary["call_count"] += 1
                if semantic["loop_behavior"]:
                    summary["loop_count"] += 1
                if semantic["comparison"]:
                    summary["comparison_count"] += 1
                    summary["has_comparison"] = True
                if semantic["generator_behavior"]:
                    summary["generator_count"] += 1
                    summary["has_generator_behavior"] = True
                if semantic["dynamic_execution"]:
                    summary["dynamic_execution_count"] += 1
                    summary["has_dynamic_execution"] = True
                if semantic["adaptive_opcode"]:
                    summary["adaptive_opcode_count"] += 1
                if semantic["load_behavior"]:
                    summary["load_count"] += 1
                if semantic["store_behavior"]:
                    summary["store_count"] += 1
                if semantic["import_behavior"]:
                    summary["has_imports"] = True
                if semantic["exception_behavior"]:
                    summary["has_exception_handling"] = True
                if getattr(instr, "is_jump_target", False):
                    summary["jump_targets"] += 1
                if opname in {"IMPORT_NAME", "IMPORT_FROM"}:
                    summary["branch_count"] += 1

            for const in code_object.co_consts:
                if hasattr(const, "co_code"):
                    child_summary = self.get_opcode_summary(const, python_version)
                    for key, value in child_summary.items():
                        if key == "semantic_flags":
                            continue
                        summary[key] += value
        except Exception:
            pass

        summary["semantic_flags"] = {
            "comparison": summary["has_comparison"],
            "generator_behavior": summary["has_generator_behavior"],
            "dynamic_execution": summary["has_dynamic_execution"],
            "imports": summary["has_imports"],
            "exception_handling": summary["has_exception_handling"],
            "adaptive_opcode": summary["adaptive_opcode_count"] > 0,
        }
        return summary

    def build_pseudo_source(self, code_object, depth: int = 0) -> str:
        lines = []
        indent = "    " * depth
        is_module = depth == 0 and code_object.co_name == "<module>"
        name = "module" if is_module else code_object.co_name
        args = ", ".join(code_object.co_varnames[:code_object.co_argcount])
        header = f"{indent}{'Module' if is_module else 'Function'}: {name}({args})"
        lines.append(header)

        imports = self.get_imports(code_object)
        if imports:
            lines.append(f"{indent}- imports: {', '.join(imports)}")

        strings = [s["value"] for s in self.get_string_constants(code_object)]
        if strings:
            snippet = ", ".join(strings[:5])
            lines.append(f"{indent}- extracted strings: {snippet}{'...' if len(strings) > 5 else ''}")

        summary = self.get_opcode_summary(code_object)
        lines.append(f"{indent}- instruction count: {summary.get('instruction_count', 0)}")
        if summary.get("call_count"):
            lines.append(f"{indent}- calls detected: {summary['call_count']}")
        if summary.get("loop_count"):
            lines.append(f"{indent}- loop/generator behavior detected: {summary['loop_count']}")
        if summary.get("comparison_count"):
            lines.append(f"{indent}- comparisons detected: {summary['comparison_count']}")
        if summary.get("dynamic_execution_count"):
            lines.append(f"{indent}- dynamic execution operations detected: {summary['dynamic_execution_count']}")
        if summary.get("adaptive_opcode_count"):
            lines.append(f"{indent}- adaptive or cache-style opcodes present: {summary['adaptive_opcode_count']}")
        if summary.get("has_exception_handling"):
            lines.append(f"{indent}- exception handling structure observed")

        if not imports and not strings and summary.get("instruction_count") == 0:
            lines.append(f"{indent}- no explicit imports or string constants found")

        for const in code_object.co_consts:
            if hasattr(const, "co_code"):
                lines.append("")
                lines.append(self.build_pseudo_source(const, depth + 1))

        return "\n".join(lines)

    def decompile_with_uncompyle6(self, filepath: str) -> str:
        """Try decompiling with uncompyle6"""
        try:
            import uncompyle6
            from io import StringIO
            out = StringIO()
            uncompyle6.decompile_file(filepath, out)
            return out.getvalue()
        except Exception as e:
            raise RuntimeError(f"uncompyle6 failed: {e}")

    def decompile_with_decompyle3(self, filepath: str) -> str:
        """Try decompiling with decompyle3"""
        try:
            import decompyle3
            from io import StringIO
            out = StringIO()
            decompyle3.decompile_file(filepath, out)
            return out.getvalue()
        except Exception as e:
            raise RuntimeError(f"decompyle3 failed: {e}")

    def decompile_with_dis(self, code_object) -> str:
        """Fallback: use dis module for opcode listing"""
        from io import StringIO
        out = StringIO()
        dis.dis(code_object, file=out)
        return f"# Decompiled with dis (source reconstruction not available)\n# Raw bytecode disassembly:\n\n'''\n{out.getvalue()}\n'''"

    def extract_code_objects(self, code_object, depth=0) -> List[Dict]:
        """Recursively extract all code objects"""
        objects = []
        try:
            info = {
                "depth": depth,
                "name": code_object.co_name,
                "filename": code_object.co_filename,
                "firstlineno": code_object.co_firstlineno,
                "argcount": code_object.co_argcount,
                "varnames": list(code_object.co_varnames),
                "names": list(code_object.co_names),
                "constants": [
                    repr(c) for c in code_object.co_consts
                    if not hasattr(c, "co_code")
                ],
                "flags": code_object.co_flags,
            }
            objects.append(info)
            for const in code_object.co_consts:
                if hasattr(const, "co_code"):
                    objects.extend(self.extract_code_objects(const, depth + 1))
        except Exception:
            pass
        return objects

    def _shannon_entropy(self, data: bytes) -> float:
        import math
        if not data:
            return 0.0
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        entropy = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _calculate_constant_entropy(self, const: Any) -> float:
        if isinstance(const, str):
            return self._shannon_entropy(const.encode("utf-8", errors="ignore"))
        if isinstance(const, bytes):
            return self._shannon_entropy(const)
        if isinstance(const, (tuple, list, dict, set)):
            return self._shannon_entropy(str(const).encode("utf-8", errors="ignore"))
        return 0.0

    def get_constants(self, code_object, path: str = "root") -> List[Dict]:
        constants = []
        try:
            for idx, const in enumerate(code_object.co_consts):
                if hasattr(const, "co_code"):
                    constants.append({
                        "path": path,
                        "index": idx,
                        "type": "code_object",
                        "name": const.co_name,
                        "argcount": const.co_argcount,
                        "firstlineno": const.co_firstlineno,
                    })
                    constants.extend(self.get_constants(const, path=f"{path}/{const.co_name}"))
                else:
                    constants.append({
                        "path": path,
                        "index": idx,
                        "type": type(const).__name__,
                        "repr": repr(const)[:200],
                        "entropy": self._calculate_constant_entropy(const),
                    })
        except Exception:
            pass
        return constants

    def calculate_entropy(self, code_object) -> Dict[str, Any]:
        entropy = {
            "average_constant_entropy": 0.0,
            "high_entropy_constants": [],
            "constant_count": 0,
        }
        try:
            constants = self.get_constants(code_object)
            entropy_values = [c.get("entropy", 0.0) for c in constants if isinstance(c.get("entropy", 0.0), float)]
            if entropy_values:
                entropy["average_constant_entropy"] = sum(entropy_values) / len(entropy_values)
            entropy["high_entropy_constants"] = [
                c for c in constants if isinstance(c.get("entropy", 0.0), float) and c.get("entropy", 0.0) > 4.5
            ][:10]
            entropy["constant_count"] = len(constants)
        except Exception:
            pass
        return entropy

    def decompile_with_pseudo(self, code_object) -> str:
        try:
            pseudo = self.build_pseudo_source(code_object)
            return (
                "# Reconstructed Python-like source from bytecode\n"
                "# This is a best-effort reverse-engineering output when full decompilation is unavailable.\n\n"
                f"{pseudo}"
            )
        except Exception as e:
            return f"# Failed to reconstruct pseudo-source: {e}\n"

    def decompile(self, filepath: str) -> DecompilerResult:
        """Main decompile method — tries all backends"""
        result = DecompilerResult()
        filepath = str(filepath)

        if not os.path.exists(filepath):
            result.error = f"File not found: {filepath}"
            return result

        # Read header
        try:
            magic, bytecode = self.read_pyc_header(filepath)
            result.magic_number = magic
            result.python_version = self.get_python_version_from_magic(magic)
        except Exception as e:
            result.error = f"Failed to read .pyc header: {e}"
            return result

        # Load code object via marshal
        code_obj = None
        try:
            code_obj = marshal.loads(bytecode)
            result.co_objects = self.extract_code_objects(code_obj)
            result.opcodes = self.get_opcodes(code_obj, result.python_version)
            result.constants = [
                repr(c) for c in code_obj.co_consts
                if not hasattr(c, "co_code")
            ]
            result.structured_constants = self.get_constants(code_obj)
            result.imports = self.get_imports(code_obj)
            result.strings = [s.get("value", "") for s in self.get_string_constants(code_obj)]
            result.pseudo_source = self.build_pseudo_source(code_obj)
            result.opcode_summary = self.get_opcode_summary(code_obj, result.python_version)
            result.entropy = self.calculate_entropy(code_obj)
            result.names = list(code_obj.co_names)
        except Exception as e:
            result.error = f"Marshal parsing failed: {e}"
            return result

        # Try decompilation backends in order
        errors = []

        if self.backends.get("uncompyle6"):
            try:
                result.source_code = self.decompile_with_uncompyle6(filepath)
                result.backend_used = "uncompyle6"
                result.success = True
                return result
            except Exception as e:
                errors.append(str(e))

        if self.backends.get("decompyle3"):
            try:
                result.source_code = self.decompile_with_decompyle3(filepath)
                result.backend_used = "decompyle3"
                result.success = True
                return result
            except Exception as e:
                errors.append(str(e))

        # Fallback to pseudo-source reconstruction from the code object
        if code_obj:
            try:
                result.source_code = self.decompile_with_pseudo(code_obj)
                result.backend_used = "pseudo-reconstruction"
                result.success = True
                result.error = (
                    "Full raw source decompilation unavailable; showing reconstructed Python-like "
                    "pseudo-source from bytecode. Errors: " + " | ".join(errors)
                )
                return result
            except Exception as e:
                errors.append(str(e))

        # Final fallback to bytecode disassembly
        if code_obj:
            try:
                result.source_code = self.decompile_with_dis(code_obj)
                result.backend_used = "dis (fallback)"
                result.success = True
                result.error = "All decompilation attempts failed; showing bytecode disassembly. Errors: " + " | ".join(errors)
                return result
            except Exception as e:
                errors.append(str(e))

        result.error = "All decompilation backends failed: " + " | ".join(errors)
        return result


class Py311Decompiler:
    """
    Decompiler for Python 3.11+ .pyc files.
    uncompyle6/decompyle3 do not support 3.11, so we use xdis or dis.
    """

    def decompile(self, filepath: str) -> str:
        lines = [
            "# ─────────────────────────────────────────────────────────────────",
            "# MalScope: Python 3.11 bytecode (magic=3495)",
            "# uncompyle6/decompyle3 do not support Python 3.11.",
            "# Showing structured bytecode disassembly via xdis/dis.",
            "# ─────────────────────────────────────────────────────────────────",
            "",
        ]

        # ── Try xdis ──────────────────────────────────────────────────────────
        try:
            import xdis.load as xload
            # xdis 6.x returns an 8-tuple:
            # (version_tuple, timestamp, magic_int, co, is_pypy, source_size, filename, ...)
            # Use * to be safe across xdis versions
            ret = xload.load_module(filepath)
            # Fields by position: version_tuple, timestamp, magic, co, impl, src_size, ...
            python_version = ret[0]
            magic_int      = ret[2]
            co             = ret[3]

            lines.append(f"# Python Version (xdis): {python_version}")
            lines.append(f"# Magic: {magic_int}")
            lines.append("")
            lines.extend(self._disassemble_xdis(co, depth=0))
            return "\n".join(lines)

        except ImportError:
            lines.append("# xdis not installed — using built-in dis")
            lines.append("")
        except Exception as e:
            lines.append(f"# xdis failed: {e} — using built-in dis")
            lines.append("")

        # ── Fallback: marshal + dis ────────────────────────────────────────────
        try:
            import struct, marshal, dis as _dis, io

            with open(filepath, "rb") as f:
                magic_raw = f.read(4)
                magic = struct.unpack("<H", magic_raw[:2])[0]
                # All Python 3.8+ (including 3.11) use a 16-byte header
                f.read(12)          # flags(4) + mtime(4) + size(4)
                bytecode = f.read()

            lines.append(f"# Magic number: {magic}")
            lines.append("")

            code_obj = marshal.loads(bytecode)
            lines.extend(self._disassemble_dis(code_obj, depth=0))
            return "\n".join(lines)

        except Exception as e:
            lines.append(f"# dis fallback failed: {e}")
            return "\n".join(lines)

    def _disassemble_xdis(self, co, depth: int) -> list:
        """Recursively disassemble with xdis."""
        import xdis.std as xstd
        import io

        lines = []
        indent = "    " * depth
        name    = getattr(co, "co_name",       "<module>")
        lineno  = getattr(co, "co_firstlineno", 0)
        argcount = getattr(co, "co_argcount",  0)
        varnames = list(getattr(co, "co_varnames", []))
        args     = varnames[:argcount]

        if depth == 0:
            lines.append("# ── Module-level code ──")
        else:
            lines.append(f"")
            lines.append(f"{indent}# ── Function: {name}  (line {lineno}) ──")
            lines.append(f"{indent}def {name}({', '.join(args)}):")

        buf = io.StringIO()
        try:
            xstd.dis(co, file=buf)
        except Exception as e:
            buf.write(f"  # xdis.dis error: {e}\n")
            import dis as _dis2
            _dis2.dis(co, file=buf)

        for ln in buf.getvalue().splitlines():
            lines.append(f"{indent}  {ln}")

        for const in getattr(co, "co_consts", []):
            if hasattr(const, "co_code"):
                lines.extend(self._disassemble_xdis(const, depth + 1))

        return lines

    def _disassemble_dis(self, co, depth: int) -> list:
        """Recursively disassemble with built-in dis."""
        import dis as _dis, io

        lines = []
        indent = "    " * depth
        name    = getattr(co, "co_name",       "<module>")
        lineno  = getattr(co, "co_firstlineno", 0)
        argcount = getattr(co, "co_argcount",  0)
        varnames = list(getattr(co, "co_varnames", []))
        args     = varnames[:argcount]

        if depth == 0:
            lines.append("# ── Module-level code ──")
        else:
            lines.append("")
            lines.append(f"{indent}# ── Function: {name}  (line {lineno}) ──")
            lines.append(f"{indent}def {name}({', '.join(args)}):")

        buf = io.StringIO()
        try:
            _dis.dis(co, file=buf)
        except Exception as e:
            buf.write(f"  # dis error: {e}\n")

        for ln in buf.getvalue().splitlines():
            lines.append(f"{indent}  {ln}")

        for const in getattr(co, "co_consts", []):
            if hasattr(const, "co_code"):
                lines.extend(self._disassemble_dis(const, depth + 1))

        return lines
