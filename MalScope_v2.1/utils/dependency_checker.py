"""
Runtime dependency health checks for optional MalScope backends.
"""

import importlib.util
import shutil
from typing import Dict, Any


PYTHON_PACKAGES = {
    "PyQt6": "GUI",
    "uncompyle6": "Python decompilation",
    "decompyle3": "Python decompilation",
    "xdis": "Python bytecode support",
    "pefile": "PE analysis",
    "lief": "binary analysis",
    "elftools": "ELF analysis",
    "capstone": "disassembly",
    "pyzipper": "AES ZIP sample extraction",
    "yara": "YARA scanning",
    "networkx": "CFG analysis",
    "graphviz": "CFG rendering",
    "anthropic": "Claude AI",
    "openai": "OpenAI AI",
    "huggingface_hub": "Hugging Face AI",
    "requests": "HTTP/AI/Ollama",
    "jinja2": "reporting",
    "olefile": "Office analysis",
    "docx": "Office analysis",
}

SYSTEM_TOOLS = {
    "dot": "Graphviz renderer",
    "javap": "Java class decompilation",
    "java": "Java tooling",
    "otool": "Mach-O analysis on macOS",
}


def check_dependencies() -> Dict[str, Any]:
    packages = {
        name: {
            "available": importlib.util.find_spec(name) is not None,
            "purpose": purpose,
        }
        for name, purpose in PYTHON_PACKAGES.items()
    }
    tools = {
        name: {
            "available": shutil.which(name) is not None,
            "purpose": purpose,
        }
        for name, purpose in SYSTEM_TOOLS.items()
    }
    missing_required = [
        name for name in ("PyQt6", "networkx", "requests")
        if not packages.get(name, {}).get("available")
    ]
    missing_optional = [
        name for name, data in {**packages, **tools}.items()
        if not data.get("available") and name not in missing_required
    ]
    return {
        "packages": packages,
        "tools": tools,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "healthy": not missing_required,
    }
