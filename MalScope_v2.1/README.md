# MalScope v2.1

AI-powered universal malware reverse engineering framework.

> For educational, defensive, and research use only. Analyze only files you own or have explicit permission to inspect.

## Features

| Module | Description |
| --- | --- |
| Universal analyzer | Detects and inspects PYC, PE, ELF, Mach-O, APK, DEX, JAR, Java class, WASM, scripts, Office docs, PDFs, ZIPs, and more. |
| Python decompiler | `.pyc` and `.pyo` analysis through uncompyle6, decompyle3, xdis, and dis fallback. |
| Opcode engine | Recursive bytecode disassembly with opcode semantics, suspicious opcode hints, constants, imports, and entropy. |
| CFG generator | Control flow graph generation using Graphviz and NetworkX. |
| Behavior detector | Static behavior scoring with MITRE ATT&CK IDs, IOC extraction, obfuscation detection, and malware-family hints. |
| YARA scanner | Built-in rules and file/source scanning across Python and universal analysis paths. |
| AI analysis | Anthropic, OpenAI, Hugging Face, and local Ollama analysis modes for explanation, deobfuscation, summary, and rule generation. |
| Safe ZIP handling | Password support, common malware sample passwords, path traversal blocking, and extraction size/depth limits. |
| Dependency health | Runtime checks for optional Python packages and system tools such as Graphviz and javap. |
| Reports | JSON, HTML, Markdown, SARIF, and ZIP forensic bundle exports with escaped HTML output. |

## Installation

### Prerequisites

- Python 3.8+
- pip

### Install dependencies

```bash
pip install -r requirements.txt
```

On Windows, native `yara-python` currently installs most cleanly with Python 3.13:

```bash
py -3.13 -m pip install -r requirements.txt
py -3.13 main.py
```

Python 3.14 may try to build `yara-python` from source and require Microsoft C++ Build Tools. If native YARA is unavailable, MalScope still uses its built-in fallback matcher.

### Optional system tools

```bash
# Graphviz is needed for CFG image rendering.
# Windows: https://graphviz.org/download/
# Linux:
sudo apt install graphviz
# macOS:
brew install graphviz
```

Install a JDK if you want Java `.class` analysis through `javap`.

## Usage

### Launch GUI

```bash
python main.py
```

### AI provider keys

You can paste a provider key in the AI settings panel or set an environment variable:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...
export HUGGINGFACE_API_TOKEN=hf_...
```

For local AI, choose Ollama in the UI and set the model name, for example `llama3`.

## Project Structure

```text
MalScope_v2/
  main.py
  requirements.txt
  setup.py
  ai/
    claude_analyzer.py
  core/
    decompiler.py
    universal_decompiler.py
    malware_detector.py
    cfg_generator.py
    unpacker.py
    yara_scanner.py
    zip_handler.py
  gui/
    main_window.py
    widgets.py
    workers.py
    styles.py
  utils/
    dependency_checker.py
    reporter.py
  tests/
    test_safety_and_reports.py
```

## Supported File Types

- Python: `.py`, `.pyc`, `.pyo`
- Native: `.exe`, `.dll`, `.elf`, `.so`, Mach-O
- Android/Java: `.apk`, `.dex`, `.jar`, `.class`
- Scripts: `.js`, `.ts`, `.ps1`, `.vbs`, `.bat`, `.cmd`, `.sh`, `.rb`, `.pl`, `.php`, `.lua`
- Documents: `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.xlsm`, `.pptx`, `.vba`
- Archives and binaries: `.zip`, `.bin`, `.wasm`

## Testing

```bash
python -m unittest discover -s tests
python -m compileall -q .
```

## Safety Notes

MalScope performs static analysis. It should not execute malware samples. ZIP extraction is guarded against path traversal and oversized archives, but you should still use an isolated analysis VM for real samples.
