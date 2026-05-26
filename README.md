# MalScope

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-00C7B7?style=for-the-badge)
![License](https://img.shields.io/badge/License-Apache--2.0-6A5CFF?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-00D9FF?style=for-the-badge)

**MalScope v2.1** is an AI-powered universal malware analysis and reverse-engineering workbench with a PyQt6 desktop GUI, static behavior scoring, IOC extraction, YARA scanning, decompilation, ZIP sample handling, report export, and optional AI analysis.

> For defensive research and education only. Analyze files you own or have explicit permission to inspect.

## One-Link Launch

Windows users can install and launch MalScope from the GitHub link with one PowerShell command:

```powershell
powershell -ExecutionPolicy Bypass -NoProfile -Command "irm https://raw.githubusercontent.com/Katiyar-crypto/MalScope/main/install_and_run.ps1 | iex"
```

The script downloads the latest `main` branch, creates a local virtual environment, installs dependencies, and starts the app.

Manual download link:
[Download MalScope ZIP](https://github.com/Katiyar-crypto/MalScope/archive/refs/heads/main.zip)

## Why MalScope

- Universal file inspection for Python bytecode, PE/ELF/Mach-O, APK/DEX/JAR/class, WASM, scripts, Office documents, PDFs, ZIP archives, and generic binaries.
- Python `.pyc` and `.pyo` decompilation with multiple backend fallbacks.
- Static behavior scoring with MITRE ATT&CK context, IOC extraction, obfuscation detection, and malware-family hints.
- YARA scanning with native `yara-python` support and a built-in fallback matcher.
- Safe ZIP extraction with encrypted malware-sample password support and ZIP Slip protection.
- AI-assisted analysis through Anthropic, OpenAI, Hugging Face, or local Ollama.
- Exportable JSON, HTML, Markdown, SARIF, and ZIP report bundles.

## Quick Start

```bash
git clone https://github.com/Katiyar-crypto/MalScope.git
cd MalScope/MalScope_v2.1
python -m pip install -r requirements.txt
python main.py
```

On Windows with Python 3.13:

```powershell
cd MalScope_v2.1
py -3.13 -m pip install -r requirements.txt
py -3.13 main.py
```

## Project Layout

```text
MalScope_v2.1/
  main.py
  requirements.txt
  setup.py
  ai/
  core/
  gui/
  rules/
  tests/
  utils/
```

## Testing

```bash
cd MalScope_v2.1
python -m unittest discover -s tests -v
python -m compileall .
```

## Notes

MalScope is a desktop GUI application. A browser link can download and launch it through the bootstrap script, but the app itself runs locally because it uses PyQt6 and local analysis engines.
