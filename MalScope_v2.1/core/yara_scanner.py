"""
MalScope - YARA Scanner Module
Integrates YARA rule scanning for malware detection
"""

import os
import re
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class YARAMatch:
    rule_name: str
    namespace: str
    tags: List[str]
    meta: Dict
    strings: List[Tuple[int, str, bytes]]  # (offset, identifier, data)
    severity: str = "MEDIUM"


@dataclass
class YARAScanResult:
    success: bool = False
    matches: List[YARAMatch] = field(default_factory=list)
    error: str = ""
    rules_loaded: int = 0
    scan_time_ms: float = 0.0
    yara_available: bool = False
    engine: str = "yara-python"


# Built-in YARA rules for Python malware
BUILTIN_RULES = r"""
rule Python_Obfuscated_Exec {
    meta:
        description = "Detects Python code with obfuscated exec/eval patterns"
        severity = "HIGH"
        mitre = "T1027"
    strings:
        $exec_decode = "exec(base64.b64decode"
        $eval_decode = "eval(base64.b64decode"
        $exec_zlib = "exec(zlib.decompress"
        $exec_compile = "exec(compile("
        $chr_obf = /chr\\(\\d+\\)\\+chr\\(\\d+\\)/
    condition:
        any of them
}

rule Python_Keylogger {
    meta:
        description = "Detects Python keylogger patterns"
        severity = "CRITICAL"
        mitre = "T1056.001"
    strings:
        $pynput = "from pynput"
        $keyboard = "import keyboard"
        $getasynckeystate = "GetAsyncKeyState"
        $on_press = "on_press"
        $on_release = "on_release"
        $keylog_file = /keylog.*\.(txt|log)/
    condition:
        2 of them
}

rule Python_Reverse_Shell {
    meta:
        description = "Detects Python reverse shell patterns"
        severity = "CRITICAL"
        mitre = "T1059.006"
    strings:
        $socket = "import socket"
        $connect = ".connect(("
        $dup2_stdin = "dup2(s.fileno(), 0)"
        $dup2_stdout = "dup2(s.fileno(), 1)"
        $subprocess = "subprocess.call([\"/bin/sh\""
        $bash = "/bin/bash"
        $cmd = "cmd.exe"
    condition:
        $socket and ($connect and ($dup2_stdin or $dup2_stdout or $subprocess or $bash or $cmd))
}

rule Python_Ransomware {
    meta:
        description = "Detects Python ransomware patterns"
        severity = "CRITICAL"
        mitre = "T1486"
    strings:
        $fernet = "from cryptography.fernet"
        $aes = "AES.new("
        $encrypt = "encrypt("
        $decrypt = "decrypt("
        $walk_encrypt = "os.walk("
        $ransom = "ransom"
        $bitcoin = "bitcoin"
        $locked = ".locked"
        $enc_ext = ".enc"
    condition:
        ($fernet or $aes) and ($walk_encrypt or $encrypt or $decrypt) and ($ransom or $bitcoin or $locked or $enc_ext)
}

rule Python_Credential_Stealer {
    meta:
        description = "Detects Python credential stealing patterns"
        severity = "CRITICAL"
        mitre = "T1555.003"
    strings:
        $chrome_login = "Login Data"
        $firefox_key = "key4.db"
        $chrome_path = "Google/Chrome"
        $cookies = "cookies.sqlite"
        $decrypt_v10 = "v10"
        $dpapi = "CryptUnprotectData"
        $browser_pass = "browser_passwords"
    condition:
        2 of them
}

rule Python_Persistence_Registry {
    meta:
        description = "Detects registry persistence mechanisms"
        severity = "HIGH"
        mitre = "T1547.001"
    strings:
        $winreg = "import winreg"
        $reg_run = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
        $hkcu = "HKEY_CURRENT_USER"
        $hklm = "HKEY_LOCAL_MACHINE"
        $setvalue = "SetValueEx"
    condition:
        ($winreg or $hkcu or $hklm) and ($reg_run or $setvalue)
}

rule Python_Process_Injection {
    meta:
        description = "Detects process injection via ctypes"
        severity = "CRITICAL"
        mitre = "T1055"
    strings:
        $ctypes = "import ctypes"
        $virtualalloc = "VirtualAlloc"
        $writeprocess = "WriteProcessMemory"
        $createremote = "CreateRemoteThread"
        $shellcode = "shellcode"
        $mmap = "mmap.mmap("
    condition:
        $ctypes and 2 of ($virtualalloc, $writeprocess, $createremote, $shellcode, $mmap)
}

rule Python_AntiDebug {
    meta:
        description = "Detects anti-debugging techniques"
        severity = "HIGH"
        mitre = "T1622"
    strings:
        $isdebuggerpresent = "IsDebuggerPresent"
        $checkremote = "CheckRemoteDebuggerPresent"
        $ntglobalflag = "NtGlobalFlag"
        $timing = /time\\.sleep\\(\\d{3,}\\)/
        $vmware = "vmware"
        $virtualbox = "virtualbox"
        $sandbox = "sandbox"
    condition:
        2 of them
}

rule Python_Data_Exfiltration {
    meta:
        description = "Detects data exfiltration patterns"
        severity = "HIGH"
        mitre = "T1048"
    strings:
        $smtp_send = "smtplib.SMTP"
        $ftp_upload = "ftplib.FTP"
        $requests_post = "requests.post("
        $discord_webhook = "discord.com/api/webhooks"
        $telegram_api = "api.telegram.org"
        $pastebin = "pastebin.com"
    condition:
        any of them
}

rule Python_Suspicious_IOCs {
    meta:
        description = "Detects suspicious network and persistence indicators in Python/script text"
        severity = "MEDIUM"
        mitre = "T1071.001"
    strings:
        $http = /https?:\/\/[A-Za-z0-9._~:\/?#\[\]@!$&'()*+,;=%-]+/
        $ip_port = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{2,5}/
        $reg_run = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
        $ps_encoded = "powershell -EncodedCommand"
    condition:
        2 of them
}

rule PE_Suspicious_Windows_API {
    meta:
        description = "Detects suspicious Windows API strings often used for injection or credential access"
        severity = "HIGH"
        mitre = "T1055"
    strings:
        $virtualalloc = "VirtualAlloc"
        $writeprocess = "WriteProcessMemory"
        $createremote = "CreateRemoteThread"
        $cryptunprotect = "CryptUnprotectData"
        $isdebugger = "IsDebuggerPresent"
        $wininet = "InternetOpen"
    condition:
        2 of them
}
"""


FALLBACK_RULES = [
    {
        "name": "Python_Obfuscated_Exec",
        "meta": {"description": "Detects Python code with obfuscated exec/eval patterns", "severity": "HIGH", "mitre": "T1027"},
        "strings": {
            "$exec_decode": b"exec(base64.b64decode",
            "$eval_decode": b"eval(base64.b64decode",
            "$exec_zlib": b"exec(zlib.decompress",
            "$exec_compile": b"exec(compile(",
            "$chr_obf": re.compile(rb"chr\(\d+\)\+chr\(\d+\)", re.I),
        },
        "condition": lambda hits: len(hits) >= 1,
    },
    {
        "name": "Python_Keylogger",
        "meta": {"description": "Detects Python keylogger patterns", "severity": "CRITICAL", "mitre": "T1056.001"},
        "strings": {
            "$pynput": b"from pynput",
            "$keyboard": b"import keyboard",
            "$getasynckeystate": b"GetAsyncKeyState",
            "$on_press": b"on_press",
            "$on_release": b"on_release",
            "$keylog_file": re.compile(rb"keylog.*\.(txt|log)", re.I),
        },
        "condition": lambda hits: len(hits) >= 2,
    },
    {
        "name": "Python_Reverse_Shell",
        "meta": {"description": "Detects Python reverse shell patterns", "severity": "CRITICAL", "mitre": "T1059.006"},
        "strings": {
            "$socket": b"import socket",
            "$connect": b".connect((",
            "$dup2_stdin": b"dup2(s.fileno(), 0)",
            "$dup2_stdout": b"dup2(s.fileno(), 1)",
            "$subprocess": b"subprocess.call([\"/bin/sh\"",
            "$bash": b"/bin/bash",
            "$cmd": b"cmd.exe",
        },
        "condition": lambda hits: "$socket" in hits and "$connect" in hits and bool({"$dup2_stdin", "$dup2_stdout", "$subprocess", "$bash", "$cmd"} & hits.keys()),
    },
    {
        "name": "Python_Ransomware",
        "meta": {"description": "Detects Python ransomware patterns", "severity": "CRITICAL", "mitre": "T1486"},
        "strings": {
            "$fernet": b"from cryptography.fernet",
            "$aes": b"AES.new(",
            "$encrypt": b"encrypt(",
            "$decrypt": b"decrypt(",
            "$walk_encrypt": b"os.walk(",
            "$ransom": b"ransom",
            "$bitcoin": b"bitcoin",
            "$locked": b".locked",
            "$enc_ext": b".enc",
        },
        "condition": lambda hits: bool({"$fernet", "$aes"} & hits.keys()) and bool({"$walk_encrypt", "$encrypt"} & hits.keys()) and bool({"$ransom", "$bitcoin", "$locked", "$enc_ext"} & hits.keys()),
    },
    {
        "name": "Python_Credential_Stealer",
        "meta": {"description": "Detects Python credential stealing patterns", "severity": "CRITICAL", "mitre": "T1555.003"},
        "strings": {
            "$chrome_login": b"Login Data",
            "$firefox_key": b"key4.db",
            "$chrome_path": b"Google/Chrome",
            "$cookies": b"cookies.sqlite",
            "$decrypt_v10": b"v10",
            "$dpapi": b"CryptUnprotectData",
            "$browser_pass": b"browser_passwords",
        },
        "condition": lambda hits: len(hits) >= 2,
    },
    {
        "name": "Python_Persistence_Registry",
        "meta": {"description": "Detects registry persistence mechanisms", "severity": "HIGH", "mitre": "T1547.001"},
        "strings": {
            "$winreg": b"import winreg",
            "$reg_run": b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "$hkcu": b"HKEY_CURRENT_USER",
            "$hklm": b"HKEY_LOCAL_MACHINE",
            "$setvalue": b"SetValueEx",
        },
        "condition": lambda hits: bool({"$winreg", "$hkcu", "$hklm"} & hits.keys()) and bool({"$reg_run", "$setvalue"} & hits.keys()),
    },
    {
        "name": "Python_Process_Injection",
        "meta": {"description": "Detects process injection via ctypes", "severity": "CRITICAL", "mitre": "T1055"},
        "strings": {
            "$ctypes": b"import ctypes",
            "$virtualalloc": b"VirtualAlloc",
            "$writeprocess": b"WriteProcessMemory",
            "$createremote": b"CreateRemoteThread",
            "$shellcode": b"shellcode",
            "$mmap": b"mmap.mmap(",
        },
        "condition": lambda hits: "$ctypes" in hits and len({"$virtualalloc", "$writeprocess", "$createremote", "$shellcode", "$mmap"} & hits.keys()) >= 2,
    },
    {
        "name": "Python_AntiDebug",
        "meta": {"description": "Detects anti-debugging techniques", "severity": "HIGH", "mitre": "T1622"},
        "strings": {
            "$isdebuggerpresent": b"IsDebuggerPresent",
            "$checkremote": b"CheckRemoteDebuggerPresent",
            "$ntglobalflag": b"NtGlobalFlag",
            "$timing": re.compile(rb"time\.sleep\(\d{3,}\)", re.I),
            "$vmware": b"vmware",
            "$virtualbox": b"virtualbox",
            "$sandbox": b"sandbox",
        },
        "condition": lambda hits: len(hits) >= 2,
    },
    {
        "name": "Python_Data_Exfiltration",
        "meta": {"description": "Detects data exfiltration patterns", "severity": "HIGH", "mitre": "T1048"},
        "strings": {
            "$smtp_send": b"smtplib.SMTP",
            "$ftp_upload": b"ftplib.FTP",
            "$requests_post": b"requests.post(",
            "$discord_webhook": b"discord.com/api/webhooks",
            "$telegram_api": b"api.telegram.org",
            "$pastebin": b"pastebin.com",
        },
        "condition": lambda hits: len(hits) >= 1,
    },
    {
        "name": "Python_Suspicious_IOCs",
        "meta": {"description": "Detects suspicious network and persistence indicators in Python/script text", "severity": "MEDIUM", "mitre": "T1071.001"},
        "strings": {
            "$http": re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.I),
            "$ip_port": re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b"),
            "$reg_run": b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "$ps_encoded": b"powershell -EncodedCommand",
        },
        "condition": lambda hits: len(hits) >= 2,
    },
    {
        "name": "PE_Suspicious_Windows_API",
        "meta": {"description": "Detects suspicious Windows API strings often used for injection or credential access", "severity": "HIGH", "mitre": "T1055"},
        "strings": {
            "$virtualalloc": b"VirtualAlloc",
            "$writeprocess": b"WriteProcessMemory",
            "$createremote": b"CreateRemoteThread",
            "$cryptunprotect": b"CryptUnprotectData",
            "$isdebugger": b"IsDebuggerPresent",
            "$wininet": b"InternetOpen",
        },
        "condition": lambda hits: len(hits) >= 2,
    },
]


class YARAScanner:
    """YARA-based malware detection"""

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir
        self._yara = None
        self._compiled_rules = None
        self._yara_available = self._check_yara()

    def _check_yara(self) -> bool:
        try:
            import yara
            self._yara = yara
            return True
        except ImportError:
            return False

    def _get_rules(self):
        """Compile and return YARA rules"""
        if self._compiled_rules:
            return self._compiled_rules

        if not self._yara:
            return None

        try:
            sources = {"builtin": BUILTIN_RULES}

            # Load custom rules from dir
            if self.rules_dir and os.path.isdir(self.rules_dir):
                for fname in Path(self.rules_dir).glob("*.yar"):
                    try:
                        sources[fname.stem] = fname.read_text()
                    except Exception:
                        pass

            self._compiled_rules = self._yara.compile(sources=sources)
            return self._compiled_rules
        except Exception:
            # Try compiling just the builtin rules
            try:
                self._compiled_rules = self._yara.compile(source=BUILTIN_RULES)
                return self._compiled_rules
            except Exception:
                return None

    def scan_data(self, data: bytes) -> YARAScanResult:
        """Scan bytes data with YARA rules"""
        import time
        result = YARAScanResult(yara_available=self._yara_available)

        if not self._yara_available:
            return self._scan_data_fallback(data)

        rules = self._get_rules()
        if not rules:
            fallback = self._scan_data_fallback(data)
            fallback.error = "Failed to compile native YARA rules; used MalScope fallback matcher"
            return fallback

        start = time.time()
        try:
            matches = rules.match(data=data)
            result.scan_time_ms = (time.time() - start) * 1000
            result.success = True

            for match in matches:
                severity = match.meta.get("severity", "MEDIUM")
                yara_match = YARAMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                    meta=dict(match.meta),
                    strings=self._extract_match_strings(match),
                    severity=severity,
                )
                result.matches.append(yara_match)

        except Exception as e:
            result.error = f"YARA scan error: {e}"

        return result

    def _scan_data_fallback(self, data: bytes) -> YARAScanResult:
        import time
        start = time.time()
        result = YARAScanResult(
            success=True,
            yara_available=False,
            rules_loaded=len(FALLBACK_RULES),
            engine="malscope-fallback",
            error="yara-python not installed; used MalScope fallback matcher",
        )

        for rule in FALLBACK_RULES:
            hits = self._fallback_rule_hits(data, rule["strings"])
            if rule["condition"](hits):
                meta = dict(rule["meta"])
                result.matches.append(YARAMatch(
                    rule_name=rule["name"],
                    namespace="fallback",
                    tags=[],
                    meta=meta,
                    strings=list(hits.values()),
                    severity=meta.get("severity", "MEDIUM"),
                ))

        result.scan_time_ms = (time.time() - start) * 1000
        return result

    def _fallback_rule_hits(self, data: bytes, patterns: Dict) -> Dict[str, Tuple[int, str, bytes]]:
        hits = {}
        lower_data = data.lower()
        for ident, pattern in patterns.items():
            if hasattr(pattern, "search"):
                match = pattern.search(data)
                if not match:
                    match = pattern.search(lower_data)
                if match:
                    hits[ident] = (match.start(), ident, match.group(0)[:200])
            else:
                needle = pattern if isinstance(pattern, bytes) else str(pattern).encode("utf-8", errors="replace")
                idx = lower_data.find(needle.lower())
                if idx >= 0:
                    hits[ident] = (idx, ident, data[idx:idx + len(needle)][:200])
        return hits

    def _extract_match_strings(self, match) -> List[Tuple[int, str, bytes]]:
        extracted = []
        for item in getattr(match, "strings", []):
            instances = getattr(item, "instances", None)
            if instances is not None:
                ident = getattr(item, "identifier", "")
                for inst in instances:
                    offset = getattr(inst, "offset", 0)
                    data = getattr(inst, "matched_data", None)
                    if callable(data):
                        data = data()
                    if data is None:
                        data = getattr(inst, "plaintext", b"")
                        if callable(data):
                            data = data()
                    extracted.append((offset, ident, data if isinstance(data, bytes) else str(data).encode()))
            else:
                offset = getattr(item, "offset", 0)
                ident = getattr(item, "identifier", "")
                data = getattr(item, "plaintext", b"")
                if callable(data):
                    data = data()
                extracted.append((offset, ident, data if isinstance(data, bytes) else str(data).encode()))
        return extracted

    def scan_file(self, filepath: str) -> YARAScanResult:
        """Scan a file with YARA"""
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            return self.scan_data(data)
        except Exception as e:
            return YARAScanResult(success=False, error=f"Cannot read file: {e}")

    def scan_source(self, source_code: str) -> YARAScanResult:
        """Scan source code text"""
        return self.scan_data(source_code.encode("utf-8", errors="replace"))

    def get_rule_count(self) -> int:
        """Count loaded rules"""
        # Count rules defined in builtin
        return len(re.findall(r"^rule\s+\w+", BUILTIN_RULES, re.MULTILINE))
