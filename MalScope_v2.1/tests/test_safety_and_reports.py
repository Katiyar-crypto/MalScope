import json
import sys
import tempfile
import zipfile
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.zip_handler import ZipHandler
from core.universal_decompiler import UniversalDecompiler, detect_file_type
from core.yara_scanner import YARAScanner
from utils.dependency_checker import check_dependencies
from utils.reporter import generate_report


class ZipSafetyTests(unittest.TestCase):
    def test_blocks_zip_slip_paths(self):
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / "bad.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../escape.py", "print('bad')")

            result = ZipHandler().extract(str(archive), output_dir=str(Path(td) / "out"))

            self.assertFalse(result.success)
            self.assertIn("Unsafe ZIP path", result.error)
            self.assertFalse((Path(td).parent / "escape.py").exists())

    def test_extracts_safe_zip(self):
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / "good.zip"
            out_dir = Path(td) / "out"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("sample.py", "import socket\n")

            result = ZipHandler().extract(str(archive), output_dir=str(out_dir))

            self.assertTrue(result.success)
            self.assertEqual(Path(result.primary_file).name, "sample.py")
            self.assertTrue((out_dir / "sample.py").exists())

    def test_extracts_winzip_aes_zip_when_pyzipper_available(self):
        try:
            import pyzipper
        except ImportError:
            self.skipTest("pyzipper unavailable")
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / "aes.zip"
            out_dir = Path(td) / "out"
            with pyzipper.AESZipFile(
                archive,
                "w",
                compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
            ) as zf:
                zf.setpassword(b"infected")
                zf.writestr("sample.dll", b"MZ test dll")

            result = ZipHandler().extract(str(archive), output_dir=str(out_dir))

            self.assertTrue(result.success)
            self.assertEqual(result.password_found, "infected")
            self.assertEqual(Path(result.primary_file).name, "sample.dll")
            self.assertTrue((out_dir / "sample.dll").exists())


class ReportTests(unittest.TestCase):
    def test_html_report_escapes_untrusted_values(self):
        result = {
            "behavior": {
                "threat_score": 40,
                "confidence_score": 70,
                "summary": "<script>alert(1)</script>",
                "indicators": [{
                    "severity": "HIGH",
                    "category": "Execution",
                    "description": "<b>exec</b>",
                    "evidence": "<img src=x onerror=alert(1)>",
                    "mitre_id": "T1059",
                    "mitre_technique": "https://attack.mitre.org/techniques/T1059/",
                }],
                "iocs": {"urls": ["http://example.test/<x>"]},
            },
            "decompile": {},
            "yara": {},
        }
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "report.html"
            self.assertTrue(generate_report(result, str(report), "html"))
            content = report.read_text(encoding="utf-8")

        self.assertNotIn("<script>alert(1)</script>", content)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", content)
        self.assertNotIn("<img src=x", content)

    def test_sarif_report_is_valid_json(self):
        result = {
            "behavior": {
                "indicators": [{
                    "severity": "HIGH",
                    "category": "Network",
                    "description": "Hardcoded URL",
                    "evidence": "http://c2.example",
                    "mitre_id": "T1071.001",
                    "mitre_technique": "https://attack.mitre.org/techniques/T1071/001/",
                }]
            }
        }
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "report.sarif"
            self.assertTrue(generate_report(result, str(report), "sarif"))
            data = json.loads(report.read_text(encoding="utf-8"))

        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(data["runs"][0]["results"][0]["ruleId"], "T1071.001")

    def test_bundle_report_contains_core_formats(self):
        result = {"behavior": {"indicators": [], "iocs": {}}, "universal": {"tabs": {"Strings": "abc"}}}
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td) / "bundle.zip"
            self.assertTrue(generate_report(result, str(bundle), "bundle"))
            with zipfile.ZipFile(bundle) as zf:
                names = set(zf.namelist())

        self.assertIn("report.html", names)
        self.assertIn("report.md", names)
        self.assertIn("report.json", names)
        self.assertIn("report.sarif", names)
        self.assertIn("tabs/Strings.txt", names)


class DependencyCheckTests(unittest.TestCase):
    def test_dependency_check_shape(self):
        health = check_dependencies()
        self.assertIn("packages", health)
        self.assertIn("tools", health)
        self.assertIn("healthy", health)
        self.assertIn("pyzipper", health["packages"])


class UniversalInputTests(unittest.TestCase):
    def test_missing_file_returns_structured_error(self):
        result = UniversalDecompiler().analyze(str(ROOT / "does-not-exist.zip"))

        self.assertFalse(result.success)
        self.assertEqual(result.file_type, "Missing File")
        self.assertIn("File not found", result.error)
        self.assertIn("Error", result.tabs)

    def test_extension_detection_falls_back_when_file_is_missing(self):
        file_type, category, language = detect_file_type(str(ROOT / "blocked.exe"))

        self.assertEqual(file_type, "PE Executable")
        self.assertEqual(category, "Binary")
        self.assertEqual(language, "Native/Python")


class YaraFallbackTests(unittest.TestCase):
    def test_fallback_matches_obfuscated_exec_and_iocs(self):
        scanner = YARAScanner()
        scanner._yara_available = False
        sample = b"""
import socket
exec(base64.b64decode('AAAA'))
http://malware-demo.example.com/panel
185.199.108.153:4444
SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
"""

        result = scanner.scan_data(sample)
        names = {m.rule_name for m in result.matches}

        self.assertTrue(result.success)
        self.assertEqual(result.engine, "malscope-fallback")
        self.assertIn("Python_Obfuscated_Exec", names)
        self.assertIn("Python_Suspicious_IOCs", names)


if __name__ == "__main__":
    unittest.main()
