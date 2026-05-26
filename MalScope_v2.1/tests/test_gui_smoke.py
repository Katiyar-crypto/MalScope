import os
import sys
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtWidgets import QApplication
    from gui.main_window import MainWindow
except ModuleNotFoundError as exc:
    QApplication = None
    MainWindow = None
    GUI_IMPORT_ERROR = exc
else:
    GUI_IMPORT_ERROR = None


@unittest.skipIf(GUI_IMPORT_ERROR is not None, f"GUI dependencies unavailable: {GUI_IMPORT_ERROR}")
class GuiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_main_window_loads_with_logo_icon(self):
        window = MainWindow()
        try:
            self.assertEqual(
                window.windowTitle(),
                "MalScope v2.1 - Universal Malware Analysis Framework",
            )
            self.assertTrue(window.logo_path.exists())
            self.assertFalse(window.windowIcon().isNull())
        finally:
            window.close()


if __name__ == "__main__":
    unittest.main()
