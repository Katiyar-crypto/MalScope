#!/usr/bin/env python3
"""
MalScope v2 — AI-Powered Universal Malware Analysis Framework
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QPalette, QColor, QFontDatabase, QIcon

from gui.main_window import MainWindow, asset_path


def main():
    # Enable high-DPI
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("MalScope")
    app.setApplicationVersion("2.1.0")
    app.setOrganizationName("MalScope Labs")
    app.setStyle("Fusion")
    logo = asset_path("malscope_logo.svg")
    if logo.exists():
        app.setWindowIcon(QIcon(str(logo)))

    # Force dark palette at OS level
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window,          QColor(5, 10, 18))
    palette.setColor(QPalette.ColorRole.WindowText,      QColor(77, 184, 212))
    palette.setColor(QPalette.ColorRole.Base,            QColor(3, 8, 16))
    palette.setColor(QPalette.ColorRole.AlternateBase,   QColor(4, 12, 24))
    palette.setColor(QPalette.ColorRole.ToolTipBase,     QColor(8, 15, 26))
    palette.setColor(QPalette.ColorRole.ToolTipText,     QColor(0, 212, 255))
    palette.setColor(QPalette.ColorRole.Text,            QColor(77, 184, 212))
    palette.setColor(QPalette.ColorRole.Button,          QColor(8, 20, 32))
    palette.setColor(QPalette.ColorRole.ButtonText,      QColor(77, 184, 212))
    palette.setColor(QPalette.ColorRole.BrightText,      QColor(0, 212, 255))
    palette.setColor(QPalette.ColorRole.Link,            QColor(0, 212, 255))
    palette.setColor(QPalette.ColorRole.Highlight,       QColor(13, 58, 92))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 212, 255))
    app.setPalette(palette)

    # Monospace terminal font throughout
    font = QFont("Courier New", 9)
    app.setFont(font)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
