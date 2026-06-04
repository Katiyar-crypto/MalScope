"""
MalScope v2 - Multi-Page GUI
Page 1: File + Analysis Setup
Page 2: Analysis Results (Source, Threats, IOCs, CFG, YARA, Strings)
Page 3: AI Analysis + Reports
"""

import os, sys, json, hashlib, tempfile
from pathlib import Path
from typing import Optional, Dict, List, Tuple

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
    QLabel, QPushButton, QFileDialog, QTextEdit, QTreeWidget,
    QTreeWidgetItem, QSplitter, QStatusBar, QProgressBar,
    QFrame, QScrollArea, QLineEdit, QComboBox, QGroupBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QApplication, QTabWidget, QSizePolicy, QToolBar, QMenuBar, QMenu
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QUrl
from PyQt6.QtGui import (
    QFont, QColor, QSyntaxHighlighter, QTextCharFormat,
    QAction, QDragEnterEvent, QDropEvent, QPainter, QPen, QBrush,
    QIcon
)

from gui.styles import DARK_STYLESHEET, SYNTAX_COLORS
from gui.widgets import ThreatScoreWidget, IOCTableWidget, IndicatorListWidget, FileDropZone, LogWidget, CFGWidget
from gui.workers import AnalysisWorker, AIWorker


def asset_path(name: str) -> Path:
    if hasattr(sys, "_MEIPASS"):
        frozen_asset = Path(sys._MEIPASS) / "assets" / name
        if frozen_asset.exists():
            return frozen_asset
    module_dir = Path(__file__).resolve().parent
    packaged_asset = module_dir / "assets" / name
    if packaged_asset.exists():
        return packaged_asset
    return module_dir.parent / "assets" / name


# ─────────────────────────────────────────────────────────────────────────────
# Nav Rail Button
# ─────────────────────────────────────────────────────────────────────────────
class NavButton(QPushButton):
    def __init__(self, icon_text: str, label: str, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.icon_text = icon_text
        self.label = label
        self.setFixedWidth(80)
        self.setFixedHeight(72)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._update_style(False)

    def _update_style(self, active: bool):
        if active:
            self.setStyleSheet("""
                QPushButton {
                    background-color: #0a3a5c;
                    border: none;
                    border-left: 3px solid #00cfff;
                    color: #00cfff;
                    font-family: 'Courier New';
                    font-size: 8px;
                    font-weight: bold;
                    letter-spacing: 1px;
                    padding: 6px 2px;
                }
            """)
        else:
            self.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    border: none;
                    border-left: 3px solid transparent;
                    color: #3a7a9c;
                    font-family: 'Courier New';
                    font-size: 8px;
                    letter-spacing: 1px;
                    padding: 6px 2px;
                }
                QPushButton:hover {
                    background-color: #0d1a28;
                    color: #7aafc8;
                    border-left: 3px solid #1a4a6e;
                }
            """)

    def setActive(self, active: bool):
        self._update_style(active)

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        active = self.styleSheet().__contains__("#00cfff")
        color = QColor("#00cfff") if active else QColor("#3a7a9c")
        painter.setPen(QPen(color))
        painter.setFont(QFont("Courier New", 15, QFont.Weight.Bold))
        painter.drawText(self.rect().adjusted(0, 6, 0, -24), Qt.AlignmentFlag.AlignHCenter, self.icon_text)
        painter.setFont(QFont("Courier New", 7))
        painter.drawText(self.rect().adjusted(0, 34, 0, -4), Qt.AlignmentFlag.AlignHCenter, self.label)
        painter.end()


# ─────────────────────────────────────────────────────────────────────────────
# Python Syntax Highlighter
# ─────────────────────────────────────────────────────────────────────────────
class PythonHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self.rules = []
        def fmt(color, bold=False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold: f.setFontWeight(QFont.Weight.Bold)
            return f
        keywords = ["def","class","import","from","return","if","else","elif",
                    "for","while","try","except","finally","with","as","pass",
                    "break","continue","lambda","yield","raise","in","not","and",
                    "or","is","None","True","False","global","nonlocal","del","assert","async","await"]
        for kw in keywords:
            self.rules.append((rf"\b{kw}\b", fmt(SYNTAX_COLORS["keyword"], True)))
        self.rules += [
            (r"#[^\n]*",                   fmt(SYNTAX_COLORS["comment"])),
            (r'"[^"\\]*(\\.[^"\\]*)*"',   fmt(SYNTAX_COLORS["string"])),
            (r"'[^'\\]*(\\.[^'\\]*)*'",   fmt(SYNTAX_COLORS["string"])),
            (r"\b\d+\b",                   fmt(SYNTAX_COLORS["number"])),
            (r"\bdef\s+(\w+)",             fmt(SYNTAX_COLORS["function"], True)),
            (r"\bclass\s+(\w+)",           fmt(SYNTAX_COLORS["class"], True)),
        ]

    def highlightBlock(self, text):
        import re
        for pattern, fmt in self.rules:
            for m in re.finditer(pattern, text):
                self.setFormat(m.start(), m.end()-m.start(), fmt)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN WINDOW
# ─────────────────────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MalScope v2.1 - Universal Malware Analysis Framework")
        self.setMinimumSize(1100, 700)
        self.resize(1400, 860)

        self.current_file: Optional[str] = None
        self.analysis_result: Optional[Dict] = None
        self.api_key: str = os.environ.get("ANTHROPIC_API_KEY","")
        self.selected_provider: str = "Anthropic"
        self.selected_ollama_model: str = "llama3"
        self._all_strings: List[str] = []
        self.logo_path = asset_path("malscope_logo.svg")
        if self.logo_path.exists():
            self.setWindowIcon(QIcon(str(self.logo_path)))

        self.setStyleSheet(DARK_STYLESHEET)
        self._build_ui()
        self._build_menu()
        self._build_statusbar()

    # ─────────────────────────────────────────────────────────────────────────
    # Build UI
    # ─────────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0,0,0,0)
        root_layout.setSpacing(0)

        # Nav Rail
        nav_rail = self._build_nav_rail()
        root_layout.addWidget(nav_rail)

        # Page stack
        self.pages = QStackedWidget()
        self.pages.addWidget(self._build_page1())   # 0 - File & Setup
        self.pages.addWidget(self._build_page2())   # 1 - Analysis Results
        self.pages.addWidget(self._build_page3())   # 2 - AI & Reports
        root_layout.addWidget(self.pages)

        # Start on page 1
        self._switch_page(0)

    def _build_nav_rail(self) -> QWidget:
        rail = QFrame()
        rail.setObjectName("navRail")
        rail.setFixedWidth(80)
        rail.setStyleSheet("""
            QFrame#navRail {
                background-color: #080f1a;
                border-right: 1px solid #1a3a5c;
            }
        """)
        layout = QVBoxLayout(rail)
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(0)

        # Logo area
        logo_frame = QFrame()
        logo_frame.setFixedHeight(64)
        logo_frame.setStyleSheet("background:#050a12; border-bottom:1px solid #1a3a5c;")
        ll = QVBoxLayout(logo_frame)
        ll.setContentsMargins(4,8,4,4)
        logo_lbl = QLabel("MS")
        logo_lbl.setFont(QFont("Courier New",16,QFont.Weight.Bold))
        logo_lbl.setStyleSheet("color:#00cfff; background:transparent;")
        logo_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if self.logo_path.exists():
            pixmap = QIcon(str(self.logo_path)).pixmap(QSize(48, 48))
            if not pixmap.isNull():
                logo_lbl.setPixmap(pixmap)
                logo_lbl.setText("")
        ll.addWidget(logo_lbl)
        layout.addWidget(logo_frame)

        # Nav buttons
        self.nav_buttons: List[NavButton] = []
        nav_items = [
            ("(1)","FILE\nSETUP"),
            ("(2)","ANALYSIS\nRESULTS"),
            ("(3)","AI &\nREPORTS"),
        ]
        for i, (icon, label) in enumerate(nav_items):
            btn = NavButton(icon, label)
            btn.clicked.connect(lambda checked, idx=i: self._switch_page(idx))
            self.nav_buttons.append(btn)
            layout.addWidget(btn)

        layout.addStretch()

        # Help button
        help_btn = NavButton("?", "HELP")
        help_btn.clicked.connect(self._show_about)
        layout.addWidget(help_btn)
        return rail

    def _switch_page(self, idx: int):
        self.pages.setCurrentIndex(idx)
        for i, btn in enumerate(self.nav_buttons):
            btn.setActive(i == idx)

    # ─────────────────────────────────────────────────────────────────────────
    # PAGE 1 — File & Setup
    # ─────────────────────────────────────────────────────────────────────────
    def _build_page1(self) -> QWidget:
        page = QWidget()
        page.setStyleSheet("background:#0b0f1a;")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(0)

        # Page header
        layout.addWidget(self._page_header("(1)  FILE & SETUP", "Load a file and configure analysis settings"))

        # Content area
        content = QWidget()
        content_layout = QHBoxLayout(content)
        content_layout.setContentsMargins(16,16,16,16)
        content_layout.setSpacing(16)

        # Left column — file drop + info
        left = QVBoxLayout()
        left.setSpacing(12)

        # Drop zone — large and prominent
        drop_frame = QFrame()
        drop_frame.setObjectName("bigDropZone")
        drop_frame.setMinimumHeight(180)
        drop_frame.setStyleSheet("""
            QFrame#bigDropZone {
                background: #0a1220;
                border: 2px dashed #1a4a6e;
                border-radius: 8px;
            }
            QFrame#bigDropZone:hover { border-color: #00cfff; }
        """)
        drop_frame.setAcceptDrops(True)
        drop_frame.dragEnterEvent = self._drag_enter
        drop_frame.dropEvent = self._drop_event
        drop_layout = QVBoxLayout(drop_frame)
        drop_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        drop_layout.setSpacing(8)

        drop_icon = QLabel("[*]")
        drop_icon.setFont(QFont("Courier New", 32, QFont.Weight.Bold))
        drop_icon.setStyleSheet("color:#1a4a6e; background:transparent;")
        drop_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        drop_layout.addWidget(drop_icon)

        drop_title = QLabel("DROP ANY FILE HERE TO ANALYZE")
        drop_title.setFont(QFont("Courier New", 12, QFont.Weight.Bold))
        drop_title.setStyleSheet("color:#5a9fc0; background:transparent; letter-spacing:3px;")
        drop_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        drop_layout.addWidget(drop_title)

        drop_sub = QLabel(".pyc  .exe  .dll  .elf  .apk  .jar  .js  .ps1  .pdf  .docx  .xlsx  .zip  and more...")
        drop_sub.setStyleSheet("color:#2a5a7a; background:transparent; font-size:10px; letter-spacing:1px;")
        drop_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        drop_layout.addWidget(drop_sub)

        btn_browse = QPushButton("[+]  Browse & Open File...")
        btn_browse.setObjectName("bigBtn")
        btn_browse.setStyleSheet("""
            QPushButton {
                background:#0a3a5c; color:#00cfff; border:1px solid #00cfff;
                border-radius:4px; padding:10px 24px; font-size:11px;
                font-family:'Courier New'; font-weight:bold; letter-spacing:2px;
                margin-top:6px;
            }
            QPushButton:hover { background:#0d4a70; color:#fff; }
        """)
        btn_browse.clicked.connect(self.open_file_dialog)
        drop_layout.addWidget(btn_browse, alignment=Qt.AlignmentFlag.AlignCenter)

        left.addWidget(drop_frame)

        # File info card
        self.file_info_card = self._section_card("FILE INFORMATION")
        fi_layout = QVBoxLayout()
        fi_layout.setSpacing(6)
        rows = [
            ("Filename",    "lbl_p1_name",    "No file loaded"),
            ("Type",        "lbl_p1_type",    "—"),
            ("Size",        "lbl_p1_size",    "—"),
            ("MD5",         "lbl_p1_md5",     "—"),
            ("SHA256",      "lbl_p1_sha256",  "—"),
            ("Entropy",     "lbl_p1_entropy", "—"),
            ("Architecture","lbl_p1_arch",    "—"),
        ]
        for row_label, attr, default in rows:
            row = QHBoxLayout()
            lk = QLabel(row_label + ":")
            lk.setFixedWidth(100)
            lk.setStyleSheet("color:#3a7a9c; font-size:9px; letter-spacing:2px;")
            lv = QLabel(default)
            lv.setStyleSheet("color:#c8d8e8; font-size:10px; font-weight:bold;")
            lv.setWordWrap(True)
            setattr(self, attr, lv)
            row.addWidget(lk)
            row.addWidget(lv)
            fi_layout.addLayout(row)
        fi_body = self.file_info_card.findChild(QWidget, "cardBody")
        if fi_body:
            fi_body.layout().addLayout(fi_layout)
        left.addWidget(self.file_info_card)
        content_layout.addLayout(left, 55)

        # Right column — settings panels
        right = QVBoxLayout()
        right.setSpacing(12)

        # AI Provider settings
        ai_card = self._section_card("AI PROVIDER SETTINGS")
        ai_body = ai_card.findChild(QWidget,"cardBody")
        ai_layout = QVBoxLayout()
        ai_layout.setSpacing(10)

        ai_layout.addWidget(self._field_label("Provider:"))
        self.provider_selector = QComboBox()
        self.provider_selector.addItems(["Anthropic (Claude)", "OpenAI", "Ollama (Local)", "HuggingFace"])
        self.provider_selector.setStyleSheet(self._combo_style())
        self.provider_selector.currentTextChanged.connect(self._on_provider_changed)
        ai_layout.addWidget(self.provider_selector)

        ai_layout.addWidget(self._field_label("API Key:"))
        self.txt_api_key_p1 = QLineEdit()
        self.txt_api_key_p1.setPlaceholderText("sk-ant-api03-...  or  sk-...  or  hf_...")
        self.txt_api_key_p1.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_api_key_p1.setStyleSheet(self._input_style())
        ai_layout.addWidget(self.txt_api_key_p1)

        ai_layout.addWidget(self._field_label("Ollama Model (if local):"))
        self.ollama_model_input = QComboBox()
        self.ollama_model_input.addItems(["llama3","mistral","deepseek-coder","phi3","codellama","llama2"])
        self.ollama_model_input.setEditable(True)
        self.ollama_model_input.setStyleSheet(self._combo_style())
        ai_layout.addWidget(self.ollama_model_input)

        btn_save_ai = QPushButton("[OK]  Save AI Settings")
        btn_save_ai.setStyleSheet(self._action_btn_style("#00cfff","#0a3a5c","#00cfff"))
        btn_save_ai.clicked.connect(self._save_ai_settings)
        ai_layout.addWidget(btn_save_ai)

        self.lbl_ai_status = QLabel("[--] Not configured")
        self.lbl_ai_status.setStyleSheet("color:#ff4466; font-size:9px; letter-spacing:1px;")
        ai_layout.addWidget(self.lbl_ai_status)

        if ai_body: ai_body.layout().addLayout(ai_layout)
        right.addWidget(ai_card)

        # ZIP Password settings
        zip_card = self._section_card("ZIP PASSWORD (Encrypted Samples)")
        zip_body = zip_card.findChild(QWidget,"cardBody")
        zip_layout = QVBoxLayout()
        zip_layout.setSpacing(8)

        zip_hint = QLabel(
            "Enter password for encrypted ZIP files.\n"
            "Common malware sample passwords:\n"
            "  infected  |  malware  |  virus  |  password  |  1234"
        )
        zip_hint.setStyleSheet("color:#5a9fc0; font-size:9px; line-height:160%;")
        zip_layout.addWidget(zip_hint)

        self.txt_zip_password = QLineEdit()
        self.txt_zip_password.setPlaceholderText("e.g.  infected")
        self.txt_zip_password.setStyleSheet(self._input_style())
        zip_layout.addWidget(self.txt_zip_password)

        btn_zip = QPushButton("[U]  Apply Password & Re-Analyze")
        btn_zip.setStyleSheet(self._action_btn_style("#00ffcc","#002a1e","#00aa88"))
        btn_zip.clicked.connect(self.run_analysis)
        zip_layout.addWidget(btn_zip)

        if zip_body: zip_body.layout().addLayout(zip_layout)
        right.addWidget(zip_card)

        # Run analysis button
        self.btn_analyze_p1 = QPushButton("[>]  RUN FULL ANALYSIS")
        self.btn_analyze_p1.setEnabled(False)
        self.btn_analyze_p1.setStyleSheet("""
            QPushButton {
                background:#0a3a5c; color:#00cfff; border:2px solid #00cfff;
                border-radius:4px; padding:14px; font-size:13px;
                font-family:'Courier New'; font-weight:bold; letter-spacing:3px;
            }
            QPushButton:hover { background:#0d5070; color:#fff; border-color:#00ffff; }
            QPushButton:disabled { background:#0a1525; color:#1a4060; border-color:#112233; }
        """)
        self.btn_analyze_p1.clicked.connect(self._run_and_switch)
        right.addWidget(self.btn_analyze_p1)
        right.addStretch()
        content_layout.addLayout(right, 45)

        layout.addWidget(content, 1)

        # Log strip
        layout.addWidget(self._build_log_strip())
        return page

    def _run_and_switch(self):
        self.run_analysis()
        # Switch to results page after short delay
        QTimer.singleShot(500, lambda: self._switch_page(1))

    # ─────────────────────────────────────────────────────────────────────────
    # PAGE 2 — Analysis Results
    # ─────────────────────────────────────────────────────────────────────────
    def _build_page2(self) -> QWidget:
        page = QWidget()
        page.setStyleSheet("background:#0b0f1a;")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(0)

        layout.addWidget(self._page_header("(2)  ANALYSIS RESULTS", "Decompiled source, threats, IOCs, CFG, YARA, strings"))

        # Tab bar for results
        self.result_tabs = QTabWidget()
        self.result_tabs.setDocumentMode(True)
        self.result_tabs.setStyleSheet("""
            QTabWidget::pane { border: none; background: #0b0f1a; }
            QTabBar::tab {
                background: #0d1320; color: #4a8aaa;
                padding: 10px 18px; border: none;
                border-right: 1px solid #0e1e30;
                border-bottom: 3px solid transparent;
                font-size: 9px; font-family:'Courier New';
                font-weight: bold; letter-spacing: 1px;
                min-width: 80px;
            }
            QTabBar::tab:selected {
                color: #00cfff; border-bottom: 3px solid #00cfff;
                background: #0f1828;
            }
            QTabBar::tab:hover:!selected { color:#88ccee; background:#0f1828; }
        """)

        self.result_tabs.addTab(self._build_overview_tab(),   "[~] Overview")
        self.result_tabs.addTab(self._build_source_tab(),     "[S] Source Code")
        self.result_tabs.addTab(self._build_threats_tab(),    "[T] Threats")
        self.result_tabs.addTab(self._build_iocs_tab(),       "[I] IOCs")
        self.result_tabs.addTab(self._build_opcodes_tab(),    "[O] Opcodes")
        self.result_tabs.addTab(self._build_cfg_tab(),        "[C] CFG")
        self.result_tabs.addTab(self._build_yara_tab(),       "[Y] YARA")
        self.result_tabs.addTab(self._build_strings_tab(),    "[Q] Strings")
        self.result_tabs.addTab(self._build_universal_tab(),  "[U] Universal")

        layout.addWidget(self.result_tabs, 1)
        layout.addWidget(self._build_log_strip())
        return page

    # ─────────────────────────────────────────────────────────────────────────
    # PAGE 3 — AI Analysis & Reports
    # ─────────────────────────────────────────────────────────────────────────
    def _build_page3(self) -> QWidget:
        page = QWidget()
        page.setStyleSheet("background:#0b0f1a;")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(0)

        layout.addWidget(self._page_header("(3)  AI ANALYSIS & REPORTS", "AI-powered code explanation, deobfuscation, YARA generation and forensic report export"))

        ai_tabs = QTabWidget()
        ai_tabs.setDocumentMode(True)
        ai_tabs.setStyleSheet("""
            QTabWidget::pane { border: none; background: #0b0f1a; }
            QTabBar::tab {
                background: #0d1320; color: #4a8aaa;
                padding: 10px 20px; border: none;
                border-right: 1px solid #0e1e30;
                border-bottom: 3px solid transparent;
                font-size: 9px; font-family:'Courier New';
                font-weight: bold; letter-spacing: 1px;
            }
            QTabBar::tab:selected { color:#dd88ff; border-bottom:3px solid #dd88ff; background:#0f1828; }
            QTabBar::tab:hover:!selected { color:#cc99ee; background:#0f1828; }
        """)
        ai_tabs.addTab(self._build_ai_tab(),     "[*] AI Analysis")
        ai_tabs.addTab(self._build_report_tab(), "[R] Export Report")

        layout.addWidget(ai_tabs, 1)
        layout.addWidget(self._build_log_strip())
        return page

    # ─────────────────────────────────────────────────────────────────────────
    # Tab content builders
    # ─────────────────────────────────────────────────────────────────────────
    def _build_overview_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(16,16,16,16)
        layout.setSpacing(12)

        # Score cards row
        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)
        self.card_score    = self._make_card("THREAT SCORE",  "—", "#ff4466")
        self.card_conf     = self._make_card("CONFIDENCE",    "—", "#ffaa00")
        self.card_indic    = self._make_card("INDICATORS",    "—", "#ff8833")
        self.card_iocs     = self._make_card("IOCs FOUND",    "—", "#00cfff")
        self.card_obf      = self._make_card("OBFUSCATIONS",  "—", "#cc88ff")
        self.card_families = self._make_card("MALWARE FAMILY","—", "#ff6688")
        for c in [self.card_score, self.card_conf, self.card_indic,
                  self.card_iocs, self.card_obf, self.card_families]:
            cards_row.addWidget(c)
        layout.addLayout(cards_row)

        # Summary + threat score gauge side by side
        mid_row = QHBoxLayout()
        mid_row.setSpacing(12)

        # Gauge
        self.threat_score_widget = ThreatScoreWidget()
        self.threat_score_widget.setFixedWidth(160)
        mid_row.addWidget(self.threat_score_widget)

        # Summary text
        sum_frame = self._section_card("ANALYSIS SUMMARY")
        sum_body = sum_frame.findChild(QWidget,"cardBody")
        self.txt_summary = QTextEdit()
        self.txt_summary.setReadOnly(True)
        self.txt_summary.setFont(QFont("Courier New",10))
        self.txt_summary.setStyleSheet("background:#060e1c; color:#c8d8e8; border:none;")
        self.txt_summary.setPlaceholderText("Run analysis to see summary...")
        if sum_body: sum_body.layout().addWidget(self.txt_summary)
        mid_row.addWidget(sum_frame, 1)
        layout.addLayout(mid_row)

        # Code objects tree
        tree_frame = self._section_card("CODE OBJECTS / FUNCTIONS")
        tree_body = tree_frame.findChild(QWidget,"cardBody")
        self.tree_code_objects = QTreeWidget()
        self.tree_code_objects.setHeaderLabels(["Name","File","Args","Line"])
        self.tree_code_objects.setStyleSheet("""
            QTreeWidget { background:#060e1c; color:#c8d8e8; border:none; font-size:9px; }
            QTreeWidget::item { padding:3px; border-bottom:1px solid #0e1e30; }
            QTreeWidget::item:selected { background:#1a3a5c; color:#00cfff; }
            QHeaderView::section { background:#0a1828; color:#4a8aaa; border:none;
                border-right:1px solid #0e1e30; padding:5px 8px; font-size:8px; letter-spacing:2px; }
        """)
        self.tree_code_objects.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        if tree_body: tree_body.layout().addWidget(self.tree_code_objects)
        layout.addWidget(tree_frame, 1)
        return w

    def _build_source_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12,12,12,12)
        layout.setSpacing(8)

        # Toolbar row
        bar = QHBoxLayout()
        self.lbl_backend = QLabel("Backend: —")
        self.lbl_backend.setStyleSheet("color:#3a7a9c; font-size:9px; letter-spacing:1px;")
        bar.addWidget(self.lbl_backend)
        bar.addStretch()
        self.lbl_pyver_src = QLabel("")
        self.lbl_pyver_src.setStyleSheet("color:#5a9fc0; font-size:9px;")
        bar.addWidget(self.lbl_pyver_src)
        btn_copy = QPushButton("[C] Copy")
        btn_copy.setStyleSheet(self._mini_btn_style())
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(self.txt_source.toPlainText()))
        bar.addWidget(btn_copy)
        layout.addLayout(bar)

        self.txt_source = QTextEdit()
        self.txt_source.setReadOnly(True)
        self.txt_source.setFont(QFont("Courier New",10))
        self.txt_source.setStyleSheet("background:#060e1c; color:#b8e0f8; border:1px solid #1a3a5c; border-radius:3px;")
        self.txt_source.setPlaceholderText("# Decompiled source code will appear here after analysis...")
        self.highlighter = PythonHighlighter(self.txt_source.document())
        layout.addWidget(self.txt_source)
        return w

    def _build_threats_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12,12,12,12)
        layout.setSpacing(8)

        bar = QHBoxLayout()
        self.lbl_threat_count = QLabel("0 indicators")
        self.lbl_threat_count.setStyleSheet("color:#5a9fc0; font-size:9px;")
        bar.addWidget(self.lbl_threat_count)
        bar.addStretch()
        layout.addLayout(bar)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.indicator_list = IndicatorListWidget()
        splitter.addWidget(self.indicator_list)

        obf_frame = self._section_card("OBFUSCATION TECHNIQUES DETECTED")
        obf_body = obf_frame.findChild(QWidget,"cardBody")
        self.txt_obfuscation = QTextEdit()
        self.txt_obfuscation.setReadOnly(True)
        self.txt_obfuscation.setFont(QFont("Courier New",10))
        self.txt_obfuscation.setStyleSheet("background:#060e1c; color:#ffcc44; border:none;")
        self.txt_obfuscation.setMaximumHeight(100)
        if obf_body: obf_body.layout().addWidget(self.txt_obfuscation)
        splitter.addWidget(obf_frame)
        splitter.setSizes([500,120])
        layout.addWidget(splitter)
        return w

    def _build_iocs_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12,12,12,12)
        layout.setSpacing(8)
        bar = QHBoxLayout()
        lbl = QLabel("INDICATORS OF COMPROMISE")
        lbl.setStyleSheet("color:#00cfff; font-size:11px; font-weight:bold; letter-spacing:3px;")
        bar.addWidget(lbl)
        bar.addStretch()
        btn_exp = QPushButton("[E] Export IOCs")
        btn_exp.setStyleSheet(self._mini_btn_style())
        btn_exp.clicked.connect(self.export_iocs)
        bar.addWidget(btn_exp)
        layout.addLayout(bar)
        self.ioc_table = IOCTableWidget()
        layout.addWidget(self.ioc_table)
        return w

    def _build_opcodes_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12,12,12,12)
        layout.setSpacing(8)
        bar = QHBoxLayout()
        self.lbl_opcount = QLabel("0 instructions")
        self.lbl_opcount.setStyleSheet("color:#5a9fc0; font-size:9px;")
        bar.addWidget(self.lbl_opcount)
        bar.addStretch()
        layout.addLayout(bar)
        self.tbl_opcodes = QTableWidget()
        self.tbl_opcodes.setColumnCount(5)
        self.tbl_opcodes.setHorizontalHeaderLabels(["OFFSET","OPCODE","MNEMONIC","ARG","ARGVAL"])
        self.tbl_opcodes.setStyleSheet(self._table_style())
        self.tbl_opcodes.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.tbl_opcodes.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.tbl_opcodes.setAlternatingRowColors(True)
        self.tbl_opcodes.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tbl_opcodes.setShowGrid(False)
        layout.addWidget(self.tbl_opcodes)
        return w

    def _build_cfg_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12,12,12,12)
        layout.setSpacing(8)
        bar = QHBoxLayout()
        lbl = QLabel("CONTROL FLOW GRAPH")
        lbl.setStyleSheet("color:#00cfff; font-size:11px; font-weight:bold; letter-spacing:3px;")
        bar.addWidget(lbl)
        bar.addStretch()
        self.btn_gen_cfg = QPushButton("[G] Generate CFG")
        self.btn_gen_cfg.setStyleSheet(self._mini_btn_style())
        self.btn_gen_cfg.setEnabled(False)
        self.btn_gen_cfg.clicked.connect(self.generate_cfg)
        bar.addWidget(self.btn_gen_cfg)
        self.btn_export_cfg = QPushButton("[E] Export PNG")
        self.btn_export_cfg.setStyleSheet(self._mini_btn_style())
        self.btn_export_cfg.setEnabled(False)
        self.btn_export_cfg.clicked.connect(self.export_cfg)
        bar.addWidget(self.btn_export_cfg)
        layout.addLayout(bar)
        self.cfg_widget = CFGWidget()
        layout.addWidget(self.cfg_widget)
        self.cfg_stats_lbl = QLabel("Load a file and click Generate CFG.")
        self.cfg_stats_lbl.setStyleSheet("color:#3a7a9c; font-size:9px;")
        layout.addWidget(self.cfg_stats_lbl)
        return w

    def _build_yara_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12,12,12,12)
        layout.setSpacing(8)
        bar = QHBoxLayout()
        self.lbl_yara_count = QLabel("0 matches")
        self.lbl_yara_count.setStyleSheet("color:#5a9fc0; font-size:9px;")
        bar.addWidget(self.lbl_yara_count)
        bar.addStretch()
        layout.addLayout(bar)
        self.tbl_yara = QTableWidget()
        self.tbl_yara.setColumnCount(4)
        self.tbl_yara.setHorizontalHeaderLabels(["RULE","SEVERITY","DESCRIPTION","MITRE"])
        self.tbl_yara.setStyleSheet(self._table_style())
        self.tbl_yara.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.tbl_yara.setAlternatingRowColors(True)
        self.tbl_yara.setShowGrid(False)
        layout.addWidget(self.tbl_yara)
        return w

    def _build_strings_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12,12,12,12)
        layout.setSpacing(8)
        bar = QHBoxLayout()
        self.lbl_strings_count = QLabel("0 strings")
        self.lbl_strings_count.setStyleSheet("color:#5a9fc0; font-size:9px;")
        bar.addWidget(self.lbl_strings_count)
        bar.addStretch()
        self.txt_strings_filter = QLineEdit()
        self.txt_strings_filter.setPlaceholderText("Filter strings...")
        self.txt_strings_filter.setFixedWidth(200)
        self.txt_strings_filter.setStyleSheet(self._input_style())
        self.txt_strings_filter.textChanged.connect(self._filter_strings)
        bar.addWidget(self.txt_strings_filter)
        btn_copy = QPushButton("[C] Copy")
        btn_copy.setStyleSheet(self._mini_btn_style())
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(self.txt_strings.toPlainText()))
        bar.addWidget(btn_copy)
        layout.addLayout(bar)
        self.txt_strings = QTextEdit()
        self.txt_strings.setReadOnly(True)
        self.txt_strings.setFont(QFont("Courier New",10))
        self.txt_strings.setStyleSheet("background:#060e1c; color:#c8d8e8; border:1px solid #1a3a5c; border-radius:3px;")
        layout.addWidget(self.txt_strings)
        return w

    def _build_universal_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12,12,12,12)
        layout.setSpacing(8)
        bar = QHBoxLayout()
        self.lbl_universal_type = QLabel("No file analyzed")
        self.lbl_universal_type.setStyleSheet("color:#00cfff; font-size:10px; font-weight:bold; letter-spacing:2px;")
        bar.addWidget(self.lbl_universal_type)
        bar.addStretch()
        layout.addLayout(bar)
        self.universal_tabs = QTabWidget()
        self.universal_tabs.setDocumentMode(True)
        self.universal_tabs.setStyleSheet("""
            QTabWidget::pane { border:1px solid #1a3a5c; background:#060e1c; }
            QTabBar::tab { background:#0d1320; color:#4a8aaa; padding:6px 14px;
                border:none; border-right:1px solid #0e1e30; border-bottom:2px solid transparent;
                font-size:9px; font-family:'Courier New'; font-weight:bold; }
            QTabBar::tab:selected { color:#00ffcc; border-bottom:2px solid #00ffcc; background:#0f1828; }
        """)
        layout.addWidget(self.universal_tabs)
        return w

    def _build_ai_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(16,16,16,16)
        layout.setSpacing(12)

        # Action buttons row
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.btn_ai_full = QPushButton("[*]  Full AI Analysis")
        self.btn_ai_full.setEnabled(False)
        self.btn_ai_full.setStyleSheet("""
            QPushButton { background:#1a0a3a; color:#dd88ff; border:1px solid #8844cc;
                border-radius:3px; padding:10px 20px; font-size:10px;
                font-family:'Courier New'; font-weight:bold; letter-spacing:1px; }
            QPushButton:hover { background:#260a50; color:#ff99ff; border-color:#bb66ff; }
            QPushButton:disabled { color:#3a1a5a; border-color:#1a0a2a; background:#0b0f1a; }
        """)
        self.btn_ai_full.clicked.connect(self.run_ai_analysis)
        btn_row.addWidget(self.btn_ai_full)

        self.btn_ai_deobf = QPushButton("[D]  Deobfuscate")
        self.btn_ai_deobf.setEnabled(False)
        self.btn_ai_deobf.setStyleSheet(self._mini_btn_style())
        self.btn_ai_deobf.clicked.connect(self.run_ai_deobfuscate)
        btn_row.addWidget(self.btn_ai_deobf)

        self.btn_ai_yara = QPushButton("[Y]  Generate YARA")
        self.btn_ai_yara.setEnabled(False)
        self.btn_ai_yara.setStyleSheet(self._mini_btn_style())
        self.btn_ai_yara.clicked.connect(self.run_ai_yara)
        btn_row.addWidget(self.btn_ai_yara)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # AI output
        self.txt_ai_output = QTextEdit()
        self.txt_ai_output.setReadOnly(True)
        self.txt_ai_output.setFont(QFont("Courier New",10))
        self.txt_ai_output.setStyleSheet("background:#0c0820; color:#ddaaff; border:1px solid #3a1a7c; border-radius:3px;")
        self.txt_ai_output.setPlaceholderText(
            "AI analysis output will appear here.\n\n"
            "Configure your API key on Page 1 (File & Setup), then click Full AI Analysis."
        )
        layout.addWidget(self.txt_ai_output)

        self.ai_progress = QProgressBar()
        self.ai_progress.setStyleSheet("""
            QProgressBar { background:#0d1a28; border:1px solid #1a3a5c; border-radius:3px; height:4px; }
            QProgressBar::chunk { background:linear-gradient(90deg,#440088,#dd88ff); border-radius:3px; }
        """)
        self.ai_progress.setVisible(False)
        layout.addWidget(self.ai_progress)
        return w

    def _build_report_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(16,16,16,16)
        layout.setSpacing(12)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        for label, fmt in [
            ("[J] Export JSON","json"),
            ("[H] Export HTML","html"),
            ("[M] Export Markdown","md"),
            ("[S] Export SARIF","sarif"),
            ("[B] Export Bundle","bundle"),
        ]:
            btn = QPushButton(label)
            btn.setStyleSheet(self._mini_btn_style())
            btn.clicked.connect(lambda _, f=fmt: self.export_report(f))
            btn_row.addWidget(btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.txt_report = QTextEdit()
        self.txt_report.setReadOnly(True)
        self.txt_report.setFont(QFont("Courier New",9))
        self.txt_report.setStyleSheet("background:#060e1c; color:#c8d8e8; border:1px solid #1a3a5c; border-radius:3px;")
        self.txt_report.setPlaceholderText("Run analysis to generate forensic report...")
        layout.addWidget(self.txt_report)
        return w

    # ─────────────────────────────────────────────────────────────────────────
    # Helper widgets
    # ─────────────────────────────────────────────────────────────────────────
    def _page_header(self, title: str, subtitle: str) -> QFrame:
        frame = QFrame()
        frame.setFixedHeight(56)
        frame.setStyleSheet("background:#080f1a; border-bottom:2px solid #1a3a5c;")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20,8,20,6)
        layout.setSpacing(2)
        t = QLabel(title)
        t.setFont(QFont("Courier New",12,QFont.Weight.Bold))
        t.setStyleSheet("color:#00cfff; letter-spacing:3px; background:transparent;")
        s = QLabel(subtitle)
        s.setFont(QFont("Courier New",8))
        s.setStyleSheet("color:#3a7a9c; letter-spacing:1px; background:transparent;")
        layout.addWidget(t)
        layout.addWidget(s)
        return frame

    def _section_card(self, title: str) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet("background:#0d1a28; border:1px solid #1a3a5c; border-radius:4px;")
        outer = QVBoxLayout(frame)
        outer.setContentsMargins(0,0,0,0)
        outer.setSpacing(0)
        title_bar = QLabel("  " + title)
        title_bar.setFixedHeight(28)
        title_bar.setStyleSheet("background:#0a1525; color:#4a8aaa; font-size:8px; letter-spacing:3px; border-bottom:1px solid #1a3a5c; border-radius:4px 4px 0 0;")
        outer.addWidget(title_bar)
        body = QWidget()
        body.setObjectName("cardBody")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(10,8,10,10)
        body_layout.setSpacing(6)
        outer.addWidget(body)
        return frame

    def _make_card(self, title: str, value: str, color: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet(f"background:#0d1a28; border:1px solid #1a3a5c; border-top:2px solid {color}44; border-radius:4px;")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12,10,12,10)
        layout.setSpacing(4)
        val_lbl = QLabel(value)
        val_lbl.setFont(QFont("Courier New",22,QFont.Weight.Bold))
        val_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        val_lbl.setStyleSheet(f"color:{color}; background:transparent;")
        title_lbl = QLabel(title)
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_lbl.setStyleSheet("color:#4a8aaa; font-size:7px; letter-spacing:2px; background:transparent;")
        layout.addWidget(val_lbl)
        layout.addWidget(title_lbl)
        card._val_lbl = val_lbl
        return card

    def _build_log_strip(self) -> QWidget:
        if not hasattr(self, '_log_widget'):
            self.log_widget = LogWidget()
        frame = QFrame()
        frame.setFixedHeight(90)
        frame.setStyleSheet("background:#060c16; border-top:1px solid #112233;")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(0,0,0,0)
        layout.addWidget(self.log_widget)
        return frame

    def _field_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet("color:#4a8aaa; font-size:9px; letter-spacing:1px;")
        return lbl

    def _combo_style(self) -> str:
        return """
            QComboBox { background:#08111e; color:#c8d8e8; border:1px solid #1a3a5c;
                border-radius:3px; padding:6px 10px; font-size:10px; font-family:'Courier New'; }
            QComboBox:hover { border-color:#00cfff; }
            QComboBox::drop-down { border:none; width:20px; }
            QComboBox QAbstractItemView { background:#0d1320; color:#c8d8e8;
                border:1px solid #1a3a5c; selection-background-color:#1a3a5c; selection-color:#00cfff; }
        """

    def _input_style(self) -> str:
        return """
            QLineEdit { background:#08111e; color:#c8d8e8; border:1px solid #1a3a5c;
                border-radius:3px; padding:7px 10px; font-size:10px; font-family:'Courier New'; }
            QLineEdit:focus { border-color:#00cfff; color:#fff; }
        """

    def _action_btn_style(self, text_color, bg, border) -> str:
        return f"""
            QPushButton {{ background:{bg}; color:{text_color}; border:1px solid {border};
                border-radius:3px; padding:9px; font-size:10px; font-family:'Courier New';
                font-weight:bold; letter-spacing:1px; }}
            QPushButton:hover {{ background:{border}22; color:#fff; border-color:{text_color}; }}
        """

    def _mini_btn_style(self) -> str:
        return """
            QPushButton { background:#112233; color:#c8d8e8; border:1px solid #1e4a6e;
                border-radius:3px; padding:5px 14px; font-size:9px; font-family:'Courier New';
                font-weight:bold; letter-spacing:1px; }
            QPushButton:hover { background:#1a3a5c; color:#00cfff; border-color:#00cfff; }
            QPushButton:disabled { color:#2a4a5a; border-color:#112233; background:#0b0f1a; }
        """

    def _table_style(self) -> str:
        return """
            QTableWidget { background:#060e1c; color:#c8d8e8; gridline-color:#0e1e30;
                border:1px solid #1a3a5c; alternate-background-color:#080f18;
                selection-background-color:#1a3a5c; selection-color:#00cfff;
                font-size:9px; font-family:'Courier New'; }
            QTableWidget::item { padding:4px 8px; border-bottom:1px solid #0e1e30; color:#c8d8e8; }
            QTableWidget::item:selected { background:#1a3a5c; color:#00cfff; }
            QHeaderView::section { background:#0a1828; color:#4a8aaa; border:none;
                border-right:1px solid #0e1e30; border-bottom:1px solid #1a3a5c;
                padding:6px 10px; font-size:8px; letter-spacing:2px; font-weight:bold; }
        """

    # ─────────────────────────────────────────────────────────────────────────
    # Menu + Statusbar
    # ─────────────────────────────────────────────────────────────────────────
    def _build_menu(self):
        mb = self.menuBar()
        mb.setStyleSheet("QMenuBar{background:#0b0f1a;color:#5a9fc0;border-bottom:1px solid #1a3a5c;font-size:10px;}"
                        "QMenuBar::item{padding:5px 12px;}"
                        "QMenuBar::item:selected{background:#112233;color:#00cfff;}"
                        "QMenu{background:#0d1320;color:#c8d8e8;border:1px solid #1a3a5c;font-size:10px;}"
                        "QMenu::item{padding:6px 20px;}"
                        "QMenu::item:selected{background:#1a3a5c;color:#00cfff;}")
        fm = mb.addMenu("File")
        open_act = QAction("[+] Open File...", self); open_act.setShortcut("Ctrl+O"); open_act.triggered.connect(self.open_file_dialog); fm.addAction(open_act)
        fm.addSeparator()
        exit_act = QAction("Exit", self); exit_act.triggered.connect(self.close); fm.addAction(exit_act)
        am = mb.addMenu("Analyze")
        run_act = QAction("[>] Run Analysis", self); run_act.setShortcut("Ctrl+R"); run_act.triggered.connect(self.run_analysis); am.addAction(run_act)
        ai_act = QAction("[*] AI Analysis", self); ai_act.setShortcut("Ctrl+Shift+A"); ai_act.triggered.connect(self.run_ai_analysis); am.addAction(ai_act)
        hm = mb.addMenu("Help")
        about_act = QAction("About MalScope", self); about_act.triggered.connect(self._show_about); hm.addAction(about_act)

    def _build_statusbar(self):
        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet("QStatusBar{background:#060c16;border-top:1px solid #112233;color:#4a8aaa;font-size:9px;}")
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Ready — drop a file or use File > Open")
        self.status_bar.addWidget(self.status_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("QProgressBar{background:#0d1a28;border:1px solid #1a3a5c;border-radius:2px;height:4px;}"
                                        "QProgressBar::chunk{background:linear-gradient(90deg,#004a7c,#00cfff,#00ffcc);border-radius:2px;}")
        self.status_bar.addPermanentWidget(self.progress_bar)
        self.status_bar.addPermanentWidget(QLabel("MalScope v2.1"))

    # ─────────────────────────────────────────────────────────────────────────
    # Drag & Drop
    # ─────────────────────────────────────────────────────────────────────────
    def _drag_enter(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls(): event.acceptProposedAction()

    def _drop_event(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls: self.load_file(urls[0].toLocalFile())

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls(): event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls: self.load_file(urls[0].toLocalFile())

    # ─────────────────────────────────────────────────────────────────────────
    # File loading
    # ─────────────────────────────────────────────────────────────────────────
    def open_file_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open File", "",
            "All Supported Files (*.pyc *.pyo *.exe *.dll *.so *.elf *.apk *.jar *.class *.dex *.wasm *.js *.ps1 *.vbs *.bat *.sh *.php *.rb *.pdf *.docx *.xlsx *.xlsm *.doc *.xls *.zip *.bin *);;All Files (*)")
        if path: self.load_file(path)

    def load_file(self, filepath: str):
        if not filepath or not os.path.exists(filepath):
            msg = f"File not found: {filepath}"
            self.status_label.setText(msg[:120])
            self.log_widget.log(msg, "error")
            QMessageBox.warning(
                self,
                "File Not Found",
                "MalScope could not find this file.\n\n"
                "It may have been moved, deleted, quarantined, or blocked by permissions.",
            )
            return
        self.current_file = filepath
        fname = Path(filepath).name
        size = os.path.getsize(filepath)
        md5, sha256 = self._hash_file(filepath)

        self.lbl_p1_name.setText(fname)
        self.lbl_p1_size.setText(f"{size:,} bytes")
        self.lbl_p1_md5.setText(md5)
        self.lbl_p1_sha256.setText(sha256[:32] + "..." if sha256 else "—")
        self.lbl_p1_type.setText(Path(filepath).suffix.upper() or "Unknown")
        self.lbl_p1_entropy.setText("—")
        self.lbl_p1_arch.setText("—")

        self.btn_analyze_p1.setEnabled(True)
        self.status_label.setText(f"Loaded: {fname}")
        self.log_widget.log(f"File loaded: {filepath}", "info")

        # Auto-analyze
        self.run_analysis()

    # ─────────────────────────────────────────────────────────────────────────
    # Analysis
    # ─────────────────────────────────────────────────────────────────────────
    def _hash_file(self, filepath: str) -> Tuple[str, str]:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()

    def run_analysis(self):
        if not self.current_file: return
        if hasattr(self, "worker") and self.worker.isRunning():
            self.log_widget.log("Analysis already running; please wait.", "warning")
            return
        self.analysis_result = None
        self.btn_analyze_p1.setEnabled(False)
        if hasattr(self, "btn_ai_full"):
            self._set_ai_buttons_enabled(False)
        if hasattr(self, "btn_gen_cfg"):
            self.btn_gen_cfg.setEnabled(False)
        if hasattr(self, "btn_export_cfg"):
            self.btn_export_cfg.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0,0)
        self.status_label.setText("Analyzing...")
        self.log_widget.log("Starting analysis...", "info")
        zip_pass = self.txt_zip_password.text().strip() or None
        self.worker = AnalysisWorker(self.current_file, zip_password=zip_pass)
        self.worker.progress.connect(lambda m: (self.status_label.setText(m), self.log_widget.log(m,"info")))
        self.worker.finished.connect(self._on_analysis_done)
        self.worker.error.connect(self._on_analysis_error)
        self.worker.start()

    def _on_analysis_done(self, result: dict):
        self.analysis_result = result
        self.progress_bar.setVisible(False)
        self.status_label.setText("Analysis complete")
        self.log_widget.log("Analysis complete", "success")
        self._populate_all(result)
        self.btn_analyze_p1.setEnabled(True)
        self._set_ai_buttons_enabled(True)
        self.btn_gen_cfg.setEnabled(True)

    def _on_analysis_error(self, error: str):
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Error: {error[:80]}")
        self.log_widget.log(f"Error: {error[:120]}", "error")
        self.btn_analyze_p1.setEnabled(True)
        self._set_ai_buttons_enabled(False)

    def _populate_all(self, result: dict):
        decompile = result.get("decompile", {})
        behavior  = result.get("behavior",  {})
        yara      = result.get("yara",      {})
        universal = result.get("universal", {})

        # Page 1 file info
        self.lbl_p1_type.setText(universal.get("file_type", decompile.get("python_version","—")))
        self.lbl_p1_arch.setText(universal.get("architecture","Native") or "—")
        ent = universal.get("entropy") or decompile.get("entropy",{})
        if isinstance(ent, float): self.lbl_p1_entropy.setText(f"{ent:.4f} / 8.0")
        self.lbl_p1_sha256.setText(universal.get("sha256","—")[:32] + "..." if universal.get("sha256") else "—")

        # Overview cards
        score = behavior.get("threat_score", 0)
        self.card_score._val_lbl.setText(str(score))
        self.card_conf._val_lbl.setText(f"{behavior.get('confidence_score',0)}%")
        self.card_indic._val_lbl.setText(str(len(behavior.get("indicators",[]))))
        total_iocs = sum(len(v) for v in behavior.get("iocs",{}).values())
        self.card_iocs._val_lbl.setText(str(total_iocs))
        self.card_obf._val_lbl.setText(str(len(behavior.get("obfuscation_detected",[]))))
        families = behavior.get("malware_families",[])
        self.card_families._val_lbl.setText(families[0] if families else "None")
        self.threat_score_widget.set_score(score)
        self.txt_summary.setPlainText(behavior.get("summary","No summary."))

        # Code objects tree
        self.tree_code_objects.clear()
        for co in result.get("code_objects",[]):
            item = QTreeWidgetItem([co.get("name","?"), co.get("filename",""), str(co.get("argcount",0)), str(co.get("firstlineno",0))])
            if co.get("depth",0) > 0: item.setForeground(0, QColor("#88ddff"))
            self.tree_code_objects.addTopLevelItem(item)

        # Source
        src = decompile.get("source_code","")
        self.txt_source.setPlainText(src or "# Decompilation failed or returned empty.")
        self.lbl_backend.setText(f"Backend: {decompile.get('backend_used','—')}")
        self.lbl_pyver_src.setText(f"Python {decompile.get('python_version','—')}")

        # Threats
        indicators = behavior.get("indicators",[])
        self.lbl_threat_count.setText(f"{len(indicators)} indicators detected")
        self.indicator_list.populate(indicators)
        obf = behavior.get("obfuscation_detected",[])
        self.txt_obfuscation.setPlainText("\n".join(f"  [!] {o}" for o in obf) if obf else "  None detected.")

        # IOCs
        self.ioc_table.populate(behavior.get("iocs",{}))

        # Opcodes
        opcodes = result.get("opcodes",[])
        self.lbl_opcount.setText(f"{len(opcodes)} instructions")
        self.tbl_opcodes.setRowCount(0)
        SUSPICIOUS = {"IMPORT_NAME","CALL_FUNCTION","CALL","MAKE_FUNCTION","LOAD_GLOBAL"}
        for i, op in enumerate(opcodes[:2000]):
            self.tbl_opcodes.insertRow(i)
            cells = [str(op.get("offset","")), str(op.get("opcode","")), op.get("opname",""), str(op.get("arg","")), op.get("argrepr","")]
            for col, val in enumerate(cells):
                item = QTableWidgetItem(val)
                item.setFont(QFont("Courier New",9))
                if col == 2 and op.get("opname") in SUSPICIOUS: item.setForeground(QColor("#ffaa00"))
                self.tbl_opcodes.setItem(i, col, item)

        # YARA
        matches = yara.get("matches",[])
        self.lbl_yara_count.setText(f"{len(matches)} rule matches")
        self.tbl_yara.setRowCount(0)
        SEV_C = {"CRITICAL":"#ff1a4a","HIGH":"#ff6600","MEDIUM":"#ffcc00","LOW":"#00ff88"}
        for i, m in enumerate(matches):
            self.tbl_yara.insertRow(i)
            sev = m.get("severity","MEDIUM")
            cells = [m.get("rule_name",""), sev, m.get("meta",{}).get("description",""), m.get("meta",{}).get("mitre","")]
            for col, val in enumerate(cells):
                item = QTableWidgetItem(val)
                item.setFont(QFont("Courier New",9))
                if col == 1: item.setForeground(QColor(SEV_C.get(sev,"#fff")))
                self.tbl_yara.setItem(i, col, item)

        # Strings
        strings = list(set(decompile.get("strings",[]) + universal.get("strings",[])))
        self._all_strings = strings
        self.txt_strings.setPlainText("\n".join(strings))
        self.lbl_strings_count.setText(f"{len(strings)} strings")

        # Universal tab
        self._populate_universal_tab(universal)

        # Report
        self._gen_report(result)

    def _populate_universal_tab(self, u: dict):
        self.universal_tabs.clear()
        ft = u.get("file_type","—")
        self.lbl_universal_type.setText(f"{ft}  |  {u.get('backend_used','—')}")
        for tab_name, tab_content in u.get("tabs",{}).items():
            tw = QWidget()
            tl = QVBoxLayout(tw)
            tl.setContentsMargins(4,4,4,4)
            te = QTextEdit()
            te.setReadOnly(True)
            te.setFont(QFont("Courier New",9))
            te.setStyleSheet("background:#060e1c; color:#c8d8e8; border:none;")
            te.setPlainText(str(tab_content) if tab_content else "(empty)")
            tl.addWidget(te)
            self.universal_tabs.addTab(tw, tab_name)
        if u.get("warnings"):
            ww = QWidget(); wl = QVBoxLayout(ww); wl.setContentsMargins(4,4,4,4)
            we = QTextEdit(); we.setReadOnly(True); we.setFont(QFont("Courier New",9))
            we.setStyleSheet("background:#1a0808; color:#ff8844; border:none;")
            we.setPlainText("\n".join(f"[!] {w}" for w in u["warnings"]))
            wl.addWidget(we); self.universal_tabs.addTab(ww,"[!] Warnings")

    def _gen_report(self, result: dict):
        b = result.get("behavior",{}); d = result.get("decompile",{})
        deps = result.get("dependency_health", {})
        missing_optional = deps.get("missing_optional", []) if isinstance(deps, dict) else []
        lines = [
            "MalScope v2.1 - Forensic Analysis Report", "="*50,
            f"File       : {self.current_file}",
            f"Type       : {result.get('universal',{}).get('file_type', d.get('python_version','-'))}",
            f"Backend    : {d.get('backend_used','-')}",
            f"Threat     : {b.get('threat_score',0)}/100  (Confidence: {b.get('confidence_score',0)}%)",
            f"YARA       : {len(result.get('yara',{}).get('matches', []))} matches",
            f"Optional   : {len(missing_optional)} missing engines/tools",
            "", "Summary:", b.get("summary",""), "",
            f"Indicators ({len(b.get('indicators',[]))}):",
        ]
        for ind in b.get("indicators",[])[:20]:
            lines.append(f"  [{ind.get('severity','?')}] {ind.get('description','')}")
        lines += ["","Obfuscation:"] + [f"  [!] {o}" for o in b.get("obfuscation_detected",[])]
        lines += ["","IOCs:"]
        for k,vals in b.get("iocs",{}).items():
            lines.append(f"  {k}: {', '.join(str(v) for v in vals[:3])}")
        self.txt_report.setPlainText("\n".join(lines))

    # ─────────────────────────────────────────────────────────────────────────
    # AI
    # ─────────────────────────────────────────────────────────────────────────
    def run_ai_analysis(self):
        self._start_ai("analyze")

    def run_ai_deobfuscate(self):
        self._start_ai("deobfuscate")

    def run_ai_yara(self):
        self._start_ai("yara")

    def _set_ai_buttons_enabled(self, enabled: bool):
        self.btn_ai_full.setEnabled(enabled)
        self.btn_ai_deobf.setEnabled(enabled)
        self.btn_ai_yara.setEnabled(enabled)

    def _start_ai(self, mode: str):
        if not self.analysis_result: return
        if hasattr(self, "ai_worker") and self.ai_worker.isRunning():
            self.log_widget.log("AI analysis already running; please wait.", "warning")
            return
        self._switch_page(2)
        key = self.txt_api_key_p1.text().strip() or self.api_key
        if not key and "Ollama" not in self.selected_provider:
            self.txt_ai_output.setPlainText("[!] Please enter your API key on Page 1 (File & Setup).")
            return
        self.txt_ai_output.setPlainText(f"[*] Running AI analysis ({mode})...\n\nPlease wait...")
        self.ai_progress.setVisible(True)
        self.ai_progress.setRange(0,0)
        self._set_ai_buttons_enabled(False)
        src = self.analysis_result.get("decompile",{}).get("source_code","")
        beh = self.analysis_result.get("behavior",{})
        self.ai_worker = AIWorker(src, beh, key, mode, self.selected_provider, self.selected_ollama_model)
        self.ai_worker.finished.connect(self._on_ai_done)
        self.ai_worker.error.connect(self._on_ai_error)
        self.ai_worker.start()

    def _on_ai_done(self, result: str):
        self.txt_ai_output.setPlainText(result)
        self.ai_progress.setVisible(False)
        self._set_ai_buttons_enabled(bool(self.analysis_result))
        self.log_widget.log("AI analysis complete", "success")

    def _on_ai_error(self, error: str):
        self.txt_ai_output.setPlainText(f"[!] AI Error:\n\n{error}")
        self.ai_progress.setVisible(False)
        self._set_ai_buttons_enabled(bool(self.analysis_result))
        self.log_widget.log(f"AI error: {error[:80]}", "error")

    # ─────────────────────────────────────────────────────────────────────────
    # CFG
    # ─────────────────────────────────────────────────────────────────────────
    def generate_cfg(self):
        if not self.analysis_result: return
        dot = self.analysis_result.get("cfg_dot","")
        if dot:
            self.cfg_widget.render_dot(dot)
            s = self.analysis_result.get("cfg_stats",{})
            self.cfg_stats_lbl.setText(f"Blocks: {s.get('total_blocks','?')}  |  Edges: {s.get('total_edges','?')}  |  Cyclomatic Complexity: {s.get('cyclomatic_complexity','?')}")
            self.btn_export_cfg.setEnabled(True)
        else:
            self.cfg_stats_lbl.setText("CFG not available — requires .pyc input with valid bytecode.")

    def export_cfg(self):
        path, _ = QFileDialog.getSaveFileName(self,"Export CFG","cfg.png","PNG (*.png);;PDF (*.pdf)")
        if path:
            self.cfg_widget.export(path,"pdf" if path.endswith(".pdf") else "png")

    # ─────────────────────────────────────────────────────────────────────────
    # Strings filter
    # ─────────────────────────────────────────────────────────────────────────
    def _filter_strings(self, text: str):
        if not text:
            self.txt_strings.setPlainText("\n".join(self._all_strings))
            self.lbl_strings_count.setText(f"{len(self._all_strings)} strings")
        else:
            filtered = [s for s in self._all_strings if text.lower() in s.lower()]
            self.txt_strings.setPlainText("\n".join(filtered))
            self.lbl_strings_count.setText(f"{len(filtered)} / {len(self._all_strings)} strings")

    # ─────────────────────────────────────────────────────────────────────────
    # Export
    # ─────────────────────────────────────────────────────────────────────────
    def export_report(self, fmt: str = "html"):
        if not self.analysis_result: return
        ext = "zip" if fmt == "bundle" else ("md" if fmt == "markdown" else fmt)
        path, _ = QFileDialog.getSaveFileName(self,"Export Report",f"malscope_report.{ext}",f"{fmt.upper()} (*.{ext})")
        if path:
            from utils.reporter import generate_report
            generate_report(self.analysis_result, path, fmt)
            self.log_widget.log(f"Report exported: {path}", "success")

    def export_iocs(self):
        if not self.analysis_result: return
        path, _ = QFileDialog.getSaveFileName(self,"Export IOCs","iocs.json","JSON (*.json)")
        if path:
            iocs = self.analysis_result.get("behavior",{}).get("iocs",{})
            with open(path,"w") as f: json.dump(iocs, f, indent=2)

    # ─────────────────────────────────────────────────────────────────────────
    # Settings
    # ─────────────────────────────────────────────────────────────────────────
    def _save_ai_settings(self):
        self.api_key = self.txt_api_key_p1.text().strip()
        self.selected_provider = self.provider_selector.currentText()
        self.selected_ollama_model = self.ollama_model_input.currentText()
        if self.api_key:
            self.lbl_ai_status.setText(f"[OK] Key set  |  Provider: {self.selected_provider}")
            self.lbl_ai_status.setStyleSheet("color:#00ff88; font-size:9px;")
        else:
            self.lbl_ai_status.setText(f"[OK] Ollama selected (model: {self.selected_ollama_model})" if "Ollama" in self.selected_provider else "[--] No key set")
            self.lbl_ai_status.setStyleSheet("color:#ffaa00; font-size:9px;")
        self.log_widget.log(f"AI settings saved: {self.selected_provider}", "success")

    def _on_provider_changed(self, text: str):
        self.selected_provider = text

    def _show_about(self):
        QMessageBox.about(self, "About MalScope",
            "<h3>MalScope v2.1</h3>"
            "<p>Universal Malware Analysis Framework</p>"
            "<p>Supports: .pyc .exe .dll .elf .apk .jar .js .ps1 .pdf .docx .zip and more</p>"
            "<p>Built with PyQt6 + Claude AI</p>")

    # Compatibility stubs
    def _update_api_status(self): pass
    def _on_ollama_model_changed(self, m): self.selected_ollama_model = m
    @property
    def zip_pass_frame(self): return None
    @zip_pass_frame.setter
    def zip_pass_frame(self, v): pass
    @property
    def lbl_filename(self): return self.lbl_p1_name
    @property
    def lbl_filesize(self): return self.lbl_p1_size
    @property
    def lbl_md5(self): return self.lbl_p1_md5
    @property
    def lbl_pyver(self): return self.lbl_p1_type
    @property
    def lbl_api_status(self): return self.lbl_ai_status
    @lbl_api_status.setter
    def lbl_api_status(self, v): self.lbl_ai_status = v
