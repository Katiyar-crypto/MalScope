"""
MalScope - Dark Cyberpunk Theme (High Contrast, Readable)
"""

DARK_STYLESHEET = """
/* ═══════════════════════════════════════════════
   GLOBAL
═══════════════════════════════════════════════ */
* {
    font-family: 'Courier New', 'Consolas', monospace;
}

QMainWindow, QWidget {
    background-color: #0b0f1a;
    color: #c8d8e8;
}

/* ═══════════════════════════════════════════════
   SIDEBAR
═══════════════════════════════════════════════ */
QFrame#sidebar {
    background-color: #0d1320;
    border-right: 2px solid #1a3a5c;
}

QLabel#logo {
    color: #00cfff;
    font-size: 20px;
    font-weight: bold;
    letter-spacing: 5px;
    padding: 14px 8px 4px 8px;
    border-bottom: 1px solid #1a3a5c;
}

QLabel#subtitle {
    color: #3a7a9c;
    font-size: 8px;
    letter-spacing: 3px;
    padding: 3px 8px 8px 8px;
}

QLabel#fileLabel {
    color: #00cfff;
    font-size: 10px;
    font-weight: bold;
}

QLabel#metaLabel {
    color: #6aafcf;
    font-size: 9px;
}

QLabel#apiStatus {
    font-size: 9px;
    padding: 6px 8px;
    border-top: 1px solid #1a3a5c;
    color: #c8d8e8;
}

QLabel#tabTitle {
    color: #00cfff;
    font-size: 12px;
    letter-spacing: 3px;
    font-weight: bold;
}

QLabel#cardTitle {
    color: #5a9fc0;
    font-size: 8px;
    letter-spacing: 3px;
}

QLabel#versionLabel {
    color: #2a4a6a;
    font-size: 8px;
    padding-right: 8px;
}

/* ═══════════════════════════════════════════════
   GROUP BOXES
═══════════════════════════════════════════════ */
QGroupBox {
    color: #5a9fc0;
    border: 1px solid #1a3a5c;
    border-radius: 4px;
    margin-top: 10px;
    padding-top: 10px;
    font-size: 8px;
    letter-spacing: 3px;
    background: rgba(0, 20, 40, 0.3);
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 6px;
    left: 10px;
    color: #5a9fc0;
    background: #0d1320;
}
QGroupBox#sideGroup {
    margin: 3px 0;
    padding: 6px 4px 4px 4px;
}

/* ═══════════════════════════════════════════════
   BUTTONS — fully visible text
═══════════════════════════════════════════════ */
QPushButton {
    background-color: #112233;
    color: #c8d8e8;
    border: 1px solid #1e4a6e;
    border-radius: 3px;
    padding: 7px 14px;
    font-size: 10px;
    font-family: 'Courier New', monospace;
    letter-spacing: 1px;
    font-weight: bold;
    text-align: left;
}
QPushButton:hover {
    background-color: #1a3a5c;
    color: #00cfff;
    border: 1px solid #00cfff;
}
QPushButton:pressed {
    background-color: #0a1a2c;
    color: #00ffcc;
}
QPushButton:disabled {
    color: #2a4a5a;
    border-color: #112233;
    background-color: #0b0f1a;
}

QPushButton#sideButton {
    background-color: #112233;
    color: #c8d8e8;
    border: 1px solid #1e4a6e;
    border-radius: 3px;
    padding: 9px 12px;
    margin: 2px 0;
    font-size: 10px;
    text-align: left;
    font-weight: bold;
}
QPushButton#sideButton:hover {
    background-color: #1a3a5c;
    color: #00cfff;
    border-color: #00cfff;
}
QPushButton#sideButton:disabled {
    color: #2a4a5a;
    border-color: #112233;
    background-color: #0d1320;
}

QPushButton#sideButtonPrimary {
    background-color: #0a3a5c;
    color: #00cfff;
    border: 1px solid #00cfff;
    border-radius: 3px;
    padding: 10px 12px;
    margin: 2px 0;
    font-size: 10px;
    text-align: left;
    font-weight: bold;
}
QPushButton#sideButtonPrimary:hover {
    background-color: #0d4a70;
    color: #ffffff;
    border-color: #00ffff;
}
QPushButton#sideButtonPrimary:disabled {
    color: #2a5a7a;
    border-color: #1a3a5c;
    background-color: #061525;
}

QPushButton#miniButton {
    padding: 5px 12px;
    font-size: 9px;
    text-align: center;
}

QPushButton#aiButton {
    background-color: #1a0a3a;
    color: #dd88ff;
    border: 1px solid #8844cc;
    padding: 7px 16px;
    font-weight: bold;
    text-align: center;
}
QPushButton#aiButton:hover {
    background-color: #260a50;
    color: #ff99ff;
    border-color: #bb66ff;
}
QPushButton#aiButton:disabled {
    color: #4a2a6a;
    border-color: #2a1a4a;
}

/* ═══════════════════════════════════════════════
   TABS
═══════════════════════════════════════════════ */
QTabWidget::pane {
    border: none;
    border-top: 2px solid #1a3a5c;
    background: #0b0f1a;
}
QTabBar::tab {
    background: #0d1320;
    color: #4a8aaa;
    padding: 8px 14px;
    border: none;
    border-right: 1px solid #112233;
    border-bottom: 2px solid transparent;
    font-size: 9px;
    letter-spacing: 1px;
    min-width: 50px;
}
QTabBar::tab:selected {
    color: #00cfff;
    border-bottom: 2px solid #00cfff;
    background: #0f1828;
}
QTabBar::tab:hover:!selected {
    color: #88ccee;
    background: #0f1828;
}

QTabWidget#universalSubTabs::pane {
    border: 1px solid #1a3a5c;
    background: #0b0f1a;
}
QTabWidget#universalSubTabs QTabBar::tab {
    background: #0d1320;
    color: #4a8aaa;
    padding: 5px 10px;
    font-size: 8px;
    border-right: 1px solid #112233;
    border-bottom: 2px solid transparent;
}
QTabWidget#universalSubTabs QTabBar::tab:selected {
    color: #00ffcc;
    border-bottom: 2px solid #00ffcc;
}

/* ═══════════════════════════════════════════════
   TEXT EDITORS — bright text on dark bg
═══════════════════════════════════════════════ */
QTextEdit {
    background-color: #08111e;
    color: #c8d8e8;
    border: 1px solid #1a3a5c;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    font-size: 10px;
    line-height: 1.6;
    selection-background-color: #1a4a7c;
    selection-color: #ffffff;
}
QTextEdit#codeEditor {
    background-color: #060e1c;
    color: #b8e0f8;
    border: 1px solid #1a3a5c;
}
QTextEdit#aiOutput {
    background-color: #0c0820;
    color: #ddaaff;
    border: 1px solid #3a1a7c;
}
QTextEdit#summaryText {
    background-color: #08111e;
    color: #c8d8e8;
    border: 1px solid #1a3a5c;
}
QTextEdit#logOutput {
    background-color: #060c16;
    color: #4a8aaa;
    border: none;
    border-top: 1px solid #112233;
    font-size: 9px;
}

/* ═══════════════════════════════════════════════
   TABLES
═══════════════════════════════════════════════ */
QTableWidget, QTableWidget#dataTable {
    background-color: #08111e;
    color: #c8d8e8;
    gridline-color: #112233;
    border: 1px solid #1a3a5c;
    alternate-background-color: #0a1525;
    selection-background-color: #1a3a5c;
    selection-color: #00cfff;
    font-size: 9px;
    font-family: 'Courier New', monospace;
}
QTableWidget::item {
    padding: 4px 8px;
    border-bottom: 1px solid #0e1e30;
    color: #c8d8e8;
}
QTableWidget::item:selected {
    background: #1a3a5c;
    color: #00cfff;
}
QHeaderView::section {
    background-color: #0d1a28;
    color: #5a9fc0;
    border: none;
    border-right: 1px solid #112233;
    border-bottom: 1px solid #1a3a5c;
    padding: 6px 10px;
    font-size: 8px;
    letter-spacing: 2px;
    font-family: 'Courier New', monospace;
    font-weight: bold;
}

/* ═══════════════════════════════════════════════
   TREE
═══════════════════════════════════════════════ */
QTreeWidget, QTreeWidget#codeTree {
    background-color: #08111e;
    color: #c8d8e8;
    border: 1px solid #1a3a5c;
    font-size: 9px;
    alternate-background-color: #0a1525;
    font-family: 'Courier New', monospace;
}
QTreeWidget::item:selected {
    background: #1a3a5c;
    color: #00cfff;
}

/* ═══════════════════════════════════════════════
   DASHBOARD CARDS
═══════════════════════════════════════════════ */
QFrame#dashCard {
    background-color: #0d1a28;
    border: 1px solid #1a3a5c;
    border-top: 2px solid #1e4a6e;
    border-radius: 4px;
    margin: 3px;
}

/* ═══════════════════════════════════════════════
   SCROLLBARS
═══════════════════════════════════════════════ */
QScrollBar:vertical {
    background: #08111e;
    width: 8px;
    border: none;
}
QScrollBar::handle:vertical {
    background: #1a3a5c;
    border-radius: 4px;
    min-height: 24px;
}
QScrollBar::handle:vertical:hover { background: #00cfff; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal {
    background: #08111e;
    height: 8px;
    border: none;
}
QScrollBar::handle:horizontal {
    background: #1a3a5c;
    border-radius: 4px;
}
QScrollBar::handle:horizontal:hover { background: #00cfff; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ═══════════════════════════════════════════════
   PROGRESS BARS
═══════════════════════════════════════════════ */
QProgressBar, QProgressBar#statusProgress, QProgressBar#aiProgress {
    background: #0d1a28;
    border: 1px solid #1a3a5c;
    border-radius: 3px;
    height: 5px;
    text-align: center;
    font-size: 7px;
    color: #5a9fc0;
}
QProgressBar::chunk,
QProgressBar#statusProgress::chunk,
QProgressBar#aiProgress::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #004a7c, stop:0.5 #00cfff, stop:1 #00ffcc);
    border-radius: 3px;
}

/* ═══════════════════════════════════════════════
   STATUS BAR
═══════════════════════════════════════════════ */
QStatusBar, QStatusBar#mainStatus {
    background: #060c16;
    border-top: 1px solid #112233;
    color: #5a9fc0;
    font-size: 9px;
    letter-spacing: 1px;
}

/* ═══════════════════════════════════════════════
   TOOLBAR
═══════════════════════════════════════════════ */
QToolBar, QToolBar#mainToolbar {
    background-color: #0d1320;
    border-bottom: 1px solid #1a3a5c;
    spacing: 3px;
    padding: 4px 10px;
}
QToolBar QToolButton {
    background: transparent;
    color: #7aafcf;
    border: none;
    padding: 5px 12px;
    border-radius: 3px;
    font-size: 10px;
    font-family: 'Courier New', monospace;
    font-weight: bold;
}
QToolBar QToolButton:hover {
    background: #112233;
    color: #00cfff;
    border: 1px solid #1a3a5c;
}

/* ═══════════════════════════════════════════════
   MENU BAR
═══════════════════════════════════════════════ */
QMenuBar {
    background: #0b0f1a;
    color: #7aafcf;
    border-bottom: 1px solid #1a3a5c;
    font-size: 10px;
    padding: 2px;
}
QMenuBar::item { padding: 5px 12px; background: transparent; }
QMenuBar::item:selected { background: #112233; color: #00cfff; }
QMenu {
    background: #0d1320;
    color: #c8d8e8;
    border: 1px solid #1a3a5c;
    font-size: 10px;
}
QMenu::item { padding: 6px 20px; }
QMenu::item:selected { background: #1a3a5c; color: #00cfff; }
QMenu::separator { height: 1px; background: #1a3a5c; margin: 2px 0; }

/* ═══════════════════════════════════════════════
   SPLITTER
═══════════════════════════════════════════════ */
QSplitter::handle { background: #1a3a5c; width: 1px; height: 1px; }

/* ═══════════════════════════════════════════════
   LINE EDIT
═══════════════════════════════════════════════ */
QLineEdit {
    background: #08111e;
    color: #c8d8e8;
    border: 1px solid #1a3a5c;
    border-radius: 3px;
    padding: 6px 10px;
    font-size: 10px;
    font-family: 'Courier New', monospace;
    selection-background-color: #1a4a7c;
}
QLineEdit:focus {
    border: 1px solid #00cfff;
    color: #ffffff;
    background: #060e1c;
}
QLineEdit#apiKeyInput {
    font-family: 'Courier New', monospace;
    letter-spacing: 1px;
}

/* ═══════════════════════════════════════════════
   COMBO BOX
═══════════════════════════════════════════════ */
QComboBox {
    background: #08111e;
    color: #c8d8e8;
    border: 1px solid #1a3a5c;
    border-radius: 3px;
    padding: 5px 10px;
    font-size: 10px;
    font-family: 'Courier New', monospace;
}
QComboBox:hover { border-color: #00cfff; }
QComboBox::drop-down { border: none; width: 20px; }
QComboBox::down-arrow { width: 10px; }
QComboBox QAbstractItemView {
    background: #0d1320;
    color: #c8d8e8;
    border: 1px solid #1a3a5c;
    selection-background-color: #1a3a5c;
    selection-color: #00cfff;
}

/* ═══════════════════════════════════════════════
   FRAMES
═══════════════════════════════════════════════ */
QFrame#panelFrame {
    background: #0a1828;
    border: 1px solid #1a3a5c;
    border-radius: 4px;
}
QFrame#dropZone {
    background-color: #0a1220;
    border: 1px dashed #1a3a5c;
    border-radius: 4px;
    margin: 6px;
}
QFrame#dropZone:hover {
    border-color: #00cfff;
    background-color: #0d1828;
}

/* ═══════════════════════════════════════════════
   SCROLL AREA
═══════════════════════════════════════════════ */
QScrollArea, QScrollArea#scrollArea { border: none; background: transparent; }
"""

SYNTAX_COLORS = {
    "keyword":  "#00cfff",
    "string":   "#00ffaa",
    "comment":  "#3a7a9c",
    "number":   "#ffcc44",
    "function": "#88ddff",
    "class":    "#ff99cc",
    "operator": "#80ccee",
    "builtin":  "#ffaa44",
}
