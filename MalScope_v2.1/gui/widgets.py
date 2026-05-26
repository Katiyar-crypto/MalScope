"""
MalScope - 3D Holographic Custom Widgets
"""

import math
import datetime
from typing import List, Dict, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView,
    QScrollArea, QSizePolicy, QApplication
)
from PyQt6.QtCore import (
    Qt, pyqtSignal, QSize, QTimer, QPropertyAnimation,
    QEasingCurve, QRect, QPoint, QRectF
)
from PyQt6.QtGui import (
    QColor, QFont, QPainter, QPen, QBrush, QDragEnterEvent,
    QDropEvent, QPainterPath, QLinearGradient, QRadialGradient,
    QConicalGradient, QPalette, QPolygonF
)
from PyQt6.QtCore import QPointF


# ─────────────────────────────────────────────────────────────────────────────
# File Drop Zone
# ─────────────────────────────────────────────────────────────────────────────

class FileDropZone(QFrame):
    file_dropped = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("dropZone")
        self.setAcceptDrops(True)
        self._hover = False
        self._pulse = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._animate)
        self._timer.start(50)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(24, 0, 24, 0)

        self._icon = QLabel("[*]")
        self._icon.setFont(QFont("Courier New", 20))
        self._icon.setStyleSheet("color: #0d3050; background: transparent;")
        layout.addWidget(self._icon)

        col = QVBoxLayout()
        col.setSpacing(2)
        self._main_lbl = QLabel("DROP ANY FILE TO ANALYZE")
        self._main_lbl.setStyleSheet(
            "color: #1a5a78; font-size: 10px; letter-spacing: 5px; "
            "font-weight: bold; background: transparent;"
        )
        self._sub_lbl = QLabel(
            ".pyc  .exe  .dll  .elf  .apk  .jar  .js  .ps1  .pdf  .docx  .zip  ···"
        )
        self._sub_lbl.setStyleSheet(
            "color: #0d2a40; font-size: 8px; letter-spacing: 2px; background: transparent;"
        )
        col.addWidget(self._main_lbl)
        col.addWidget(self._sub_lbl)
        layout.addLayout(col)
        layout.addStretch()

        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet(
            "color: #00cfff; font-size: 9px; letter-spacing: 1px; background: transparent;"
        )
        layout.addWidget(self._status_lbl)

    def _animate(self):
        self._pulse = (self._pulse + 0.05) % (2 * math.pi)
        if self._hover:
            self.update()

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._hover = True
            self._main_lbl.setStyleSheet(
                "color: #00cfff; font-size: 11px; letter-spacing: 3px; "
                "font-weight: bold; background: transparent;"
            )
            self._icon.setStyleSheet("color: #00cfff; background: transparent;")
            self.update()

    def dragLeaveEvent(self, event):
        self._hover = False
        self._main_lbl.setStyleSheet(
            "color: #1a5a78; font-size: 10px; letter-spacing: 5px; "
            "font-weight: bold; background: transparent;"
        )
        self._icon.setStyleSheet("color: #0d3050; background: transparent;")
        self.update()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            import os
            path = urls[0].toLocalFile()
            fname = os.path.basename(path)
            self._status_lbl.setText(f"⬡  {fname}")
            self._hover = False
            self.update()
            self.file_dropped.emit(path)

    def paintEvent(self, event):
        super().paintEvent(event)
        if not self._hover:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        glow = abs(math.sin(self._pulse))
        c = QColor(0, 212, 255, int(30 * glow))
        pen = QPen(QColor(0, 212, 255, int(180 * glow)), 1)
        painter.setPen(pen)
        painter.setBrush(QBrush(c))
        r = self.rect().adjusted(3, 3, -3, -3)
        painter.drawRoundedRect(r, 4, 4)
        painter.end()


# ─────────────────────────────────────────────────────────────────────────────
# 3D Threat Score Gauge
# ─────────────────────────────────────────────────────────────────────────────

class ThreatScoreWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.score = 0
        self._anim_score = 0.0
        self._rotation = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(30)
        self.setMinimumHeight(140)
        self.setMaximumHeight(150)

    def set_score(self, score: int):
        self.score = max(0, min(100, score))

    def _tick(self):
        # Animate score counter
        if self._anim_score < self.score:
            self._anim_score = min(self._anim_score + 2.0, self.score)
        elif self._anim_score > self.score:
            self._anim_score = max(self._anim_score - 2.0, self.score)
        self._rotation = (self._rotation + 0.8) % 360
        self.update()

    def _color(self) -> QColor:
        s = self._anim_score
        if s < 30:   return QColor(0, 255, 150)
        if s < 60:   return QColor(255, 180, 0)
        if s < 80:   return QColor(255, 80, 20)
        return QColor(255, 20, 60)

    def _label(self) -> str:
        s = self._anim_score
        if s == 0:   return "CLEAN"
        if s < 30:   return "LOW"
        if s < 60:   return "MEDIUM"
        if s < 80:   return "HIGH"
        return "CRITICAL"

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        cx, cy = w // 2, h // 2 + 4
        R = min(w, h) // 2 - 16

        # ── Outer rotating dashes (3D orbit ring) ─────────────────────
        dash_count = 24
        for i in range(dash_count):
            angle = math.radians(self._rotation + i * (360 / dash_count))
            r_inner = R + 6
            r_outer = R + 10 + (4 if i % 3 == 0 else 0)
            x1 = cx + r_inner * math.cos(angle)
            y1 = cy + r_inner * math.sin(angle)
            x2 = cx + r_outer * math.cos(angle)
            y2 = cy + r_outer * math.sin(angle)
            alpha = 60 + int(80 * abs(math.sin(angle)))
            c = self._color()
            c.setAlpha(alpha)
            painter.setPen(QPen(c, 1.5))
            painter.drawLine(int(x1), int(y1), int(x2), int(y2))

        # ── Background arc ─────────────────────────────────────────────
        bg_pen = QPen(QColor(13, 48, 80), 8)
        bg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(bg_pen)
        painter.drawArc(cx-R, cy-R, R*2, R*2, 225*16, -270*16)

        # ── Score arc with glow ────────────────────────────────────────
        if self._anim_score > 0:
            span = int(-270 * 16 * self._anim_score / 100)
            color = self._color()

            # Glow layer
            glow_pen = QPen(QColor(color.red(), color.green(), color.blue(), 40), 16)
            glow_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(glow_pen)
            painter.drawArc(cx-R, cy-R, R*2, R*2, 225*16, span)

            # Main arc
            main_pen = QPen(color, 8)
            main_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(main_pen)
            painter.drawArc(cx-R, cy-R, R*2, R*2, 225*16, span)

        # ── Score number ───────────────────────────────────────────────
        color = self._color()
        painter.setPen(QPen(color))
        painter.setFont(QFont("Courier New", 20, QFont.Weight.Bold))
        score_str = str(int(self._anim_score))
        fm = painter.fontMetrics()
        tw = fm.horizontalAdvance(score_str)
        painter.drawText(cx - tw//2, cy + 8, score_str)

        # ── Label ──────────────────────────────────────────────────────
        painter.setPen(QPen(QColor(26, 90, 120)))
        painter.setFont(QFont("Courier New", 7))
        label = self._label()
        lw = painter.fontMetrics().horizontalAdvance(label)
        painter.drawText(cx - lw//2, cy + 24, label)

        # ── Title ──────────────────────────────────────────────────────
        painter.setFont(QFont("Courier New", 7))
        title = "THREAT SCORE"
        tw2 = painter.fontMetrics().horizontalAdvance(title)
        painter.drawText(cx - tw2//2, cy - R - 6, title)

        painter.end()


# ─────────────────────────────────────────────────────────────────────────────
# IOC Table
# ─────────────────────────────────────────────────────────────────────────────

class IOCTableWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["TYPE", "VALUE", "CNT"])
        self.table.setObjectName("dataTable")
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setShowGrid(False)
        layout.addWidget(self.table)

    TYPE_ICONS = {
        "ip_addresses": "◉ IP",
        "domains": "◈ DOM",
        "urls": "◆ URL",
        "emails": "◇ MAIL",
        "file_paths": "▸ PATH",
        "registry_keys": "▪ REG",
        "base64_strings": "◐ B64",
        "hashes": "# HASH",
    }
    TYPE_COLORS = {
        "ip_addresses": "#ff4444",
        "domains": "#ff8800",
        "urls": "#ffcc00",
        "emails": "#44ff88",
        "file_paths": "#44ccff",
        "registry_keys": "#ff44cc",
        "base64_strings": "#cc88ff",
        "hashes": "#88ddff",
    }

    def populate(self, iocs: Dict):
        self.table.setRowCount(0)
        row = 0
        for ioc_type, values in iocs.items():
            for val in values:
                self.table.insertRow(row)
                label = self.TYPE_ICONS.get(ioc_type, f"• {ioc_type}")
                color = QColor(self.TYPE_COLORS.get(ioc_type, "#4db8d4"))

                type_item = QTableWidgetItem(label)
                type_item.setForeground(color)
                type_item.setFont(QFont("Courier New", 9, QFont.Weight.Bold))

                val_item = QTableWidgetItem(str(val))
                val_item.setFont(QFont("Courier New", 9))
                val_item.setForeground(QColor("#4db8d4"))

                cnt_item = QTableWidgetItem("1")
                cnt_item.setFont(QFont("Courier New", 9))
                cnt_item.setForeground(QColor("#1a5a78"))

                self.table.setItem(row, 0, type_item)
                self.table.setItem(row, 1, val_item)
                self.table.setItem(row, 2, cnt_item)
                row += 1


# ─────────────────────────────────────────────────────────────────────────────
# Indicator List (Threats tab)
# ─────────────────────────────────────────────────────────────────────────────

class IndicatorListWidget(QWidget):
    SEV_COLORS = {
        "CRITICAL": "#ff1a4a",
        "HIGH":     "#ff6600",
        "MEDIUM":   "#ffcc00",
        "LOW":      "#00ff88",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["SEV", "CATEGORY", "DESCRIPTION", "MITRE"])
        self.table.setObjectName("dataTable")
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setShowGrid(False)
        layout.addWidget(self.table)

    def populate(self, indicators: List[Dict]):
        self.table.setRowCount(0)
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_ind = sorted(indicators, key=lambda x: order.get(x.get("severity", "LOW"), 4))

        for i, ind in enumerate(sorted_ind):
            self.table.insertRow(i)
            sev = ind.get("severity", "LOW")
            color = QColor(self.SEV_COLORS.get(sev, "#4db8d4"))

            sev_item = QTableWidgetItem(f"▮ {sev}")
            sev_item.setForeground(color)
            sev_item.setFont(QFont("Courier New", 8, QFont.Weight.Bold))

            cat_item = QTableWidgetItem(ind.get("category", ""))
            cat_item.setFont(QFont("Courier New", 9))
            cat_item.setForeground(QColor("#4db8d4"))

            desc_item = QTableWidgetItem(ind.get("description", ""))
            desc_item.setFont(QFont("Courier New", 9))
            desc_item.setForeground(QColor("#2d7a9a"))

            mitre_item = QTableWidgetItem(ind.get("mitre_id", ""))
            mitre_item.setFont(QFont("Courier New", 8))
            mitre_item.setForeground(QColor("#1a5a78"))

            self.table.setItem(i, 0, sev_item)
            self.table.setItem(i, 1, cat_item)
            self.table.setItem(i, 2, desc_item)
            self.table.setItem(i, 3, mitre_item)


# ─────────────────────────────────────────────────────────────────────────────
# Animated Log Widget
# ─────────────────────────────────────────────────────────────────────────────

class LogWidget(QWidget):
    LOG_COLORS = {
        "info":    "#5a9fc0",
        "success": "#00ff88",
        "warning": "#ffaa00",
        "error":   "#ff3366",
    }
    LOG_PREFIX = {
        "info":    ">",
        "success": "OK",
        "warning": "!!",
        "error":   "XX",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QWidget()
        header.setFixedHeight(18)
        header.setStyleSheet("background: #060c16; border-top: 1px solid #112233;")
        hlayout = QHBoxLayout(header)
        hlayout.setContentsMargins(10, 0, 10, 0)
        lbl = QLabel("SYSTEM LOG")
        lbl.setStyleSheet("color: #2a5a7a; font-size: 8px; letter-spacing: 3px; background: transparent;")
        hlayout.addWidget(lbl)
        hlayout.addStretch()
        layout.addWidget(header)

        self.txt = QTextEdit()
        self.txt.setReadOnly(True)
        self.txt.setObjectName("logOutput")
        self.txt.setFont(QFont("Courier New", 9))
        layout.addWidget(self.txt)

    def log(self, msg: str, level: str = "info"):
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:11]
        color = self.LOG_COLORS.get(level, "#1a5a78")
        prefix = self.LOG_PREFIX.get(level, ">")
        html = (
            f'<span style="color:#0d2a3a;font-family:Courier New">[{ts}]</span>'
            f'<span style="color:{color};font-family:Courier New"> {prefix} {msg}</span>'
        )
        self.txt.append(html)
        self.txt.verticalScrollBar().setValue(self.txt.verticalScrollBar().maximum())


# ─────────────────────────────────────────────────────────────────────────────
# CFG Widget
# ─────────────────────────────────────────────────────────────────────────────

class CFGWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._dot_source = ""
        self._image_path = ""

        self.img_label = QLabel()
        self.img_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.img_label.setStyleSheet(
            "background: #08111e; color: #4a8aaa; font-family: 'Courier New'; "
            "font-size: 9px; letter-spacing: 2px;"
        )
        self.img_label.setText("[ Generate CFG to visualize Control Flow Graph ]")

        scroll = QScrollArea()
        scroll.setWidget(self.img_label)
        scroll.setWidgetResizable(True)
        scroll.setObjectName("scrollArea")
        layout.addWidget(scroll)

        self.txt_dot = QTextEdit()
        self.txt_dot.setReadOnly(True)
        self.txt_dot.setFont(QFont("Courier New", 8))
        self.txt_dot.setObjectName("codeEditor")
        self.txt_dot.setMaximumHeight(120)
        self.txt_dot.setPlaceholderText("// DOT source will appear here...")
        layout.addWidget(self.txt_dot)

    def render_dot(self, dot_source: str):
        self._dot_source = dot_source
        self.txt_dot.setPlainText(dot_source)
        try:
            import graphviz, tempfile, os
            from PyQt6.QtGui import QPixmap
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
                tmp = f.name
            g = graphviz.Source(dot_source)
            g.render(tmp.replace(".png", ""), format="png", cleanup=True)
            if os.path.exists(tmp):
                pix = QPixmap(tmp)
                if not pix.isNull():
                    scaled = pix.scaledToWidth(
                        min(pix.width(), 900),
                        Qt.TransformationMode.SmoothTransformation
                    )
                    self.img_label.setPixmap(scaled)
                    self._image_path = tmp
                    return
        except Exception:
            pass
        self.img_label.setText(
            "GRAPHVIZ NOT INSTALLED — DOT SOURCE SHOWN BELOW\n"
            "Paste at graphviz.online to visualize"
        )

    def export(self, path: str, fmt: str = "png") -> bool:
        if not self._dot_source:
            return False
        try:
            import graphviz
            g = graphviz.Source(self._dot_source)
            g.render(path.replace(f".{fmt}", ""), format=fmt, cleanup=True)
            return True
        except Exception:
            return False
