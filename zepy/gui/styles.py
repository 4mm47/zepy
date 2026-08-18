"""
Zepy - AI Vulnerability Detection Framework
Cyber Dark Neon Theme Stylesheet (QSS) for PyQt5 GUI
"""

CYBER_DARK_QSS = """
/* Global Application Style */
QWidget {
    background-color: #0B0F19;
    color: #F3F4F6;
    font-family: 'Segoe UI', 'SF Pro Display', Roboto, Helvetica, Arial, sans-serif;
    font-size: 13px;
}

/* Header & Banner */
#HeaderFrame {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #161B2E, stop:1 #0F172A);
    border-bottom: 2px solid #1E293B;
    padding: 12px 20px;
}

#ZepyBadge {
    background-color: #FF2A6D;
    color: #FFFFFF;
    font-weight: 900;
    font-size: 13px;
    padding: 4px 10px;
    border-radius: 4px;
    letter-spacing: 2px;
}

#AppTitle {
    font-size: 20px;
    font-weight: 800;
    color: #FFFFFF;
}

#AppSubtitle {
    font-size: 11px;
    color: #94A3B8;
}

/* Tabs */
QTabWidget::pane {
    border: 1px solid #1E293B;
    background-color: #0B0F19;
    top: -1px;
}

QTabBar::tab {
    background-color: #111827;
    color: #94A3B8;
    padding: 10px 24px;
    font-weight: 700;
    font-size: 13px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    border: 1px solid #1E293B;
    border-bottom: none;
    margin-right: 4px;
}

QTabBar::tab:selected {
    background-color: #1E293B;
    color: #05D9E8;
    border-top: 2px solid #05D9E8;
}

QTabBar::tab:hover:!selected {
    background-color: #1A2234;
    color: #E2E8F0;
}

/* Push Buttons */
QPushButton {
    background-color: #1E293B;
    color: #F8FAFC;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
    font-size: 13px;
}

QPushButton:hover {
    background-color: #2D3A4F;
    border-color: #05D9E8;
    color: #05D9E8;
}

QPushButton:pressed {
    background-color: #0F172A;
}

QPushButton#PrimaryScanBtn {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FF2A6D, stop:1 #FF5E00);
    color: #FFFFFF;
    font-weight: 800;
    font-size: 14px;
    border: none;
    padding: 10px 22px;
    border-radius: 6px;
}

QPushButton#PrimaryScanBtn:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FF4380, stop:1 #FF7426);
    box-shadow: 0 0 12px rgba(255, 42, 109, 0.5);
}

QPushButton#AnalyzePromptBtn {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #05D9E8, stop:1 #01FFC3);
    color: #000000;
    font-weight: 800;
    font-size: 14px;
    border: none;
    padding: 10px 22px;
    border-radius: 6px;
}

QPushButton#AnalyzePromptBtn:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #25E2EF, stop:1 #27FFCD);
}

/* Inputs & LineEdits */
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {
    background-color: #111827;
    border: 1px solid #1E293B;
    border-radius: 6px;
    padding: 8px 12px;
    color: #F8FAFC;
    selection-background-color: #FF2A6D;
    font-size: 13px;
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
    border: 1px solid #05D9E8;
    background-color: #141D30;
}

QComboBox::drop-down {
    border: none;
    width: 24px;
}

QComboBox QAbstractItemView {
    background-color: #111827;
    border: 1px solid #1E293B;
    color: #F8FAFC;
    selection-background-color: #1E293B;
    selection-color: #05D9E8;
}

/* Tables */
QTableWidget {
    background-color: #0F172A;
    border: 1px solid #1E293B;
    border-radius: 6px;
    gridline-color: #1E293B;
    selection-background-color: #1E293B;
    selection-color: #05D9E8;
}

QHeaderView::section {
    background-color: #161F33;
    color: #94A3B8;
    padding: 8px 10px;
    border: none;
    border-right: 1px solid #1E293B;
    border-bottom: 1px solid #1E293B;
    font-weight: 700;
    font-size: 12px;
    text-transform: uppercase;
}

/* Progress Bar */
QProgressBar {
    background-color: #111827;
    border: 1px solid #1E293B;
    border-radius: 4px;
    height: 12px;
    text-align: center;
    color: #F8FAFC;
    font-size: 10px;
    font-weight: bold;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FF2A6D, stop:0.5 #05D9E8, stop:1 #01FFC3);
    border-radius: 3px;
}

/* Group Boxes & Cards */
QGroupBox {
    background-color: #111827;
    border: 1px solid #1E293B;
    border-radius: 8px;
    margin-top: 18px;
    padding-top: 14px;
    font-weight: 700;
    color: #05D9E8;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    padding: 0 6px;
    background-color: #111827;
}

/* ScrollBars */
QScrollBar:vertical {
    background: #0B0F19;
    width: 8px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #1E293B;
    min-height: 20px;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover {
    background: #334155;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background: #0B0F19;
    height: 8px;
    margin: 0;
}
QScrollBar::handle:horizontal {
    background: #1E293B;
    min-width: 20px;
    border-radius: 4px;
}
QScrollBar::handle:horizontal:hover {
    background: #334155;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
"""
