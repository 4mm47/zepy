"""
Zepy - AI Vulnerability Detection Framework
Main Window: Central GUI frame with Cyber styling, navigation tabs and status header.
"""

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTabWidget,
    QStatusBar, QFrame
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon, QFont

from zepy.gui.styles import CYBER_DARK_QSS
from zepy.gui.scanner_tab import ScannerTab
from zepy.gui.prompt_tab import PromptTab
from zepy.gui.rules_tab import RulesTab
from zepy.rules.definitions import RULES_DATABASE


class ZepyMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ZEPY — AI & LLM Vulnerability Detection System")
        self.resize(1280, 840)
        self.setMinimumSize(960, 640)

        # Apply Global Cyber Dark QSS Theme
        self.setStyleSheet(CYBER_DARK_QSS)

        self._init_ui()

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 1. Signature Header Bar with ZEPY Badge & Cyber Glow
        header_frame = QFrame()
        header_frame.setObjectName("HeaderFrame")
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(20, 12, 20, 12)

        # Left Branding
        brand_layout = QHBoxLayout()
        lbl_zepy = QLabel("ZEPY")
        lbl_zepy.setObjectName("ZepyBadge")
        
        title_box = QVBoxLayout()
        lbl_title = QLabel("ZEPY AI-SHIELD  v1.0.0")
        lbl_subtitle = QLabel("Advanced Large Language Model & AI Static Security Vulnerability Detection Platform")
        lbl_subtitle.setObjectName("AppSubtitle")
        title_box.addWidget(lbl_title)
        title_box.addWidget(lbl_subtitle)

        brand_layout.addWidget(lbl_zepy)
        brand_layout.addSpacing(8)
        brand_layout.addLayout(title_box)

        # Right Meta Status
        status_box = QVBoxLayout()
        lbl_engine_status = QLabel("● ENGINE ACTIVE")
        lbl_engine_status.setStyleSheet("color: #01FFC3; font-weight: bold; font-size: 11px;")
        lbl_rule_count = QLabel(f"OWASP Top 10 for LLMs • {len(RULES_DATABASE)}+ Security Rules")
        lbl_rule_count.setStyleSheet("color: #94A3B8; font-size: 11px;")
        status_box.addWidget(lbl_engine_status, alignment=Qt.AlignRight)
        status_box.addWidget(lbl_rule_count, alignment=Qt.AlignRight)

        header_layout.addLayout(brand_layout)
        header_layout.addStretch()
        header_layout.addLayout(status_box)

        main_layout.addWidget(header_frame)

        # 2. Main Tabbed Interface
        self.tabs = QTabWidget()
        self.scanner_tab = ScannerTab()
        self.prompt_tab = PromptTab()
        self.rules_tab = RulesTab()

        self.tabs.addTab(self.scanner_tab, "📁 Codebase & File Scanner")
        self.tabs.addTab(self.prompt_tab, "⚡ Live Prompt & Jailbreak Tester")
        self.tabs.addTab(self.rules_tab, "🛡️ Vulnerability & Rules Catalog")

        main_layout.addWidget(self.tabs, 1)

        # 3. Status Bar
        status_bar = QStatusBar()
        status_bar.setStyleSheet("background-color: #0B0F19; border-top: 1px solid #1E293B; color: #64748B; padding: 4px 12px;")
        status_bar.showMessage("ZEPY AI-Shield Engine Ready. Select a codebase folder or file to begin auditing.")
        self.setStatusBar(status_bar)
