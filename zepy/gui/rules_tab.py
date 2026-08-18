"""
Zepy - AI Vulnerability Detection Framework
Rules Tab: Searchable Rules Knowledgebase and Vulnerability Explorer
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter, QTextEdit, QGroupBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor

from zepy.rules.rule_manager import RuleManager
from zepy.core.models import Severity


class RulesTab(QWidget):
    def __init__(self):
        super().__init__()
        self.rule_mgr = RuleManager()
        self.all_rules = self.rule_mgr.get_all_rules()
        self.filtered_rules = list(self.all_rules)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        # 1. Search and Filter Bar
        filter_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search vulnerability rules by title, CWE, OWASP, keyword...")
        self.search_input.textChanged.connect(self._apply_filter)

        self.combo_sev = QComboBox()
        self.combo_sev.addItems(["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.combo_sev.currentIndexChanged.connect(self._apply_filter)

        filter_layout.addWidget(self.search_input, 1)
        filter_layout.addWidget(QLabel("Severity:"))
        filter_layout.addWidget(self.combo_sev)
        layout.addLayout(filter_layout)

        # 2. Main Split View: Rules Table (Left) + Rule Details (Right)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Rules Table
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["ID", "Severity", "Rule Title"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.itemSelectionChanged.connect(self._on_rule_select)
        splitter.addWidget(self.table)

        # Details Panel
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.setSpacing(10)

        desc_group = QGroupBox("Vulnerability Specification & Threat Details")
        desc_vbox = QVBoxLayout(desc_group)
        self.desc_viewer = QTextEdit()
        self.desc_viewer.setReadOnly(True)
        self.desc_viewer.setStyleSheet("background-color: #0F172A; color: #E2E8F0; border: 1px solid #1E293B;")
        desc_vbox.addWidget(self.desc_viewer)
        details_layout.addWidget(desc_group, 1)

        examples_group = QGroupBox("Secure vs Vulnerable Implementation Patterns")
        examples_vbox = QVBoxLayout(examples_group)
        self.examples_viewer = QTextEdit()
        self.examples_viewer.setReadOnly(True)
        self.examples_viewer.setFont(QFont("Consolas", 10))
        self.examples_viewer.setStyleSheet("background-color: #030712; color: #38BDF8; border: 1px solid #1E293B;")
        examples_vbox.addWidget(self.examples_viewer)
        details_layout.addWidget(examples_group, 1)

        splitter.addWidget(details_widget)
        splitter.setSizes([450, 750])
        layout.addWidget(splitter, 1)

        self._populate_table()

    def _apply_filter(self):
        search = self.search_input.text().lower().strip()
        sev_text = self.combo_sev.currentText()

        self.filtered_rules = []
        for r in self.all_rules:
            if sev_text != "All Severities" and r.severity.value != sev_text:
                continue
            if search:
                matches = (
                    search in r.id.lower() or
                    search in r.title.lower() or
                    search in r.description.lower() or
                    search in r.cwe_id.lower() or
                    search in r.owasp_id.lower()
                )
                if not matches:
                    continue
            self.filtered_rules.append(r)

        self._populate_table()

    def _populate_table(self):
        self.table.setRowCount(len(self.filtered_rules))
        for row, r in enumerate(self.filtered_rules):
            id_item = QTableWidgetItem(r.id)
            id_item.setFont(QFont("Consolas", 9, QFont.Bold))
            id_item.setForeground(QColor("#05D9E8"))

            sev_item = QTableWidgetItem(r.severity.value)
            sev_item.setTextAlignment(Qt.AlignCenter)
            sev_item.setFont(QFont("Segoe UI", 9, QFont.Bold))
            if r.severity == Severity.CRITICAL:
                sev_item.setForeground(QColor("#FF2A6D"))
            elif r.severity == Severity.HIGH:
                sev_item.setForeground(QColor("#FF5E00"))
            elif r.severity == Severity.MEDIUM:
                sev_item.setForeground(QColor("#FFB800"))
            elif r.severity == Severity.LOW:
                sev_item.setForeground(QColor("#05D9E8"))
            else:
                sev_item.setForeground(QColor("#01FFC3"))

            title_item = QTableWidgetItem(r.title)
            title_item.setFont(QFont("Segoe UI", 9))

            self.table.setItem(row, 0, id_item)
            self.table.setItem(row, 1, sev_item)
            self.table.setItem(row, 2, title_item)

        if self.filtered_rules:
            self.table.selectRow(0)

    def _on_rule_select(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        if row < 0 or row >= len(self.filtered_rules):
            return

        r = self.filtered_rules[row]
        self._display_rule_details(r)

    def _display_rule_details(self, r):
        desc = (
            f"RULE ID: {r.id}\n"
            f"TITLE: {r.title}\n"
            f"SEVERITY: {r.severity.value}  |  CWE: {r.cwe_id}  |  STANDARD: {r.owasp_id}\n"
            f"{'─' * 60}\n"
            f"DESCRIPTION:\n{r.description}\n\n"
            f"REMEDIATION STRATEGY:\n{r.remediation}"
        )
        self.desc_viewer.setText(desc)

        examples = (
            f"# ── SECURE REMEDIATION PATTERN ──────────────────\n"
            f"{r.good_example}\n\n"
            f"# ── VULNERABLE DETECTED PATTERN ─────────────────\n"
            f"{r.bad_example}"
        )
        self.examples_viewer.setText(examples)
