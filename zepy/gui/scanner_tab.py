"""
Zepy - AI Vulnerability Detection Framework
Scanner Tab: Workspace static analysis, AST inspection, split code viewer & report generator.
"""

import os
import webbrowser
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QTextEdit, QComboBox, QProgressBar, QMessageBox, QGroupBox, QFrame
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QTextCursor, QTextCharFormat

from zepy.core.models import ScanResult, Vulnerability, Severity
from zepy.core.engine import SecurityScanEngine
from zepy.core.reporter import SecurityReporter


class ScanWorker(QThread):
    progress = pyqtSignal(int, int, str)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, target_path: str, severity_filter=None):
        super().__init__()
        self.target_path = target_path
        self.severity_filter = severity_filter

    def run(self):
        try:
            engine = SecurityScanEngine()
            result = engine.scan(
                self.target_path,
                progress_callback=lambda c, t, p: self.progress.emit(c, t, p),
                severity_filter=self.severity_filter
            )
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class ScannerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.current_scan_result: ScanResult = None
        self.filtered_vulns = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        # 1. Target Path Selection Bar
        path_box = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Select codebase directory or file to audit...")
        self.path_input.setText(os.getcwd())

        btn_browse_folder = QPushButton("📁 Browse Folder")
        btn_browse_folder.clicked.connect(self._browse_folder)

        btn_browse_file = QPushButton("📄 Browse File")
        btn_browse_file.clicked.connect(self._browse_file)

        self.btn_scan = QPushButton("⚡ START AUDIT")
        self.btn_scan.setObjectName("PrimaryScanBtn")
        self.btn_scan.setCursor(Qt.PointingHandCursor)
        self.btn_scan.clicked.connect(self._start_scan)

        path_box.addWidget(QLabel("Target:"))
        path_box.addWidget(self.path_input, 1)
        path_box.addWidget(btn_browse_folder)
        path_box.addWidget(btn_browse_file)
        path_box.addWidget(self.btn_scan)
        layout.addLayout(path_box)

        # 2. Metrics Bar
        self.metrics_frame = QFrame()
        self.metrics_frame.setStyleSheet("background-color: #111827; border: 1px solid #1E293B; border-radius: 8px; padding: 6px;")
        metrics_layout = QHBoxLayout(self.metrics_frame)
        metrics_layout.setContentsMargins(12, 6, 12, 6)

        self.lbl_score = QLabel("Score: --/100")
        self.lbl_score.setFont(QFont("Segoe UI", 12, QFont.Bold))
        self.lbl_score.setStyleSheet("color: #01FFC3;")

        self.lbl_crit = QLabel("Critical: 0")
        self.lbl_crit.setStyleSheet("color: #FF2A6D; font-weight: bold;")

        self.lbl_high = QLabel("High: 0")
        self.lbl_high.setStyleSheet("color: #FF5E00; font-weight: bold;")

        self.lbl_med = QLabel("Medium: 0")
        self.lbl_med.setStyleSheet("color: #FFB800; font-weight: bold;")

        self.lbl_low = QLabel("Low: 0")
        self.lbl_low.setStyleSheet("color: #05D9E8; font-weight: bold;")

        self.lbl_files = QLabel("Files: 0")
        self.lbl_files.setStyleSheet("color: #94A3B8;")

        metrics_layout.addWidget(self.lbl_score)
        metrics_layout.addSpacing(20)
        metrics_layout.addWidget(self.lbl_crit)
        metrics_layout.addWidget(self.lbl_high)
        metrics_layout.addWidget(self.lbl_med)
        metrics_layout.addWidget(self.lbl_low)
        metrics_layout.addStretch()
        metrics_layout.addWidget(self.lbl_files)
        layout.addWidget(self.metrics_frame)

        # 3. Progress Bar & Status
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # 4. Filter & Search Bar
        filter_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Quick search findings (Rule, Title, Path, CWE)...")
        self.search_input.textChanged.connect(self._apply_filter)

        self.combo_sev = QComboBox()
        self.combo_sev.addItems(["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.combo_sev.currentIndexChanged.connect(self._apply_filter)

        filter_layout.addWidget(self.search_input, 1)
        filter_layout.addWidget(QLabel("Filter:"))
        filter_layout.addWidget(self.combo_sev)
        layout.addLayout(filter_layout)

        # 5. Main Split View: Findings Table (Left) + Code & Remediation Inspector (Right)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Findings Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Severity", "Vulnerability Title", "Location", "Standard / CWE"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.itemSelectionChanged.connect(self._on_table_select)
        splitter.addWidget(self.table)

        # Inspector Panel (Right)
        inspector_widget = QWidget()
        inspector_layout = QVBoxLayout(inspector_widget)
        inspector_layout.setContentsMargins(0, 0, 0, 0)
        inspector_layout.setSpacing(10)

        # Code Viewer
        code_group = QGroupBox("Source Code Inspector")
        code_vbox = QVBoxLayout(code_group)
        self.code_viewer = QTextEdit()
        self.code_viewer.setReadOnly(True)
        self.code_viewer.setFont(QFont("Consolas", 10))
        self.code_viewer.setStyleSheet("background-color: #030712; color: #E2E8F0; border: 1px solid #1E293B;")
        code_vbox.addWidget(self.code_viewer)
        inspector_layout.addWidget(code_group, 3)

        # Remediation Panel
        rem_group = QGroupBox("Remediation & Defense Advisor")
        rem_vbox = QVBoxLayout(rem_group)
        self.rem_viewer = QTextEdit()
        self.rem_viewer.setReadOnly(True)
        self.rem_viewer.setStyleSheet("background-color: #0F172A; color: #01FFC3; border: 1px solid #1E293B; font-size: 13px;")
        rem_vbox.addWidget(self.rem_viewer)
        inspector_layout.addWidget(rem_group, 2)

        splitter.addWidget(inspector_widget)
        splitter.setSizes([550, 650])
        layout.addWidget(splitter, 1)

        # 6. Bottom Action Bar
        action_layout = QHBoxLayout()
        
        btn_open_html = QPushButton("🌐 Open Interactive HTML Report")
        btn_open_html.setStyleSheet("background-color: #1E293B; color: #05D9E8; font-weight: bold;")
        btn_open_html.clicked.connect(self._open_html_report)

        btn_export_json = QPushButton("💾 Export JSON")
        btn_export_json.clicked.connect(self._export_json)

        btn_export_csv = QPushButton("📊 Export CSV")
        btn_export_csv.clicked.connect(self._export_csv)

        action_layout.addWidget(btn_open_html)
        action_layout.addWidget(btn_export_json)
        action_layout.addWidget(btn_export_csv)
        action_layout.addStretch()

        layout.addLayout(action_layout)

    def _browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Project Folder", self.path_input.text())
        if folder:
            self.path_input.setText(folder)

    def _browse_file(self):
        file, _ = QFileDialog.getOpenFileName(
            self, "Select Source File", self.path_input.text(),
            "All Supported (*.py *.json *.yaml *.yml *.env *.prompt *.txt *.js *.ts);;Python (*.py);;All Files (*.*)"
        )
        if file:
            self.path_input.setText(file)

    def _start_scan(self):
        target = self.path_input.text().strip()
        if not target or not os.path.exists(target):
            QMessageBox.warning(self, "Invalid Path", "Please select a valid file or directory.")
            return

        self.btn_scan.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self.worker = ScanWorker(target)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_scan_finished)
        self.worker.error.connect(self._on_scan_error)
        self.worker.start()

    def _on_progress(self, completed: int, total: int, file_path: str):
        if total > 0:
            pct = int((completed / total) * 100)
            self.progress_bar.setValue(pct)
            self.progress_bar.setFormat(f"Auditing [{completed}/{total}] {os.path.basename(file_path)}")

    def _on_scan_finished(self, result: ScanResult):
        self.btn_scan.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.current_scan_result = result
        self._update_metrics(result)
        self._apply_filter()

    def _on_scan_error(self, error_msg: str):
        self.btn_scan.setEnabled(True)
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "Scan Error", f"Failed to complete security scan:\n{error_msg}")

    def _update_metrics(self, result: ScanResult):
        m = result.metrics
        self.lbl_score.setText(f"Score: {m.security_score}/100")
        if m.security_score >= 80:
            self.lbl_score.setStyleSheet("color: #01FFC3; font-weight: bold; font-size: 13px;")
        elif m.security_score >= 50:
            self.lbl_score.setStyleSheet("color: #FFB800; font-weight: bold; font-size: 13px;")
        else:
            self.lbl_score.setStyleSheet("color: #FF2A6D; font-weight: bold; font-size: 13px;")

        self.lbl_crit.setText(f"Critical: {m.critical_count}")
        self.lbl_high.setText(f"High: {m.high_count}")
        self.lbl_med.setText(f"Medium: {m.medium_count}")
        self.lbl_low.setText(f"Low: {m.low_count}")
        self.lbl_files.setText(f"Files Scanned: {m.total_files_scanned} ({m.total_lines_scanned:,} lines)")

    def _apply_filter(self):
        if not self.current_scan_result:
            return

        search = self.search_input.text().lower().strip()
        sev_filter = self.combo_sev.currentText()

        self.filtered_vulns = []
        for v in self.current_scan_result.vulnerabilities:
            if sev_filter != "All Severities" and v.severity.value != sev_filter:
                continue
            if search:
                matches = (
                    search in v.title.lower() or
                    search in v.id.lower() or
                    search in v.file_path.lower() or
                    (v.cwe_id and search in v.cwe_id.lower()) or
                    (v.owasp_id and search in v.owasp_id.lower())
                )
                if not matches:
                    continue
            self.filtered_vulns.append(v)

        self._populate_table()

    def _populate_table(self):
        self.table.setRowCount(len(self.filtered_vulns))
        
        for row, v in enumerate(self.filtered_vulns):
            # Severity Item
            sev_item = QTableWidgetItem(v.severity.value)
            sev_item.setTextAlignment(Qt.AlignCenter)
            sev_item.setFont(QFont("Segoe UI", 9, QFont.Bold))
            if v.severity == Severity.CRITICAL:
                sev_item.setForeground(QColor("#FF2A6D"))
            elif v.severity == Severity.HIGH:
                sev_item.setForeground(QColor("#FF5E00"))
            elif v.severity == Severity.MEDIUM:
                sev_item.setForeground(QColor("#FFB800"))
            elif v.severity == Severity.LOW:
                sev_item.setForeground(QColor("#05D9E8"))
            else:
                sev_item.setForeground(QColor("#01FFC3"))

            # Title Item
            title_item = QTableWidgetItem(v.title)
            title_item.setFont(QFont("Segoe UI", 9, QFont.Bold))

            # Location Item
            rel_path = os.path.basename(v.file_path)
            loc_item = QTableWidgetItem(f"{rel_path}:{v.line_number}")
            loc_item.setFont(QFont("Consolas", 9))
            loc_item.setForeground(QColor("#05D9E8"))

            # Standard Item
            std_item = QTableWidgetItem(f"{v.owasp_id.split(':')[0]} • {v.cwe_id}")
            std_item.setFont(QFont("Segoe UI", 9))
            std_item.setForeground(QColor("#94A3B8"))

            self.table.setItem(row, 0, sev_item)
            self.table.setItem(row, 1, title_item)
            self.table.setItem(row, 2, loc_item)
            self.table.setItem(row, 3, std_item)

        if self.filtered_vulns:
            self.table.selectRow(0)
        else:
            self.code_viewer.clear()
            self.rem_viewer.clear()

    def _on_table_select(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        if row < 0 or row >= len(self.filtered_vulns):
            return

        v = self.filtered_vulns[row]
        self._display_vulnerability_details(v)

    def _display_vulnerability_details(self, v: Vulnerability):
        # 1. Load File Content and Highlight Vulnerable Line
        try:
            if os.path.exists(v.file_path):
                with open(v.file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                self.code_viewer.clear()
                cursor = self.code_viewer.textCursor()

                highlight_format = QTextCharFormat()
                highlight_format.setBackground(QColor("#450A0A" if v.severity == Severity.CRITICAL else "#431407"))
                highlight_format.setForeground(QColor("#FFFFFF"))

                normal_format = QTextCharFormat()
                normal_format.setForeground(QColor("#E2E8F0"))

                line_num_format = QTextCharFormat()
                line_num_format.setForeground(QColor("#64748B"))

                target_line_cursor = None

                for idx, line_text in enumerate(lines, start=1):
                    prefix = f"{idx:4d} | "
                    cursor.insertText(prefix, line_num_format)
                    
                    if idx == v.line_number:
                        cursor.insertText(line_text, highlight_format)
                        target_line_cursor = QTextCursor(cursor)
                    else:
                        cursor.insertText(line_text, normal_format)

                if target_line_cursor:
                    self.code_viewer.setTextCursor(target_line_cursor)
                    self.code_viewer.ensureCursorVisible()
            else:
                self.code_viewer.setText(v.code_snippet or "Source file preview unavailable.")
        except Exception as e:
            self.code_viewer.setText(f"Could not load file: {e}\n\nSnippet:\n{v.code_snippet}")

        # 2. Update Remediation & Info View
        rem_text = (
            f"VULNERABILITY: {v.title}\n"
            f"SEVERITY: {v.severity.value}  |  STANDARD: {v.owasp_id}  |  CWE: {v.cwe_id}\n"
            f"LOCATION: {v.file_path} (Line {v.line_number})\n"
            f"{'─' * 60}\n"
            f"THREAT DESCRIPTION:\n{v.description}\n\n"
            f"REMEDIATION STRATEGY:\n{v.remediation}"
        )
        self.rem_viewer.setText(rem_text)

    def _open_html_report(self):
        if not self.current_scan_result:
            QMessageBox.information(self, "No Scan", "Run a security audit first before exporting.")
            return

        report_path = os.path.join(os.getcwd(), "zepy_security_report.html")
        SecurityReporter.export_html(self.current_scan_result, report_path)
        webbrowser.open(f"file://{os.path.abspath(report_path)}")

    def _export_json(self):
        if not self.current_scan_result:
            QMessageBox.information(self, "No Scan", "Run a security audit first before exporting.")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Save JSON Report", "zepy_report.json", "JSON Files (*.json)")
        if path:
            SecurityReporter.export_json(self.current_scan_result, path)
            QMessageBox.information(self, "Export Successful", f"JSON report saved to:\n{path}")

    def _export_csv(self):
        if not self.current_scan_result:
            QMessageBox.information(self, "No Scan", "Run a security audit first before exporting.")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Save CSV Report", "zepy_report.csv", "CSV Files (*.csv)")
        if path:
            SecurityReporter.export_csv(self.current_scan_result, path)
            QMessageBox.information(self, "Export Successful", f"CSV report saved to:\n{path}")
