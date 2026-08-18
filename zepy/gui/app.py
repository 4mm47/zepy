"""
Zepy - AI Vulnerability Detection Framework
GUI Application Entrypoint
"""

import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from zepy.gui.main_window import ZepyMainWindow


def run_gui():
    """Launches the PyQt5 Zepy GUI application."""
    # Enable High DPI scaling
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("ZEPY AI Vulnerability Detector")
    
    window = ZepyMainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    run_gui()
