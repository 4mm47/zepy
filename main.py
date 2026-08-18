#!/usr/bin/env python3
"""
ZEPY — AI & LLM Vulnerability Detection System
Root Entrypoint for CLI and Desktop GUI.

Usage:
  python main.py gui                  # Launch PyQt5 Dark Cyber Desktop GUI
  python main.py scan <path>          # Audit directory or file
  python main.py prompt "<text>"      # Live prompt threat & jailbreak analyzer
  python main.py rules                # List security rules & OWASP LLM database
"""

import sys
from zepy.cli import main

if __name__ == "__main__":
    main()
