"""
Zepy - AI Vulnerability Detection Framework
Base Detector Interface
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from zepy.core.models import Vulnerability


class BaseDetector(ABC):
    """Abstract base class for all static & semantic vulnerability detectors."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    def scan_code(self, file_path: str, code_content: str) -> List[Vulnerability]:
        """
        Scans source code content and returns a list of detected vulnerabilities.
        """
        pass

    def extract_snippet(self, content: str, line_number: int, context_lines: int = 2) -> str:
        """Helper to extract line with surrounding context."""
        lines = content.splitlines()
        if not lines or line_number < 1 or line_number > len(lines):
            return ""
        
        start = max(0, line_number - 1 - context_lines)
        end = min(len(lines), line_number + context_lines)
        
        snippet_lines = []
        for idx in range(start, end):
            curr_line_num = idx + 1
            prefix = " > " if curr_line_num == line_number else "   "
            snippet_lines.append(f"{curr_line_num:4d}{prefix}{lines[idx]}")
            
        return "\n".join(snippet_lines)
