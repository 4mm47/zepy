"""
Zepy - AI Vulnerability Detection Framework
Scanning Engine: Multi-threaded security orchestrator and detector coordinator.
"""

import os
import time
from pathlib import Path
from typing import List, Callable, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from zepy.core.models import Vulnerability, ScanResult, Severity
from zepy.detectors.base import BaseDetector
from zepy.detectors.ast_detector import AstDetector
from zepy.detectors.regex_detector import RegexDetector
from zepy.detectors.llm_owasp_detector import LLMOwaspDetector


class SecurityScanEngine:
    SUPPORTED_EXTENSIONS = {
        ".py", ".pyw", ".json", ".yaml", ".yml", ".env", ".prompt",
        ".txt", ".js", ".ts", ".jsx", ".tsx", ".sh", ".toml"
    }

    IGNORE_DIRS = {
        ".git", ".svn", "__pycache__", "node_modules", "venv", ".venv",
        "env", ".env", "dist", "build", ".pytest_cache", ".idea", ".vscode"
    }

    def __init__(self, detectors: Optional[List[BaseDetector]] = None, max_workers: int = 4):
        self.detectors: List[BaseDetector] = detectors or [
            AstDetector(),
            RegexDetector(),
            LLMOwaspDetector(),
        ]
        self.max_workers = max_workers

    def collect_target_files(self, target_path: str, custom_extensions: Optional[Set[str]] = None) -> List[str]:
        """Collects all matching code files from target file or folder."""
        path_obj = Path(target_path).resolve()
        if not path_obj.exists():
            raise FileNotFoundError(f"Target path '{target_path}' does not exist.")

        allowed_exts = custom_extensions or self.SUPPORTED_EXTENSIONS

        if path_obj.is_file():
            return [str(path_obj)]

        collected_files = []
        for root, dirs, files in os.walk(path_obj):
            # Modify dirs in-place to skip ignored directories
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS and not d.startswith(".")]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in allowed_exts or file.startswith(".env"):
                    full_p = os.path.join(root, file)
                    collected_files.append(full_p)

        return collected_files

    def _scan_single_file(self, file_path: str) -> tuple[List[Vulnerability], int]:
        """Reads and scans a single file with all registered detectors."""
        vulnerabilities: List[Vulnerability] = []
        line_count = 0

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            line_count = len(content.splitlines())

            for detector in self.detectors:
                findings = detector.scan_code(file_path, content)
                vulnerabilities.extend(findings)

        except Exception as err:
            # Silently handle unreadable or locked files
            pass

        return vulnerabilities, line_count

    def scan(
        self,
        target_path: str,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        severity_filter: Optional[Severity] = None,
        custom_extensions: Optional[Set[str]] = None
    ) -> ScanResult:
        """
        Executes a full vulnerability scan across the target path.
        """
        start_time = time.time()
        files = self.collect_target_files(target_path, custom_extensions)
        total_files = len(files)

        all_vulnerabilities: List[Vulnerability] = []
        total_lines = 0
        completed = 0

        if total_files == 0:
            result = ScanResult(target_path=target_path)
            result.compute_metrics(duration=time.time() - start_time, files_count=0, lines_count=0)
            return result

        # Multi-threaded file execution
        with ThreadPoolExecutor(max_workers=min(self.max_workers, max(1, total_files))) as executor:
            future_to_file = {executor.submit(self._scan_single_file, f): f for f in files}

            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                completed += 1
                try:
                    file_vulns, lines = future.result()
                    all_vulnerabilities.extend(file_vulns)
                    total_lines += lines
                except Exception:
                    pass

                if progress_callback:
                    progress_callback(completed, total_files, file_path)

        # De-duplicate findings (by file, line, rule_id)
        seen_keys = set()
        deduped_vulns: List[Vulnerability] = []
        for v in all_vulnerabilities:
            key = (v.file_path, v.line_number, v.id.split("-")[0])
            if key not in seen_keys:
                seen_keys.add(key)
                if severity_filter is None or v.severity == severity_filter:
                    deduped_vulns.append(v)

        # Sort by severity weight descending, then file and line number
        deduped_vulns.sort(key=lambda x: (-x.severity.weight, x.file_path, x.line_number))

        duration = time.time() - start_time
        scan_result = ScanResult(
            target_path=target_path,
            vulnerabilities=deduped_vulns
        )
        scan_result.compute_metrics(duration=duration, files_count=total_files, lines_count=total_lines)

        return scan_result
