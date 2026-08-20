"""
Zepy - Security Audit Logger
Append-only JSONL audit trail stored at ~/.zepy/audit.jsonl.
Every scan and prompt analysis event is recorded.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from zepy.core.models import ScanResult

_AUDIT_DIR = Path.home() / ".zepy"
_AUDIT_FILE = _AUDIT_DIR / "audit.jsonl"


def _ensure_audit_dir() -> None:
    _AUDIT_DIR.mkdir(parents=True, exist_ok=True)


def _write_entry(entry: Dict[str, Any]) -> None:
    _ensure_audit_dir()
    try:
        with open(_AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def log_scan(result: ScanResult, command: str = "scan") -> None:
    """Log a completed codebase scan to the audit trail."""
    _write_entry({
        "event": "scan",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "target": result.target_path,
        "scanner_version": result.scanner_version,
        "files_scanned": result.metrics.total_files_scanned,
        "lines_scanned": result.metrics.total_lines_scanned,
        "scan_duration_seconds": result.metrics.scan_duration_seconds,
        "security_score": result.metrics.security_score,
        "findings": {
            "total": len(result.vulnerabilities),
            "critical": result.metrics.critical_count,
            "high": result.metrics.high_count,
            "medium": result.metrics.medium_count,
            "low": result.metrics.low_count,
            "info": result.metrics.info_count,
        }
    })


def log_prompt_analysis(threat_score: float, threat_level: str, attack_vectors: list) -> None:
    """Log a prompt threat analysis event."""
    _write_entry({
        "event": "prompt_analysis",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat_score": threat_score,
        "threat_level": threat_level,
        "attack_vectors": attack_vectors,
    })


def read_audit_log(limit: int = 50) -> list:
    """Read the last N entries from the audit log."""
    try:
        lines = _AUDIT_FILE.read_text(encoding="utf-8").strip().splitlines()
        entries = []
        for line in lines[-limit:]:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return entries
    except (OSError, FileNotFoundError):
        return []


def get_audit_log_path() -> str:
    return str(_AUDIT_FILE)
