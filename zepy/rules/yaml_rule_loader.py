"""
Zepy - Custom YAML Rule Engine
Load user-defined detection rules from a .zepy-rules.yaml file at runtime.
"""

import re
from pathlib import Path
from typing import List, Optional, Dict, Any

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from zepy.detectors.base import BaseDetector
from zepy.core.models import Vulnerability, Severity, VulnerabilityCategory


_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_CATEGORY_MAP = {
    "prompt_injection": VulnerabilityCategory.LLM01_PROMPT_INJECTION,
    "insecure_output": VulnerabilityCategory.LLM02_INSECURE_OUTPUT,
    "supply_chain": VulnerabilityCategory.LLM05_SUPPLY_CHAIN,
    "secret_leak": VulnerabilityCategory.API_KEY_LEAK,
    "deserialization": VulnerabilityCategory.DESERIALIZATION,
    "code_injection": VulnerabilityCategory.CODE_INJECTION,
    "excessive_agency": VulnerabilityCategory.LLM08_EXCESSIVE_AGENCY,
}


# ---------------------------------------------------------------------------
# Schema for custom rule YAML entries
# ---------------------------------------------------------------------------
#
# rules:
#   - id: "CUSTOM-001"
#     name: "Dangerous Custom Pattern"
#     severity: high
#     category: code_injection          # optional, default: code_injection
#     pattern: "dangerous_function\("   # Python regex
#     message: "Found dangerous_function call."
#     remediation: "Replace with safe_function()."
#     cwe: "CWE-78"
#     owasp: "LLM02:2025-Insecure-Output-Handling"
#     file_extensions: [".py"]          # optional whitelist
# ---------------------------------------------------------------------------

DEFAULT_RULE_FILE_NAMES = [".zepy-rules.yaml", ".zepy-rules.yml", "zepy-rules.yaml", "zepy-rules.yml"]


def _find_rule_file(custom_path: Optional[str] = None, search_dirs: Optional[List[str]] = None) -> Optional[Path]:
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return p

    for directory in (search_dirs or ["."]):
        for name in DEFAULT_RULE_FILE_NAMES:
            candidate = Path(directory) / name
            if candidate.exists():
                return candidate
    return None


def load_custom_rules(rule_file_path: Optional[str] = None, search_dirs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Load custom rules from a YAML file.
    Returns list of parsed rule dicts, empty list if not found or YAML not available.
    """
    if not _YAML_AVAILABLE:
        return []

    rule_file = _find_rule_file(rule_file_path, search_dirs)
    if rule_file is None:
        return []

    try:
        with open(rule_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        rules = data.get("rules", []) if isinstance(data, dict) else []
        return [r for r in rules if isinstance(r, dict) and "id" in r and "pattern" in r]
    except Exception:
        return []


class YamlRuleDetector(BaseDetector):
    """
    Runs user-defined regex patterns from a .zepy-rules.yaml file
    against source files. Supports extension whitelisting per rule.
    """

    def __init__(self, rule_file_path: Optional[str] = None, search_dirs: Optional[List[str]] = None):
        super().__init__(
            name="Custom YAML Rule Detector",
            description="Applies user-defined regex security rules from .zepy-rules.yaml"
        )
        raw_rules = load_custom_rules(rule_file_path, search_dirs)
        self._compiled: List[Dict[str, Any]] = []
        for rule in raw_rules:
            try:
                compiled = {
                    **rule,
                    "_re": re.compile(rule["pattern"]),
                    "_severity": _SEVERITY_MAP.get(str(rule.get("severity", "medium")).lower(), Severity.MEDIUM),
                    "_category": _CATEGORY_MAP.get(str(rule.get("category", "code_injection")).lower(), VulnerabilityCategory.CODE_INJECTION),
                    "_extensions": [e.lower() for e in rule.get("file_extensions", [])] or None,
                }
                self._compiled.append(compiled)
            except re.error:
                pass  # Skip rules with invalid regex patterns

    @property
    def rule_count(self) -> int:
        return len(self._compiled)

    def scan_code(self, file_path: str, code_content: str) -> List[Vulnerability]:
        if not self._compiled:
            return []

        findings: List[Vulnerability] = []
        file_ext = Path(file_path).suffix.lower()

        for rule in self._compiled:
            # Extension whitelist check
            allowed_exts = rule["_extensions"]
            if allowed_exts and file_ext not in allowed_exts:
                continue

            for match in rule["_re"].finditer(code_content):
                line_no = code_content[: match.start()].count("\n") + 1
                col_no = match.start() - code_content.rfind("\n", 0, match.start())
                snippet = self.extract_snippet(code_content, line_no)

                vuln = Vulnerability(
                    id=f"{rule['id']}-{line_no}",
                    title=rule.get("name", rule["id"]),
                    category=rule["_category"],
                    severity=rule["_severity"],
                    description=rule.get("message", f"Custom rule {rule['id']} matched at line {line_no}."),
                    file_path=file_path,
                    line_number=line_no,
                    column_number=col_no,
                    code_snippet=snippet,
                    remediation=rule.get("remediation", "Review and fix the matched pattern."),
                    cwe_id=rule.get("cwe", ""),
                    owasp_id=rule.get("owasp", ""),
                    confidence=0.85,
                    metadata={
                        "detector": "yaml_rule_detector",
                        "rule_id": rule["id"],
                        "match": match.group(0)[:80],
                    }
                )
                findings.append(vuln)

        return findings
