"""
Zepy - Supply Chain Dependency Auditor
Scans requirements.txt, pyproject.toml, setup.py, and Pipfile against a
bundled offline advisory database for known vulnerable AI/LLM packages.
"""

import json
import re
from pathlib import Path
from typing import List, Optional
from packaging.version import Version, InvalidVersion

from zepy.detectors.base import BaseDetector
from zepy.core.models import Vulnerability, Severity, VulnerabilityCategory


# Path to bundled offline advisory DB
_ADVISORY_DB_PATH = Path(__file__).parent.parent / "rules" / "advisory_db.json"


def _load_advisory_db() -> list:
    try:
        return json.loads(_ADVISORY_DB_PATH.read_text(encoding="utf-8"))["advisories"]
    except Exception:
        return []


_ADVISORY_DB = _load_advisory_db()


def _severity_from_str(s: str) -> Severity:
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    return mapping.get(s.upper(), Severity.MEDIUM)


def _parse_requirements_txt(content: str) -> List[tuple]:
    """Parse requirements.txt lines → list of (package, version_str, line_no)."""
    results = []
    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Remove inline comments
        line = line.split("#")[0].strip()
        # Match: package==version or package>=version etc.
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([=<>!~^]+)\s*([0-9][0-9A-Za-z\.\-\+\*]*)", line)
        if m:
            results.append((m.group(1).lower().replace("_", "-"), m.group(3), i))
    return results


def _parse_pyproject_toml(content: str) -> List[tuple]:
    """Extract dependencies from pyproject.toml text → (package, version, line_no)."""
    results = []
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        m = re.search(r'"([A-Za-z0-9_\-\.]+)\s*([=<>!~^]+)\s*([0-9][0-9A-Za-z\.\-\+\*]*)"', line)
        if m:
            results.append((m.group(1).lower().replace("_", "-"), m.group(3), i))
    return results


def _parse_setup_py(content: str) -> List[tuple]:
    """Scan install_requires list in setup.py."""
    results = []
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        m = re.search(r"['\"]([A-Za-z0-9_\-\.]+)\s*([=<>!~^]+)\s*([0-9][0-9A-Za-z\.\-\+\*]*)['\"]", line)
        if m:
            results.append((m.group(1).lower().replace("_", "-"), m.group(3), i))
    return results


def _check_against_db(pkg: str, version_str: str) -> Optional[dict]:
    """Returns matching advisory if the package version is vulnerable, else None."""
    for advisory in _ADVISORY_DB:
        if advisory["package"].lower() != pkg.lower():
            continue
        try:
            pkg_ver = Version(version_str)
            vuln_below = Version(advisory["vulnerable_below"])
            if pkg_ver < vuln_below:
                return advisory
        except InvalidVersion:
            # Wildcard or non-parseable — flag as potentially vulnerable
            return advisory
    return None


class SupplyChainDetector(BaseDetector):
    """
    Scans Python dependency manifests against a bundled offline CVE advisory
    database covering AI/LLM packages (torch, transformers, langchain, etc.)
    """

    MANIFEST_FILES = {
        "requirements.txt", "requirements-dev.txt", "requirements-prod.txt",
        "dev-requirements.txt", "pyproject.toml", "setup.py", "Pipfile",
    }

    def __init__(self):
        super().__init__(
            name="Supply Chain Dependency Auditor",
            description="Checks dependency manifests against an offline advisory DB for vulnerable AI/LLM packages."
        )

    def scan_code(self, file_path: str, code_content: str) -> List[Vulnerability]:
        filename = Path(file_path).name.lower()
        if filename not in self.MANIFEST_FILES:
            return []

        # Select parser based on filename
        if filename in ("requirements.txt", "requirements-dev.txt", "requirements-prod.txt", "dev-requirements.txt"):
            deps = _parse_requirements_txt(code_content)
        elif filename == "pyproject.toml":
            deps = _parse_pyproject_toml(code_content)
        elif filename == "setup.py":
            deps = _parse_setup_py(code_content)
        elif filename == "pipfile":
            deps = _parse_requirements_txt(code_content)  # similar format
        else:
            return []

        findings: List[Vulnerability] = []
        for pkg, ver_str, line_no in deps:
            advisory = _check_against_db(pkg, ver_str)
            if advisory:
                snippet = self.extract_snippet(code_content, line_no)
                vuln = Vulnerability(
                    id=f"SC-{advisory['cve'].replace('-', '')}-{line_no}",
                    title=f"Vulnerable AI/LLM Dependency: {pkg}=={ver_str}",
                    category=VulnerabilityCategory.LLM05_SUPPLY_CHAIN,
                    severity=_severity_from_str(advisory["severity"]),
                    description=(
                        f"{advisory['cve']}: {advisory['description']} "
                        f"(Detected: {pkg}=={ver_str}, safe version: >={advisory['vulnerable_below']})"
                    ),
                    file_path=file_path,
                    line_number=line_no,
                    column_number=1,
                    code_snippet=snippet,
                    remediation=advisory["remediation"],
                    cwe_id=advisory["cwe"],
                    owasp_id=advisory["owasp"],
                    confidence=0.97,
                    metadata={
                        "detector": "supply_chain_detector",
                        "package": pkg,
                        "version": ver_str,
                        "cve": advisory["cve"],
                        "safe_version": advisory["vulnerable_below"],
                    }
                )
                findings.append(vuln)

        return findings
