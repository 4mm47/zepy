"""
Zepy - Software Bill of Materials (SBOM) Generator
Generates CycloneDX v1.5 JSON SBOM listing dependencies and security findings.
"""

import json
import hashlib
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from zepy.core.models import ScanResult


def _get_installed_packages() -> List[Dict[str, Any]]:
    """Retrieve installed Python packages via pip list --json."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except Exception:
        pass
    return []


def _pkg_to_component(pkg: Dict[str, str]) -> Dict[str, Any]:
    name = pkg.get("name", "")
    version = pkg.get("version", "0.0.0")
    purl = f"pkg:pypi/{name.lower()}@{version}"
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl,
        "licenses": [],
        "externalReferences": [
            {
                "type": "distribution",
                "url": f"https://pypi.org/project/{name}/{version}/"
            }
        ]
    }


def _vuln_to_cyclonedx(v) -> Dict[str, Any]:
    return {
        "id": v.cwe_id or v.id,
        "source": {
            "name": "ZEPY AI-Shield",
            "url": "https://github.com/4mm47/zepy"
        },
        "ratings": [
            {
                "source": {"name": "ZEPY"},
                "severity": v.severity.value.lower(),
                "method": "other",
            }
        ],
        "cwes": [int(v.cwe_id.replace("CWE-", ""))] if v.cwe_id and v.cwe_id.startswith("CWE-") else [],
        "description": v.description,
        "recommendation": v.remediation,
        "affects": [
            {
                "ref": Path(v.file_path).name,
                "versions": [{"version": "1.0.0", "status": "affected"}]
            }
        ]
    }


def generate_sbom(
    scan_result: Optional[ScanResult] = None,
    project_name: str = "ZEPY Scanned Project",
    project_version: str = "1.0.0",
    project_url: str = "https://github.com/4mm47/zepy",
) -> Dict[str, Any]:
    """
    Generate a CycloneDX v1.5 BOM as a Python dict.
    """
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    packages = _get_installed_packages()
    components = [_pkg_to_component(p) for p in packages]

    vulnerabilities = []
    if scan_result:
        for v in scan_result.vulnerabilities:
            vulnerabilities.append(_vuln_to_cyclonedx(v))

    serial_number = f"urn:uuid:{hashlib.sha256((project_name + now_iso).encode()).hexdigest()[:32]}"

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": now_iso,
            "tools": [
                {
                    "vendor": "ZEPY Security Research",
                    "name": "ZEPY AI-Shield",
                    "version": "1.0.0",
                    "externalReferences": [
                        {"type": "website", "url": project_url}
                    ]
                }
            ],
            "component": {
                "type": "application",
                "name": project_name,
                "version": project_version,
            }
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }
    return bom


def export_sbom(
    output_path: str,
    scan_result: Optional[ScanResult] = None,
    project_name: str = "ZEPY Scanned Project",
    project_version: str = "1.0.0",
) -> None:
    """Write the CycloneDX SBOM JSON to a file."""
    bom = generate_sbom(
        scan_result=scan_result,
        project_name=project_name,
        project_version=project_version,
    )
    Path(output_path).write_text(json.dumps(bom, indent=2), encoding="utf-8")
