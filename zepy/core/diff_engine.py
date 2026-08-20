"""
Zepy - Baseline Regression Diff Engine
Compares two scan results to surface only new, fixed, or persisting findings.
"""

import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path

from zepy.core.models import ScanResult, Vulnerability, Severity


@dataclass
class DiffReport:
    new_findings: List[Vulnerability] = field(default_factory=list)
    fixed_findings: List[Vulnerability] = field(default_factory=list)
    persisting_findings: List[Vulnerability] = field(default_factory=list)
    baseline_path: str = ""
    current_target: str = ""

    @property
    def has_regressions(self) -> bool:
        return len(self.new_findings) > 0

    @property
    def summary(self) -> Dict[str, int]:
        return {
            "new": len(self.new_findings),
            "fixed": len(self.fixed_findings),
            "persisting": len(self.persisting_findings),
        }

    def to_dict(self) -> dict:
        return {
            "baseline_path": self.baseline_path,
            "current_target": self.current_target,
            "summary": self.summary,
            "new_findings": [v.to_dict() for v in self.new_findings],
            "fixed_findings": [v.to_dict() for v in self.fixed_findings],
            "persisting_findings": [v.to_dict() for v in self.persisting_findings],
        }


def _vuln_fingerprint(v: Vulnerability) -> str:
    """Stable fingerprint: rule_id + relative file + line number."""
    # Strip the last numeric suffix from the ID (e.g. AST-DESER-001-37 → AST-DESER-001)
    rule_id = "-".join(v.id.split("-")[:-1]) if "-" in v.id else v.id
    return f"{rule_id}::{Path(v.file_path).name}::{v.line_number}"


class DiffEngine:
    @staticmethod
    def compute_diff(baseline_result: ScanResult, current_result: ScanResult) -> DiffReport:
        """
        Compute regression diff between a baseline and a new scan.
        Returns new (regressions), fixed, and persisting findings.
        """
        baseline_fps = {_vuln_fingerprint(v): v for v in baseline_result.vulnerabilities}
        current_fps = {_vuln_fingerprint(v): v for v in current_result.vulnerabilities}

        new_keys = set(current_fps.keys()) - set(baseline_fps.keys())
        fixed_keys = set(baseline_fps.keys()) - set(current_fps.keys())
        persisting_keys = set(baseline_fps.keys()) & set(current_fps.keys())

        return DiffReport(
            new_findings=[current_fps[k] for k in sorted(new_keys)],
            fixed_findings=[baseline_fps[k] for k in sorted(fixed_keys)],
            persisting_findings=[current_fps[k] for k in sorted(persisting_keys)],
            baseline_path=baseline_result.target_path,
            current_target=current_result.target_path,
        )

    @staticmethod
    def load_baseline(path: str) -> Optional[ScanResult]:
        """Load a previously saved JSON scan result as a baseline."""
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            result = ScanResult(target_path=raw.get("target_path", path))
            vulns = []
            for f in raw.get("findings", []):
                try:
                    vulns.append(Vulnerability(
                        id=f["id"],
                        title=f["title"],
                        category=f.get("category", ""),
                        severity=Severity(f["severity"]),
                        description=f.get("description", ""),
                        file_path=f.get("file_path", ""),
                        line_number=int(f.get("line_number", 0)),
                        column_number=int(f.get("column_number", 1)),
                        code_snippet=f.get("code_snippet", ""),
                        remediation=f.get("remediation", ""),
                        cwe_id=f.get("cwe_id", ""),
                        owasp_id=f.get("owasp_id", ""),
                        confidence=float(f.get("confidence", 0.95)),
                        metadata=f.get("metadata", {}),
                    ))
                except Exception:
                    continue
            result.vulnerabilities = vulns
            return result
        except Exception:
            return None

    @staticmethod
    def export_diff_html(diff: DiffReport, output_path: str) -> None:
        """Export a focused regression-only HTML report."""
        def _badge(sev: str) -> str:
            colors = {
                "CRITICAL": "#FF2A6D", "HIGH": "#FF5E00",
                "MEDIUM": "#FFB800", "LOW": "#05D9E8", "INFO": "#01FFC3"
            }
            c = colors.get(sev, "#aaa")
            return f'<span style="background:{c};color:#000;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{sev}</span>'

        def _rows(findings: List[Vulnerability], badge_color: str) -> str:
            if not findings:
                return f'<tr><td colspan="4" style="color:#666;padding:16px">None</td></tr>'
            rows = ""
            for v in findings:
                rows += f"""
                <tr>
                  <td>{_badge(v.severity.value)}</td>
                  <td style="color:#05D9E8">{v.title}</td>
                  <td style="color:#aaa;font-size:12px">{Path(v.file_path).name}:{v.line_number}</td>
                  <td style="color:#888;font-size:12px">{v.cwe_id or ''} {v.owasp_id or ''}</td>
                </tr>"""
            return rows

        s = diff.summary
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ZEPY Diff Report</title>
<style>
  body{{font-family:'Segoe UI',monospace;background:#0B0F19;color:#E0E0E0;margin:0;padding:24px}}
  h1{{color:#FF2A6D;font-size:22px}} h2{{color:#05D9E8;font-size:16px;margin-top:28px}}
  .badge-box{{display:flex;gap:16px;margin:16px 0}}
  .card{{background:#131928;border:1px solid #222;border-radius:8px;padding:12px 20px;min-width:120px}}
  .card .num{{font-size:32px;font-weight:bold}} .new{{color:#FF2A6D}} .fix{{color:#01FFC3}} .per{{color:#FFB800}}
  table{{width:100%;border-collapse:collapse;margin-top:8px}}
  th{{background:#1a2035;color:#888;text-align:left;padding:8px 12px;font-size:12px}}
  td{{padding:8px 12px;border-bottom:1px solid #1a2035;vertical-align:top}}
</style>
</head>
<body>
<h1>⚡ ZEPY — Baseline Diff Report</h1>
<p style="color:#666">Baseline: <code style="color:#aaa">{diff.baseline_path}</code> &nbsp;→&nbsp; Current: <code style="color:#aaa">{diff.current_target}</code></p>
<div class="badge-box">
  <div class="card"><div class="num new">{s['new']}</div><div>New (Regressions)</div></div>
  <div class="card"><div class="num fix">{s['fixed']}</div><div>Fixed</div></div>
  <div class="card"><div class="num per">{s['persisting']}</div><div>Persisting</div></div>
</div>

<h2>🔴 New Findings (Regressions)</h2>
<table><tr><th>Severity</th><th>Title</th><th>Location</th><th>Standard</th></tr>
{_rows(diff.new_findings, '#FF2A6D')}</table>

<h2>✅ Fixed Findings</h2>
<table><tr><th>Severity</th><th>Title</th><th>Location</th><th>Standard</th></tr>
{_rows(diff.fixed_findings, '#01FFC3')}</table>

<h2>🔁 Persisting Findings</h2>
<table><tr><th>Severity</th><th>Title</th><th>Location</th><th>Standard</th></tr>
{_rows(diff.persisting_findings, '#FFB800')}</table>

<p style="color:#444;font-size:11px;margin-top:32px">Generated by ZEPY AI-Shield v1.0.0</p>
</body></html>"""
        Path(output_path).write_text(html, encoding="utf-8")
