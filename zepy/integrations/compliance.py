"""
Zepy - Compliance Report Generator
Generates SOC 2 Type II / ISO 27001 security evidence HTML reports
by mapping ZEPY findings to compliance control domains.
"""

from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from zepy.core.models import ScanResult, Vulnerability, Severity


# ---------------------------------------------------------------------------
# Control domain mappings per framework
# ---------------------------------------------------------------------------

SOC2_DOMAINS = {
    "CC6 — Logical & Physical Access Controls": [
        "LLM06", "CWE-798", "CWE-200", "SEC-KEY", "SEC-PROMPT",
    ],
    "CC7 — System Operations": [
        "LLM02", "CWE-94", "CWE-78", "AST-EXEC", "AST-LLMOUT",
    ],
    "CC8 — Change Management / Supply Chain": [
        "LLM05", "CWE-502", "AST-DESER", "SC-CVE",
    ],
    "CC9 — Risk Mitigation": [
        "LLM01", "LLM03", "LLM04", "LLM08", "SEC-POISON", "SEC-RAG",
    ],
    "A1 — Availability": [
        "LLM04", "CWE-400",
    ],
}

ISO27001_DOMAINS = {
    "A.8 — Application Security": [
        "LLM01", "LLM02", "CWE-94", "CWE-78", "AST-EXEC",
    ],
    "A.8.24 — Cryptography & Secrets": [
        "CWE-798", "CWE-200", "SEC-KEY", "SEC-PROMPT",
    ],
    "A.8.8 — Vulnerability Management": [
        "LLM05", "CWE-502", "AST-DESER", "SC-CVE",
    ],
    "A.8.28 — Secure Coding": [
        "LLM02", "LLM03", "CWE-20", "CWE-89",
    ],
    "A.5.23 — Third-Party / Supply Chain": [
        "LLM05", "SC-CVE",
    ],
}


def _match_domain(vuln: Vulnerability, domain_keys: List[str]) -> bool:
    identifiers = [
        vuln.owasp_id or "", vuln.cwe_id or "", vuln.id,
        vuln.metadata.get("rule_id", ""), vuln.metadata.get("detector", ""),
    ]
    for key in domain_keys:
        for ident in identifiers:
            if key.lower() in ident.lower():
                return True
    return False


def _group_by_domain(findings: List[Vulnerability], domain_map: Dict[str, List[str]]) -> Dict[str, List[Vulnerability]]:
    grouped: Dict[str, List[Vulnerability]] = {d: [] for d in domain_map}
    for v in findings:
        for domain, keys in domain_map.items():
            if _match_domain(v, keys):
                grouped[domain].append(v)
    return grouped


def _severity_color(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "#FF2A6D",
        Severity.HIGH: "#FF5E00",
        Severity.MEDIUM: "#FFB800",
        Severity.LOW: "#05D9E8",
        Severity.INFO: "#01FFC3",
    }.get(sev, "#aaa")


def _finding_rows(findings: List[Vulnerability]) -> str:
    if not findings:
        return '<tr><td colspan="4" style="color:#3a3a3a;padding:8px">No findings in this domain ✅</td></tr>'
    rows = ""
    for v in findings:
        c = _severity_color(v.severity)
        rows += f"""<tr>
          <td><span style="background:{c};color:#000;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold">{v.severity.value}</span></td>
          <td style="color:#ccc">{v.title}</td>
          <td style="color:#888;font-size:12px">{Path(v.file_path).name}:{v.line_number}</td>
          <td style="color:#666;font-size:12px">{v.cwe_id} / {v.owasp_id}</td>
        </tr>"""
    return rows


def generate_compliance_html(
    result: ScanResult,
    framework: str = "soc2",
    org_name: str = "Your Organization",
) -> str:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fw = framework.lower()
    domain_map = ISO27001_DOMAINS if fw == "iso27001" else SOC2_DOMAINS
    fw_label = "ISO/IEC 27001:2022" if fw == "iso27001" else "SOC 2 Type II"
    grouped = _group_by_domain(result.vulnerabilities, domain_map)

    total = len(result.vulnerabilities)
    critical = result.metrics.critical_count
    high = result.metrics.high_count
    score = result.metrics.security_score

    domain_sections = ""
    for domain, findings in grouped.items():
        status = "PASS ✅" if not findings else f"⚠️ {len(findings)} Finding(s)"
        status_color = "#01FFC3" if not findings else "#FF5E00"
        domain_sections += f"""
        <div class="domain">
          <div class="domain-header">
            <span class="domain-title">{domain}</span>
            <span style="color:{status_color};font-weight:bold;font-size:13px">{status}</span>
          </div>
          <table><tr>
            <th>Severity</th><th>Finding</th><th>Location</th><th>Standard</th>
          </tr>{_finding_rows(findings)}</table>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ZEPY Compliance Evidence — {fw_label}</title>
<style>
  body{{font-family:'Segoe UI',sans-serif;background:#0B0F19;color:#E0E0E0;margin:0;padding:32px}}
  .header{{border-bottom:2px solid #FF2A6D;padding-bottom:16px;margin-bottom:24px}}
  h1{{color:#FF2A6D;font-size:24px;margin:0}} h2{{color:#05D9E8;font-size:18px}}
  .meta{{color:#666;font-size:13px;margin-top:4px}}
  .summary-row{{display:flex;gap:16px;margin-bottom:28px}}
  .scard{{background:#131928;border:1px solid #222;border-radius:8px;padding:14px 20px;min-width:110px}}
  .scard .num{{font-size:28px;font-weight:bold}}
  .crit{{color:#FF2A6D}} .high{{color:#FF5E00}} .score-c{{color:#05D9E8}}
  .domain{{background:#131928;border:1px solid #1e2a40;border-radius:8px;padding:16px 20px;margin-bottom:16px}}
  .domain-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}}
  .domain-title{{color:#ccc;font-weight:600;font-size:14px}}
  table{{width:100%;border-collapse:collapse}}
  th{{background:#1a2035;color:#888;text-align:left;padding:6px 10px;font-size:12px}}
  td{{padding:6px 10px;border-bottom:1px solid #1a2035;vertical-align:top;font-size:13px}}
  .footer{{color:#333;font-size:11px;margin-top:40px;border-top:1px solid #1a2035;padding-top:12px}}
  .disclaimer{{background:#1a1a0a;border:1px solid #333;border-radius:6px;padding:12px 16px;margin-bottom:24px;color:#888;font-size:12px}}
</style>
</head>
<body>
<div class="header">
  <h1>⚡ ZEPY AI Security — Compliance Evidence Report</h1>
  <div class="meta">
    Framework: <strong style="color:#ccc">{fw_label}</strong> &nbsp;|&nbsp;
    Organization: <strong style="color:#ccc">{org_name}</strong> &nbsp;|&nbsp;
    Generated: <strong style="color:#ccc">{now_str}</strong> &nbsp;|&nbsp;
    Target: <code style="color:#aaa">{result.target_path}</code>
  </div>
</div>

<div class="disclaimer">
  ⚠️ <strong>Disclaimer:</strong> This report is auto-generated security evidence produced by ZEPY's static analysis engine.
  It supplements (not replaces) a formal compliance audit conducted by a qualified assessor.
</div>

<h2>Executive Summary</h2>
<div class="summary-row">
  <div class="scard"><div class="num score-c">{score}</div><div>Security Score / 100</div></div>
  <div class="scard"><div class="num crit">{critical}</div><div>Critical</div></div>
  <div class="scard"><div class="num high">{high}</div><div>High</div></div>
  <div class="scard"><div class="num" style="color:#ccc">{total}</div><div>Total Findings</div></div>
  <div class="scard"><div class="num" style="color:#aaa">{result.metrics.total_files_scanned}</div><div>Files Scanned</div></div>
</div>

<h2>{fw_label} Control Domain Findings</h2>
{domain_sections}

<div class="footer">
  Generated by ZEPY AI-Shield v1.0.0 &nbsp;|&nbsp;
  Scan ID: {result.timestamp} &nbsp;|&nbsp;
  <a href="https://github.com/4mm47/zepy" style="color:#05D9E8">github.com/4mm47/zepy</a>
</div>
</body>
</html>"""


def export_compliance_report(
    result: ScanResult,
    output_path: str,
    framework: str = "soc2",
    org_name: str = "Your Organization",
) -> None:
    html = generate_compliance_html(result, framework, org_name)
    Path(output_path).write_text(html, encoding="utf-8")
