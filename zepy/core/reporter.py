"""
Zepy - AI Vulnerability Detection Framework
Reporter: Generates Rich Console tables, Standalone Cyber Dark HTML, JSON, and CSV reports.
"""

import os
import csv
import json
from typing import List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.syntax import Syntax

from zepy.core.models import ScanResult, Vulnerability, Severity
from zepy.core.banner import print_banner

import sys

# Ensure stdout and stderr use utf-8 on Windows
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(force_terminal=True)


class SecurityReporter:
    @staticmethod
    def print_cli_report(result: ScanResult) -> None:
        """Renders an aesthetically rich cybersecurity scan report to the terminal."""
        print_banner()

        metrics = result.metrics
        
        # 1. Summary Cards
        summary_table = Table(box=box.ROUNDED, expand=True, border_style="bold #05D9E8")
        summary_table.add_column("[*] Target Path", style="bold white")
        summary_table.add_column("Files Scanned", justify="center", style="cyan")
        summary_table.add_column("Total Lines", justify="center", style="cyan")
        summary_table.add_column("Scan Time", justify="center", style="magenta")
        summary_table.add_column("Security Score", justify="center", style="bold green" if metrics.security_score >= 80 else "bold yellow" if metrics.security_score >= 50 else "bold red")

        summary_table.add_row(
            os.path.basename(result.target_path) or result.target_path,
            str(metrics.total_files_scanned),
            f"{metrics.total_lines_scanned:,}",
            f"{metrics.scan_duration_seconds:.2f}s",
            f"{metrics.security_score}/100"
        )
        console.print(summary_table)

        # 2. Severity Breakdown Bar
        sev_table = Table(box=box.SIMPLE_HEAVY, expand=True)
        sev_table.add_column("CRITICAL", justify="center", style="bold red")
        sev_table.add_column("HIGH", justify="center", style="bold dark_orange")
        sev_table.add_column("MEDIUM", justify="center", style="bold yellow")
        sev_table.add_column("LOW", justify="center", style="bold cyan")
        sev_table.add_column("INFO", justify="center", style="bold green")

        sev_table.add_row(
            str(metrics.critical_count),
            str(metrics.high_count),
            str(metrics.medium_count),
            str(metrics.low_count),
            str(metrics.info_count)
        )
        console.print(Panel(sev_table, title="[bold #FF2A6D]── Vulnerability Severity Breakdown ──[/bold #FF2A6D]", border_style="#FF2A6D", box=box.ROUNDED))

        # 3. Detailed Findings List
        if not result.vulnerabilities:
            console.print(Panel(
                Text("[+] No vulnerabilities detected! The codebase passed all AI security checks.", style="bold green", justify="center"),
                border_style="green", box=box.ROUNDED
            ))
            return

        findings_table = Table(
            title=f"Detected Vulnerabilities ({len(result.vulnerabilities)} findings)",
            box=box.HEAVY_EDGE,
            header_style="bold bright_white on #161b22",
            border_style="#05D9E8",
            expand=True
        )
        findings_table.add_column("Severity", justify="center", width=12)
        findings_table.add_column("Vulnerability Title / ID", style="bold white", width=34)
        findings_table.add_column("Location", style="cyan", width=26)
        findings_table.add_column("Standard / CWE", style="yellow", width=16)
        findings_table.add_column("Remediation", style="green")

        for v in result.vulnerabilities:
            sev_badge = f"[{v.severity.rich_color}]{v.severity.value}[/{v.severity.rich_color}]"
            rel_file = os.path.relpath(v.file_path, os.path.dirname(result.target_path)) if os.path.dirname(result.target_path) else os.path.basename(v.file_path)
            loc_str = f"{rel_file}:{v.line_number}"
            std_str = f"{v.owasp_id.split(':')[0] if v.owasp_id else ''}\n{v.cwe_id}"

            findings_table.add_row(
                sev_badge,
                f"[bold]{v.title}[/bold]\n[dim]{v.id}[/dim]",
                loc_str,
                std_str,
                v.remediation[:120] + ("..." if len(v.remediation) > 120 else "")
            )

        console.print(findings_table)
        console.print(f"[dim]Run with [bold cyan]--html report.html[/bold cyan] to generate an interactive visual dashboard.[/dim]\n")

    @staticmethod
    def export_json(result: ScanResult, output_path: str) -> None:
        """Exports scan results to a formatted JSON file."""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result.to_json(indent=2))
        console.print(f"[bold green]✓[/bold green] JSON report generated: [cyan]{output_path}[/cyan]")

    @staticmethod
    def export_csv(result: ScanResult, output_path: str) -> None:
        """Exports findings to a CSV file."""
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "ID", "Title", "Severity", "Category", "File", "Line", "CWE", "OWASP", "Description", "Remediation"
            ])
            for v in result.vulnerabilities:
                writer.writerow([
                    v.id, v.title, v.severity.value, v.category.value if hasattr(v.category, "value") else str(v.category),
                    v.file_path, v.line_number, v.cwe_id, v.owasp_id, v.description, v.remediation
                ])
        console.print(f"[bold green]✓[/bold green] CSV report generated: [cyan]{output_path}[/cyan]")

    @staticmethod
    def export_html(result: ScanResult, output_path: str) -> None:
        """Generates a standalone, dark-cyberpunk interactive HTML dashboard report."""
        metrics = result.metrics
        score_color = "#01FFC3" if metrics.security_score >= 80 else "#FFB800" if metrics.security_score >= 50 else "#FF2A6D"
        
        # Build JSON findings for client-side search/filter
        findings_json = json.dumps([v.to_dict() for v in result.vulnerabilities])

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZEPY AI Vulnerability Audit Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg: #090D16;
            --surface: #121824;
            --surface-border: #1E293B;
            --text: #F8FAFC;
            --text-dim: #94A3B8;
            --zepy-crimson: #FF2A6D;
            --zepy-orange: #FF5E00;
            --zepy-amber: #FFB800;
            --zepy-cyan: #05D9E8;
            --zepy-mint: #01FFC3;
            --font-mono: 'Consolas', 'Monaco', 'Courier New', monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1300px;
            margin: 0 auto;
        }}
        /* Header & Banner */
        .header {{
            background: linear-gradient(135deg, rgba(255,42,109,0.12) 0%, rgba(5,217,232,0.08) 100%);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 24px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        }}
        .logo-title {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        .badge-zepy {{
            background: var(--zepy-crimson);
            color: #fff;
            padding: 4px 10px;
            font-weight: 800;
            font-size: 14px;
            border-radius: 6px;
            letter-spacing: 2px;
            text-transform: uppercase;
        }}
        .app-name {{
            font-size: 26px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(90deg, #FFFFFF, var(--zepy-cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .meta-text {{
            font-size: 13px;
            color: var(--text-dim);
            margin-top: 4px;
        }}
        /* Metric Grid */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .metric-card {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            transition: transform 0.2s ease, border-color 0.2s ease;
        }}
        .metric-card:hover {{
            transform: translateY(-2px);
            border-color: var(--zepy-cyan);
        }}
        .metric-value {{
            font-size: 32px;
            font-weight: 800;
            margin-bottom: 4px;
        }}
        .metric-label {{
            font-size: 13px;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        /* Charts & Breakdown Section */
        .visual-section {{
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }}
        .chart-box {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }}
        .chart-box h3 {{
            font-size: 15px;
            margin-bottom: 12px;
            color: var(--text-dim);
        }}
        .summary-box {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 24px;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }}
        .summary-box h3 {{
            font-size: 18px;
            margin-bottom: 12px;
            color: var(--zepy-cyan);
        }}
        .summary-box p {{
            color: var(--text-dim);
            font-size: 14px;
            line-height: 1.6;
        }}
        /* Filter & Search Bar */
        .filter-bar {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 10px;
            padding: 14px 20px;
            display: flex;
            gap: 12px;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}
        .search-input {{
            background: var(--bg);
            border: 1px solid var(--surface-border);
            color: #fff;
            padding: 8px 14px;
            border-radius: 6px;
            flex: 1;
            min-width: 250px;
            font-size: 14px;
        }}
        .filter-btn {{
            background: var(--surface-border);
            border: none;
            color: var(--text);
            padding: 8px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 13px;
            transition: all 0.2s;
        }}
        .filter-btn.active {{
            background: var(--zepy-cyan);
            color: #000;
        }}
        /* Findings Table & Accordion */
        .finding-card {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 10px;
            margin-bottom: 14px;
            overflow: hidden;
            transition: border-color 0.2s;
        }}
        .finding-card:hover {{
            border-color: #334155;
        }}
        .finding-header {{
            padding: 16px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            user-select: none;
        }}
        .finding-title-group {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .sev-tag {{
            font-weight: 800;
            font-size: 11px;
            padding: 4px 8px;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .sev-CRITICAL {{ background: rgba(255,42,109,0.2); color: var(--zepy-crimson); border: 1px solid var(--zepy-crimson); }}
        .sev-HIGH {{ background: rgba(255,94,0,0.2); color: var(--zepy-orange); border: 1px solid var(--zepy-orange); }}
        .sev-MEDIUM {{ background: rgba(255,184,0,0.2); color: var(--zepy-amber); border: 1px solid var(--zepy-amber); }}
        .sev-LOW {{ background: rgba(5,217,232,0.2); color: var(--zepy-cyan); border: 1px solid var(--zepy-cyan); }}
        .sev-INFO {{ background: rgba(1,255,195,0.2); color: var(--zepy-mint); border: 1px solid var(--zepy-mint); }}

        .finding-title {{
            font-weight: 700;
            font-size: 15px;
        }}
        .finding-location {{
            font-family: var(--font-mono);
            font-size: 13px;
            color: var(--zepy-cyan);
        }}
        .finding-body {{
            padding: 0 20px 20px 20px;
            border-top: 1px solid var(--surface-border);
            background: rgba(0,0,0,0.2);
            display: block;
        }}
        .finding-desc {{
            margin-top: 14px;
            font-size: 14px;
            color: #CBD5E1;
        }}
        .code-snippet {{
            background: #030712;
            border: 1px solid #1F2937;
            border-radius: 6px;
            padding: 12px;
            font-family: var(--font-mono);
            font-size: 13px;
            margin-top: 12px;
            color: #E2E8F0;
            overflow-x: auto;
            white-space: pre;
        }}
        .remediation-box {{
            background: rgba(1, 255, 195, 0.05);
            border-left: 4px solid var(--zepy-mint);
            padding: 12px 16px;
            border-radius: 0 6px 6px 0;
            margin-top: 14px;
            font-size: 13px;
        }}
        .remediation-title {{
            font-weight: 700;
            color: var(--zepy-mint);
            margin-bottom: 4px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="logo-title">
                    <span class="badge-zepy">ZEPY</span>
                    <h1 class="app-name">ZEPY AI Vulnerability Auditor</h1>
                </div>
                <div class="meta-text">Target: <strong>{result.target_path}</strong> • Generated on {result.timestamp}</div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 12px; color: var(--text-dim);">SECURITY POSTURE SCORE</div>
                <div style="font-size: 38px; font-weight: 900; color: {score_color};">{metrics.security_score} <span style="font-size: 18px; color: var(--text-dim);">/ 100</span></div>
            </div>
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value" style="color: var(--zepy-crimson);">{metrics.critical_count}</div>
                <div class="metric-label">Critical Risks</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: var(--zepy-orange);">{metrics.high_count}</div>
                <div class="metric-label">High Risks</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: var(--zepy-amber);">{metrics.medium_count}</div>
                <div class="metric-label">Medium Risks</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: var(--zepy-cyan);">{metrics.low_count}</div>
                <div class="metric-label">Low Risks</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: #fff;">{metrics.total_files_scanned}</div>
                <div class="metric-label">Files Scanned</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: #fff;">{metrics.scan_duration_seconds:.2f}s</div>
                <div class="metric-label">Audit Duration</div>
            </div>
        </div>

        <div class="visual-section">
            <div class="chart-box">
                <h3>Severity Distribution</h3>
                <canvas id="sevChart" width="220" height="220"></canvas>
            </div>
            <div class="summary-box">
                <h3>⚡ ZEPY Executive Security Assessment</h3>
                <p>
                    The scan analyzed <strong>{metrics.total_files_scanned} files</strong> ({metrics.total_lines_scanned:,} lines) and identified <strong>{len(result.vulnerabilities)} security issues</strong>.
                    {'Immediate remediation is required for Critical and High severity findings to prevent potential remote code execution or model credential exposure.' if metrics.critical_count + metrics.high_count > 0 else 'Great job! No high-severity vulnerabilities were detected during static analysis.'}
                </p>
            </div>
        </div>

        <div class="filter-bar">
            <input type="text" id="searchInput" class="search-input" placeholder="Search findings by rule ID, title, file path, CWE..." onkeyup="renderFindings()">
            <button class="filter-btn active" onclick="setSeverityFilter('ALL', this)">ALL ({len(result.vulnerabilities)})</button>
            <button class="filter-btn" onclick="setSeverityFilter('CRITICAL', this)">Critical ({metrics.critical_count})</button>
            <button class="filter-btn" onclick="setSeverityFilter('HIGH', this)">High ({metrics.high_count})</button>
            <button class="filter-btn" onclick="setSeverityFilter('MEDIUM', this)">Medium ({metrics.medium_count})</button>
            <button class="filter-btn" onclick="setSeverityFilter('LOW', this)">Low ({metrics.low_count})</button>
        </div>

        <div id="findingsContainer"></div>
    </div>

    <script>
        const findings = {findings_json};
        let activeSeverity = 'ALL';

        function renderChart() {{
            const ctx = document.getElementById('sevChart').getContext('2d');
            new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{{
                        data: [{metrics.critical_count}, {metrics.high_count}, {metrics.medium_count}, {metrics.low_count}, {metrics.info_count}],
                        backgroundColor: ['#FF2A6D', '#FF5E00', '#FFB800', '#05D9E8', '#01FFC3'],
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: false,
                    plugins: {{ legend: {{ display: false }} }},
                    cutout: '72%'
                }}
            }});
        }}

        function setSeverityFilter(sev, btn) {{
            activeSeverity = sev;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderFindings();
        }}

        function renderFindings() {{
            const container = document.getElementById('findingsContainer');
            const search = document.getElementById('searchInput').value.toLowerCase();
            container.innerHTML = '';

            const filtered = findings.filter(v => {{
                const matchesSev = (activeSeverity === 'ALL' || v.severity === activeSeverity);
                const matchesSearch = !search || 
                    v.title.toLowerCase().includes(search) || 
                    v.id.toLowerCase().includes(search) ||
                    v.file_path.toLowerCase().includes(search) ||
                    (v.cwe_id && v.cwe_id.toLowerCase().includes(search)) ||
                    (v.owasp_id && v.owasp_id.toLowerCase().includes(search));
                return matchesSev && matchesSearch;
            }});

            if (filtered.length === 0) {{
                container.innerHTML = '<div style="text-align: center; padding: 40px; color: var(--text-dim);">No matching vulnerabilities found.</div>';
                return;
            }}

            filtered.forEach((v, index) => {{
                const card = document.createElement('div');
                card.className = 'finding-card';
                card.innerHTML = `
                    <div class="finding-header" onclick="toggleBody('body-${{index}}')">
                        <div class="finding-title-group">
                            <span class="sev-tag sev-${{v.severity}}">${{v.severity}}</span>
                            <span class="finding-title">${{v.title}}</span>
                        </div>
                        <div class="finding-location">${{v.file_path}}:${{v.line_number}}</div>
                    </div>
                    <div id="body-${{index}}" class="finding-body">
                        <div class="finding-desc">${{v.description}}</div>
                        ${{v.code_snippet ? `<div class="code-snippet">${{escapeHtml(v.code_snippet)}}</div>` : ''}}
                        <div class="remediation-box">
                            <div class="remediation-title">🛡️ Remediation Strategy (${{v.cwe_id || 'Security Fix'}} • ${{v.owasp_id || 'Standard'}}):</div>
                            <div>${{v.remediation}}</div>
                        </div>
                    </div>
                `;
                container.appendChild(card);
            }});
        }}

        function toggleBody(id) {{
            const el = document.getElementById(id);
            if (el) el.style.display = (el.style.display === 'none') ? 'block' : 'none';
        }}

        function escapeHtml(str) {{
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }}

        window.onload = function() {{
            renderChart();
            renderFindings();
        }};
    </script>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        console.print(f"[bold green]✓[/bold green] Standalone Cyber HTML report generated: [cyan]{output_path}[/cyan]")
