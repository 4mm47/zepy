"""
Zepy - AI Vulnerability Detection Framework
CLI Interface: Advanced AI & LLM static vulnerability detection system.
"""

import sys
import os
import argparse
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from zepy.core.banner import print_banner, print_quick_banner
from zepy.core.models import Severity
from zepy.core.engine import SecurityScanEngine
from zepy.core.reporter import SecurityReporter
from zepy.core.diff_engine import DiffEngine
from zepy.detectors.prompt_analyzer import PromptAnalyzer
from zepy.rules.rule_manager import RuleManager
from zepy.integrations.ci_generator import write_ci_file
from zepy.integrations.sbom import export_sbom
from zepy.integrations.compliance import export_compliance_report
from zepy.integrations.audit_log import read_audit_log, log_prompt_analysis

console = Console()


def handle_scan(args):
    """Handles scanning a target folder or file from CLI."""
    target_path = args.path or "."
    if not os.path.exists(target_path):
        console.print(f"[bold red]Error:[/bold red] Target path '{target_path}' does not exist.")
        sys.exit(1)

    sev_filter = None
    if args.severity:
        try:
            sev_filter = Severity(args.severity.upper())
        except ValueError:
            console.print(f"[bold yellow]Warning:[/bold yellow] Invalid severity filter '{args.severity}'. Ignoring.")

    engine = SecurityScanEngine(
        max_workers=args.workers or 4,
        custom_rules_path=args.custom_rules,
        target_dir=target_path
    )

    with console.status(f"[bold cyan]Auditing AI Codebase, Model Pipelines & Checkpoints in '{target_path}'...[/bold cyan]", spinner="dots"):
        result = engine.scan(target_path, severity_filter=sev_filter)

    # Baseline Diff Mode
    if args.baseline:
        baseline_result = DiffEngine.load_baseline(args.baseline)
        if baseline_result:
            diff_report = DiffEngine.compute_diff(baseline_result, result)
            s = diff_report.summary
            diff_table = Table(title="⚡ Baseline Regression Diff Analysis", box=box.ROUNDED, border_style="magenta")
            diff_table.add_column("Regression Type", style="bold white")
            diff_table.add_column("Count", justify="center")
            diff_table.add_row("🔴 New Findings (Regressions)", f"[bold red]{s['new']}[/bold red]")
            diff_table.add_row("✅ Fixed Findings", f"[bold green]{s['fixed']}[/bold green]")
            diff_table.add_row("🔁 Persisting Findings", f"[yellow]{s['persisting']}[/yellow]")
            console.print(diff_table)

            if args.diff_html:
                DiffEngine.export_diff_html(diff_report, args.diff_html)
                console.print(f"[bold green]✓[/bold green] Diff HTML report generated: [cyan]{args.diff_html}[/cyan]")
        else:
            console.print(f"[bold yellow]Warning:[/bold yellow] Could not load baseline report at '{args.baseline}'.")

    # 1. Print CLI Report
    SecurityReporter.print_cli_report(result)

    # 2. Exports
    if args.html:
        SecurityReporter.export_html(result, args.html)
    if args.json:
        SecurityReporter.export_json(result, args.json)
    if args.csv:
        SecurityReporter.export_csv(result, args.csv)
    if args.sarif:
        SecurityReporter.export_sarif(result, args.sarif)

    # 3. Policy Enforcement (--fail-on)
    if args.fail_on:
        try:
            fail_sev = Severity(args.fail_on.upper())
            matching_findings = [v for v in result.vulnerabilities if v.severity.weight >= fail_sev.weight]
            if matching_findings:
                console.print(f"\n[bold red]❌ POLICY VIOLATION:[/bold red] Found {len(matching_findings)} issue(s) at or above [bold]{fail_sev.value}[/bold] severity.")
                sys.exit(3)
        except ValueError:
            console.print(f"[bold yellow]Warning:[/bold yellow] Invalid --fail-on severity '{args.fail_on}'.")

    # Standard exit code
    if result.metrics.critical_count > 0:
        sys.exit(2)
    elif result.metrics.high_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


def handle_prompt_analysis(args):
    """Handles live prompt security analysis."""
    print_quick_banner()
    prompt_text = args.prompt_text

    if not prompt_text:
        console.print("[bold yellow]Enter prompt string to evaluate (Ctrl+C to cancel):[/bold yellow]")
        prompt_text = input("> ")

    analyzer = PromptAnalyzer()
    detection = analyzer.analyze_prompt(prompt_text)

    # Log to audit trail
    try:
        log_prompt_analysis(detection.threat_score, detection.threat_level.value, detection.threat_types)
    except Exception:
        pass

    # Print Result Card
    card_table = Table(box=box.ROUNDED, expand=True, border_style="#05D9E8")
    card_table.add_column("Property", style="bold white", width=22)
    card_table.add_column("Security Assessment", style="cyan")

    card_table.add_row("Threat Level", f"[{detection.threat_level.rich_color}]{detection.threat_level.value}[/{detection.threat_level.rich_color}]")
    card_table.add_row("Threat Score", f"{detection.threat_score:.1f} / 100.0")
    card_table.add_row("Shannon Entropy", f"{detection.entropy_score:.2f}")
    card_table.add_row("Obfuscation Detected", f"[bold red]YES[/bold red]" if detection.obfuscation_detected else "[green]None[/green]")
    card_table.add_row("Attack Vectors", ", ".join(detection.threat_types) if detection.threat_types else "None (Benign)")

    console.print(Panel(card_table, title="[bold #FF2A6D]⚡ ZEPY Live Prompt Threat Report ⚡[/bold #FF2A6D]", box=box.HEAVY_EDGE))

    if detection.matched_patterns:
        console.print("\n[bold #FF5E00]Matched Threat Indicators:[/bold #FF5E00]")
        for pat in detection.matched_patterns:
            console.print(f"  [red]•[/red] [dim]{pat}[/dim]")

    console.print("\n[bold #01FFC3]🛡️ Defense & Guardrail Remediation:[/bold #01FFC3]")
    console.print(f"  {detection.remediation_advice}\n")


def handle_rules(args):
    """Displays all active rules in the knowledgebase."""
    print_quick_banner()
    rule_mgr = RuleManager()
    rules = rule_mgr.get_all_rules()

    table = Table(title=f"🛡️ ZEPY Security Knowledgebase ({len(rules)} Active Rules)", box=box.ROUNDED, expand=True)
    table.add_column("Rule ID", style="bold cyan", width=16)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Standard / CWE", style="yellow", width=18)
    table.add_column("Title & Description", style="white")

    for r in rules:
        table.add_row(
            r.id,
            f"[{r.severity.rich_color}]{r.severity.value}[/{r.severity.rich_color}]",
            f"{r.owasp_id.split(':')[0] if r.owasp_id else ''}\n{r.cwe_id}",
            f"[bold]{r.title}[/bold]\n[dim]{r.description[:110]}...[/dim]"
        )

    console.print(table)


def handle_generate_ci(args):
    """Generates CI/CD workflow files."""
    print_quick_banner()
    platform = args.platform.lower()
    out_dir = args.output or "."
    fail_on = args.fail_on or "HIGH"

    try:
        written_path = write_ci_file(platform, output_dir=out_dir, fail_on=fail_on)
        console.print(Panel(
            f"[bold green]✓ Successfully generated {platform.upper()} CI workflow![/bold green]\n\n"
            f"File created: [bold cyan]{written_path}[/bold cyan]\n"
            f"Policy: Fail on [bold]{fail_on}[/bold] severity and above.",
            title="CI/CD Workflow Generated",
            border_style="green"
        ))
    except Exception as e:
        console.print(f"[bold red]Failed to generate CI file:[/bold red] {e}")


def handle_sbom(args):
    """Generates CycloneDX SBOM."""
    print_quick_banner()
    target_path = args.path or "."
    output_path = args.output or "zepy-sbom.json"

    engine = SecurityScanEngine(target_dir=target_path)
    with console.status("[bold cyan]Generating CycloneDX Software Bill of Materials...[/bold cyan]"):
        result = engine.scan(target_path)
        export_sbom(output_path, scan_result=result, project_name=os.path.basename(os.path.abspath(target_path)))

    console.print(Panel(
        f"[bold green]✓ CycloneDX v1.5 SBOM generated successfully![/bold green]\n\n"
        f"Output file: [bold cyan]{output_path}[/bold cyan]\n"
        f"Includes Python dependencies with PURLs and mapped vulnerabilities.",
        title="CycloneDX SBOM",
        border_style="green"
    ))


def handle_compliance(args):
    """Generates SOC 2 or ISO 27001 compliance evidence report."""
    print_quick_banner()
    target_path = args.path or "."
    framework = args.framework or "soc2"
    output_path = args.output or f"zepy-compliance-{framework}.html"
    org_name = args.org or "Your Organization"

    engine = SecurityScanEngine(target_dir=target_path)
    with console.status(f"[bold cyan]Compiling {framework.upper()} compliance evidence report...[/bold cyan]"):
        result = engine.scan(target_path)
        export_compliance_report(result, output_path=output_path, framework=framework, org_name=org_name)

    console.print(Panel(
        f"[bold green]✓ Compliance Evidence Report Generated![/bold green]\n\n"
        f"Framework: [bold]{framework.upper()}[/bold]\n"
        f"Report file: [bold cyan]{output_path}[/bold cyan]\n"
        f"Mapped {len(result.vulnerabilities)} findings to control domains.",
        title="Compliance Evidence",
        border_style="green"
    ))


def handle_audit(args):
    """Displays recent scan and security audit log entries."""
    print_quick_banner()
    limit = args.limit or 20
    entries = read_audit_log(limit=limit)

    if not entries:
        console.print("[dim]No audit log entries found yet. Run a scan to populate the audit trail.[/dim]")
        return

    table = Table(title=f"📜 ZEPY Local Audit Log (Last {len(entries)} events)", box=box.ROUNDED, expand=True)
    table.add_column("Timestamp (UTC)", style="dim", width=22)
    table.add_column("Event", style="bold cyan", width=18)
    table.add_column("Details", style="white")

    for e in entries:
        evt = e.get("event", "unknown")
        ts = e.get("timestamp", "")[:19].replace("T", " ")
        if evt == "scan":
            det = f"Target: {e.get('target', '')} | Score: {e.get('security_score', '')} | Findings: {e.get('findings', {}).get('total', 0)}"
        elif evt == "prompt_analysis":
            det = f"Threat Level: {e.get('threat_level', '')} | Score: {e.get('threat_score', '')} | Vectors: {', '.join(e.get('attack_vectors', []))}"
        else:
            det = str(e)
        table.add_row(ts, evt, det)

    console.print(table)


def handle_gui(args):
    """Launches the PyQt5 Desktop GUI."""
    try:
        from zepy.gui.app import run_gui
        run_gui()
    except Exception as e:
        console.print(f"[bold red]Failed to launch GUI:[/bold red] {e}")


def main():
    parser = argparse.ArgumentParser(
        prog="zepy",
        description="ZEPY — Advanced AI & LLM Static Vulnerability Detection System"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # 1. Scan Command
    scan_parser = subparsers.add_parser("scan", help="Scan a directory or file for AI vulnerabilities & supply chain risks")
    scan_parser.add_argument("path", nargs="?", default=".", help="Target directory or file path (default: current dir)")
    scan_parser.add_argument("--html", type=str, help="Generate interactive HTML report file path")
    scan_parser.add_argument("--json", type=str, help="Generate JSON report file path")
    scan_parser.add_argument("--csv", type=str, help="Generate CSV report file path")
    scan_parser.add_argument("--sarif", type=str, help="Generate SARIF v2.1 report for GitHub / VS Code / GitLab")
    scan_parser.add_argument("--baseline", type=str, help="Path to baseline JSON report for regression diff scan")
    scan_parser.add_argument("--diff-html", type=str, help="Path to write regression diff HTML report")
    scan_parser.add_argument("--custom-rules", type=str, help="Path to custom YAML rule definitions file")
    scan_parser.add_argument("--fail-on", type=str, choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="CI/CD policy threshold to fail build")
    scan_parser.add_argument("--severity", type=str, choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], help="Filter by minimum severity")
    scan_parser.add_argument("--workers", type=int, default=4, help="Number of concurrent scanning threads")
    scan_parser.set_defaults(func=handle_scan)

    # 2. Prompt Test Command
    prompt_parser = subparsers.add_parser("prompt", help="Analyze raw prompt string for jailbreaks & injection")
    prompt_parser.add_argument("prompt_text", nargs="?", default="", help="Prompt string to analyze")
    prompt_parser.set_defaults(func=handle_prompt_analysis)

    # 3. Rules Command
    rules_parser = subparsers.add_parser("rules", help="List all built-in security rules and CWE/OWASP mappings")
    rules_parser.set_defaults(func=handle_rules)

    # 4. Generate CI Command
    ci_parser = subparsers.add_parser("generate-ci", help="Generate GitHub Actions, GitLab CI, or pre-commit config")
    ci_parser.add_argument("--platform", type=str, default="github", choices=["github", "gitlab", "pre-commit"], help="Target CI platform")
    ci_parser.add_argument("--output", type=str, default=".", help="Output directory")
    ci_parser.add_argument("--fail-on", type=str, default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Policy failure severity threshold")
    ci_parser.set_defaults(func=handle_generate_ci)

    # 5. SBOM Command
    sbom_parser = subparsers.add_parser("sbom", help="Generate CycloneDX v1.5 Software Bill of Materials (SBOM)")
    sbom_parser.add_argument("path", nargs="?", default=".", help="Target project directory")
    sbom_parser.add_argument("--output", type=str, default="zepy-sbom.json", help="Output SBOM JSON path")
    sbom_parser.set_defaults(func=handle_sbom)

    # 6. Compliance Command
    comp_parser = subparsers.add_parser("compliance", help="Generate SOC 2 or ISO 27001 compliance evidence report")
    comp_parser.add_argument("path", nargs="?", default=".", help="Target project directory")
    comp_parser.add_argument("--framework", type=str, default="soc2", choices=["soc2", "iso27001"], help="Compliance standard")
    comp_parser.add_argument("--output", type=str, default=None, help="Output HTML file path")
    comp_parser.add_argument("--org", type=str, default="Your Organization", help="Organization name")
    comp_parser.set_defaults(func=handle_compliance)

    # 7. Audit Log Command
    audit_parser = subparsers.add_parser("audit", help="View local append-only security audit log")
    audit_parser.add_argument("--limit", type=int, default=20, help="Number of recent entries to show")
    audit_parser.set_defaults(func=handle_audit)

    # 8. GUI Command
    gui_parser = subparsers.add_parser("gui", help="Launch the Zepy PyQt5 Dark Cyber Desktop GUI")
    gui_parser.set_defaults(func=handle_gui)

    # Default action if no args
    if len(sys.argv) == 1:
        print_banner()
        parser.print_help()
        return

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        print_banner()
        parser.print_help()


if __name__ == "__main__":
    main()
