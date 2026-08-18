"""
Zepy - AI Vulnerability Detection Framework
CLI Interface: Rich terminal scanner, prompt analyzer, rule viewer, and GUI launcher.
"""

import sys
import os
import argparse
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from zepy.core.banner import print_banner, print_quick_banner, RARE_ASCII_LOGO
from zepy.core.models import Severity
from zepy.core.engine import SecurityScanEngine
from zepy.core.reporter import SecurityReporter
from zepy.detectors.prompt_analyzer import PromptAnalyzer
from zepy.rules.rule_manager import RuleManager

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

    engine = SecurityScanEngine(max_workers=args.workers or 4)

    with console.status(f"[bold cyan]Auditing AI Codebase & Prompt Pipelines in '{target_path}'...[/bold cyan]", spinner="dots"):
        result = engine.scan(target_path, severity_filter=sev_filter)

    # 1. Print CLI Report
    SecurityReporter.print_cli_report(result)

    # 2. Exports
    if args.html:
        SecurityReporter.export_html(result, args.html)
    if args.json:
        SecurityReporter.export_json(result, args.json)
    if args.csv:
        SecurityReporter.export_csv(result, args.csv)

    # Exit code based on critical/high findings
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
    scan_parser = subparsers.add_parser("scan", help="Scan a directory or file for AI vulnerabilities")
    scan_parser.add_argument("path", nargs="?", default=".", help="Target directory or file path (default: current dir)")
    scan_parser.add_argument("--html", type=str, help="Generate interactive HTML report file path")
    scan_parser.add_argument("--json", type=str, help="Generate JSON report file path")
    scan_parser.add_argument("--csv", type=str, help="Generate CSV report file path")
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

    # 4. GUI Command
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
