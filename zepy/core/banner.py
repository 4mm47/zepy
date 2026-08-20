"""
Zepy - AI Vulnerability Detection Framework
RARE Cyber ASCII Banner and Terminal Styler
"""

import sys
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

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

# High-impact cyber cyberpunk ZEPY ASCII Art
ZEPY_ASCII_LOGO = r"""
███████╗███████╗██████╗ ██╗   ██╗
╚══███╔╝██╔════╝██╔══██╗╚██╗ ██╔╝
  ███╔╝ █████╗  ██████╔╝ ╚████╔╝ 
 ███╔╝  ██╔══╝  ██╔═══╝   ╚██╔╝  
███████╗███████╗██║        ██║   
╚══════╝╚══════╝╚═╝        ╚═╝   
"""

# Alias for backwards compatibility
RARE_ASCII_LOGO = ZEPY_ASCII_LOGO

ZEPY_SUB_BANNER = r"""
  [+] Z E P Y  A I - S H I E L D  v 1 . 0 . 0
  ── Advanced LLM & AI Static Security Scanner ──
"""

MINI_LOGO = """
  Z E P Y  A I - V U L N E R A B I L I T Y - D E T E C T O R
"""


def print_banner(verbose: bool = True):
    """Prints the stylish signature ZEPY banner to terminal."""
    gradient_colors = ["#FF2A6D", "#FF5E00", "#FFB800", "#05D9E8", "#01FFC3"]
    
    logo_lines = ZEPY_ASCII_LOGO.strip().split("\n")
    styled_text = Text()
    
    for i, line in enumerate(logo_lines):
        color = gradient_colors[i % len(gradient_colors)]
        styled_text.append(line + "\n", style=f"bold {color}")
    
    styled_text.append(ZEPY_SUB_BANNER, style="bold cyan")

    panel = Panel(
        styled_text,
        box=box.DOUBLE_EDGE,
        border_style="bold bright_magenta",
        subtitle="[bold #01FFC3]Defensive AI Security Auditing Engine[/bold #01FFC3]",
        subtitle_align="center"
    )
    console.print(panel)


def print_quick_banner():
    """Prints a single-line compact cyber header."""
    console.print(f"[bold #FF2A6D][*] ZEPY[/bold #FF2A6D] [bold #05D9E8]AI Security Suite v1.0.0[/bold #05D9E8] [dim]| OWASP Top 10 LLM & SAST Engine[/dim]")

