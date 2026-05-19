"""
main.py
CRA SBOM Compliance Checker — CLI entry point.
Ties together SBOM parsing, CRA compliance checking,
NVD vulnerability lookup, and HTML report generation.
"""

import os
import sys
import subprocess
import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from sbom_parser import parse_sbom
from cra_checker import check_sbom
from nvd_lookup import lookup_all_components
from report import generate_report

app = typer.Typer(
    name="cra-sbom-checker",
    help="EU Cyber Resilience Act SBOM Compliance Checker",
    add_completion=False,
)

console = Console()


def print_banner():
    """Prints the tool banner."""
    console.print(Panel(
        "[bold white]CRA SBOM Compliance Checker[/bold white]\n"
        "[dim]EU Cyber Resilience Act — Annex I Gap Analysis Tool[/dim]\n"
        "[dim]Graduate Cybersecurity Research Project[/dim]",
        border_style="blue",
        padding=(1, 4),
    ))


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="Path to a CycloneDX JSON SBOM file OR a directory to scan with Syft"
    ),
    output: str = typer.Option(
        "report.html",
        "--output", "-o",
        help="Output path for the HTML report"
    ),
    api_key: str = typer.Option(
        None,
        "--api-key", "-k",
        help="NVD API key (or set NVD_API_KEY environment variable)"
    ),
    max_components: int = typer.Option(
        10,
        "--max-components", "-m",
        help="Maximum number of components to check against NVD"
    ),
    skip_nvd: bool = typer.Option(
        False,
        "--skip-nvd",
        help="Skip NVD vulnerability lookup (faster, offline mode)"
    ),
):
    """
    Scan a project or SBOM file for EU CRA compliance gaps.

    Examples:\n
        python main.py scan sample_sbom.json\n
        python main.py scan ./myproject --output myreport.html\n
        python main.py scan sample_sbom.json --skip-nvd\n
    """
    print_banner()

    # ── Step 1: Get or generate SBOM ──────────────────────────────────────
    sbom_path = target

    if not target.endswith(".json"):
        console.print(f"\n[bold blue]Step 1/4:[/bold blue] Generating SBOM for: {target}")
        sbom_path = "temp_scan_sbom.json"
        try:
            result = subprocess.run(
                ["syft", target, "-o", "cyclonedx-json"],
                capture_output=True,
                text=True
            )
            # Handle Windows encoding
            with open(sbom_path, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            console.print(f"[green]✓ SBOM generated: {sbom_path}[/green]")
        except Exception as e:
            console.print(f"[red]✗ Failed to generate SBOM: {e}[/red]")
            console.print("[yellow]Tip: Make sure Syft is installed and in your PATH[/yellow]")
            raise typer.Exit(1)
    else:
        console.print(f"\n[bold blue]Step 1/4:[/bold blue] Using existing SBOM: {target}")

    # ── Step 2: Parse SBOM ─────────────────────────────────────────────────
    console.print(f"\n[bold blue]Step 2/4:[/bold blue] Parsing SBOM...")
    try:
        # Handle Windows UTF-16 encoding
        try:
            parsed = parse_sbom(sbom_path)
        except Exception:
            with open(sbom_path, "w", encoding="utf-8") as f_out:
                f_out.write(
                    open(sbom_path, "r", encoding="utf-16").read()
                )
            parsed = parse_sbom(sbom_path)

        console.print(
            f"[green]✓ Parsed successfully — "
            f"{parsed['total_components']} components found[/green]"
        )
        meta = parsed["metadata"]
        console.print(f"  Project : {meta['project_name']}")
        console.print(f"  Version : {meta['project_version']}")
        console.print(f"  Tool    : {meta['tool']}")

    except Exception as e:
        console.print(f"[red]✗ Failed to parse SBOM: {e}[/red]")
        raise typer.Exit(1)

    # ── Step 3: CRA Compliance Check ───────────────────────────────────────
    console.print(f"\n[bold blue]Step 3/4:[/bold blue] Running CRA compliance checks...")
    try:
        checker_results = check_sbom(parsed)
        score = checker_results["score"]
        summary = checker_results["summary"]

        score_style = (
            "green" if score["label"] == "CRA COMPLIANT"
            else "yellow" if score["label"] == "PARTIALLY COMPLIANT"
            else "red"
        )

        console.print(
            f"[green]✓ Compliance check complete[/green]"
        )
        console.print(
            f"  Score  : [{score_style}][bold]{score['percentage']}% "
            f"— {score['label']}[/bold][/{score_style}]"
        )
        console.print(f"  Passed : [green]{summary['passed']}[/green]")
        console.print(f"  Failed : [red]{summary['failed']}[/red]")
        console.print(
            f"  HIGH failures   : [red]{summary['HIGH_fail']}[/red]"
        )
        console.print(
            f"  MEDIUM failures : [yellow]{summary['MEDIUM_fail']}[/yellow]"
        )

    except Exception as e:
        console.print(f"[red]✗ CRA check failed: {e}[/red]")
        raise typer.Exit(1)

    # ── Step 4: NVD Lookup ─────────────────────────────────────────────────
    nvd_results = {
        "all_cves": [],
        "total_cves": 0,
        "components_checked": 0,
        "severity_counts": {
            "CRITICAL": 0, "HIGH": 0,
            "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0
        },
        "component_results": {},
    }

    if skip_nvd:
        console.print(
            f"\n[bold blue]Step 4/4:[/bold blue] "
            f"[dim]NVD lookup skipped (--skip-nvd flag)[/dim]"
        )
    else:
        console.print(
            f"\n[bold blue]Step 4/4:[/bold blue] "
            f"Querying NVD API (up to {max_components} components)..."
        )

        # Resolve API key
        nvd_api_key = api_key or os.environ.get("NVD_API_KEY", "").strip()
        if not nvd_api_key:
            console.print(
                "[yellow]Warning: No NVD API key found. "
                "Set NVD_API_KEY or use --api-key[/yellow]"
            )
        else:
            console.print(
                f"[green]✓ NVD API key loaded ({len(nvd_api_key)} chars)[/green]"
            )

        try:
            nvd_results = lookup_all_components(
                parsed["components"],
                api_key=nvd_api_key,
                max_components=max_components,
            )
            counts = nvd_results["severity_counts"]
            console.print(
                f"[green]✓ NVD lookup complete — "
                f"{nvd_results['total_cves']} CVEs found[/green]"
            )
            console.print(
                f"  CRITICAL: [red]{counts['CRITICAL']}[/red]  "
                f"HIGH: [red]{counts['HIGH']}[/red]  "
                f"MEDIUM: [yellow]{counts['MEDIUM']}[/yellow]  "
                f"LOW: [green]{counts['LOW']}[/green]"
            )
        except Exception as e:
            console.print(f"[yellow]Warning: NVD lookup failed: {e}[/yellow]")
            console.print("[yellow]Continuing without vulnerability data...[/yellow]")

    # ── Generate Report ────────────────────────────────────────────────────
    console.print(f"\n[bold]Generating HTML report...[/bold]")
    try:
        report_path = generate_report(
            checker_results=checker_results,
            nvd_results=nvd_results,
            output_path=output,
        )
        console.print(f"[green]✓ Report saved: {report_path}[/green]")
    except Exception as e:
        console.print(f"[red]✗ Report generation failed: {e}[/red]")
        raise typer.Exit(1)

    # ── Final Summary ──────────────────────────────────────────────────────
    console.print(Panel(
        f"[bold]Scan Complete![/bold]\n\n"
        f"Project     : {parsed['metadata']['project_name']}\n"
        f"Components  : {parsed['total_components']}\n"
        f"CRA Score   : [{score_style}]{score['percentage']}% "
        f"— {score['label']}[/{score_style}]\n"
        f"CVEs Found  : {nvd_results['total_cves']}\n"
        f"Report      : {output}",
        border_style="green",
        title="✓ Done",
    ))

    console.print(
        f"\n[dim]Open [bold]{output}[/bold] in your browser to view the full report.[/dim]\n"
    )


if __name__ == "__main__":
    app()