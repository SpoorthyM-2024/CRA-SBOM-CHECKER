"""
nvd_lookup.py
Queries the NIST National Vulnerability Database (NVD) API
to find known CVEs for each component in the SBOM.
"""

import os
import time
import sys
import requests
from dataclasses import dataclass
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from sbom_parser import parse_sbom

# NVD API endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limiting — 0.6 seconds between requests to stay within NVD limits
REQUEST_DELAY = 0.6

console = Console()


@dataclass
class CVE:
    """Represents a single CVE finding."""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published: str
    component: str
    version: str


def lookup_component(
    name: str,
    version: Optional[str],
    api_key: Optional[str] = None
) -> list:
    """
    Queries NVD API for CVEs matching a component name.
    Returns a list of CVE objects.
    """
    if not name or name.strip().lower() == "unknown":
        return []

    # Clean up component name for search
    keyword = name.replace("/", " ").replace("-", " ").strip()
    if not keyword:
        return []

    headers = {}
    if api_key:
        headers["apiKey"] = api_key.strip()

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 5,
    }

    try:
        response = requests.get(
            NVD_API_URL,
            headers=headers,
            params=params,
            timeout=15
        )

        if response.status_code == 200:
            data = response.json()
            cves = _parse_cve_response(data, name, version or "unknown")
            return cves

        elif response.status_code == 403:
            console.print(f"  [red][!] API key invalid or rate limit hit for: {name}[/red]")
            return []

        elif response.status_code == 404:
            return []

        else:
            console.print(f"  [yellow][!] NVD API returned {response.status_code} for: {name}[/yellow]")
            return []

    except requests.exceptions.Timeout:
        console.print(f"  [yellow][!] Timeout for: {name}[/yellow]")
        return []

    except requests.exceptions.ConnectionError:
        console.print(f"  [red][!] Connection error for: {name}[/red]")
        return []

    except Exception as e:
        console.print(f"  [red][!] Unexpected error for {name}: {e}[/red]")
        return []


def _parse_cve_response(
    data: dict,
    component_name: str,
    version: str
) -> list:
    """Parses NVD API response into CVE objects."""
    cves = []
    vulnerabilities = data.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "unknown")

        # Get English description
        description = "No description available"
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")[:200]
                break

        # Get severity and CVSS score
        severity, score = _extract_severity(cve_data)

        # Get published date
        published = cve_data.get("published", "unknown")[:10]

        cves.append(CVE(
            cve_id=cve_id,
            description=description,
            severity=severity,
            cvss_score=score,
            published=published,
            component=component_name,
            version=version,
        ))

    return cves


def _extract_severity(cve_data: dict) -> tuple:
    """Extracts CVSS severity and score — tries v3.1, v3.0, then v2."""
    metrics = cve_data.get("metrics", {})

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
            return severity, float(score)

    return "UNKNOWN", 0.0


def lookup_all_components(
    components: list,
    api_key: Optional[str] = None,
    max_components: int = 10
) -> dict:
    """
    Runs NVD lookup for all components up to max_components.
    Returns a full results summary.
    """
    all_cves = []
    component_results = {}
    checked = 0
    limit = min(len(components), max_components)

    console.print(f"\n[bold]Querying NVD API for {limit} components...[/bold]\n")

    for comp in components[:max_components]:
        console.print(f"  [cyan]→[/cyan] Checking: [bold]{comp.name}[/bold] {comp.version or ''}")
        cves = lookup_component(comp.name, comp.version, api_key)

        if cves:
            console.print(f"    [red]Found {len(cves)} CVE(s)[/red]")
        else:
            console.print(f"    [green]No CVEs found[/green]")

        component_results[comp.name] = cves
        all_cves.extend(cves)
        checked += 1
        time.sleep(REQUEST_DELAY)

    # Count by severity
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0
    }
    for cve in all_cves:
        sev = cve.severity.upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["UNKNOWN"] += 1

    return {
        "component_results": component_results,
        "all_cves": all_cves,
        "total_cves": len(all_cves),
        "components_checked": checked,
        "severity_counts": severity_counts,
    }


def print_results(results: dict) -> None:
    """Prints NVD lookup results to the terminal."""
    counts = results["severity_counts"]

    # Summary panel
    console.print(Panel(
        f"[red]CRITICAL: {counts['CRITICAL']}[/red]   "
        f"[orange1]HIGH: {counts['HIGH']}[/orange1]   "
        f"[yellow]MEDIUM: {counts['MEDIUM']}[/yellow]   "
        f"[green]LOW: {counts['LOW']}[/green]   "
        f"[dim]UNKNOWN: {counts['UNKNOWN']}[/dim]",
        title=f"CVEs Found: {results['total_cves']} across {results['components_checked']} components",
        border_style="blue",
    ))

    if not results["all_cves"]:
        console.print("\n[green]No CVEs found for the checked components.[/green]")
        return

    # CVE table
    table = Table(title="CVE Findings", show_lines=True)
    table.add_column("CVE ID", style="cyan", width=16)
    table.add_column("Component", width=20)
    table.add_column("Severity", width=10)
    table.add_column("Score", width=6)
    table.add_column("Published", width=12)
    table.add_column("Description")

    for cve in results["all_cves"]:
        sev_style = (
            "red" if cve.severity in ["CRITICAL", "HIGH"]
            else "yellow" if cve.severity == "MEDIUM"
            else "green"
        )
        desc = cve.description
        if len(desc) > 100:
            desc = desc[:100] + "..."

        table.add_row(
            cve.cve_id,
            cve.component,
            f"[{sev_style}]{cve.severity}[/{sev_style}]",
            f"[{sev_style}]{cve.cvss_score}[/{sev_style}]",
            cve.published,
            desc,
        )

    console.print(table)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]Usage: python nvd_lookup.py <sbom.json>[/red]")
        sys.exit(1)

    # Get API key
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if not api_key:
        console.print("[yellow]Warning: NVD_API_KEY not set. Running without key (rate limited).[/yellow]")
    else:
        console.print(f"[green]NVD API key loaded ({len(api_key)} chars)[/green]")

    filepath = sys.argv[1]
    console.print(f"\n[bold blue]NVD Vulnerability Lookup:[/bold blue] {filepath}")

    # Parse SBOM
    try:
        parsed = parse_sbom(filepath)
        console.print(f"[green]SBOM parsed — {parsed['total_components']} components found[/green]")
    except Exception as e:
        console.print(f"[red]Error parsing SBOM: {e}[/red]")
        sys.exit(1)

    # Run lookup
    try:
        results = lookup_all_components(
            parsed["components"],
            api_key=api_key,
            max_components=10
        )
    except Exception as e:
        console.print(f"[red]Error during NVD lookup: {e}[/red]")
        sys.exit(1)

    # Print results
    print_results(results)