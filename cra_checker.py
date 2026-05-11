"""
cra_checker.py
Checks parsed SBOM data against CRA Annex I compliance rules
defined in cra_rules.yaml and produces a structured results report.
"""

import yaml
from dataclasses import dataclass
from typing import Optional
from sbom_parser import Component


@dataclass
class RuleResult:
    """Result of a single rule check."""
    rule_id: str
    cra_ref: str
    title: str
    severity: str
    nist_mapping: str
    status: str        # PASS / FAIL
    component: Optional[str] = None
    reason: Optional[str] = None


def load_rules(rules_path: str = "cra_rules.yaml") -> dict:
    """Loads CRA compliance rules from the YAML config file."""
    with open(rules_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def check_sbom(parsed_sbom: dict, rules_path: str = "cra_rules.yaml") -> dict:
    """
    Runs all CRA compliance checks against a parsed SBOM.
    Returns a full results report.
    """
    rules = load_rules(rules_path)
    metadata = parsed_sbom["metadata"]
    components = parsed_sbom["components"]

    sbom_results = _check_sbom_rules(metadata, rules["sbom_rules"])
    component_results = _check_component_rules(components, rules["component_rules"])

    all_results = sbom_results + component_results

    # Calculate compliance score
    score = _calculate_score(all_results, rules["scoring"])

    # Count by severity and status
    summary = _build_summary(all_results)

    return {
        "metadata": metadata,
        "sbom_results": sbom_results,
        "component_results": component_results,
        "all_results": all_results,
        "summary": summary,
        "score": score,
        "total_components": parsed_sbom["total_components"],
    }


def _check_sbom_rules(metadata: dict, sbom_rules: list) -> list[RuleResult]:
    """Checks SBOM-level rules against metadata."""
    results = []
    for rule in sbom_rules:
        field = rule["field"]
        value = metadata.get(field)
        check = rule["check"]
        passed, reason = _apply_check(check, value)
        results.append(RuleResult(
            rule_id=rule["id"],
            cra_ref=rule["cra_ref"],
            title=rule["title"],
            severity=rule["severity"],
            nist_mapping=rule["nist_mapping"],
            status="PASS" if passed else "FAIL",
            component="[SBOM]",
            reason=reason,
        ))
    return results


def _check_component_rules(
    components: list[Component], component_rules: list
) -> list[RuleResult]:
    """Checks every component against all component-level rules."""
    results = []
    for comp in components:
        comp_dict = comp.to_dict()
        for rule in component_rules:
            field = rule["field"]
            value = comp_dict.get(field)
            check = rule["check"]
            passed, reason = _apply_check(check, value)
            results.append(RuleResult(
                rule_id=rule["id"],
                cra_ref=rule["cra_ref"],
                title=rule["title"],
                severity=rule["severity"],
                nist_mapping=rule["nist_mapping"],
                status="PASS" if passed else "FAIL",
                component=comp.name,
                reason=reason,
            ))
    return results


def _apply_check(check: str, value) -> tuple[bool, str]:
    """Applies a named check to a value. Returns (passed, reason)."""
    if check == "not_empty":
        if value and str(value).strip() and str(value).strip().lower() != "unknown":
            return True, "Value present"
        return False, "Value is missing or empty"

    elif check == "not_empty_list":
        if value and len(value) > 0:
            return True, "Value present"
        return False, "List is empty or missing"

    elif check == "not_unknown":
        if value and str(value).strip().lower() != "unknown":
            return True, "Value present"
        return False, "Value is missing or set to unknown"

    elif check == "greater_than_zero":
        if value and int(value) > 0:
            return True, f"{value} components found"
        return False, "No components found in SBOM"

    return False, f"Unknown check type: {check}"


def _calculate_score(results: list[RuleResult], scoring_config: dict) -> dict:
    """Calculates a weighted compliance score."""
    weights = scoring_config["weights"]
    thresholds = scoring_config["thresholds"]

    total_weight = 0
    passed_weight = 0

    for r in results:
        w = weights.get(r.severity, 1)
        total_weight += w
        if r.status == "PASS":
            passed_weight += w

    if total_weight == 0:
        percentage = 0
    else:
        percentage = round((passed_weight / total_weight) * 100, 1)

    if percentage >= thresholds["compliant"]:
        label = "CRA COMPLIANT"
        color = "green"
    elif percentage >= thresholds["partial"]:
        label = "PARTIALLY COMPLIANT"
        color = "yellow"
    else:
        label = "NON-COMPLIANT"
        color = "red"

    return {
        "percentage": percentage,
        "label": label,
        "color": color,
        "passed_weight": passed_weight,
        "total_weight": total_weight,
    }


def _build_summary(results: list[RuleResult]) -> dict:
    """Builds a summary count of pass/fail by severity."""
    summary = {
        "total": len(results),
        "passed": 0,
        "failed": 0,
        "HIGH_fail": 0,
        "MEDIUM_fail": 0,
        "LOW_fail": 0,
        "HIGH_pass": 0,
        "MEDIUM_pass": 0,
        "LOW_pass": 0,
    }
    for r in results:
        if r.status == "PASS":
            summary["passed"] += 1
            summary[f"{r.severity}_pass"] += 1
        else:
            summary["failed"] += 1
            summary[f"{r.severity}_fail"] += 1
    return summary


if __name__ == "__main__":
    import sys
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from sbom_parser import parse_sbom

    console = Console()

    if len(sys.argv) < 2:
        console.print("[red]Usage: python cra_checker.py <sbom.json>[/red]")
        sys.exit(1)

    filepath = sys.argv[1]
    console.print(f"\n[bold blue]Running CRA Compliance Check:[/bold blue] {filepath}\n")

    parsed = parse_sbom(filepath)
    report = check_sbom(parsed)
    summary = report["summary"]
    score = report["score"]

    # Print compliance score
    console.print(Panel(
        f"[bold {score['color']}]{score['label']}[/bold {score['color']}]\n"
        f"Score: [bold]{score['percentage']}%[/bold] "
        f"({score['passed_weight']}/{score['total_weight']} weighted points)",
        title="CRA Compliance Score",
        border_style=score["color"],
    ))

    # Print summary
    console.print(f"\n[bold]Results Summary[/bold]")
    console.print(f"  Total checks : {summary['total']}")
    console.print(f"  Passed       : [green]{summary['passed']}[/green]")
    console.print(f"  Failed       : [red]{summary['failed']}[/red]")
    console.print(f"\n  HIGH failures   : [red]{summary['HIGH_fail']}[/red]")
    console.print(f"  MEDIUM failures : [yellow]{summary['MEDIUM_fail']}[/yellow]")
    console.print(f"  LOW failures    : [green]{summary['LOW_fail']}[/green]\n")

    # Print SBOM-level results
    sbom_table = Table(title="SBOM-Level CRA Checks")
    sbom_table.add_column("Rule ID", style="cyan")
    sbom_table.add_column("Title")
    sbom_table.add_column("Severity")
    sbom_table.add_column("Status")
    sbom_table.add_column("NIST Mapping", style="dim")

    for r in report["sbom_results"]:
        status_style = "green" if r.status == "PASS" else "red"
        sev_style = "red" if r.severity == "HIGH" else "yellow" if r.severity == "MEDIUM" else "green"
        sbom_table.add_row(
            r.rule_id,
            r.title,
            f"[{sev_style}]{r.severity}[/{sev_style}]",
            f"[{status_style}]{r.status}[/{status_style}]",
            r.nist_mapping,
        )
    console.print(sbom_table)

    # Print component failures only
    fail_table = Table(title="Component-Level Failures (first 15)")
    fail_table.add_column("Component", style="cyan")
    fail_table.add_column("Rule ID")
    fail_table.add_column("Issue")
    fail_table.add_column("Severity")

    failures = [r for r in report["component_results"] if r.status == "FAIL"]
    for r in failures[:15]:
        sev_style = "red" if r.severity == "HIGH" else "yellow" if r.severity == "MEDIUM" else "green"
        fail_table.add_row(
            r.component,
            r.rule_id,
            r.title,
            f"[{sev_style}]{r.severity}[/{sev_style}]",
        )
    console.print(fail_table)
    if len(failures) > 15:
        console.print(f"[dim]... and {len(failures) - 15} more failures[/dim]")