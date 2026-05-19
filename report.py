"""
report.py
Generates a professional HTML compliance report combining
CRA gap analysis results and NVD vulnerability findings.
"""

import json
from datetime import datetime


def generate_report(
    checker_results: dict,
    nvd_results: dict,
    output_path: str = "report.html"
) -> str:
    """
    Generates a full HTML compliance report.
    Returns the output file path.
    """
    metadata = checker_results["metadata"]
    score = checker_results["score"]
    summary = checker_results["summary"]
    sbom_results = checker_results["sbom_results"]
    component_results = checker_results["component_results"]
    all_cves = nvd_results.get("all_cves", [])
    cve_counts = nvd_results.get("severity_counts", {})

    # Deduplicate CVEs
    seen_cves = set()
    unique_cves = []
    for cve in all_cves:
        if cve.cve_id not in seen_cves:
            seen_cves.add(cve.cve_id)
            unique_cves.append(cve)

    # Build HTML
    html = _build_html(
        metadata=metadata,
        score=score,
        summary=summary,
        sbom_results=sbom_results,
        component_results=component_results,
        unique_cves=unique_cves,
        cve_counts=cve_counts,
        nvd_results=nvd_results,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path


def _score_color(score_label: str) -> str:
    """Returns a hex color based on compliance label."""
    if score_label == "CRA COMPLIANT":
        return "#2e7d32"
    elif score_label == "PARTIALLY COMPLIANT":
        return "#f57f17"
    return "#c62828"


def _severity_badge(severity: str) -> str:
    """Returns an HTML badge for a severity level."""
    colors = {
        "HIGH": ("#ffebee", "#c62828"),
        "MEDIUM": ("#fff8e1", "#f57f17"),
        "LOW": ("#e8f5e9", "#2e7d32"),
        "CRITICAL": ("#fce4ec", "#880e4f"),
        "UNKNOWN": ("#f5f5f5", "#616161"),
    }
    bg, text = colors.get(severity.upper(), ("#f5f5f5", "#616161"))
    return (
        f'<span style="background:{bg};color:{text};padding:2px 8px;'
        f'border-radius:4px;font-size:12px;font-weight:600;">{severity}</span>'
    )


def _status_badge(status: str) -> str:
    """Returns an HTML badge for PASS/FAIL status."""
    if status == "PASS":
        return '<span style="background:#e8f5e9;color:#2e7d32;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:600;">✓ PASS</span>'
    return '<span style="background:#ffebee;color:#c62828;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:600;">✗ FAIL</span>'


def _build_html(
    metadata, score, summary, sbom_results,
    component_results, unique_cves, cve_counts, nvd_results
) -> str:
    """Builds the complete HTML report string."""

    score_color = _score_color(score["label"])
    generated_at = datetime.now().strftime("%B %d, %Y at %H:%M")

    # Build SBOM checks rows
    sbom_rows = ""
    for r in sbom_results:
        sbom_rows += f"""
        <tr>
            <td><code>{r.rule_id}</code></td>
            <td>{r.title}</td>
            <td>{_severity_badge(r.severity)}</td>
            <td>{_status_badge(r.status)}</td>
            <td><code>{r.nist_mapping}</code></td>
            <td style="font-size:12px;color:#666;">{r.cra_ref}</td>
        </tr>"""

    # Build component failures rows — deduplicated
    seen_failures = set()
    comp_rows = ""
    fail_count = 0
    for r in component_results:
        if r.status == "FAIL":
            key = f"{r.component}-{r.rule_id}"
            if key not in seen_failures:
                seen_failures.add(key)
                comp_rows += f"""
                <tr>
                    <td><code>{r.component}</code></td>
                    <td><code>{r.rule_id}</code></td>
                    <td>{r.title}</td>
                    <td>{_severity_badge(r.severity)}</td>
                    <td><code>{r.nist_mapping}</code></td>
                </tr>"""
                fail_count += 1

    # Build CVE rows
    cve_rows = ""
    for cve in unique_cves:
        cve_rows += f"""
        <tr>
            <td><a href="https://nvd.nist.gov/vuln/detail/{cve.cve_id}" 
                target="_blank" style="color:#1565c0;">{cve.cve_id}</a></td>
            <td><code>{cve.component}</code></td>
            <td>{_severity_badge(cve.severity)}</td>
            <td><strong>{cve.cvss_score}</strong></td>
            <td>{cve.published}</td>
            <td style="font-size:12px;">{cve.description[:120]}...</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CRA SBOM Compliance Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #f5f5f5; color: #212121; line-height: 1.6; }}
        .header {{ background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
                  color: white; padding: 40px; }}
        .header h1 {{ font-size: 28px; font-weight: 700; margin-bottom: 6px; }}
        .header p {{ opacity: 0.8; font-size: 14px; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 30px 20px; }}
        .card {{ background: white; border-radius: 8px; padding: 24px;
                margin-bottom: 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }}
        .card h2 {{ font-size: 18px; font-weight: 600; color: #1a237e;
                   margin-bottom: 16px; padding-bottom: 10px;
                   border-bottom: 2px solid #e8eaf6; }}
        .score-box {{ text-align: center; padding: 30px;
                     border: 3px solid {score_color}; border-radius: 12px;
                     margin-bottom: 24px; }}
        .score-label {{ font-size: 32px; font-weight: 700;
                       color: {score_color}; margin-bottom: 8px; }}
        .score-pct {{ font-size: 48px; font-weight: 800; color: {score_color}; }}
        .score-sub {{ color: #666; font-size: 14px; margin-top: 6px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px;
                      margin-bottom: 24px; }}
        .stat-card {{ background: white; border-radius: 8px; padding: 20px;
                     text-align: center; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }}
        .stat-card .number {{ font-size: 36px; font-weight: 700; }}
        .stat-card .label {{ font-size: 13px; color: #666; margin-top: 4px; }}
        .red {{ color: #c62828; }}
        .green {{ color: #2e7d32; }}
        .amber {{ color: #f57f17; }}
        .blue {{ color: #1565c0; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
        th {{ background: #1a237e; color: white; padding: 10px 12px;
             text-align: left; font-weight: 500; font-size: 13px; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #eeeeee;
             vertical-align: top; }}
        tr:hover {{ background: #f8f9ff; }}
        tr:nth-child(even) {{ background: #fafafa; }}
        tr:nth-child(even):hover {{ background: #f8f9ff; }}
        .disclaimer {{ background: #fff8e1; border-left: 4px solid #ffc107;
                      padding: 16px; border-radius: 0 8px 8px 0;
                      font-size: 13px; color: #555; margin-bottom: 24px; }}
        .footer {{ text-align: center; color: #999; font-size: 12px;
                  padding: 20px; }}
        code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 3px;
               font-size: 12px; }}
        .section-intro {{ color: #555; font-size: 14px; margin-bottom: 16px; }}
    </style>
</head>
<body>

<div class="header">
    <h1>CRA SBOM Compliance Report</h1>
    <p>EU Cyber Resilience Act — Annex I Gap Analysis</p>
    <p style="margin-top:8px;">Project: <strong>{metadata['project_name']}</strong> &nbsp;|&nbsp;
       Generated: <strong>{generated_at}</strong> &nbsp;|&nbsp;
       Tool: <strong>{metadata['tool']}</strong></p>
</div>

<div class="container">

    <div class="disclaimer">
        <strong>Academic Research Tool:</strong> This report is generated for educational
        purposes using publicly available SBOM data and the NIST NVD API.
        CRA compliance determinations require formal legal assessment.
    </div>

    <!-- Compliance Score -->
    <div class="score-box">
        <div class="score-label">{score['label']}</div>
        <div class="score-pct">{score['percentage']}%</div>
        <div class="score-sub">
            {score['passed_weight']} / {score['total_weight']} weighted compliance points
        </div>
    </div>

    <!-- Stats Grid -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="number blue">{summary['total']}</div>
            <div class="label">Total Checks Run</div>
        </div>
        <div class="stat-card">
            <div class="number green">{summary['passed']}</div>
            <div class="label">Checks Passed</div>
        </div>
        <div class="stat-card">
            <div class="number red">{summary['failed']}</div>
            <div class="label">Checks Failed</div>
        </div>
        <div class="stat-card">
            <div class="number amber">{nvd_results['total_cves']}</div>
            <div class="label">CVEs Found</div>
        </div>
    </div>

    <!-- Severity Breakdown -->
    <div class="card">
        <h2>Failure Breakdown by Severity</h2>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;">
            <div style="text-align:center;padding:16px;background:#ffebee;border-radius:8px;">
                <div style="font-size:32px;font-weight:700;color:#c62828;">
                    {summary['HIGH_fail']}</div>
                <div style="color:#c62828;font-weight:600;">HIGH Failures</div>
                <div style="font-size:12px;color:#666;margin-top:4px;">
                    Must fix before EU market entry</div>
            </div>
            <div style="text-align:center;padding:16px;background:#fff8e1;border-radius:8px;">
                <div style="font-size:32px;font-weight:700;color:#f57f17;">
                    {summary['MEDIUM_fail']}</div>
                <div style="color:#f57f17;font-weight:600;">MEDIUM Failures</div>
                <div style="font-size:12px;color:#666;margin-top:4px;">
                    Fix within 90 days</div>
            </div>
            <div style="text-align:center;padding:16px;background:#e8f5e9;border-radius:8px;">
                <div style="font-size:32px;font-weight:700;color:#2e7d32;">
                    {summary['LOW_fail']}</div>
                <div style="color:#2e7d32;font-weight:600;">LOW Failures</div>
                <div style="font-size:12px;color:#666;margin-top:4px;">
                    Fix within 180 days</div>
            </div>
        </div>
    </div>

    <!-- CVE Severity Breakdown -->
    <div class="card">
        <h2>Vulnerability Summary (NVD)</h2>
        <p class="section-intro">
            CVEs found across {nvd_results['components_checked']} components
            queried against the NIST National Vulnerability Database.
        </p>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;">
            <div style="text-align:center;padding:16px;background:#fce4ec;border-radius:8px;">
                <div style="font-size:28px;font-weight:700;color:#880e4f;">
                    {cve_counts.get('CRITICAL', 0)}</div>
                <div style="color:#880e4f;font-weight:600;">CRITICAL</div>
            </div>
            <div style="text-align:center;padding:16px;background:#ffebee;border-radius:8px;">
                <div style="font-size:28px;font-weight:700;color:#c62828;">
                    {cve_counts.get('HIGH', 0)}</div>
                <div style="color:#c62828;font-weight:600;">HIGH</div>
            </div>
            <div style="text-align:center;padding:16px;background:#fff8e1;border-radius:8px;">
                <div style="font-size:28px;font-weight:700;color:#f57f17;">
                    {cve_counts.get('MEDIUM', 0)}</div>
                <div style="color:#f57f17;font-weight:600;">MEDIUM</div>
            </div>
            <div style="text-align:center;padding:16px;background:#e8f5e9;border-radius:8px;">
                <div style="font-size:28px;font-weight:700;color:#2e7d32;">
                    {cve_counts.get('LOW', 0)}</div>
                <div style="color:#2e7d32;font-weight:600;">LOW</div>
            </div>
        </div>
    </div>

    <!-- SBOM Level Checks -->
    <div class="card">
        <h2>SBOM-Level CRA Checks</h2>
        <p class="section-intro">
            Checks applied to the SBOM document as a whole against
            CRA Annex I, Part II, §1 documentation requirements.
        </p>
        <table>
            <thead>
                <tr>
                    <th>Rule ID</th>
                    <th>Requirement</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>NIST Mapping</th>
                    <th>CRA Reference</th>
                </tr>
            </thead>
            <tbody>{sbom_rows}</tbody>
        </table>
    </div>

    <!-- Component Failures -->
    <div class="card">
        <h2>Component-Level CRA Failures ({fail_count} unique failures)</h2>
        <p class="section-intro">
            Each row represents a unique component failing a specific
            CRA compliance rule. Deduplicated across all SBOM components.
        </p>
        <table>
            <thead>
                <tr>
                    <th>Component</th>
                    <th>Rule ID</th>
                    <th>Issue</th>
                    <th>Severity</th>
                    <th>NIST Mapping</th>
                </tr>
            </thead>
            <tbody>{comp_rows}</tbody>
        </table>
    </div>

    <!-- CVE Findings -->
    <div class="card">
        <h2>CVE Findings ({len(unique_cves)} unique vulnerabilities)</h2>
        <p class="section-intro">
            Vulnerabilities identified via NIST NVD API lookup.
            Click CVE ID to view full details on NVD.
        </p>
        <table>
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>Component</th>
                    <th>Severity</th>
                    <th>CVSS Score</th>
                    <th>Published</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>{cve_rows}</tbody>
        </table>
    </div>

    <!-- Regulatory Context -->
    <div class="card">
        <h2>Regulatory Context</h2>
        <table>
            <thead>
                <tr><th>Item</th><th>Detail</th></tr>
            </thead>
            <tbody>
                <tr><td>Regulation</td>
                    <td>EU Cyber Resilience Act (CRA) — Regulation (EU) 2024/2847</td></tr>
                <tr><td>Enforceable From</td><td>December 11, 2027</td></tr>
                <tr><td>Scope</td>
                    <td>All products with digital elements placed on the EU market</td></tr>
                <tr><td>Maximum Penalty</td>
                    <td>EUR 15,000,000 or 2.5% of global annual turnover</td></tr>
                <tr><td>SBOM Requirement</td>
                    <td>CRA Annex I, Part II, §1 — Machine-readable format required</td></tr>
                <tr><td>NIST Framework Used</td><td>NIST CSF 2.0 (February 2024)</td></tr>
                <tr><td>Reference</td>
                    <td><a href="https://eur-lex.europa.eu" target="_blank"
                        style="color:#1565c0;">eur-lex.europa.eu</a></td></tr>
            </tbody>
        </table>
    </div>

</div>

<div class="footer">
    CRA SBOM Compliance Checker &nbsp;|&nbsp;
    Graduate Cybersecurity Research Project &nbsp;|&nbsp;
    Generated {generated_at} &nbsp;|&nbsp;
    Data sourced from NIST NVD API
</div>

</body>
</html>"""


if __name__ == "__main__":
    print("report.py loaded successfully.")
    print("Use main.py to generate a full report.")