"""
parser.py
Parses a CycloneDX JSON SBOM file and extracts component data
for CRA Annex I compliance checking.
"""

import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Component:
    """Represents a single software component from the SBOM."""
    name: str
    version: Optional[str]
    supplier: Optional[str]
    licenses: list[str]
    hashes: list[str]
    purl: Optional[str]
    component_type: Optional[str]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "supplier": self.supplier,
            "licenses": self.licenses,
            "hashes": self.hashes,
            "purl": self.purl,
            "component_type": self.component_type,
        }


def parse_sbom(filepath: str) -> dict:
    """
    Reads a CycloneDX JSON SBOM file and returns:
    - metadata about the SBOM
    - a list of Component objects
    """
    try:
        with open(filepath, "r", encoding="utf-8-sig") as f:
            sbom_data = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"SBOM file not found: {filepath}")
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON in SBOM file: {filepath}")

    # Extract SBOM metadata
    metadata = _extract_metadata(sbom_data)

    # Extract all components
    components = _extract_components(sbom_data)

    return {
        "metadata": metadata,
        "components": components,
        "total_components": len(components),
    }


def _extract_metadata(sbom_data: dict) -> dict:
    """Extracts top-level SBOM metadata."""
    metadata = sbom_data.get("metadata", {})
    component = metadata.get("component", {})

    return {
        "sbom_version": sbom_data.get("version", "unknown"),
        "spec_version": sbom_data.get("specVersion", "unknown"),
        "serial_number": sbom_data.get("serialNumber", "unknown"),
        "project_name": component.get("name", "unknown"),
        "project_version": component.get("version", "unknown"),
        "timestamp": metadata.get("timestamp", "unknown"),
        "tool": _extract_tool(metadata),
    }


def _extract_tool(metadata: dict) -> str:
    """Extracts the tool used to generate the SBOM."""
    tools = metadata.get("tools", {})
    if isinstance(tools, dict):
        components = tools.get("components", [])
        if components:
            t = components[0]
            return f"{t.get('name', 'unknown')} {t.get('version', '')}"
    return "unknown"


def _extract_components(sbom_data: dict) -> list[Component]:
    """Extracts all components from the SBOM."""
    raw_components = sbom_data.get("components", [])
    components = []

    for raw in raw_components:
        component = Component(
            name=raw.get("name", "unknown"),
            version=raw.get("version", None),
            supplier=_extract_supplier(raw),
            licenses=_extract_licenses(raw),
            hashes=_extract_hashes(raw),
            purl=raw.get("purl", None),
            component_type=raw.get("type", None),
        )
        components.append(component)

    return components


def _extract_supplier(raw: dict) -> Optional[str]:
    """Extracts supplier/publisher name from a component."""
    supplier = raw.get("supplier", {})
    if isinstance(supplier, dict):
        return supplier.get("name", None)
    publisher = raw.get("publisher", None)
    return publisher


def _extract_licenses(raw: dict) -> list[str]:
    """Extracts license identifiers from a component."""
    licenses = []
    for lic in raw.get("licenses", []):
        if isinstance(lic, dict):
            inner = lic.get("license", {})
            if isinstance(inner, dict):
                lic_id = inner.get("id") or inner.get("name")
                if lic_id:
                    licenses.append(lic_id)
    return licenses


def _extract_hashes(raw: dict) -> list[str]:
    """Extracts hash values from a component."""
    hashes = []
    for h in raw.get("hashes", []):
        if isinstance(h, dict):
            alg = h.get("alg", "")
            val = h.get("content", "")
            if alg and val:
                hashes.append(f"{alg}:{val[:16]}...")
    return hashes


if __name__ == "__main__":
    import sys
    from rich.console import Console
    from rich.table import Table

    console = Console()

    if len(sys.argv) < 2:
        console.print("[red]Usage: python parser.py <sbom.json>[/red]")
        sys.exit(1)

    filepath = sys.argv[1]
    console.print(f"\n[bold blue]Parsing SBOM:[/bold blue] {filepath}\n")

    result = parse_sbom(filepath)
    meta = result["metadata"]

    # Print metadata
    console.print("[bold]SBOM Metadata[/bold]")
    console.print(f"  Project     : {meta['project_name']}")
    console.print(f"  Version     : {meta['project_version']}")
    console.print(f"  Spec        : CycloneDX {meta['spec_version']}")
    console.print(f"  Generated   : {meta['timestamp']}")
    console.print(f"  Tool        : {meta['tool']}")
    console.print(f"  Components  : {result['total_components']}\n")

    # Print components table
    table = Table(title="Components Found")
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("Supplier", style="yellow")
    table.add_column("Licenses", style="magenta")
    table.add_column("Hashes", style="blue")

    for comp in result["components"][:20]:  # show first 20
        table.add_row(
            comp.name,
            comp.version or "N/A",
            comp.supplier or "N/A",
            ", ".join(comp.licenses) if comp.licenses else "N/A",
            "✓" if comp.hashes else "✗",
        )

    console.print(table)
    if result["total_components"] > 20:
        console.print(f"[dim]... and {result['total_components'] - 20} more components[/dim]")