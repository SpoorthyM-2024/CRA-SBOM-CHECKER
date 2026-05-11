# CRA SBOM Compliance Checker

A Python-based command-line tool that generates a Software Bill of Materials (SBOM) 
for any open-source project and checks it against the EU Cyber Resilience Act (CRA) 
Annex I compliance requirements.

## What it does
- Generates a CycloneDX-format SBOM using Anchore Syft
- Parses and analyzes SBOM components against CRA requirements
- Queries the NVD API for known CVEs in each component
- Produces a color-coded HTML compliance report with a CRA compliance score

## Tech Stack
- Python 3.11+
- Anchore Syft (SBOM generation)
- CycloneDX (SBOM format standard)
- NVD API (vulnerability enrichment)
- Rich (terminal output)
- Typer (CLI interface)

## Frameworks Referenced
- EU Cyber Resilience Act (CRA) Annex I
- NIST CSF 2.0
- CISA Secure by Design

## Setup
```bash
git clone https://github.com/SpoorthyM-2024/cra-sbom-checker
cd cra-sbom-checker
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

## Usage
```bash
python main.py --sbom sbom.json --output report.html
```

## Project Structure
cra-sbom-checker/
├── main.py              # CLI entry point
├── parser.py            # SBOM parser module
├── cra_checker.py       # CRA compliance checker
├── nvd_lookup.py        # NVD API vulnerability lookup
├── report.py            # HTML report generator
├── cra_rules.yaml       # CRA compliance rules config
├── requirements.txt     # Python dependencies
└── README.md            # This file

## Academic Context
This tool was developed as a graduate cybersecurity research project exploring 
the technical implications of the EU Cyber Resilience Act for open-source 
software supply chains.

## Disclaimer
This tool is for educational and research purposes only. It uses publicly 
available vulnerability data from the NIST National Vulnerability Database (NVD).