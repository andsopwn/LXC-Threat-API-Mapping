#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''vuln_api_pipeline.py – Proof-of-concept pipeline for identifying vulnerable API usage

Pipeline steps implemented (placeholders marked TODO):
    1. Generate SBOM for a container image via Syft
    2. Parse SBOM to enumerate vulnerable packages/CVEs (using Grype DB or Trivy JSON)
    3. Fetch detailed NVD records for each CVE and extract risky API symbols
    4. Scan local source code (AST) for those API symbols and capture context snippets
    5. Produce a markdown report that maps CVE → API → source-location → snippet

Author: Capstone Team 5 (2025)
'''

from __future__ import annotations  # Python ≥3.9 type hint forward refs
import argparse
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

import requests  # pip install requests
from rich import print  # pip install rich
from rich.progress import track

# ---------------------------------------------------------------------------
# Dataclass models
# ---------------------------------------------------------------------------

@dataclass
class CVERecord:
    cve_id: str
    description: str
    cvss: float | None
    apis: List[str] = field(default_factory=list)

@dataclass
class APIMatch:
    file_path: pathlib.Path
    line_no: int
    api_symbol: str
    context: str  # snippet

# ---------------------------------------------------------------------------
# Step 1 – SBOM generation via Syft
# ---------------------------------------------------------------------------

def generate_sbom(image: str, sbom_path: pathlib.Path) -> None:
    '''Generate CycloneDX JSON SBOM for the given container image using Syft.'''
    cmd = f'syft {shlex.quote(image)} -o cyclonedx-json > {shlex.quote(str(sbom_path))}'
    print(f'[bold cyan]• Generating SBOM:[/] {cmd}')
    subprocess.run(cmd, shell=True, check=True)

# ---------------------------------------------------------------------------
# Step 2 – Extract CVE list from SBOM/Grype JSON
# ---------------------------------------------------------------------------

def extract_cves_from_sbom(sbom_path: pathlib.Path) -> List[str]:
    '''Parse CycloneDX SBOM and return list of CVE identifiers (string).'''
    with sbom_path.open('r', encoding='utf-8') as f:
        sbom = json.load(f)

    vulnerabilities = sbom.get('vulnerabilities', [])
    cves = {v['id'] for v in vulnerabilities if v.get('id', '').startswith('CVE-')}
    print(f'[bold cyan]• CVEs detected in SBOM:[/] {len(cves)} found')
    return sorted(cves)

# ---------------------------------------------------------------------------
# Step 3 – Retrieve NVD JSON & extract risky API names
# ---------------------------------------------------------------------------

NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cve/1.0/'

def fetch_nvd_record(cve_id: str) -> dict:
    url = NVD_API_URL + cve_id
    resp = requests.get(url, timeout=30)
    if resp.status_code != 200:
        raise RuntimeError(f'Failed to fetch {cve_id}: HTTP {resp.status_code}')
    return resp.json()

def extract_api_symbols(nvd_json: dict) -> List[str]:
    '''Very naive keyword extraction of API/function names from NVD description/CWE.'''
    description_items = nvd_json['result']['CVE_Items'][0]['cve']['description']['description_data']
    text = ' '.join(item['value'] for item in description_items)
    # heuristic: match sequences like module.func, func(), Class.method
    pattern = re.compile(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*')
    candidates = pattern.findall(text)
    # filter very short/common words
    apis = [c for c in candidates if len(c) > 3 and not c.isupper()]
    return sorted(set(apis))

def build_cve_records(cve_ids: Sequence[str]) -> List[CVERecord]:
    records: List[CVERecord] = []
    for cve_id in track(cve_ids, description='Fetching NVD records'):
        nvd_json = fetch_nvd_record(cve_id)
        apis = extract_api_symbols(nvd_json)
        # extract CVSS v3 base score if present
        cvss = None
        try:
            cvss = nvd_json['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
        except KeyError:
            pass
        description = nvd_json['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
        records.append(CVERecord(cve_id, description, cvss, apis))
    return records

# ---------------------------------------------------------------------------
# Step 4 – Codebase AST / grep search for API occurrences
# ---------------------------------------------------------------------------

def scan_source_for_apis(source_dir: pathlib.Path, api_symbols: Sequence[str]) -> List[APIMatch]:
    '''Simple regex based search; replace with AST parser for production.'''
    matches: List[APIMatch] = []
    pattern = re.compile(r'(?P<api>' + '|'.join(re.escape(a) for a in api_symbols) + r')')
    for path in source_dir.rglob('*.py'):
        with path.open('r', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                if pattern.search(line):
                    context = collect_context(path, i)
                    matches.append(APIMatch(path, i, pattern.search(line)['api'], context))
    print(f'[bold cyan]• Source API matches:[/] {len(matches)} occurrences found')
    return matches

def collect_context(file_path: pathlib.Path, line_no: int, context_lines: int = 4) -> str:
    lines = file_path.read_text(errors='ignore').splitlines()
    start = max(line_no - context_lines - 1, 0)
    end = min(line_no + context_lines, len(lines))
    snippet = '\n'.join(f'{idx+1:4d}: {l}' for idx, l in enumerate(lines[start:end], start))
    return snippet

# ---------------------------------------------------------------------------
# Step 5 – Report generation
# ---------------------------------------------------------------------------

def render_markdown_report(cve_records: List[CVERecord], matches: List[APIMatch], output_path: pathlib.Path) -> None:
    print(f'[bold cyan]• Writing report:[/] {output_path}')
    with output_path.open('w', encoding='utf-8') as md:
        md.write('# Vulnerable API Usage Report\n\n')
        md.write(f'- Total CVEs: {len(cve_records)}\n')
        md.write(f'- Total API matches in source: {len(matches)}\n\n')

        for cve in cve_records:
            md.write(f'## {cve.cve_id}\n')
            if cve.cvss:
                md.write(f'- CVSS v3: **{cve.cvss}**\n')
            md.write(f'- Extracted APIs: {", ".join(cve.apis) or "(none)"}\n')
            md.write(f'- Description: {cve.description[:200]}...\n\n')
            related = [m for m in matches if m.api_symbol in cve.apis]
            if not related:
                md.write('No occurrences in source.\n\n')
                continue
            for match in related:
                md.write(f'### {match.file_path}:{match.line_no}\n')
                md.write('```python\n')
                md.write(match.context)
                md.write('\n```\n\n')

# ---------------------------------------------------------------------------
# CLI driver
# ---------------------------------------------------------------------------

def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description='Identify vulnerable API usage from SBOM + NVD + source scan')
    parser.add_argument('--image', required=True, help='Container image tag (e.g., python:3.12-alpine)')
    parser.add_argument('--source', required=True, type=pathlib.Path, help='Local source code directory')
    parser.add_argument('--report', default='vuln_report.md', type=pathlib.Path, help='Output markdown report path')
    parser.add_argument('--tmpdir', default='.sbom', type=pathlib.Path, help='Working directory')
    args = parser.parse_args(argv)

    args.tmpdir.mkdir(parents=True, exist_ok=True)
    sbom_path = args.tmpdir / 'sbom.json'

    # 1. SBOM
    generate_sbom(args.image, sbom_path)

    # 2. CVE list
    cve_ids = extract_cves_from_sbom(sbom_path)

    # 3. NVD fetch + API extraction
    cve_records = build_cve_records(cve_ids)

    # Flatten API symbol set
    api_set = sorted({api for rec in cve_records for api in rec.apis})
    if not api_set:
        print('[bold yellow]No API symbols extracted; exiting.')
        sys.exit(0)

    # 4. Scan source
    matches = scan_source_for_apis(args.source, api_set)

    # 5. Report
    render_markdown_report(cve_records, matches, args.report)
    print('[bold green]Done!')


if __name__ == '__main__':
    main()
