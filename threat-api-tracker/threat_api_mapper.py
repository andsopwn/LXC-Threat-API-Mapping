#!/usr/bin/env python3

from __future__ import annotations

import ast
import argparse
import json
import logging
from pathlib import Path
from typing import Dict, Set, Any

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("threat_mapper")

# ---------------------------------------------------------------------------
# Alias helper
# ---------------------------------------------------------------------------

def build_aliases(tree: ast.AST) -> Dict[str, str]:
    aliases: Dict[str, str] = {}
    class V(ast.NodeVisitor):
        def visit_Import(self, node: ast.Import):  # type: ignore[override]
            for n in node.names:
                root = n.name.split('.') [0]
                aliases[n.asname or root] = n.name
        def visit_ImportFrom(self, node: ast.ImportFrom):  # type: ignore[override]
            if node.module is None:
                return
            for n in node.names:
                aliases[n.asname or n.name] = f"{node.module}.{n.name}"
    V().visit(tree)
    return aliases

# ---------------------------------------------------------------------------
# Risk DB – build lookup tables
# ---------------------------------------------------------------------------

def load_risk_tables(path: Path, min_epss: float|None, kev_only: bool):
    data = json.loads(path.read_text())
    api_meta: Dict[str, dict] = {}
    short_map: Dict[str, Set[str]] = {}
    for rec in data:
        epss = rec.get("epss")
        if min_epss is not None and (epss or 0) < min_epss:
            continue
        if kev_only and not rec.get("kev"):
            continue
        for api in rec.get("apis", []):
            meta = api_meta.setdefault(api, {
                "cve": set(),
                "severity": rec.get("severity"),
                "epss": epss,
                "kev": rec.get("kev"),
                "exploitDB": rec.get("exploitDB"),
            })
            meta["cve"].add(rec["cve"])
            short_map.setdefault(api.split('.')[-1], set()).add(api)
    return api_meta, short_map

# ---------------------------------------------------------------------------
# Iterate calls with alias resolution
# ---------------------------------------------------------------------------

def iter_calls(code: str, tree: ast.AST, aliases: Dict[str, str]):
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = None
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            base, attr = node.func.value.id, node.func.attr
            mod = aliases.get(base, base)
            dotted = f"{mod}.{attr}"
        elif isinstance(node.func, ast.Name):
            name = node.func.id
            mod = aliases.get(name)
            dotted = f"{mod}.{name}" if mod else name
        if dotted:
            yield node.lineno, dotted, ast.get_source_segment(code, node)[:120]

# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan(code_root: Path, risk_db: Path, out_path: Path, min_epss: float|None, kev_only: bool, debug: bool):
    api_meta, short_map = load_risk_tables(risk_db, min_epss, kev_only)
    results = []
    py_files = list(code_root.rglob("*.py"))
    for py in py_files:
        try:
            code = py.read_text(encoding="utf-8")
            tree = ast.parse(code)
        except Exception as e:
            log.warning("skip %s (%s)", py, e)
            continue
        aliases = build_aliases(tree)
        for line, dotted, snippet in iter_calls(code, tree, aliases):
            target_api = None
            if dotted in api_meta:
                target_api = dotted
            else:
                short = dotted.split('.')[-1]
                if len(short_map.get(short, [])) == 1:
                    target_api = next(iter(short_map[short]))
            if target_api:
                meta = api_meta[target_api]
                rec = {
                    "file": str(py.relative_to(code_root)),
                    "line": line,
                    "api": target_api,
                    "cve": sorted(meta["cve"]),
                    "severity": meta.get("severity"),
                    "epss": meta.get("epss"),
                    "kev": meta.get("kev"),
                    "exploitDB": meta.get("exploitDB"),
                    "snippet": snippet,
                }
                results.append(rec)
                if debug:
                    log.info("MATCH %s:%d → %s CVE=%s epss=%s kev=%s", rec["file"], line, target_api, rec["cve"], rec["epss"], rec["kev"])
    out_path.write_text(json.dumps(results, indent=2))
    log.info("★ scanned %d .py files, %d matches → %s", len(py_files), len(results), out_path)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    pr = argparse.ArgumentParser(description="Map vulnerable API calls with enriched metadata")
    pr.add_argument("--code", required=True, type=Path, help="Root of source tree")
    pr.add_argument("--risk", default=Path("risk_db.json"), type=Path, help="risk_db(_enriched).json path")
    pr.add_argument("--out", default=Path("threat_map.json"), type=Path)
    pr.add_argument("--min-epss", type=float, help="Skip CVEs with EPSS below this value")
    pr.add_argument("--kev-only", action="store_true", help="Only include CVEs in CISA KEV catalog")
    pr.add_argument("--debug", action="store_true")
    args = pr.parse_args()

    if not args.code.exists():
        pr.error("code path does not exist")
    if not args.risk.exists():
        pr.error("risk db not found")
    if args.debug:
        log.setLevel(logging.DEBUG)
    scan(args.code, args.risk, args.out, args.min_epss, args.kev_only, args.debug)

if __name__ == "__main__":
    main()
