#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vuln_api_pipeline.py – sub‑module: vulnerability collection → risky‑API extraction

This file focuses **only** on the two middle stages of the larger pipeline:
    • `VulnerabilityCollector` – downloads CVE metadata from NVD (using `nvdlib`) and
      caches it locally so we respect the API rate‑limit.
    • `RiskyAPIMatcher` – heuristically extracts function / API symbols that commonly
      appear in CVE descriptions, references or CWE text.

Example CLI usage
-----------------
$ python vuln_api_pipeline.py --cve CVE-2020-14343 CVE-2022-3602  \
                             --key $NVD_API_KEY > risky_api.json

Output (pretty‑printed JSON):
{
  "CVE-2020-14343": ["yaml.load", "yaml.FullLoader"],
  "CVE-2022-3602": ["openssl", "X509_verify_cert"]
}

Requirements
~~~~~~~~~~~~
    pip install nvdlib tqdm requests
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Set

import nvdlib
from tqdm import tqdm

###############################################################################
# 1. Vulnerability metadata collection (NVD)                                 #
###############################################################################

class VulnerabilityCollector:
    """Download & cache NVD CVE records.

    Parameters
    ----------
    cache_dir : str
        Directory where raw JSON docs are stored to avoid repeated API hits.
    api_key : str | None
        Optional NVD API key – strongly recommended to avoid tight rate‑limits.
    """

    def __init__(self, cache_dir: str = ".cache/nvd", api_key: str | None = None):
        self.cache = Path(cache_dir)
        self.cache.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key

    # --------------------------------------------------------------------- #
    def _cache_path(self, cve_id: str) -> Path:
        return self.cache / f"{cve_id}.json"

    # --------------------------------------------------------------------- #
    def fetch_single(self, cve_id: str) -> dict:  # noqa: D401
        """Return a **raw dict** for *one* CVE, hitting the cache if possible."""
        cached = self._cache_path(cve_id)
        if cached.exists():
            return json.loads(cached.read_text(encoding="utf‑8"))

        # nvdlib returns a list; we expect exactly one element when searching by ID
        objs = nvdlib.searchCVE(cveId=cve_id, key=self.api_key)
        if not objs:
            raise ValueError(f"CVE not found: {cve_id}")
        record = objs[0].__dict__  # convert pydantic‑like obj to plain dict
        cached.write_text(json.dumps(record, ensure_ascii=False, indent=2),
                          encoding="utf‑8")
        return record

    # --------------------------------------------------------------------- #
    def fetch_many(self, cve_ids: List[str]) -> List[dict]:
        """Download a batch of CVEs with progress bar and basic error handling."""
        results: List[dict] = []
        for cid in tqdm(cve_ids, desc="Fetching NVD", unit="cve"):
            try:
                results.append(self.fetch_single(cid))
            except Exception as exc:  # pragma: no cover – informational
                print(f"[WARN] {cid}: {exc}", file=sys.stderr)
        return results

###############################################################################
# 2. Heuristic extraction of risky APIs / symbols                            #
###############################################################################

class RiskyAPIMatcher:
    """Pull probable API / function identifiers from NVD text blocks.

    The extractor purposefully errs on the side of *recall* – we collect many
    candidates first, then downstream ranking (e.g. call‑graph correlation)
    can drop false‑positives.
    """

    # → identifiers look like pkg.func or Class.method etc. min length ≥ 3 chars
    _TOKEN_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_.]{2,}")

    _STOP_WORDS: Set[str] = {
        "function", "method", "variable", "class", "file", "package", "module",
        "library", "framework", "application", "software", "process",
    }

    def __init__(self, extra_stop: Set[str] | None = None):
        self.stop = self._STOP_WORDS.union(extra_stop or set())

    # ------------------------------------------------------------------ #
    def _extract_tokens(self, text: str) -> Set[str]:
        """Regex‑scan *text* and return unique identifier‑like tokens."""
        return {
            t.rstrip(".():, ")  # strip trailing punctuation
            for t in self._TOKEN_RE.findall(text)
            if t.lower() not in self.stop and "." in t  # want dotted names mostly
        }

    # ------------------------------------------------------------------ #
    def extract_from_cve(self, cve: dict) -> Set[str]:
        """Given raw NVD record → set of candidate APIs."""
        candidates: Set[str] = set()

        # ① descriptions (multiple languages possible)
        for desc in cve.get("cve", {}).get("descriptions", []):
            candidates |= self._extract_tokens(desc.get("value", ""))

        # ② problemTypes → cwe names sometimes contain symbols
        for pt in cve.get("cve", {}).get("problemTypes", []):
            for d in pt.get("descriptions", []):
                candidates |= self._extract_tokens(d.get("description", ""))

        # ③ references (URLs occasionally include library names)
        for ref in cve.get("cve", {}).get("references", []):
            candidates |= self._extract_tokens(ref.get("url", ""))

        return candidates

###############################################################################
# 3. Convenience wrapper                                                    #
###############################################################################

def collect_risky_apis(cve_ids: List[str], *, api_key: str | None = None,
                       cache_dir: str = ".cache/nvd") -> Dict[str, List[str]]:
    """Return mapping {CVE‑ID: [ risky_api, ... ]}."""
    coll = VulnerabilityCollector(cache_dir=cache_dir, api_key=api_key)
    matcher = RiskyAPIMatcher()

    mapping: Dict[str, List[str]] = {}
    for rec in coll.fetch_many(cve_ids):
        apis = sorted(matcher.extract_from_cve(rec))
        mapping[rec["id"]] = apis
    return mapping

###############################################################################
# 4. Command‑line entry                                                     #
###############################################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch NVD records and extract risky API symbols.")
    parser.add_argument("--cve", nargs="+", required=True,
                        help="One or more CVE identifiers (space‑separated)")
    parser.add_argument("--key", help="NVD API key (optional)")
    parser.add_argument("--cache", default=".cache/nvd",
                        help="Directory for on‑disk JSON cache (default: .cache/nvd)")
    args = parser.parse_args()

    data = collect_risky_apis(args.cve, api_key=args.key, cache_dir=args.cache)
    json.dump(data, sys.stdout, ensure_ascii=False, indent=2)
    print()  # newline
