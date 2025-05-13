#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import requests
try:
    import nvdlib  # type: ignore
    _NVD_OK = True
except ModuleNotFoundError:
    nvdlib = None  # type: ignore
    _NVD_OK = False

# ------------------------- 설정 / 상수 -------------------------
NVD_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL  = "https://api.first.org/data/v1/epss"  # ?cve=<ID>
KEV_URL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
API_KEY   = os.getenv("NVD_API_KEY")
HEADERS   = {"X-Api-Key": API_KEY} if API_KEY else {}
RATE_NVD  = 2.0
RATE_EPSS = 1.0
FUNC_RX   = re.compile(r"\b([A-Za-z_][\w\.]{2,})\s*\(")
CACHE_DIR = Path.home() / ".cache" / "cve_fetch"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# ------------------------- cache utils -------------------------

def _cache_path(name: str) -> Path:
    return CACHE_DIR / f"{name}.json"


def _load_json(name: str, ttl_days: int = 1) -> Any | None:
    fp = _cache_path(name)
    if fp.exists() and time.time() - fp.stat().st_mtime < ttl_days * 86400:
        try:
            return json.loads(fp.read_text())
        except Exception:
            fp.unlink(missing_ok=True)
    return None


def _save_json(name: str, data: Any):
    _cache_path(name).write_text(json.dumps(data))

# ------------------------- KEV dataset -------------------------

def load_kev_set() -> Set[str]:
    if (data := _load_json("kev", ttl_days=1)) is not None:
        return set(data)
    kev_js = requests.get(KEV_URL, timeout=20).json()
    kev = {v["cveID"] for v in kev_js.get("vulnerabilities", [])}
    _save_json("kev", list(kev))
    return kev

KEV_SET: Set[str] = load_kev_set()

# ------------------------- NVD fetch ---------------------------

def _fetch_nvd_requests(cve: str) -> dict:
    r = requests.get(NVD_URL, params={"cveId": cve}, headers=HEADERS, timeout=20)
    r.raise_for_status()
    time.sleep(RATE_NVD)
    return r.json()


def _fetch_nvd_lib(cve: str) -> dict:
    res = list(nvdlib.searchCVE(cveId=cve, key=API_KEY))  # type: ignore[arg-type]
    if not res:
        raise ValueError("not found via nvdlib")
    return {"vulnerabilities": [{"cve": res[0].model_dump(by_alias=True)}]}  # type: ignore[attr-defined]


def fetch_nvd(cve: str) -> dict:
    cache_name = f"nvd_{cve}"
    if (data := _load_json(cache_name, ttl_days=2)) is not None:
        return data
    try:
        blob = _fetch_nvd_lib(cve) if _NVD_OK else _fetch_nvd_requests(cve)
    except Exception:
        blob = _fetch_nvd_requests(cve)
    _save_json(cache_name, blob)
    return blob

# ------------------------- EPSS fetch --------------------------

def fetch_epss(cve: str) -> Tuple[float | None, float | None]:
    cache = _load_json(f"epss_{cve}")
    if cache:
        return cache
    js = requests.get(EPSS_URL, params={"cve": cve}, timeout=15).json()
    time.sleep(RATE_EPSS)
    if js.get("data"):
        d = js["data"][0]
        pair = (float(d["epss"]), float(d["percentile"]))
        _save_json(f"epss_{cve}", pair)
        return pair
    return None, None

# ------------------------- core extract helpers ---------------

def _extract_api_names(text: str) -> List[str]:
    return list({m.group(1) for m in FUNC_RX.finditer(text)})


def _parse_cve_record(rec: dict, epss_pair: Tuple[float | None, float | None]) -> Dict[str, Any]:
    cve = rec["cve"]
    cid = cve["id"]
    desc = " ".join(d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en")

    metrics = cve.get("metrics", {})
    cvss = {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            cvss = metrics[key][0]["cvssData"]
            break

    packages = {p.get("product") for aff in cve.get("affects", []) for p in aff.get("packages", []) if p.get("product")}
    epss, pct = epss_pair

    return {
        "cve": cid,
        "packages": sorted(packages),
        "apis": _extract_api_names(desc),
        "cvssVector": cvss.get("vectorString", ""),
        "attackVector": cvss.get("attackVector", ""),
        "severity": cvss.get("baseSeverity", ""),
        "epss": epss,
        "epssPercentile": pct,
        "description": desc[:500],
        "kev": cid in KEV_SET,
    }


def _parse_blob(blob: dict, epss_pair: Tuple[float | None, float | None]) -> List[dict]:
    return [_parse_cve_record(v, epss_pair) for v in blob.get("vulnerabilities", [])]

# ------------------------- SBOM CVE listing -------------------

def sbom_to_cves(path: Path) -> List[str]:
    bom = json.loads(path.read_text())
    ids = set()
    for v in bom.get("vulnerabilities", []):
        cid = v.get("cve") or v.get("id", "")
        if cid.startswith("CVE-"):
            ids.add(cid)
    return sorted(ids)

# ------------------------- build risk DB ----------------------

def build_db(cve_ids: List[str]) -> List[dict]:
    db = []
    for cid in cve_ids:
        blob = fetch_nvd(cid)
        db.extend(_parse_blob(blob, fetch_epss(cid)))
    return db

# ------------------------- CLI --------------------------------

def main():
    pa = argparse.ArgumentParser(description="Create risk_db.json with EPSS & KEV metadata")
    g = pa.add_mutually_exclusive_group(required=True)
    g.add_argument("--cve", nargs="+", help="CVE IDs")
    g.add_argument("--sbom", type=Path, help="CycloneDX SBOM JSON")
    pa.add_argument("--out", type=Path, default=Path("risk_db.json"))
    args = pa.parse_args()

    cves = args.cve if args.cve else sbom_to_cves(args.sbom)
    db = build_db(cves)
    args.out.write_text(json.dumps(db, indent=2))
    print(f"★ saved {len(db)} records → {args.out}")

if __name__ == "__main__":
    main()