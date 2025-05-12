#!/usr/bin/env python3

from __future__ import annotations

import os
import re
import json
import time
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple

# ------------------------- 3rd‑party imports -------------------------
import requests  # 필수
try:
    import nvdlib  # 선택
    _NVDLIB_OK = True
except ModuleNotFoundError:  # pragma: no cover
    nvdlib = None  # type: ignore
    _NVDLIB_OK = False

# ------------------------- 설정 / 상수 -------------------------
NVD_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL  = "https://api.first.org/data/v1/epss"  # ?cve=<ID>
API_KEY   = os.getenv("NVD_API_KEY")
HEADERS   = {"X-Api-Key": API_KEY} if API_KEY else {}
RATE_NVD  = 2.0  # NVD fallback delay (req/min <= 30)
RATE_EPSS = 1.0  # FIRST API 친화적 간격
FUNC_RX   = re.compile(r"\b([A-Za-z_][\w\.]{2,})\s*\(")
CACHE_DIR = Path.home() / ".cache" / "cve_fetch"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# ------------------------- cache util -------------------------

def _cache_path(cve: str, suffix: str) -> Path:
    return CACHE_DIR / f"{cve}{suffix}.json"


def _load_cache(cve: str, suffix: str) -> Any | None:
    fp = _cache_path(cve, suffix)
    if fp.exists():
        try:
            return json.loads(fp.read_text())
        except Exception:
            fp.unlink(missing_ok=True)
    return None


def _save_cache(cve: str, suffix: str, data: Any):
    _cache_path(cve, suffix).write_text(json.dumps(data))

# --------------------------------------------------------------------
# NVD crawl (nvdlib → fallback requests) + caching
# --------------------------------------------------------------------

def _fetch_cve_via_requests(cve: str) -> dict:
    logging.info("HTTP NVD fetch %s", cve)
    r = requests.get(NVD_URL, params={"cveId": cve}, headers=HEADERS, timeout=20)
    r.raise_for_status()
    time.sleep(RATE_NVD)
    return r.json()


def _fetch_cve_via_nvdlib(cve: str) -> dict:
    logging.info("nvdlib fetch %s", cve)
    res = list(nvdlib.searchCVE(cveId=cve, key=API_KEY))  # type: ignore[arg-type]
    if not res:
        raise ValueError(f"CVE {cve} not found via nvdlib")
    model = res[0]
    return {"vulnerabilities": [{"cve": model.model_dump(by_alias=True)}]}  # type: ignore[attr-defined]


def fetch_nvd(cve: str) -> dict:
    if (data := _load_cache(cve, "_nvd")) is not None:
        logging.debug("NVD cache hit %s", cve)
        return data
    try:
        data = _fetch_cve_via_nvdlib(cve) if _NVDLIB_OK else _fetch_cve_via_requests(cve)
    except Exception as e:  # pragma: no cover
        logging.warning("nvdlib fail → fallback requests (%s)", e)
        data = _fetch_cve_via_requests(cve)
    _save_cache(cve, "_nvd", data)
    return data

# --------------------------------------------------------------------
# EPSS -> (FIRST API) + Caching
# --------------------------------------------------------------------

def _fetch_epss_remote(cve: str) -> Tuple[float | None, float | None]:
    logging.info("EPSS fetch %s", cve)
    r = requests.get(EPSS_URL, params={"cve": cve}, timeout=15)
    r.raise_for_status()
    time.sleep(RATE_EPSS)
    js = r.json()
    if js.get("total"):
        d = js["data"][0]
        return float(d["epss"]), float(d["percentile"])
    return None, None


def fetch_epss(cve: str) -> Tuple[float | None, float | None]:
    if (data := _load_cache(cve, "_epss")) is not None:
        return data["epss"], data["percentile"]
    epss, pct = _fetch_epss_remote(cve)
    _save_cache(cve, "_epss", {"epss": epss, "percentile": pct})
    return epss, pct

# --------------------------------------------------------------------
# 3) JSON → risk DB
# --------------------------------------------------------------------

def _extract_api_names(text: str) -> List[str]:
    return list({m.group(1) for m in FUNC_RX.finditer(text)})


def _parse_cve_record(rec: dict, epss_pair: Tuple[float | None, float | None]) -> Dict[str, Any]:
    cve = rec["cve"]
    cve_id = cve["id"]
    desc = " ".join(d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en")

    # CVSS 우선순위
    metrics = cve.get("metrics", {})
    cvss = {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        met_list = metrics.get(key)
        if met_list:
            cvss = met_list[0].get("cvssData", {})
            break

    packages = {pkg.get("product")
                for aff in cve.get("affects", [])
                for pkg in aff.get("packages", [])
                if pkg.get("product")}

    epss, pct = epss_pair

    return {
        "cve": cve_id,
        "packages": sorted(packages),
        "apis": _extract_api_names(desc),
        "cvssVector": cvss.get("vectorString", ""),
        "attackVector": cvss.get("attackVector", ""),
        "severity": cvss.get("baseSeverity", ""),
        "epss": epss,
        "epssPercentile": pct,
        "description": desc[:500],
    }


def _parse_cve_blob(blob: dict, epss_pair: Tuple[float | None, float | None]) -> List[dict]:
    return [_parse_cve_record(v, epss_pair) for v in blob.get("vulnerabilities", [])]

# --------------------------------------------------------------------
# SBOM → CVE list
# --------------------------------------------------------------------

def _read_sbom_for_cves(path: Path) -> List[str]:
    bom = json.loads(path.read_text())
    vulns = bom.get("vulnerabilities", [])
    cves: set[str] = set()
    for v in vulns:
        cid = v.get("cve") or v.get("id") or ""
        if cid.startswith("CVE-"):
            cves.add(cid)
        else:
            for rating in v.get("ratings", []):
                ref = rating.get("reference", "")
                if ref.startswith("CVE-"):
                    cves.add(ref)
    return sorted(cves)

# --------------------------------------------------------------------
# main
# --------------------------------------------------------------------

def build_risk_index(cve_ids: List[str]) -> List[dict]:
    db: List[dict] = []
    for cid in cve_ids:
        nvd_blob = fetch_nvd(cid)
        epss_pair = fetch_epss(cid)
        db.extend(_parse_cve_blob(nvd_blob, epss_pair))
    return db


def main():
    ap = argparse.ArgumentParser(description="NVD+EPSS → Risky API DB (nvdlib/requests)")
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--cve", nargs="+", help="CVE ID list")
    grp.add_argument("--sbom", type=Path, help="CycloneDX SBOM JSON file")
    ap.add_argument("--out", type=Path, default=Path("risk_db.json"), help="Output file path")
    args = ap.parse_args()

    cve_ids = args.cve if args.cve else _read_sbom_for_cves(args.sbom)
    if not args.cve:
        logging.info("SBOM → %d unique CVEs", len(cve_ids))

    risk_db = build_risk_index(cve_ids)
    args.out.write_text(json.dumps(risk_db, indent=2))
    logging.info("Saved %d records → %s", len(risk_db), args.out)


if __name__ == "__main__":
    main()
