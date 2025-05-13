<details>
<summary> test image overview </summary> 

``` bash
└── test_target/
    ├── app/
    │   ├── config.py
    │   ├── server.py
    │   ├── services/
    │   │   ├── crypto_service.py
    │   │   ├── fetch_service.py
    │   │   ├── file_service.py
    │   │   ├── health_service.py
    │   │   ├── metrics_service.py
    │   │   ├── parse_service.py
    │   │   └── yaml_service.py
    │   └── utils/
    │       └── logger.py
    ├── Dockerfile
    ├── requirements.txt
    ├── run.sh
    ├── static.yaml
    └── tests/
        └── test_server.py
```
</details>

<br>

# 1. NVD API EXTRACTOR
+ Generate risk_db.json with CVE metadata, vulnerable APIs, EPSS score * percentil, CISA Key flag
+ Compatible with downstream threat_api_mapper.py enriched workflow.

Usage
``` bash
python3 nvd_api_extractor.py --cve CVE-2020-14343 CVE-2024-21591
```
linkage with ast
``` bash
python3 astvisualizer.py test_target/app -t $(jq -r '.[].apis[]' risk_db.json | sort -u | tr '\n' ' ') -o callflow
```

<details>
<summary> output example </summary>
risk_db.json

``` json
[
  {
    "cve": "CVE-2020-14343",
    "packages": [],
    "apis": [],
    "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "attackVector": "NETWORK",
    "severity": "CRITICAL",
    "epss": 0.14625,
    "epssPercentile": 0.94077,
    "description": "A vulnerability was discovered in the PyYAML library in versions before 5.4, where it is susceptible to arbitrary code execution when it processes untrusted YAML files through the full_load method or with the FullLoader loader. Applications that use the library to process untrusted input may be vulnerable to this flaw. This flaw allows an attacker to execute arbitrary code on the system by abusing the python/object/new constructor. This flaw is due to an incomplete fix for CVE-2020-1747."
  },
  {
    "cve": "CVE-2024-21591",
    "packages": [],
    "apis": [
      "Service",
      "Execution"
    ],
    "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "attackVector": "NETWORK",
    "severity": "CRITICAL",
    "epss": 0.23476,
    "epssPercentile": 0.95633,
    "description": "\nAn Out-of-bounds Write vulnerability in J-Web of Juniper Networks Junos OS on SRX Series and EX Series allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS), or Remote Code Execution (RCE) and obtain root privileges on the device.\n\nThis issue is caused by use of an insecure function allowing an attacker to overwrite arbitrary memory.\n\nThis issue affects Juniper Networks Junos OS SRX Series and EX Series:\n\n\n\n  *  Junos OS versions earlier than 20.4R3-S9;\n  *  Junos"
  }
]
```
</details>

<br> 

# 2. Threat API Mapper
+ maps vulnerable API calls → CVE records and carries through enriched metadata such as EPSS, Exploit-DB ...

| 목적 | 예시 명령 | 설명 |
|-|-|-|
| default | python3 threat_api_mapper.py --code ../test_target --risk risk_db.json | risk_db.json 또는 enriched 전체를 기준으로 API 매핑 |
| Debug | python3 threat_api_mapper.py --code ../test_target --risk risk_db.json --debug | 매치될 때마다 콘솔에 MATCH ... 로 표시 |
| EPSS 0.7 이상만 | python3 threat_api_mapper.py --code ../test_target --risk risk_db.json --min-epss 0.7 | epss 0.7 이상인 CVE만 고려하여 매핑 |
| KEV 목록 CVE만 | python3 threat_api_mapper.py --code ../test_target --risk risk_db.json --kev-only | CISA KEV 카탈로그에 포함된 CVE만 대상 |
| 모든 필터 & 커스텀 출력 경로 | python3 threat_api_mapper.py --code ../backend --risk ../data/risk_db_enriched.json --out ../report/threat_map_high.json --min-epss 0.9 --kev-only --debug | EPSS 0.7 이상 AND KEV에 있는 CVE만 결과를 리포트에 따로 저장하고 디버그 표시 |

