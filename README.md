<div align="center">

<img src="source/cover.jpg" alt="RØOT — offline AppSec training range" width="900">

# RØOT

### Break it safely. Fix it properly.

An offline-first AppSec workspace for OWASP practice, remediation, verification,
and CVE prioritization.

[**Live demo**](https://madnessbrainsbl.github.io/ROOT/) ·
[**Open app**](https://madnessbrainsbl.github.io/ROOT/app/)

[![CI](https://github.com/madnessbrainsbl/ROOT/actions/workflows/ci.yml/badge.svg)](https://github.com/madnessbrainsbl/ROOT/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-Apache--2.0-ef2b33?style=flat-square)
![Runtime](https://img.shields.io/badge/runtime-offline-22c55e?style=flat-square)

</div>

[⚡ Quick start](#-quick-start) ·
[🧭 Navigation guide](#-navigation-guide) ·
[📊 Framework comparison](#-framework-comparison) ·
[📦 Included content](#-included-content) ·
[🛡️ Responsible use](#️-responsible-use) ·
[🤝 Contributing](#-contributing)

---

## What is RØOT?

RØOT turns a security topic into a repeatable workflow: understand the trust
boundary, reproduce the flaw in a controlled browser simulation, compare the
remediation, and verify the lesson with a quiz. It runs locally with no SaaS
account, API key, analytics service, or live target.

Built for developers learning AppSec, teams validating controls, and educators
running offline labs.

---

## ⚡ Quick start

Requirements: Python 3.10+ and a modern browser.

```bash
git clone https://github.com/madnessbrainsbl/ROOT.git
cd ROOT
python3 serve.py   # Windows: python serve.py
```

Open <http://127.0.0.1:8080/> for the landing page or
<http://127.0.0.1:8080/app/> for the workspace.

### Docker

```bash
docker compose up --build
```

The container needs no credentials and keeps its generated SQLite database in a
temporary writable filesystem.

---

## 🧭 Navigation guide

I want to… | Open
--- | ---
Practice a web vulnerability | [OWASP Web Top 10](https://madnessbrainsbl.github.io/ROOT/app/#/owasp)
Test an API risk | [OWASP API Security Top 10](https://madnessbrainsbl.github.io/ROOT/app/#/api)
Turn a requirement into evidence | [ASVS](https://madnessbrainsbl.github.io/ROOT/app/#/asvs)
Plan testing or threat modelling | [Security frameworks](https://madnessbrainsbl.github.io/ROOT/app/#/frameworks)
Prioritize a public vulnerability | [Zero-Days / KEV](https://madnessbrainsbl.github.io/ROOT/app/#/cves)
Find a security tool or command | [Tools](https://madnessbrainsbl.github.io/ROOT/app/#/tools) and [Commands](https://madnessbrainsbl.github.io/ROOT/app/#/commands)
Document an authorized assessment | [Report templates](https://madnessbrainsbl.github.io/ROOT/app/#/reports)

---

## 📊 Framework comparison

Choose the method by the question it answers:

Framework | Best for | RØOT route
--- | --- | ---
OWASP Top 10 | Prioritizing common web risks | [Web Top 10](https://madnessbrainsbl.github.io/ROOT/app/#/owasp)
OWASP API Security Top 10 | API authorization, authentication, and abuse cases | [API Top 10](https://madnessbrainsbl.github.io/ROOT/app/#/api)
OWASP ASVS | Verifiable application-security requirements | [ASVS](https://madnessbrainsbl.github.io/ROOT/app/#/asvs)
OWASP WSTG | A repeatable web-testing method | [WSTG](https://madnessbrainsbl.github.io/ROOT/app/#/frameworks/wstg)
OWASP SAMM | AppSec-program maturity | [SAMM](https://madnessbrainsbl.github.io/ROOT/app/#/frameworks/samm)
STRIDE / PASTA / LINDDUN | Threat modelling and abuse paths | [Threat modelling](https://madnessbrainsbl.github.io/ROOT/app/#/frameworks/threat-modeling)
NIST SSDF / SLSA / SBOM | Secure delivery and supply chain | [Secure SDLC](https://madnessbrainsbl.github.io/ROOT/app/#/frameworks/sdlc)
CVSS / EPSS / KEV / SSVC | Vulnerability prioritization | [Vulnerability lifecycle](https://madnessbrainsbl.github.io/ROOT/app/#/frameworks/vulnerability-lifecycle)

Quick decision guide:

- Need to learn or demonstrate a flaw → start with Web or API Top 10.
- Need an acceptance criterion → use ASVS.
- Need a testing plan → use WSTG or the lifecycle map.
- Need to decide what to fix first → combine KEV, EPSS, exploitability, and asset context.

---

## 📦 Included content

| Content | Count |
| --- | ---: |
| Web CTF challenges | 30 |
| OWASP API Security mini-labs | 10 |
| Bilingual quiz questions | 500 |
| Public CISA KEV records | 250 |
| Security tool references | 420 |
| Security standards and methods | 50 |
| Payload examples in 66 categories | 1,224 |
| Attack-chain scenarios | 114 |
| Command builders | 59 |

## Offline CVE data

RØOT bundles a deliberately small public CISA KEV and CVE List V5 snapshot.
It never downloads data at startup. The browser uses the tracked JSON seed;
the Python server indexes it in SQLite.

- Provenance and SHA-256: [`data/cves_public.provenance.json`](data/cves_public.provenance.json)
- Rebuild the public seed: `python scripts/build_cve_seed.py --limit 250`
- Set `ROOT_CVE_MODE=public` to force the tracked public dataset locally.

## Architecture

```text
Browser (vanilla JavaScript)
├── OWASP Web / API / LLM / ASVS workspace
├── CTF simulations, quizzes, tools, payloads, chains, and reports
├── sql.js knowledge workspace + local browser progress
└── GET /api/cves → Python standard-library server → SQLite
```

The runtime uses no third-party Python package and no frontend framework.

## 🛡️ Responsible use

RØOT is for education and systems you own or are explicitly authorized to
assess. Do not use its examples, payloads, simulations, or command references
to access, disrupt, alter, or extract data from another system. The CVE snapshot
is a study aid, not live threat intelligence; confirm material decisions against
the primary vendor advisory and the referenced CVE or CISA entry.

## 🤝 Contributing

Keep changes focused, avoid new production dependencies without agreement, and
include the smallest relevant test. Content must cite compatible sources and
licenses. Do not submit secrets, personal data, proprietary material, or live
target data.

## License and notices

RØOT is licensed under [Apache-2.0](LICENSE). Bundled material retains its own
terms where applicable: [sql.js](https://github.com/sql-js/sql.js) (MIT),
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
(MIT), OWASP ASVS (CC BY-SA 4.0), locally hosted fonts (SIL OFL),
[CISA KEV](https://github.com/cisagov/kev-data), and
[CVE List V5](https://github.com/CVEProject/cvelistV5). Full license texts are
in [`licenses/`](licenses/).
