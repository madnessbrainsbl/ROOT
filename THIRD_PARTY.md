# Third-party notices

RØOT is licensed under Apache-2.0. The following bundled material remains
subject to its own license or source terms.

| Component or data | License / terms | Use in RØOT |
|---|---|---|
| [sql.js](https://github.com/sql-js/sql.js) | MIT | `js/sql-wasm.js` and `js/sql-wasm.wasm` power the end-user browser SQL workspace. The license is copied to `licenses/sql.js-LICENSE.txt`. |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | MIT | The payload reference library contains adapted examples. Attribution and the license are preserved in `licenses/PayloadsAllTheThings-LICENSE.txt`. |
| Space Grotesk, JetBrains Mono, Orbitron, VT323 | SIL Open Font License 1.1 | Locally hosted web fonts. The license is copied to `licenses/fonts-OFL-1.1.txt`. |
| [CISA KEV](https://github.com/cisagov/kev-data) | U.S. government/public data; see source notices | Supplies the bundled Known Exploited Vulnerabilities selection. |
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | See CVE Program terms and repository notices | Supplies published CNA descriptions, affected products, CWE, and CVSS fields where available. |

The precise CVE seed sources, generation time, record count, and SHA-256 are
recorded in `data/cves_public.provenance.json`. Regenerate it with
`python scripts/build_cve_seed.py --limit 250`.

## Standards and educational references

RØOT uses category names and identifiers from the following public standards:

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Common Weakness Enumeration](https://cwe.mitre.org/)

OWASP and CWE names identify public vulnerability categories. They do not
imply endorsement of RØOT by OWASP, MITRE, CISA, the CVE Program, or NIST.

## Project content

RØOT's application code, bilingual explanations, UI, simulated lab flows,
attack-chain organization, and report templates are distributed under the
project license unless a notice above says otherwise. Short command flags and
widely known probe strings are presented as technical reference material.

Artwork and screenshots in `cover.jpg`, `image/`, and `source/` were supplied
for this project and are covered by the project license unless noted in the
file itself.

See [DISCLAIMER.md](DISCLAIMER.md) for responsible-use requirements.
