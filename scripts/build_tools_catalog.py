#!/usr/bin/env python3
"""Build the runtime tool catalog from synchronized English and Russian Markdown."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "js" / "tools" / "catalog.js"
EN_SOURCE = ROOT / "js" / "tools" / "security_tools_catalog_en_v2_2026-07-30.md"
RU_SOURCE = ROOT / "js" / "tools" / "security_tools_catalog_ru_v2_2026-07-30.md"
VERSION = 31

# The Markdown groups are intentionally broader than the UI taxonomy.
NEW_METADATA = {
    "microsoft-sentinel": ("devsecops", "siem"),
    "google-security-operations": ("devsecops", "siem"),
    "splunk-enterprise-security": ("devsecops", "siem"),
    "elastic-security": ("devsecops", "edr-xdr"),
    "cortex-xsiam": ("devsecops", "edr-xdr"),
    "thehive": ("devsecops", "siem"),
    "misp": ("devsecops", "threat-intel"),
    "opencti": ("devsecops", "threat-intel"),
    "sigma": ("devsecops", "detection-engineering"),
    "yara-x": ("devsecops", "detection-engineering"),
    "security-onion": ("devsecops", "ndr"),
    "suricata": ("devsecops", "ndr"),
    "zeek": ("devsecops", "ndr"),
    "osquery": ("devsecops", "threat-hunting"),
    "velociraptor": ("devsecops", "dfir"),
    "arkime": ("devsecops", "ndr"),
    "keycloak": ("appsec", "identity"),
    "teleport": ("devsecops", "iam"),
    "openbao": ("devsecops", "secrets-mgmt"),
    "infisical": ("devsecops", "secrets-mgmt"),
    "tenable-vulnerability-management": ("appsec", "vuln-scan"),
    "qualys-vmdr": ("appsec", "vuln-scan"),
    "rapid7-insightvm": ("appsec", "vuln-scan"),
    "cortex-xpanse": ("appsec", "recon"),
    "guac": ("devsecops", "supply-chain"),
    "chainguard-images": ("devsecops", "supply-chain"),
    "wolfi": ("devsecops", "supply-chain"),
    "stepsecurity": ("devsecops", "cicd"),
    "garak": ("appsec", "ai-security"),
    "pyrit": ("appsec", "ai-security"),
    "promptfoo": ("appsec", "ai-security"),
    "gitguardian-ggshield": ("appsec", "secret-scanning"),
    "github-secret-scanning": ("appsec", "secret-scanning"),
    "nosey-parker": ("appsec", "secret-scanning"),
    "renovate": ("appsec", "dependency-management"),
    "snyk": ("appsec", "appsec-platform"),
    "socket": ("appsec", "sca"),
    "burpsuite": ("appsec", "dast"),
    "owasp-zap": ("appsec", "dast"),
    "stackhawk": ("appsec", "dast"),
    "arachni": ("appsec", "dast"),
    "nikto": ("appsec", "dast"),
    "nuclei": ("appsec", "dast"),
    "w3af": ("appsec", "dast"),
    "caido": ("appsec", "proxy"),
    "amazon-guardduty": ("appsec", "cloud"),
    "f5-distributed-cloud": ("appsec", "waf"),
    "in-toto": ("appsec", "supply-chain"),
    "nessus": ("appsec", "vuln-scan"),
    "rekor": ("appsec", "supply-chain"),
    "signal-sciences-fastly": ("appsec", "waf"),
    "slsa": ("appsec", "supply-chain"),
    "chain-bench": ("devsecops", "supply-chain"),
    "kubeconform": ("devsecops", "kubernetes"),
    "attacksurfacemapper": ("bugbounty", "recon"),
    "autorecon": ("bugbounty", "recon"),
    "dnsdumpster": ("bugbounty", "osint"),
    "nmapautomator": ("bugbounty", "recon"),
    "rustscan": ("bugbounty", "network"),
    "projectdiscovery-suite": ("bugbounty", "recon"),
    "cobalt-strike": ("redteam", "c2"),
    "certipy": ("redteam", "active-directory"),
    "crackmapexec-netexec": ("redteam", "lateral-movement"),
    "psudohash": ("redteam", "privilege-escalation"),
    "roadtools": ("redteam", "active-directory"),
    "rubeus": ("redteam", "credential-access"),
    "sharphound": ("redteam", "active-directory"),
    "checksec": ("redteam", "reverse-engineering"),
    "mobsf": ("mobile", "mobile"),
    "nowsecure": ("mobile", "mobile"),
    "ostorlab": ("mobile", "mobile"),
    "magisk": ("mobile", "runtime"),
    "firebasescanner": ("mobile", "mobile"),
    "theharvester": ("offensive", "passive-osint"),
    "securitytrails": ("offensive", "passive-osint"),
    "crt-sh": ("offensive", "passive-osint"),
    "github-code-search": ("offensive", "passive-osint"),
}

TAGS_OVERRIDES = {
    "gitguardian-ggshield": "appsec,handbook,secret-scanning",
    "github-secret-scanning": "appsec,handbook,secret-scanning",
    "nosey-parker": "appsec,handbook,secret-scanning",
    "renovate": "appsec,dependency-management,handbook",
    "snyk": "appsec-platform,sast,container,iac,commercial",
    "socket": "appsec,sca,supply-chain,handbook",
    "burpsuite": "appsec,dast,proxy,manual,web,handbook",
    "owasp-zap": "appsec,dast,proxy,scanner,owasp,free,handbook",
    "stackhawk": "appsec,dast,api,handbook",
    "arachni": "appsec,dast,legacy,web,handbook",
    "nikto": "appsec,dast,template-scan,scanner,web,handbook",
    "nuclei": "appsec,dast,template-scan,scanner,templates,handbook",
    "w3af": "appsec,dast,template-scan,scanner,web,handbook",
    "caido": "appsec,proxy,manual,web,handbook",
    "amazon-guardduty": "appsec,cloud,cnapp,threat-detection,handbook",
    "f5-distributed-cloud": "appsec,waf,handbook",
    "in-toto": "appsec,supply-chain,handbook",
    "nessus": "appsec,vuln-scan,network,pentest,handbook",
    "rekor": "appsec,supply-chain,handbook",
    "signal-sciences-fastly": "appsec,waf,handbook",
    "slsa": "appsec,supply-chain,handbook",
    "chain-bench": "devsecops,supply-chain,cis",
    "cobalt-strike": "redteam,c2,pentest,handbook",
}

OFFENSIVE_PHASES = {
    "bugbounty": {
        "api-discovery": "api-discovery",
        "fuzzing": "content-discovery",
        "network": "network-discovery",
        "osint": "passive-osint",
        "recon": "attack-surface",
        "secret-scanning": "vulnerability-discovery",
        "evasion": "exploitation-validation",
        "exploitation": "exploitation-validation",
    },
    "redteam": {
        "osint": "passive-osint",
        "recon": "recon",
        "active-directory": "internal-recon",
        "cloud": "cloud-identity-recon",
        "network": "internal-recon",
        "reverse-engineering": "vulnerability-discovery",
        "defense-evasion": "exploitation-validation",
        "delivery": "exploitation-validation",
        "c2": "post-exploitation",
        "credential-access": "post-exploitation",
        "exfiltration": "post-exploitation",
        "lateral-movement": "post-exploitation",
        "persistence": "post-exploitation",
        "privilege-escalation": "post-exploitation",
    },
}

OFFENSIVE_EXCEPTIONS = {
    "autopoisoner": "post-exploitation",
    "raccoon": "vulnerability-discovery",
    "amass": "domain-discovery",
    "subfinder": "domain-discovery",
    "assetfinder": "domain-discovery",
    "dnsx": "domain-discovery",
    "aquatone": "screenshots",
    "eyewitness": "screenshots",
    "gau": "passive-osint",
    "waybackurls": "passive-osint",
    "gf": "url-collection",
    "hakrawler": "web-crawling",
    "katana": "web-crawling",
    "gospider": "web-crawling",
    "httpx": "http-probing",
    "arjun": "parameter-discovery",
    "paramspider": "parameter-discovery",
    "qsreplace": "parameter-discovery",
    "x8": "parameter-discovery",
    "feroxbuster": "content-discovery",
    "dirsearch": "content-discovery",
    "ffuf": "content-discovery",
    "gobuster": "content-discovery",
    "wfuzz": "content-discovery",
    "dirb": "content-discovery",
    "autorecon": "network-discovery",
    "nmapautomator": "network-discovery",
    "masscan": "network-discovery",
    "nmap": "network-discovery",
    "naabu": "network-discovery",
    "whatweb": "fingerprinting",
    "wafw00f": "fingerprinting",
    "githound": "passive-osint",
    "censys": "passive-osint",
    "shodan": "passive-osint",
    "wireshark": "traffic-analysis",
    "beef": "exploitation-validation",
    "recon-ng": "passive-osint",
    "o365recon": "cloud-identity-recon",
    "roadtools": "cloud-identity-recon",
    "cloudenum": "cloud-identity-recon",
    "bloodhound": "internal-recon",
    "sharphound": "internal-recon",
    "bloodhound-python": "internal-recon",
    "certipy": "internal-recon",
    "enum4linux-ng": "internal-recon",
    "smbclient": "internal-recon",
    "rpcclient": "internal-recon",
    "ldapsearch": "internal-recon",
    "kiterunner": "api-discovery",
    "graphw00f": "api-discovery",
    "kerbrute": "exploitation-validation",
    "evil-winrm": "post-exploitation",
    "smbmap": "post-exploitation",
    "searchsploit": "vulnerability-discovery",
    "cewl": "credential-utilities",
    "crunch": "credential-utilities",
    "credmaster": "exploitation-validation",
    "domainpasswordspray": "exploitation-validation",
    "hydra": "exploitation-validation",
    "sprayingtoolkit": "exploitation-validation",
    "thesprayer": "exploitation-validation",
    "trevorspray": "exploitation-validation",
    "hashpump": "exploitation-validation",
    "responder": "internal-recon",
    "tcpdump": "traffic-analysis",
}


def offensive_phase(item: dict) -> str | None:
    track = item["track"]
    if track == "offensive":
        return OFFENSIVE_EXCEPTIONS.get(item["id"], item["category"])
    if track not in OFFENSIVE_PHASES:
        return None
    return OFFENSIVE_EXCEPTIONS.get(item["id"], OFFENSIVE_PHASES[track].get(item["category"], "vulnerability-discovery"))


def load_runtime() -> dict:
    text = CATALOG.read_text(encoding="utf-8")
    start = text.index("{")
    end = text.rindex(";")
    return json.loads(text[start:end])


def parse_cards(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    matches = list(re.finditer(r"^## (.+?)\n\n\*\*Slug:\*\* `([^`]+)`[^\n]*\n", text, re.M))
    cards = []
    for index, match in enumerate(matches):
        body = text[match.end() : matches[index + 1].start() if index + 1 < len(matches) else len(text)]
        sections = {
            heading.strip(): value.strip()
            for heading, value in re.findall(r"^### (.+?)\n(.*?)(?=^### |\Z)", body, re.M | re.S)
        }
        cards.append({"name": match.group(1).strip(), "id": match.group(2).strip(), "sections": sections})
    return cards


def section(card: dict, *names: str) -> str:
    for name in names:
        if name in card["sections"]:
            return card["sections"][name]
    raise ValueError(f"{card['id']}: missing one of {', '.join(names)}")


def prose(value: str) -> str:
    value = re.sub(r"```.*?```", "", value, flags=re.S)
    value = re.sub(r"^>\s*", "", value, flags=re.M)
    value = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", value)
    value = value.replace("**", "").replace("`", "")
    return re.sub(r"\s+", " ", value).strip()


def first_link(card: dict, names: tuple[str, ...]) -> str:
    links = re.findall(r"https://[^\s)]+", section(card, *names))
    if not links:
        raise ValueError(f"{card['id']}: no official HTTPS link")
    return links[0]


def render() -> str:
    runtime = load_runtime()
    existing = {item["id"]: item for item in runtime["items"]}
    english = parse_cards(EN_SOURCE)
    russian = parse_cards(RU_SOURCE)

    en_ids = [card["id"] for card in english]
    ru_ids = [card["id"] for card in russian]
    if en_ids != ru_ids:
        raise ValueError("English and Russian card order or IDs differ")
    if len(en_ids) != len(set(en_ids)):
        raise ValueError("duplicate Markdown tool IDs")
    if len(en_ids) != 420:
        raise ValueError(f"expected 420 Markdown cards, got {len(en_ids)}")

    next_code = max(int(item["code"]) for item in existing.values() if str(item.get("code", "")).isdigit()) + 1
    items = []
    for en_card, ru_card in zip(english, russian):
        tool_id = en_card["id"]
        if tool_id in existing:
            item = dict(existing[tool_id])
        else:
            track, category = NEW_METADATA[tool_id]
            item = {
                "id": tool_id,
                "name": en_card["name"],
                "url": first_link(en_card, ("Official links",)),
                "track": track,
                "category": category,
                "mitre": None,
                "code": f"{next_code:04d}",
                "example": "",
                "install": first_link(en_card, ("Official links",)),
                "tags": f"{track},{category},handbook",
            }
            next_code += 1

        if tool_id in NEW_METADATA:
            item["track"], item["category"] = NEW_METADATA[tool_id]
        if tool_id in TAGS_OVERRIDES:
            item["tags"] = TAGS_OVERRIDES[tool_id]
        phase = offensive_phase(item)
        if phase:
            item["track"], item["category"] = "offensive", phase
            tags = item["tags"].split(",")
            for tag in ("offensive", phase):
                if tag not in tags:
                    tags.append(tag)
            item["tags"] = ",".join(tags)
        item["id"] = tool_id
        item["name"] = en_card["name"]
        item["desc_en"] = prose(section(en_card, "What it is"))
        item["desc_ru"] = prose(section(ru_card, "Что это"))
        item["usage_en"] = prose(section(en_card, "How it is used"))
        item["usage_ru"] = prose(section(ru_card, "Как применяют"))
        items.append(item)

    unexpected = set(NEW_METADATA) - set(en_ids)
    if unexpected:
        raise ValueError(f"new metadata has unknown IDs: {sorted(unexpected)}")
    missing_new = set(en_ids) - set(existing) - set(NEW_METADATA)
    if missing_new:
        raise ValueError(f"new Markdown IDs need UI metadata: {sorted(missing_new)}")

    catalog = {"version": VERSION, "items": items}
    return "/* Generated by scripts/build_tools_catalog.py from synchronized Markdown sources. */\nconst TOOLS_CATALOG = " + json.dumps(catalog, ensure_ascii=False, indent=2) + ";\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = render()
    if args.check:
        if CATALOG.read_text(encoding="utf-8") != output:
            raise SystemExit("js/tools/catalog.js is out of date; run scripts/build_tools_catalog.py")
        return
    CATALOG.write_text(output, encoding="utf-8")


if __name__ == "__main__":
    main()
