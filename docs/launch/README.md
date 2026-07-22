# RØOT v0.1.0 launch kit

Use these drafts only after the tagged release, public Pages deployment, and
Docker image are available. The numbers below match the v0.1.0 repository.

## Show HN

**Title:** Show HN: RØOT – an offline OWASP and AppSec training range

I built RØOT, a self-hosted application-security learning range that works
locally without a SaaS account or external target.

It connects OWASP Web and API theory to controlled browser simulations,
vulnerable-versus-remediated code, CTF flags, and bilingual quizzes. The first
release contains 30 Web challenges, 10 API mini-labs, 500 questions, and a
reproducible 250-record CISA KEV/CVE List V5 snapshot.

Python 3.10 is enough, or you can run the Docker image. The project does not
download data on startup and does not accept external API credentials.

Demo: https://madnessbrainsbl.github.io/ROOT/

Source: https://github.com/madnessbrainsbl/ROOT

I would value feedback on installation, navigation, lab difficulty, and whether
the remediation explanations lead to better fixes.

## r/selfhosted

**Title:** I built a self-hosted offline AppSec practice range with OWASP labs

RØOT is a local application-security learning workspace for people who do not
want their practice workflow tied to a cloud account. It includes Web and API
labs, CTF-style simulations, secure-code comparisons, quizzes, a small public
CVE snapshot, payload references, attack chains, command builders, and report
templates.

Run it with `docker compose up --build` and open port 8080. The container is
read-only except for a temporary SQLite database, and no token is required.

I am looking for honest reports about clean installation, mobile navigation,
and which lab needs the most work—not promotional replies.

Demo: https://madnessbrainsbl.github.io/ROOT/

Repository: https://github.com/madnessbrainsbl/ROOT

## LinkedIn

I have released RØOT v0.1.0, an open-source, offline-first AppSec practice
range.

RØOT combines OWASP Web and API learning tracks, controlled browser CTF
challenges, vulnerable and remediated code, bilingual quizzes, and a local
public CVE catalog. It runs with Python or Docker and requires no cloud account
or API credential.

The first release includes 30 Web challenges, 10 API mini-labs, 500 bilingual
questions, and 250 traceable CISA KEV/CVE List V5 records.

I am looking for AppSec practitioners and learners willing to test one lab and
report what is confusing or technically inaccurate.

Demo: https://madnessbrainsbl.github.io/ROOT/

Source: https://github.com/madnessbrainsbl/ROOT

## Technical article outline

**Working title:** Building an offline OWASP training range without vulnerable
infrastructure

1. Why deterministic simulations are useful before live targets.
2. The learning loop: theory, exploit reasoning, remediation, quiz.
3. Keeping the Python runtime dependency-free.
4. Serving the same CVE seed through SQLite and static GitHub Pages.
5. Trust boundaries and deliberate limitations.
6. What feedback v0.1.0 needs.

## OWASP talk proposal

**Title:** Building an Offline AppSec Training Range for OWASP Web and API
Security

**Abstract:** This talk demonstrates how a framework-free local application can
connect OWASP concepts to controlled exploit simulations, remediation examples,
and assessment without provisioning vulnerable cloud targets. It covers the
learning model, browser and SQLite architecture, content provenance, safety
boundaries, and lessons from building the first 40 practical exercises.

**Format:** 20-minute talk or 45-minute guided workshop.
