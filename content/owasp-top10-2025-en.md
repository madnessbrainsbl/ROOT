# OWASP Top 10:2025 — theory by category

> 8th edition, released November 2025 (first major update since 2021). Dataset: ~175k CVEs, 589 CWEs, data from 2.8 million applications (Bugcrowd, Contrast Security, Semgrep, Veracode, Wallarm, and others). Methodology: 8 categories from statistics (CWE incidence rates in tested apps + CVSS Exploit/Impact); 2 categories (A03 and A09) added by community survey vote because they are hard to detect statistically in test data.

## Changes vs 2021

| 2025 | 2021 | Change |
|---|---|---|
| A01 Broken Access Control | A01 Broken Access Control | Still #1; absorbed SSRF (was A10:2021) |
| A02 Security Misconfiguration | A05 Security Misconfiguration | Jump #5 → #2 |
| A03 Software Supply Chain Failures | A06 Vulnerable and Outdated Components | Expanded: not only known CVEs in components, but the whole supply chain (CI/CD, package registries, IDEs) |
| A04 Cryptographic Failures | A02 Cryptographic Failures | Drop #2 → #4 |
| A05 Injection | A03 Injection | Drop #3 → #5 |
| A06 Insecure Design | A04 Insecure Design | Drop #4 → #6 |
| A07 Authentication Failures | A07 Identification and Authentication Failures | Renamed; same rank |
| A08 Software or Data Integrity Failures | A08 Software and Data Integrity Failures | Same rank |
| A09 Security Logging & Alerting Failures | A09 Security Logging and Monitoring Failures | Renamed (emphasis on alerting, not just logging) |
| A10 Mishandling of Exceptional Conditions | — (new) | New category: error handling, fail-open, race conditions |

SSRF (A10:2021) is no longer a standalone category — it is folded into Broken Access Control, because SSRF is essentially access-control failure for server-side reachability of internal resources.

---

## A01:2025 — Broken Access Control

**Rank:** #1. 100% of tested applications had at least one CWE from this category — the most common vulnerability class overall. 40 related CWEs; highest occurrence count in the dataset.

### Theory

Access control is policy enforcement: a user must not act outside permissions granted to them. Models usually have three layers:
- **Authentication** — who you are (not this category; see A07);
- **Authorization** — what you are allowed to do;
- **Enforcement** — where and how permission is actually checked in code.

Broken Access Control happens when enforcement is missing or trusts attacker-controlled inputs (client code, request parameters, hidden fields, JWTs without proper signature/exp checks).

Key principle: access control only works when checks run in trusted server-side code. Any “check” only on the frontend (hiding a button, disabled fields, JS routing) is UX, not access control.

### Subcategories (what belongs here)

1. **IDOR / BOLA (Insecure Direct Object Reference / Broken Object Level Authorization)** — direct access to an object by id (`/api/orders/1234`) without verifying ownership.
2. **BFLA (Broken Function Level Authorization)** — access to an admin function without a role check (`POST /admin/users/delete`).
3. **Privilege Escalation** — vertical (user → admin) and horizontal (user A → user B’s data).
4. **Path Traversal** (CWE-22/23/36) — escaping the allowed directory via `../`.
5. **Force Browsing** (CWE-425) — guessing/enumerating URLs not linked in the UI.
6. **CORS misconfiguration** — `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`, or reflecting Origin without validation.
7. **CSRF** (CWE-352) — forcing an authenticated user to perform an action without intent (where anti-CSRF tokens/SameSite are missing).
8. **Metadata tampering** — JWT tricks (`alg=none`, `kid` swap, missing signature verification), hidden fields/cookies for privilege gain.
9. **SSRF** (CWE-918, moved here in 2025) — server requests internal/arbitrary resources on the attacker’s behalf (cloud metadata, internal services, localhost).
10. **Open Redirect** (CWE-601) — phishing / allow-list bypass primitive.
11. **Exposure of sensitive info** (CWE-200/201) — data leak via API responses even when the action is “denied” (e.g. 403 vs 404 enables enumeration).

### How it is tested (pentest methodology)

- Role × endpoint matrix: every privileged endpoint as unauthenticated, low-priv, and other-tenant users.
- IDOR fuzzing: sequential/predictable id increments, swapping UUIDs from another session.
- Compare UI behavior vs direct requests (curl/Burp) — hidden UI often still hits open APIs.
- Method checks: GET protected but PUT/DELETE/PATCH on the same resource not.
- JWT: `alg=none`, `kid` path/JWK injection, HMAC secret brute, missing `aud`/`iss`/`exp`.
- SSRF: localhost/127.0.0.1, `169.254.169.254`, DNS rebinding, redirect allow-list bypass, IPv6/decimal/octal IP forms.
- CORS: arbitrary Origin — is it reflected with Allow-Credentials: true?

### Defenses

- Deny by default — allow only explicitly.
- Single reusable authorization point (not copy-pasted across controllers).
- Record ownership checks in the domain model, not only at the route layer.
- Rate limiting on sensitive endpoints.
- Server-side session invalidation on logout; short-lived JWT + refresh tokens.
- Log authorization failures and alert on repeated failures.

---

## A02:2025 — Security Misconfiguration

**Rank:** #2 (was #5 in 2021 — largest upward jump). 16 CWEs, average incidence 3.00%. Growth reflects more behavior driven by configuration (cloud IaC, k8s manifests, feature flags) rather than code.

### Theory

The gap between “securely written code” and a “securely deployed system.” Misconfiguration can appear at any stack layer: OS, web server, app server, database, framework, cloud services (S3, IAM), orchestrators.

Typical manifestations:
- Debug/verbose modes in production (stack traces, debug endpoints like Django `DEBUG=True`, unauthenticated Spring Boot Actuator).
- Default accounts/passwords never changed after install.
- Unnecessary features enabled (extra ports, sample apps, TRACE/OPTIONS).
- Missing security headers (CSP, X-Content-Type-Options, X-Frame-Options, HSTS).
- Overly detailed error messages leaking stacks/versions.
- Over-permissive cloud ACLs (public buckets, overly broad IAM).
- No hardening — “out-of-the-box” defaults left as-is.
- Config drift between environments (staging vs prod).

### How it is tested

- HTTP method checks (OPTIONS/TRACE/PUT/DELETE) on all endpoints.
- Default paths: `/actuator`, `/.env`, `/swagger-ui`, `/wp-admin`, `/.git/`, `/console`, cloud metadata.
- Response header review for missing security headers.
- Force errors (bad Content-Type, broken JSON) — look for stack/version leaks.
- Cloud inventory: public buckets, `0.0.0.0/0` security groups, default VPC.
- Banner versioning (Server, X-Powered-By) mapped to known CVEs.

### Defenses

- Repeatable hardening and automated deployment (IaC) with the same baseline in every environment.
- Minimal platform: remove unused features, samples, docs.
- Regular config review as part of patch management (see A03).
- Segmented architecture (containers/cloud groups/ACLs) between components.
- Automated config effectiveness checks in all environments (CI, config-as-code tests).

---

## A03:2025 — Software Supply Chain Failures

**Rank:** #3 (new expansion of A06:2021 Vulnerable and Outdated Components). 50% of community survey respondents ranked it #1 — while only 11 CVEs map directly to category CWEs in test data (hard to auto-detect), it has the highest average incidence when found (5.72%) and the highest Exploit/Impact score among categories.

### Theory

In 2021 the category was mostly “known vulnerable components” (outdated libraries with public CVEs). In 2025 scope covers the full software lifecycle: build, distribute, update — including **unknown** compromises through trusted channels, not only CVE IDs.

A component (library, framework, container image, CI runner, IDE plugin) usually runs with the same privileges as the app. Compromising a dependency compromises the application.

Vulnerability signs:
- No inventory of all components (direct and transitive), client and server.
- Unsupported/outdated software (OS, DB, runtimes included).
- No regular vulnerability scanning / security bulletins.
- No change management for CI/CD, code repos, artifact stores.
- Components pulled from untrusted sources.
- No separation of duties (one person can commit and deploy to prod without review).
- CI/CD weaker than the systems it builds and deploys.

### Typical attack scenarios

1. **Trusted vendor compromise** — classic: SolarWinds (2019), ~18,000 organizations via a legitimate update.
2. **Conditionally triggered backdoor** — malware activates only under specific conditions (e.g. high-value crypto-wallet supply-chain cases).
3. **Self-propagating registry worm** — e.g. npm “Shai-Hulud”-style campaigns: post-install steals tokens and republishes infected package versions.
4. **Known component CVEs** — Struts2 RCE (CVE-2017-5638, Equifax), Log4Shell (CVE-2021-44228).

### How it is tested

- Build an SBOM and match against OSV/NVD.
- Analyze transitive trees (not only top-level manifests).
- Pipeline integrity: who can merge/deploy without review, branch protection, signed artifacts.
- Artifact provenance — reproducible builds, signatures (Sigstore/cosign, SLSA).
- Audit package registry tokens and IDE extensions.

### Defenses

- Central SBOM + continuous composition analysis (Dependency-Track, Dependency-Check, retire.js, etc.).
- Packages only from official sources; prefer signed artifacts.
- Staged/canary rollouts instead of simultaneous fleet updates.
- Harden repos, developer workstations, CI/CD (MFA, least privilege, tamper-evident logs, environment-scoped secrets).
- Monitor unsupported libraries with a migration plan.

---

## A04:2025 — Cryptographic Failures

**Rank:** #4 (was #2 in 2021). 32 CWEs, average incidence 3.80%.

### Theory

Protecting data in transit and at rest — confidentiality and integrity via cryptography. Formerly Sensitive Data Exposure (2017); renamed in 2021 because exposure is a symptom and cryptographic failure is the root cause.

First classify which data needs protection (PII, credentials, financial, health, business secrets) under applicable law (GDPR, PCI DSS, HIPAA, etc.).

Typical failures:
- Cleartext transport (HTTP, SMTP, FTP instead of TLS).
- Weak/obsolete algorithms (MD5/SHA1 for passwords, DES/RC4, home-grown crypto).
- Default/weak keys, no rotation.
- No certificate validation; ignoring TLS handshake errors.
- Passwords without salt or with fast hashes (raw MD5/SHA-256 instead of bcrypt/scrypt/argon2/PBKDF2).
- Predictable/reused IVs (ECB, static IV in CBC).
- Keeping sensitive data longer than needed (caches/logs/backups).
- Confusing encoding with encryption (Base64 as “protection”).

### How it is tested

- TLS config (testssl.sh): protocol versions, ciphers, HSTS, cert validity.
- Sensitive data in cleartext: URL query strings, localStorage/cookies without Secure/HttpOnly.
- Crypto primitives in code/binaries (hardcoded keys, weak algorithms).
- Password storage format (when dumps are in scope).
- Padding oracle / bit-flipping for CBC modes.

### Defenses

- Data classification and minimization (tokenization/truncation).
- Encrypt sensitive data at rest and in transit with modern algorithms (TLS 1.2+/1.3, AES-GCM).
- Separate key management (KMS/HSM), rotation, keys separated from data.
- Passwords only via slow salted KDFs (Argon2id, bcrypt, scrypt).
- Disable caching of sensitive responses.
- Verify trust chains; never invent your own crypto.

---

## A05:2025 — Injection

**Rank:** #5 (was #3 in 2021). 38 CWEs — most related CVEs of any category. Ranges from high-frequency/low-impact (XSS) to low-frequency/high-impact (SQLi).

### Theory

Injection is when untrusted data is passed to an interpreter (SQL, OS shell, LDAP, XPath, NoSQL, template engine, ORM) as part of a command/query so the interpreter cannot separate data from code/structure.

Root cause: missing separation of control plane and data plane when building queries — string concatenation instead of parameterization.

### Subtypes

- **SQL Injection** — classic, including blind (boolean/time), UNION, error-based, second-order.
- **NoSQL Injection** — MongoDB operators (`$where`, `$ne`) via JSON parameters.
- **OS Command Injection** — user input into `exec`/`system`/shell backticks.
- **LDAP Injection** — LDAP filter manipulation.
- **XPath/XML Injection**, including XXE (sometimes overlaps A08 depending on mechanism).
- **Cross-Site Scripting (XSS)** — Reflected, Stored, DOM-based.
- **Template Injection (SSTI)** — Jinja2/Twig/FreeMarker → often RCE.
- **Header/CRLF Injection** — response splitting.
- **Expression Language Injection** — OGNL, SpEL (Spring, Struts).

### How it is tested

- Fuzz all inputs (params, headers, cookies, files, JSON/XML) with `' " ; -- <script> {{7*7}} $(whoami)`.
- Differential responses (timing for time-based blind; content deltas for boolean).
- Context-aware XSS payloads (attribute/tag/JS string/URL).
- SSTI probes (`{{7*7}}`, `${7*7}`) and engine fingerprinting.
- Static analysis for string concat into DB/shell sinks.

### Defenses

- Parameterized queries / prepared statements (never string-build queries).
- Safe ORM APIs (remember ORM can still inject if misused).
- Positive server-side input validation (allow-lists).
- Context-aware output encoding.
- CSP as XSS defense-in-depth.
- Least-privilege DB accounts.

---

## A06:2025 — Insecure Design

**Rank:** #6 (was #4 in 2021). Industry improved threat modeling / secure-by-design, so rank dropped.

### Theory

Missing or ineffective **architectural and design controls**. Unlike Security Misconfiguration (good control, bad config) or Injection (good idea, bad implementation), Insecure Design means the design itself never included the needed control — even perfect coding cannot save it.

Example: no CAPTCHA/rate-limit on limited stock checkout so bots buy everything — design failure, not a coding typo.

Key concepts:
- **Threat modeling** at design time, not post-release.
- Reusable **secure design patterns** and reference architectures.
- **Business logic abuse** — legitimate features misused (refund loops, loyalty races, parallel limit bypass).
- Trust boundary separation at architecture level.
- Cannot be “patched” — requires redesign.

### How it is tested

- Formal threat modeling (STRIDE, PASTA, attack trees) as a pentest phase.
- Business-logic races (double spend via parallel requests).
- Process limits (coupons, quotas, promos).
- Abuse-case testing, not only happy path.

### Defenses

- SDL with threat modeling for critical stories/features at design time.
- Library of reusable secure components (auth, rate limiting as services).
- Unit/integration tests covering attacker scenarios, not only positive cases.
- Tier segregation by trust and data sensitivity.
- Resource limits per user/service/API as architecture, not afterthought.

---

## A07:2025 — Authentication Failures

**Rank:** #7 (unchanged). Renamed from “Identification and Authentication Failures.” Industry improved via standard auth frameworks (OAuth2/OIDC, managed IdPs vs custom auth).

### Theory

Identity proofing weakens when:
- Brute force / credential stuffing allowed (no rate limit/lockout/CAPTCHA).
- Weak/default/well-known passwords (“Password1”, admin/admin).
- Weak recovery / security questions / predictable reset tokens.
- Passwords stored cleartext or weakly hashed (overlaps A04).
- Missing or weak MFA.
- Session ID in URL (`;jsessionid=`), no session rotation after login (fixation).
- Poor timeout/invalidation, especially on shared devices.

### How it is tested

- Password policy; rate limit/lockout on login and forgot-password.
- User enumeration via error messages/timing.
- Session fixation: is SID set pre-login; does it change after?
- Entropy of reset tokens and SIDs.
- MFA bypass (race, server not enforcing MFA state, downgrade).
- OAuth/OIDC: open redirect_uri, missing state, missing PKCE for public clients.

### Defenses

- MFA for sensitive functions where feasible.
- No default accounts; force password change.
- NIST 800-63B password guidance (length over complexity theater; breached-password checks).
- Rate limiting and progressive delays without verbose failure reasons.
- Server-side sessions: high-entropy random SID, invalidate on logout/timeout, rotate after privilege changes.

---

## A08:2025 — Software or Data Integrity Failures

**Rank:** #8 (unchanged).

### Theory

Missing integrity checks when the app trusts sources/content without cryptographic verification. Vs A03 (Supply Chain): A08 is integrity of a specific artifact/data; A03 is the broader build/delivery ecosystem.

Key scenarios:
- **Insecure deserialization** — untrusted objects → RCE (Java, PHP, pickle, .NET BinaryFormatter).
- **No signature/hash verification** on auto-update (plugins/CDN updates).
- **CI/CD without integrity controls** — unauthorized code becomes “trusted.”
- Untrusted plugins/CDN JS without Subresource Integrity (SRI).

### How it is tested

- Deserialization sinks (`ObjectInputStream`, `unserialize()`, `pickle.loads()`) and gadget chains (ysoserial-class tools).
- CDN scripts for SRI (`integrity=`).
- Auto-update: is signature/hash verified before install?
- CI/CD: unsigned artifacts; swap between build and deploy.

### Defenses

- Digital signatures for software/data origin.
- Dependencies only from expected verified/signed channels.
- SRI for third-party scripts; CSP for script sources.
- Avoid deserializing untrusted data; prefer JSON + schema; sandbox if unavoidable.
- Mandatory review before merge; no deploy without checks.

---

## A09:2025 — Security Logging & Alerting Failures

**Rank:** #9 (unchanged). Renamed from “Logging and Monitoring Failures” — emphasis on **alerting**, because logs without response do not detect incidents.

### Theory

Without enough logging and monitoring, incidents cannot be found. Under-represented in automated test data (hard for scanners to prove “no log”) — enters Top 10 largely via community survey.

Signs of failure:
- Auditable events (logins, failed logins, access denials, high-severity server errors) not logged.
- Logs lack forensic context (user id, timestamp, IP, trace id).
- Logs only local, no SIEM, no protection against attacker tampering/deletion.
- No effective real-time alerting — discovery takes weeks/months instead of hours.
- App cannot detect, escalate, or signal an active attack in real time.

### How it is tested

- Do failed logins / authz denials / obvious SQLi-XSS attempts create logs?
- Log injection (CRLF into log fields) to forge records.
- Can you reconstruct an incident timeline from logs?
- Can a compromised app process delete/modify its own logs?

### Defenses

- Log auth, access control, and server-side validation events with forensic context — never raw passwords/tokens.
- Centralize to SIEM with alerting and escalation.
- Structured logging resistant to injection.
- Incident response playbooks and drills (NIST 800-61r2).
- During DAST/pentest, expect noticeable alerts; silence is itself a finding.

---

## A10:2025 — Mishandling of Exceptional Conditions

**Rank:** #10 (new). 24 CWEs; high average testability coverage (37.95%) among new/small categories; relatively low average incidence (2.95%) but huge total CVE (3416) and occurrence (769k) counts across languages/platforms.

### Theory

Some of these CWEs used to sit under vague “poor code quality.” OWASP narrowed the focus to **how the system behaves when something abnormal happens**.

Three failure types:
1. App **does not prevent** the exceptional condition (no input validation, no limits).
2. App **does not detect** it when it happens (swallowed errors — `catch (Exception e) {}`).
3. App **reacts incorrectly** after it happens (fail open instead of fail closed; partial transaction rollback).

Causes: incomplete validation, catch-all high in the stack, unexpected environment state (memory, privileges, network), inconsistent exception handling, unhandled exceptions.

May appear as logic bugs, overflows, races, fraud, resource/timing/authz failures.

### Key CWEs

- CWE-209/CWE-550 — error messages leak sensitive info (stacks, versions, paths) used for recon (e.g. precise SQLi).
- CWE-636 “Not Failing Securely (Failing Open)” — on error the system **allows** instead of **denies** (e.g. authz service down → allow).
- CWE-703/754/755 — improper check/handling of exceptional conditions.
- CWE-476 NULL Pointer Dereference — crash/DoS or logic skip.
- CWE-234/235 — missing/extra parameters mishandled.
- CWE-369 Divide By Zero — unhandled arithmetic exceptions.

### Typical attack scenarios

1. **Resource exhaustion (DoS)** — exception on upload path does not free resources; repeated errors exhaust handles/connections/memory.
2. **Sensitive data exposure via DB errors** — full DB error text shown; attacker forces varied errors to map schema for SQLi.
3. **State corruption in multi-step transactions** — mid-transaction disconnect; without full rollback (fail closed), races enable double-spend or bad balances.

### How it is tested

- Force errors with bad Content-Type, mid-multipart disconnects, edge values (`null`, empty, negatives, huge strings).
- Check error messages for internal leaks (stacks, paths, library versions, SQL).
- Race multi-step flows (parallel withdraw/coupon/limited purchase).
- Dependency outage behavior (fail open vs fail closed) — what happens to authz if the authz service is down?
- Load/stress for resource exhaustion via unhandled exceptions.

### Defenses

- Handle exceptions where they occur (not only a global catch-all): log + alert + safe user message.
- **Fail closed**, not fail open: multi-step ops fully roll back on failure.
- One application-wide error/logging/alerting strategy.
- Rate limiting, quotas, throttling to prevent abnormal conditions.
- Strict input validation/sanitization on entry.
- Threat model and review error handling; stress and penetration test the final system.

---

## Summary table

| # | Category | CWE | Core idea |
|---|---|---|---|
| A01 | Broken Access Control | 40 | Authorization missing/broken; includes IDOR/BFLA/CSRF/SSRF/CORS |
| A02 | Security Misconfiguration | 16 | Gap between secure code and secure deployment |
| A03 | Software Supply Chain Failures | 6 | Compromised deps, CI/CD, package registries |
| A04 | Cryptographic Failures | 32 | Weak/missing protection for data in transit/at rest |
| A05 | Injection | 38 | Untrusted data interpreted as code/query structure |
| A06 | Insecure Design | — | Architectural failure; not fixable by a patch |
| A07 | Authentication Failures | 36 | Weak identity proofing, brute force, session mgmt |
| A08 | Software or Data Integrity Failures | — | No signature/provenance verification |
| A09 | Security Logging & Alerting Failures | — | Incident not detected/escalated in time |
| A10 | Mishandling of Exceptional Conditions | 24 | Incorrect reaction to abnormal conditions (new) |

Source: [owasp.org/Top10/2025](https://owasp.org/Top10/2025/)
