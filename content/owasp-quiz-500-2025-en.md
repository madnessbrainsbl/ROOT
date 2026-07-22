# OWASP Top 10:2025 Quiz — 500 Questions (50 per category)

Format: question → 4 options (A–D) → correct answer. Brief explanations included where the topic is nuanced or overlaps with another category.

---

## A01:2025 — Broken Access Control (50 questions)

1. Which of the following does NOT belong to Broken Access Control in OWASP Top 10:2025? A) IDOR B) SQL Injection C) BFLA D) CSRF
   Answer: **B** (SQL Injection is an Injection (A05) issue, not Broken Access Control. IDOR, BFLA, and CSRF are all access-control failures listed under A01:2025.)

2. Which CWE corresponds to Server-Side Request Forgery in the 2025 edition? A) CWE-352 B) CWE-601 C) CWE-918 D) CWE-862
   Answer: **C** (CWE-918 is the standard CWE for Server-Side Request Forgery. In OWASP Top 10:2025, SSRF is folded into A01 Broken Access Control rather than a standalone category.)

3. IDOR stands for: A) Internal Denial of Resource B) Insecure Direct Object Reference C) Internal Data Object Retrieval D) Indirect Direct Object Request
   Answer: **B** (IDOR stands for Insecure Direct Object Reference: accessing an object by a user-supplied id without verifying the caller is allowed to use that object.)

4. The "deny by default" principle means: A) all requests are logged B) access is granted only to explicitly authorized roles; everything else is denied C) all errors are hidden from the user D) the server rejects TLS 1.0
   Answer: **B** (Deny by default means only explicitly authorized roles or permissions get access; anything not listed is refused. Logging or hiding errors does not implement this principle.)

5. BFLA stands for: A) Broken Function Level Authorization B) Basic File Level Access C) Backend Function Logic Attack D) Broken Field Level Auth
   Answer: **A** (BFLA means Broken Function Level Authorization — missing or weak checks that a caller may invoke a privileged function (for example an admin API).)

6. Why doesn't checking access rights only on the frontend (hiding a button in the UI) count as access control? A) It's too slow B) JS cannot be tested C) An attacker can call the API/endpoint directly, bypassing the UI D) Browsers block such checks
   Answer: **C** (UI-only checks are not enforcement: an attacker can call the same API with curl or a proxy and skip the hidden button entirely. Access control must run on the trusted server.)

7. Which HTTP status code distinction (403 vs 404) can help an attacker enumerate resources? A) Reveals the server version B) Lets an attacker distinguish "resource exists but no access" from "resource doesn't exist" C) Indicates WAF usage D) Doesn't matter for access control
   Answer: **B** (Returning 403 for existing forbidden resources and 404 only when missing lets attackers map what exists. Consistent responses reduce sensitive-info enumeration (CWE-200 style leaks).)

8. What is force browsing (CWE-425)? A) Automatic browser update B) Guessing/enumerating URLs not linked in the UI C) Forced redirect D) DDoS via browser
   Answer: **B** (Force browsing (CWE-425) is guessing or requesting URLs not linked in the UI to reach hidden admin pages or files that lack server-side authorization.)

9. A CORS misconfiguration vulnerability occurs when: A) the server doesn't support CORS at all B) Access-Control-Allow-Origin reflects any Origin together with Allow-Credentials: true C) HTTPS is used D) the Content-Type header is missing
   Answer: **B** (Reflecting any Origin with Access-Control-Allow-Credentials: true lets a malicious site read authenticated cross-origin responses. That is a classic CORS access-control failure.)

10. The cookie attribute whose absence is listed under A01:2025 (CWE-1275) is: A) Secure B) HttpOnly C) SameSite D) Max-Age
    Answer: **C** (CWE-1275 covers missing SameSite on cookies. Without SameSite (and related CSRF defenses), browsers may send session cookies on cross-site requests, enabling CSRF under A01.)

11. An attacker modifies a JWT, setting alg to "none". Which class of vulnerability does this exploit? A) Cryptographic Failure B) Missing server-side signature verification (Broken Access Control) C) Injection D) Insecure Design
    Answer: **B** (Accepting JWT alg=none (or skipping signature verification) is missing server-side authz/integrity of the token — metadata tampering under Broken Access Control, not a pure crypto design choice.)

12. A CSRF attack requires the attacker to: A) know the victim's password B) have the victim authenticated and trick them into performing an action via a crafted request without their knowledge C) have physical access to the victim's device D) be in a MITM position on the network
    Answer: **B** (CSRF abuses the browser’s automatic sending of the victim’s session to a site where the victim is already logged in; the attacker does not need the password if the session cookie is attached.)

13. Which header/mechanism is the primary defense against CSRF alongside an anti-CSRF token? A) X-Frame-Options B) SameSite cookie attribute C) Content-Security-Policy D) X-Content-Type-Options
    Answer: **B** (Besides anti-CSRF tokens, the SameSite cookie attribute limits when cookies are sent on cross-site requests and is a primary browser-side CSRF defense listed with A01 controls.)

14. Path Traversal (CWE-22) is most often exploited through: A) an SQL query B) sequences like ../../../etc/passwd in parameters that handle file paths C) an XML parser D) the Referer HTTP header
    Answer: **B** (Path Traversal (CWE-22) injects ../-style segments into path parameters so the server reads files outside the intended directory (for example /etc/passwd).)

15. Confused Deputy (CWE-441) in the context of Broken Access Control describes a situation where: A) a user confuses their login and password B) a privileged component is tricked into acting on behalf of a less-privileged attacker C) two admins have conflicting rights D) a certificate has expired
    Answer: **B** (Confused Deputy (CWE-441) is when a privileged component acts on attacker-controlled input and thus performs privileged actions the attacker could not do directly.)

16. Why was SSRF folded into Broken Access Control in 2025 instead of remaining a separate category? A) SSRF is obsolete as a class B) At its core, SSRF is a violation of the server's access control over internal resources C) SSRF no longer occurs D) It was a community vote with no underlying rationale
    Answer: **B** (OWASP 2025 treats SSRF as the server being tricked into reaching internal resources the attacker should not access — an access-control failure over server-side reachability, not a separate Top 10 rank.)

17. A typical target of an SSRF attack in cloud infrastructure is: A) bypassing a CAPTCHA B) the cloud metadata endpoint (e.g., 169.254.169.254) C) the provider's DNS server D) an NTP server
    Answer: **B** (Cloud instance metadata (often 169.254.169.254) holds credentials and config; SSRF that can hit it is a high-impact internal access-control bypass.)

18. Which technique can bypass an SSRF allow-list that checks the domain rather than the resolved IP? A) DNS rebinding B) Base64 encoding C) Increment ID D) XML entity expansion
    Answer: **A** (DNS rebinding makes a hostname resolve first to an allow-listed IP, then later to an internal IP, defeating domain-only SSRF allow-lists that never recheck the resolved address.)

19. A pentester is testing for IDOR. Which methodology is most effective? A) Port scanning only B) Replacing the ID/UUID in a request with a value obtained from a different (someone else's) session C) Checking the TLS version D) Brute-forcing the password
    Answer: **B** (Effective IDOR testing swaps object identifiers between sessions (or tenants) while keeping the same auth context, proving the server does not enforce ownership.)

20. Vertical privilege escalation differs from horizontal privilege escalation in that: A) vertical is user → admin access, horizontal is access to another user's data at the same level B) vertical only occurs in mobile apps C) horizontal is impossible without MFA D) there is no difference
    Answer: **A** (Vertical escalation raises privilege level (user to admin); horizontal stays at the same role but accesses another principal’s resources.)

21. According to OWASP 2025 data, what percentage of tested applications contained at least one CWE from the Broken Access Control category? A) 25% B) 50% C) 73% D) 100%
    Answer: **D** (OWASP Top 10:2025 reports that 100% of tested applications had at least one CWE from Broken Access Control — the most common category by occurrence.)

22. Which of the following is a correct practice for implementing access control per OWASP? A) Re-implement the check in every controller from scratch B) Implement it once and reuse it throughout the application C) Rely on hiding endpoints (security through obscurity) D) Store access rights in an unsigned cookie
    Answer: **B** (OWASP recommends a single reusable authorization mechanism instead of copy-pasted checks, obscurity, or client-controlled rights stores that are easy to miss or forge.)

23. CWE-566 from the A01:2025 list describes: A) XSS via SQL B) Authorization Bypass Through User-Controlled SQL Primary Key C) Weak TLS cipher D) Memory leak
    Answer: **B** (CWE-566 is Authorization Bypass Through User-Controlled SQL Primary Key: a client-chosen primary key is used in a query without an ownership/authorization check.)

24. Burp Suite is most often used when testing access control to: A) fuzz memory B) intercept and manually/automatically (Intruder) modify requests — swapping parameters, roles, tokens C) statically analyze source code D) scan Wi-Fi
    Answer: **B** (Burp Suite’s proxy and Intruder let testers rewrite ids, roles, methods, and tokens to prove missing server-side authorization — the core of access-control testing.)

25. Why should a stateful session ID be invalidated server-side on logout? A) To reduce database size B) So a token left in the browser (or stolen) cannot be reused after logout C) It's a direct GDPR requirement D) Not required if HTTPS is used
    Answer: **B** (If the server still accepts a session after logout, a leftover or stolen session id remains valid. Server-side invalidation ends the session on the trusted side.)

26. Which of the following is NOT a Broken Access Control mitigation? A) Rate limiting on sensitive endpoints B) Logging access-control failures C) Storing passwords with bcrypt D) Record-ownership–based permission model
    Answer: **C** (Storing passwords with bcrypt is a cryptographic control (A04 Cryptographic Failures), not an access-control mitigation. Rate limits, authz logging, and ownership models are A01 defenses.)

27. Directory listing (CWE-548) left enabled on a web server can lead to: A) improved SEO B) disclosure of the file structure, potentially exposing sensitive files C) improved performance D) automatic traffic encryption
    Answer: **B** (Enabled directory listing (CWE-548) reveals file and path structure and can expose backups, configs, or other sensitive content that should not be browsable.)

28. Open Redirect (CWE-601) is usually used by an attacker to: A) mount a DoS attack B) phish victims — a legitimate-looking link on the target's domain redirects to a malicious site C) perform SQL injection D) bypass an IP-based WAF
    Answer: **B** (Open Redirect (CWE-601) is mainly abused for phishing: a trusted domain URL redirects users to a malicious site, increasing credibility of the lure.)

29. What does "Authorization Bypass Through User-Controlled Key" (CWE-639) mean? A) A weak cryptographic key B) The app uses a client-supplied value as the key to access a record without verifying ownership C) An API key leaked in git D) Use of a default password
    Answer: **B** (CWE-639 means the app takes a user-controlled key (id, path, etc.) to fetch a record and skips verifying that the authenticated user owns or may access it — classic IDOR/BOLA.)

30. Zero Trust architecture relates to Broken Access Control in that it: A) removes the need for authentication B) assumes every request is verified for authorization, rather than trusting the fact of being "inside the perimeter" C) replaces TLS D) is unrelated to access control
    Answer: **B** (Zero Trust assumes no implicit trust from network location: every request must be authenticated and authorized, which directly addresses Broken Access Control patterns.)

31. The symptom "an accessible API with missing access controls for POST, PUT and DELETE" means: A) GET requests are protected by an authorization check, but the modifying methods are not B) the API doesn't work at all C) HTTPS is absent D) Swagger docs are missing
    Answer: **A** (Protecting only GET while leaving POST/PUT/DELETE open is incomplete method-level authorization: read may be gated, but state-changing operations are not.)

32. A classic OWASP example: an attacker changes the acct parameter in a URL for their own account to someone else's. This is an example of: A) CSRF B) IDOR C) XSS D) SSRF
    Answer: **B** (Changing acct (or similar id) to another user’s value without ownership checks is the textbook IDOR / Insecure Direct Object Reference scenario.)

33. Which check is NOT sufficient defense against access-control attacks? A) server-side role check on every request B) hiding a link in the UI only C) checking record ownership in the domain model D) rate limiting + logging denials
    Answer: **B** (Hiding a link only changes UX; the endpoint may still work for a direct request. Real defense is server-side authorization, ownership checks, and monitoring.)

34. Leftover .git metadata in the web root (CWE-538) is dangerous because it: A) increases page load time B) can expose commit history, including accidentally committed secrets C) causes XSS D) blocks search-engine indexing
    Answer: **B** (Public .git metadata (CWE-538) can expose full commit history and blobs, including secrets that were committed and later «removed» from the working tree.)

35. Which of the following is an example of horizontal privilege escalation? A) A regular user gains admin rights B) User A reads user B's private messages while having the same privilege level C) Guest access is disabled D) The admin password is changed
    Answer: **B** (Horizontal escalation is peer-level abuse: same role, another user’s data (for example reading someone else’s messages). Gaining admin is vertical escalation.)

36. Why are short-lived JWTs paired with a refresh token preferable to long-lived JWTs? A) They reduce server compute load B) They shrink the window during which a stolen access token remains valid C) JWT otherwise doesn't support signatures D) An HTML5 requirement
    Answer: **B** (Short-lived access JWTs expire quickly if stolen; refresh tokens can be rotated and revoked, shrinking the useful lifetime of a compromised access token.)

37. The difference between Missing Authorization (CWE-862) and Incorrect Authorization (CWE-863): A) the former means the check is absent entirely, the latter means a check exists but is implemented incorrectly B) they're synonyms C) the former applies only to APIs D) the latter applies only to databases
    Answer: **A** (CWE-862 Missing Authorization means no check at all; CWE-863 Incorrect Authorization means a check runs but the logic or policy is wrong.)

38. When auditing a CORS policy, the first thing to check is: A) the Node.js version B) whether an arbitrary Origin is reflected in Access-Control-Allow-Origin together with Allow-Credentials: true C) cookie size D) presence of robots.txt
    Answer: **B** (The critical CORS audit is whether untrusted Origins are reflected with Allow-Credentials: true, enabling credentialed cross-origin data theft.)

39. UNIX Symlink Following (CWE-61) is a vulnerability where: A) the application mishandles symbolic links, allowing access to files outside the intended directory B) the server hangs under high traffic C) the browser doesn't support JS D) the TLS certificate has expired
    Answer: **A** (UNIX Symlink Following (CWE-61) occurs when the app follows symlinks unsafely and reads or writes files outside the intended directory tree.)

40. Per OWASP, "Modeling access controls should enforce _____ rather than allowing users to CRUD any record" — the missing phrase: A) role hierarchy B) record ownership C) IP whitelisting D) session duration
    Answer: **B** (OWASP guidance stresses enforcing record ownership in the access model so users cannot CRUD arbitrary records just because they know an id.)

41. What's the correct way to test BFLA on an endpoint like /admin/deleteUser? A) Check that the button is unavailable to a regular user in the UI B) Send a direct HTTP request as a low-priv user directly (curl/Burp), bypassing the UI C) Check server logs D) Read the API documentation
    Answer: **B** (BFLA is proven by calling the privileged function as a low-privilege user directly (curl/Burp). UI button visibility alone does not prove server-side denial.)

42. Which attack technique does NOT belong to Broken Access Control? A) Parameter tampering B) Time-based blind SQL injection C) JWT alg=none D) Force browsing
    Answer: **B** (Time-based blind SQL injection is an Injection (A05) technique. Parameter tampering, JWT alg=none, and force browsing are access-control related.)

43. Does using a role-based model (RBAC) alone guarantee the absence of Broken Access Control? A) Yes, always B) No — a poor server-side implementation of the role check can still be vulnerable C) Yes, if JWT is used D) Yes, if the app is written in Java
    Answer: **B** (RBAC only helps if roles are checked correctly on every sensitive path server-side. A model without sound enforcement still yields Broken Access Control.)

44. What's the correct sequence of actions when an IDOR is found during a pentest? A) Immediately post about it on social media B) Document a PoC, assess impact (what data is exposed), report through the responsible-disclosure/bug bounty program C) Mass-download every user's data as "proof" D) Ignore it if the severity seems low
    Answer: **B** (Ethical process is PoC documentation, impact assessment, and report via responsible disclosure or bug bounty — not public dumps or mass data exfiltration.)

45. CWE-425 (Direct Request/Forced Browsing) is most often found by a tester through: A) static code analysis for XSS B) attempting direct access to known/predicted paths without going through the normal navigation flow C) fuzzing input forms D) checking response headers
    Answer: **B** (CWE-425 is found by requesting known or predicted paths and admin URLs outside the normal UI flow, proving forced browsing of unprotected resources.)

46. What's the difference between Authentication and Authorization in the context of A01? A) They're the same thing B) Authentication is who you are, Authorization is what you're allowed to do C) Authorization only applies to passwords D) Authentication only applies to APIs
    Answer: **B** (Authentication establishes identity; authorization decides permitted actions. A01 is mainly about authorization enforcement failures after (or without) proper identity checks.)

47. An app checks permissions on the frontend, but the REST API doesn't verify them server-side. Which tool best exposes this? A) Nmap B) curl/Postman/Burp — calling the API directly, bypassing the frontend C) Wireshark for Wi-Fi analysis D) John the Ripper
    Answer: **B** (Direct API calls with curl, Postman, or Burp bypass the frontend permission UI and show whether the server enforces authorization independently.)

48. Per OWASP recommendations, unit and integration tests should include: A) only happy-path scenarios B) functional access-control tests (verifying denial for unauthorized roles) C) only load testing D) only UI tests
    Answer: **B** (OWASP recommends automated functional tests that assert unauthorized roles are denied, not only happy-path success scenarios.)

49. Which of the following best describes the root cause of Broken Access Control as a whole? A) A weak user password B) The gap between the declared access policy and its actual enforcement in trusted server-side code C) Lack of HTTPS D) An outdated framework version
    Answer: **B** (Root cause is the gap between the stated access policy and what trusted server-side code actually enforces on each request and resource.)

50. Which measure is MOST effective against mass automated exploitation of IDOR via sequential ID enumeration? A) Using random UUIDs instead of sequential IDs + mandatory server-side ownership checks B) Increasing password length C) Disabling JavaScript D) Switching programming languages
    Answer: **A** (Random UUIDs slow mass sequential guessing, but mandatory server-side ownership checks stop IDOR even if an id is known — both together are most effective.)

---
## A02:2025 — Security Misconfiguration (50 questions)

1. Security Misconfiguration jumped from #5 (2021) to #2 (2025) mainly because: A) SQL injections increased B) more application behavior is now driven by configuration (cloud IaC, k8s, feature flags) C) password quality declined D) HTTPS was deprecated
   Answer: **B** (A02 rose from #5 to #2 largely because modern systems put more behavior in configuration (IaC, Kubernetes, feature flags), so misconfiguration impact and frequency grew.)

2. Which of the following is a classic Security Misconfiguration example? A) Missing SQL query parameterization B) DEBUG=True left enabled in a production Django app C) A weak password-hashing algorithm D) Missing MFA
   Answer: **B** (DEBUG=True in production Django is a classic misconfiguration: verbose errors and debug features expose internals. SQL parameterization and password hashing are other categories.)

3. Spring Boot Actuator exposed without authentication at /actuator is an example of: A) XSS B) Security Misconfiguration C) CSRF D) Insecure Design
   Answer: **B** (Unauthenticated Spring Boot Actuator is an exposed management surface left improperly secured — textbook Security Misconfiguration, not XSS or CSRF.)

4. Which HTTP method is often mistakenly left enabled, though unneeded, and can expose request headers (XST attack)? A) GET B) POST C) TRACE D) HEAD
   Answer: **C** (HTTP TRACE is rarely needed in production and can echo request headers (including cookies) for cross-site tracing (XST). It should usually be disabled as hardening.)

5. The HSTS header relates to: A) protection against SQL injection B) security misconfiguration/hardening — enforcing HTTPS usage C) user authorization D) database encryption
   Answer: **B** (HSTS is a security-hardening response header that forces browsers to use HTTPS, reducing SSL stripping and accidental cleartext visits — an A02 configuration control.)

6. A publicly accessible S3 bucket containing sensitive data is an example of: A) Injection B) cloud resource misconfiguration C) Broken Authentication D) XXE
   Answer: **B** (A public S3 bucket with sensitive data is cloud ACL/policy misconfiguration, not injection or authentication logic failure in application code.)

7. CSP (Content-Security-Policy) relates to: A) protecting against XSS/some content-injection types by restricting sources of executable code B) API authorization C) traffic encryption D) rate limiting
   Answer: **A** (CSP restricts which sources may load scripts and other content, reducing XSS and some injection of executable content when correctly configured as a security header.)

8. Why does keeping staging and production configurations identical matter for security? A) It saves money B) Configuration drift between environments creates unpredictable vulnerabilities not caught during testing C) It doesn't matter for security D) Required only for SOX compliance
   Answer: **B** (If staging and production configs diverge, tests miss prod-only insecure settings. Aligning environments reduces configuration drift and surprise production exposure.)

9. Which of the following is a recommended practice per OWASP A02:2025? A) Leave sample apps and default docs on prod for developer convenience B) A repeatable hardening process via IaC applied consistently to every environment C) Reuse the same password for all service accounts D) Disable error logging to speed things up
   Answer: **B** (OWASP recommends repeatable hardening via Infrastructure as Code applied the same way in every environment, not leaving samples, shared passwords, or disabled logging on prod.)

10. Exposing a stack trace with the framework version in an error response is a risk because: A) it increases response time B) it gives an attacker information to match against known CVEs for that version C) it directly violates GDPR D) it causes a memory leak
    Answer: **B** (Stack traces with framework versions help attackers map the stack to known CVEs and craft exploits; they should not be returned to end users in production.)

11. Default credentials (admin/admin) left unchanged after installation fall under: A) Cryptographic Failure B) Security Misconfiguration C) Insecure Design D) Injection
    Answer: **B** (Leaving default admin/admin credentials is configuration hygiene failure after install — a core Security Misconfiguration pattern, not crypto algorithm design.)

12. An AWS security group rule of "0.0.0.0/0" on port 22 (SSH) is an example of: A) Injection B) an excessively open network configuration (misconfiguration) C) XSS D) CSRF
    Answer: **B** (0.0.0.0/0 on SSH opens management access to the whole Internet — an overly permissive network security-group misconfiguration.)

13. The X-Content-Type-Options: nosniff header prevents: A) SQL injection B) MIME-sniffing attacks, where the browser interprets a file differently than its declared Content-Type C) CSRF D) memory leaks
    Answer: **B** (X-Content-Type-Options: nosniff stops browsers from MIME-sniffing a response into a different type, which can turn uploaded content into executable script.)

14. The average incidence rate for A02:2025 was approximately: A) 0.5% B) 3.00% C) 15% D) 50%
    Answer: **B** (OWASP Top 10:2025 cites an average incidence around 3.00% for A02 Security Misconfiguration among the category’s CWEs.)

15. Why is "removing unused features, ports, and services" an important hardening measure? A) It saves disk space B) It reduces the attack surface — fewer potential points of exploitation C) It speeds up compilation D) Required only for mobile apps
    Answer: **B** (Removing unused features, ports, and services shrinks the attack surface so there are fewer listening services and components to exploit or misconfigure.)

16. Which tool is most commonly used by a pentester to check a server's TLS configuration? A) sqlmap B) testssl.sh / nmap --script ssl-enum-ciphers C) John the Ripper D) Metasploit exploit modules only
    Answer: **B** (testssl.sh and nmap ssl-enum-ciphers scripts are standard tools to enumerate TLS versions, ciphers, and cert issues; sqlmap and password crackers target other problems.)

17. The difference between Security Misconfiguration and Insecure Design (A06): A) misconfiguration is incorrectly configuring a properly designed control; insecure design means the control is entirely absent from the architecture B) they're the same thing C) misconfiguration applies only to networking D) insecure design applies only to passwords
    Answer: **A** (Misconfiguration wrongly sets a control that should exist; Insecure Design (A06) means the security control was never designed into the architecture.)

18. A /.env path accidentally accessible on a web server can expose: A) frontend source code B) environment variables — often API keys, database passwords, secrets C) the user list D) git commit history
    Answer: **B** (A web-reachable .env often dumps environment variables with API keys, DB passwords, and other secrets — a deployment/config exposure, not just frontend source.)

19. Which of the following is part of automated configuration checking in CI/CD? A) Manual QA testing of every release B) Config-as-code with automated tests verifying the baseline configuration before deployment C) Disabling all tests to speed up releases D) Using production data in the dev environment
    Answer: **B** (Automated config checking in CI/CD means config-as-code plus tests that enforce the security baseline before deploy, not skipping tests or using prod data in dev.)

20. Why is verbose/debug mode especially dangerous specifically in production? A) It slows down the server B) It exposes internal information (paths, versions, stack traces) useful for an attack, that end users don't need C) It requires more memory D) It's incompatible with HTTPS
    Answer: **B** (Debug/verbose mode in production leaks paths, versions, and stacks useful to attackers and unnecessary for normal users — a common A02 production failure.)

21. A /swagger-ui path accessible without authentication is risky because: A) it increases server load B) it exposes the full API spec — all endpoints, parameters, data structure C) it causes XSS D) it disables CORS
    Answer: **B** (Public unauthenticated Swagger UI reveals the full API surface (endpoints, parameters, schemas), greatly aiding reconnaissance and targeted abuse.)

22. Which of the following is NOT an example of security misconfiguration? A) An unencrypted password in the DB B) An open Kubernetes Dashboard without authentication C) Directory listing enabled D) An unchanged default admin password
    Answer: **A** (An unencrypted password in the database is a Cryptographic Failure (A04). Open dashboards, directory listing, and default admin passwords are misconfiguration examples.)

23. The term "out-of-the-box configuration" in the A02 context means: A) configuration customized for specific needs B) configuration "as-is" after install, without security hardening applied C) configuration that only works offline D) an experimental feature
    Answer: **B** (Out-of-the-box means leaving vendor defaults as installed without hardening — sample apps, open ports, and insecure defaults stay enabled.)

24. Lack of segmentation between application components (containers/cloud groups/ACLs) relates to: A) a good practice for performance B) a failure of defense-in-depth at the architecture/network-configuration level C) a GDPR requirement D) a CDN necessity
    Answer: **B** (Missing segmentation between components weakens defense-in-depth: one breach can reach others via open network paths or overly broad ACLs.)

25. How do you correctly test for extra HTTP methods on an endpoint? A) Send an OPTIONS request and analyze the Allow header, then manually try TRACE/PUT/DELETE B) Only use GET requests C) Read the Swagger docs D) Ask the developer
    Answer: **A** (OPTIONS reveals allowed methods via Allow; then actively probing TRACE/PUT/DELETE confirms what is really enabled beyond documentation claims.)

26. Why is a Server: Apache/2.4.29 banner in a server response a potential risk? A) It slows down the response B) It lets an attacker match the version against known CVEs C) It's required for SEO D) It's not a risk at all
    Answer: **B** (A precise Server version banner helps fingerprint the stack and match known CVEs, lowering the cost of targeted exploitation.)

27. Which of the following correctly describes "continuous configuration verification"? A) A one-time check at first deployment B) An automated, repeated process verifying configuration effectiveness across all environments, rather than a one-off setup C) A once-a-year audit check only D) Manual QA-only verification
    Answer: **B** (Continuous configuration verification is automated, repeated checking that the secure baseline still holds in all environments — not a one-time install checkbox.)

28. A cloud metadata service (169.254.169.254) accessible without restriction from an application is most often exploited in combination with which other vulnerability? A) XSS B) SSRF C) CSRF D) Brute-force
    Answer: **B** (Unrestricted app access to 169.254.169.254 is usually chained with SSRF so the attacker forces the server to fetch cloud credentials from metadata.)

29. Which of the following is the "minimal platform" principle? A) Install as many packages as possible "just in case" B) Remove unused features, components, docs, and sample apps C) Always use the newest OS version without testing D) Disable all logs to save space
    Answer: **B** (Minimal platform means stripping unused features, samples, docs, and components so defaults and forgotten services do not expand the attack surface.)

30. A CWE in the A02:2025 list (16 CWEs total) most likely includes: A) CWE-798 Hardcoded Credentials B) CWE-79 XSS C) CWE-89 SQL Injection D) CWE-306 Missing Authentication
    Answer: **A** (Hardcoded credentials (CWE-798) fit configuration/secrets hygiene issues associated with A02’s CWE set; XSS and SQLi belong to other Top 10 categories.)

31. A Kubernetes pod running with privileged: true without necessity is an example of: A) Injection B) Security Misconfiguration in cloud/container infrastructure C) Broken Authentication D) Cryptographic Failure
    Answer: **B** (Unnecessary privileged: true on a Kubernetes pod is container/cloud privilege misconfiguration that expands host compromise impact.)

32. Why is a single centralized configuration-management point preferable to manually configuring each server individually? A) It's cheaper to develop B) It reduces config drift and human error risk at scale C) It doesn't require testing D) It's unrelated to security
    Answer: **B** (Centralized config management reduces snowflake servers, human error, and config drift at scale compared with hand-tuning each host.)

33. Directory listing on a web server (e.g., Apache Options +Indexes) maps to which CWE? A) CWE-79 B) CWE-548 C) CWE-89 D) CWE-352
    Answer: **B** (Directory listing maps to CWE-548 (Exposure of Information Through Directory Listing), commonly enabled by web-server options such as Apache Indexes.)

34. Is it true that security misconfiguration can occur at the OS, web server, database, framework, and cloud service level simultaneously? A) No, only at the application level B) Yes — it's a cross-layer category spanning the entire stack C) No, only in the cloud D) No, only in legacy systems
    Answer: **B** (Yes: A02 spans OS, web/app servers, databases, frameworks, and cloud services — misconfiguration can appear at any stack layer simultaneously.)

35. What's the right sequence of actions upon finding an open admin interface during a pentest? A) Immediately publish it on a blog B) Document it, verify potential unauthorized access/actions, report it to the client with a remediation recommendation C) Use the interface for ongoing access without approval D) Ignore it as minor
    Answer: **B** (On finding an open admin interface, document, carefully verify impact within scope, and report remediation guidance — do not exploit for ongoing access or publicize prematurely.)

36. The absence of X-Frame-Options/frame-ancestors in CSP makes an app vulnerable to: A) SQL injection B) Clickjacking C) SSRF D) Path Traversal
    Answer: **B** (Without X-Frame-Options or CSP frame-ancestors, pages can be embedded in hostile iframes for clickjacking, tricking users into unintended UI actions.)

37. Which of the following best describes the link between A02 and A03 (Supply Chain)? A) They're unrelated B) Insecure configuration of any part of the supply chain (CI/CD, registries) is itself a form of misconfiguration, so the categories overlap C) A03 only covers browser vulnerabilities D) A02 only applies to databases
    Answer: **B** (Insecure CI/CD, registry, or pipeline settings are supply-chain issues (A03) that are also misconfigurations (A02); the categories overlap on config of trusted build paths.)

38. Per OWASP, a "segregated application architecture" is recommended for: A) reducing infrastructure costs B) limiting blast radius when one component is compromised, via segmentation C) speeding up development D) reducing compile time
    Answer: **B** (Segregated architecture limits blast radius via network/ACL segmentation so compromise of one component does not automatically reach others.)

39. Deliberately sending an incorrect Content-Type to trigger a stack-trace disclosure is a testing technique for: A) SQL Injection B) Security Misconfiguration (error handling) C) CSRF D) Clickjacking
    Answer: **B** (Forcing errors with a bad Content-Type to elicit stack traces tests verbose error handling misconfiguration — an A02 reconnaissance technique.)

40. Why is automated (IaC) configuration deployment preferable to manual setup via SSH/console? A) It's faster to type commands B) Reproducibility, git-based versioning, no "snowflake" servers with drift C) IaC doesn't need testing D) It doesn't matter
    Answer: **B** (IaC gives reproducible, versioned configs and avoids snowflake manual hosts that silently drift from the secure baseline.)

41. A publicly accessible /wp-admin path on WordPress, unrestricted by IP/VPN, is a risk in the context of: A) XSS B) Misconfiguration + a potential entry point for brute-force attacks (overlapping with A07) C) SSRF D) Deserialization
    Answer: **B** (Public /wp-admin without IP/VPN restriction is exposure of an admin surface (misconfiguration) and a common brute-force entry point, overlapping A07 authentication attacks.)

42. Which of the following is a bad practice in the context of A02? A) Using a WAF as an additional layer of defense B) Leaving software version banners unchanged on public-facing services C) Regular configuration reviews D) Minimizing installed packages
    Answer: **B** (Leaving full version banners on public services aids attacker fingerprinting and CVE matching; reviews, package minimization, and layered defenses are good practices.)

43. Misconfiguration-related CVEs are most often exploited via: A) complex 0-day chains B) simple automated bot scanning of known paths/ports C) social engineering D) physical access
    Answer: **B** (Misconfiguration CVEs are frequently hit by mass bots scanning known paths, default ports, and banners — not primarily by complex 0-day chains.)

44. Checking HTTP security headers (CSP, X-Frame-Options, HSTS, etc.) is typically done via: A) Nikto/securityheaders.com/manual response-header inspection B) SQLMap C) John the Ripper D) Metasploit exploit modules
    Answer: **A** (Security headers are checked with scanners like Nikto, services such as securityheaders.com, or manual inspection of responses — not SQLMap or password crackers.)

45. Disabling unnecessary headers like X-Powered-By relates to: A) obfuscation that reduces ease of server fingerprinting B) data encryption C) a mandatory measure that fully eliminates the risk D) a direct PCI DSS requirement
    Answer: **A** (Removing X-Powered-By and similar banners is lightweight obfuscation that makes fingerprinting slightly harder; it does not replace patching or real hardening.)

46. Which statement best describes the root cause of the A02:2025 category? A) A weak user password B) The gap between "securely written code" and "securely deployed/configured system" C) Lack of database encryption D) Incorrect business logic
    Answer: **B** (A02’s root theme is the gap between secure code and a securely deployed, configured system across stack and cloud settings.)

47. Which is true about the number of CWEs in the A02:2025 category? A) 40 CWEs B) 16 CWEs C) 6 CWEs D) 24 CWEs
    Answer: **B** (OWASP Top 10:2025 associates Security Misconfiguration (A02) with 16 CWEs (while A01 is much larger, e.g. about 40 CWEs).)

48. A backup file (backup.zip, index.php.bak) left in the web root is an example of: A) SSRF B) Security Misconfiguration, potentially exposing source code C) CSRF D) Broken Authentication
    Answer: **B** (Leftover web-root backups (backup.zip, .bak) are deployment hygiene misconfiguration that may expose source code and secrets if downloaded.)

49. Which measure is MOST effective against automated scanners (like Shodan/Censys) discovering open S3 buckets en masse? A) Renaming the bucket to something more complex B) Explicitly configuring private access + blocking public ACLs at the account level (S3 Block Public Access) + auditing with IaC scanners C) Disabling access logging D) Using a longer AWS region name
    Answer: **B** (Against mass discovery of open buckets, enforce private defaults, account-level S3 Block Public Access, and continuous IaC/ACL auditing — not cosmetic renaming.)

50. Why is regularly updating the security baseline (rather than a one-time setup) critical for A02? A) Security requirements and threats change over time, and configuration "freezes" if it isn't revisited B) It's only required during a once-a-year audit C) The baseline never changes after initial setup D) It has no practical significance
    Answer: **A** (Threats and best practices evolve; a one-time baseline freezes and ages. Regular baseline updates keep hardening aligned with new services and risks.)

---
## A03:2025 — Software Supply Chain Failures (50 questions)

1. Which 2021 category does A03:2025 expand upon? A) A02:2021 Cryptographic Failures B) A06:2021 Vulnerable and Outdated Components C) A09:2021 Security Logging D) A10:2021 SSRF
   Answer: **B** (A03:2025 Software Supply Chain Failures expands A06:2021 Vulnerable and Outdated Components: from known library CVEs to the full supply-chain lifecycle (build, CI/CD, registries, updates).)

2. How many CWEs are listed under A03:2025 per OWASP data? A) 40 B) 32 C) 6 D) 24
   Answer: **C** (Per OWASP Top 10:2025 data, A03 maps to 6 CWEs — relatively few, reflecting how hard supply-chain issues are to detect automatically in test datasets.)

3. Why did A03 rank highly largely thanks to the community survey rather than statistics alone? A) The data was lost B) It's hard to test automatically, so it's underrepresented in test data despite being highly dangerous in practice C) The category is new and no data exists yet at all D) OWASP decided not to use data for this category on principle
   Answer: **B** (Supply-chain attacks are underrepresented in automated test statistics (few direct CVEs), yet the community survey ranked their real-world risk high — so A03 entered the top largely via community vote.)

4. What is an SBOM? A) Security Breach Operations Manual B) Software Bill of Materials — an inventory of all software components and dependencies C) Server Backup Object Model D) Standard Binary Object Mapping
   Answer: **B** (An SBOM (Software Bill of Materials) is an inventory of all software components and dependencies, enabling continuous tracking of vulnerabilities in direct and transitive libraries.)

5. The SolarWinds attack (2019) is a classic example of: A) SQL injection B) a trusted-vendor compromise via a legitimate update (supply chain attack) C) a DDoS attack D) employee phishing
   Answer: **B** (SolarWinds (2019) is the classic trusted-vendor compromise: malware shipped through a legitimate Orion update, affecting thousands of organizations.)

6. The Shai-Hulud npm attack (2025) was notable because: A) it was the first discovered XSS vulnerability B) it was the first successful self-propagating npm worm, stealing and using victims' own npm tokens C) it was a DNS server attack D) it exploited a browser vulnerability
   Answer: **B** (Shai-Hulud (npm, 2025) was the first successful self-propagating npm worm: post-install stole victims' tokens and republished infected versions of their packages.)

7. A transitive dependency is: A) a dependency added manually by the developer B) a dependency of a dependency — a library pulled in by another library you use C) an outdated dependency version D) a dependency used only in the test environment
   Answer: **B** (A transitive dependency is a dependency of a dependency: a library pulled in by another package rather than one you declare directly in the manifest.)

8. Log4Shell (CVE-2021-44228) belongs to category A03 because: A) it's a vulnerability in the web app itself B) it's a critical RCE in a widely used component (Apache Log4j) that affected thousands of dependent products C) it's a DNS configuration flaw D) it's a phishing attack
   Answer: **B** (Log4Shell is a critical RCE in the widely used Apache Log4j component; thousands of products inherited it via dependency, which is typical of A03.)

9. Which of the following is correct dependency-management practice? A) Auto-update all dependencies to the latest version without checking compatibility B) Centrally generate an SBOM and continuously track direct and transitive dependency versions C) Never update dependencies after the first release D) Use only dependencies with no pinned version (latest)
   Answer: **B** (Correct practice is to centrally generate an SBOM and continuously track direct and transitive dependency versions against vulnerability databases.)

10. Staged/canary rollout of updates is recommended because: A) it's cheaper B) it limits exposure if a vendor or update turns out compromised — not all systems update at once C) it's legally required D) it speeds up development
    Answer: **B** (Staged/canary rollout limits blast radius: if an update or vendor is compromised, not every system receives the malicious version at once.)

11. The Bybit theft ($1.5B, 2025) is an example of a supply chain attack that: A) fired immediately after installation for all users B) was a conditionally-triggered backdoor, activating only when a specific target wallet was used C) was an ordinary phishing attack D) exploited a browser vulnerability
    Answer: **B** (Bybit ($1.5B, 2025) illustrates a conditionally triggered backdoor: malicious code activated only when a specific target wallet was used.)

12. The Struts2 RCE (CVE-2017-5638), linked to the Equifax breach, is an example of: A) misconfiguration B) a known vulnerability in a widely used component (framework) C) social engineering D) DDoS
    Answer: **B** (CVE-2017-5638 in Apache Struts2 is a known vulnerability in a popular framework used in the Equifax breach — a classic vulnerable-component scenario under A03.)

13. Why does "separation of duty" in CI/CD matter for supply chain security? A) It speeds up releases B) No single person can unilaterally write code and push it to prod without independent review — reducing insider or compromised-account attack risk C) It's only required for financial organizations D) It doesn't affect security
    Answer: **B** (Separation of duty prevents one person from unilaterally moving code from commit to production without independent review, reducing insider or compromised-account risk.)

14. Retire.js and OWASP Dependency-Check are tools for: A) network scanning B) detecting known-vulnerable versions of client-/server-side libraries C) performance testing D) password generation
    Answer: **B** (Retire.js and OWASP Dependency-Check scan client- and server-side libraries for known-vulnerable versions — core composition-analysis tools for A03.)

15. Signed artifacts (signed packages/builds) help prevent: A) SQL injection B) tampering with/modifying a package by an attacker during distribution (a supply-chain integrity failure) C) memory leaks D) CSRF
    Answer: **B** (Signed artifacts help detect package tampering during distribution: integrity fails if an attacker modifies a build without a valid signature.)

16. Which of the following is a sign you're exposed to A03 per OWASP? A) You run regular pentests B) You don't track component versions, including transitive dependencies C) You use a WAF D) You apply MFA everywhere
    Answer: **B** (Per OWASP, a sign of A03 exposure is not tracking component versions, including transitive dependencies on client and server.)

17. PhantomRaven (npm, 2025) was: A) a Chrome browser vulnerability B) a malicious campaign discovered in 126+ npm packages C) a Kubernetes configuration flaw D) a phishing attack targeting developers via email
    Answer: **B** (PhantomRaven (npm, 2025) was a malicious campaign found in 126+ npm packages — an example of package-registry ecosystem compromise.)

18. Glassworm (2025) spread via: A) a PostgreSQL vulnerability B) VS Code Marketplace extensions (a self-propagating worm) C) a Docker Hub vulnerability D) an SSH vulnerability
    Answer: **B** (Glassworm (2025) spread via VS Code Marketplace extensions as a self-propagating worm — an attack on the developer toolchain within the supply chain.)

19. Why should an organization have a change-management process for CI/CD settings, IDEs, and code repositories? A) It's only required for large enterprises B) It enables tracking and auditing changes across every part of the supply chain, including detecting unauthorized modifications C) It doesn't affect security, only convenience D) It's required solely for ISO 9001 compliance
    Answer: **B** (Change management for CI/CD, IDEs, and repos enables auditing changes across the supply chain and detecting unauthorized configuration modifications.)

20. CWE-1104 in the A03:2025 list refers to: A) SQL Injection B) Use of Unmaintained Third Party Components C) Cross-Site Scripting D) Missing Authentication
    Answer: **B** (CWE-1104 in the A03:2025 list is Use of Unmaintained Third Party Components — relying on third-party components that lack vendor support.)

21. What's the right strategy when an unmaintained library with no available patches is found in a project? A) Ignore the issue B) Migrate to an alternative or, if impossible, deploy a virtual patch to monitor/protect it C) Delete the entire application D) Keep using it unchanged forever
    Answer: **B** (For an unmaintained library with no patches, OWASP recommends migrating to an alternative or, if that is impossible, a virtual patch with monitoring and protection.)

22. Components (libraries/frameworks) in an application typically execute: A) in an isolated sandbox with no access to app data B) with the same privileges as the application itself — so compromising them equals compromising the app C) read-only mode only D) always in a separate container by default
    Answer: **B** (Libraries and frameworks typically run with the same privileges as the application, so compromising a dependency equals compromising the app itself.)

23. Which of the following is part of OWASP's recommended CI/CD build-server hardening? A) A shared account for all developers B) Separation of duties, access control, signed builds, tamper-evident logs, environment-scoped secrets C) Disabling logging for speed D) Storing secrets in plaintext in the repo for convenience
    Answer: **B** (OWASP CI/CD hardening includes separation of duties, access control, signed builds, tamper-evident logs, and environment-scoped secrets.)

24. Why is it recommended to deliberately pin a specific dependency version instead of automatically pulling "latest"? A) Latest is always safer B) A controlled, deliberate upgrade reduces the risk of unexpectedly getting a compromised/incompatible version C) Latest versions are always slower D) It doesn't matter for security
    Answer: **B** (Pinning a specific version instead of "latest" enables controlled upgrades and reduces the risk of unexpectedly pulling a compromised or incompatible dependency.)

25. A container registry (e.g., Docker Hub) without strict image control is risky because: A) it takes up too much space B) a malicious or outdated image with vulnerabilities can be silently used in production C) it slows down builds D) it requires a license
    Answer: **B** (Without strict image control in a registry (e.g., Docker Hub), a malicious or outdated vulnerable image can silently be used in production.)

26. The average incidence rate for A03:2025 (when found) turned out to be: A) the lowest among all categories B) the highest among all categories (5.72%), despite few CVEs in the dataset C) zero D) unmeasurable
    Answer: **B** (When found, A03 has the highest average incidence rate among OWASP Top 10:2025 categories — 5.72% — despite few CVEs in the dataset.)

27. Which of the following correctly describes the relationship between A03 and A08 (Software/Data Integrity Failures)? A) They're the same thing B) A03 covers the entire supply chain process/ecosystem, A08 covers verifying the integrity of a specific artifact/data at a lower level C) A08 applies only to databases D) They're unrelated
    Answer: **B** (A03 covers the whole supply-chain ecosystem (build, delivery, dependencies), while A08 covers verifying integrity of a specific artifact or data at a lower level.)

28. Which measure is NOT one of OWASP's A03 recommendations? A) Maintaining an SBOM B) Using only components from official sources over trusted channels C) Ignoring security bulletins to save time D) Monitoring CVE/NVD/OSV databases for the components in use
    Answer: **C** (Ignoring security bulletins is an anti-pattern, not a recommendation; OWASP instead requires regular bulletin monitoring and vulnerability scanning.)

29. Which of the following is an example of a proper patch management process? A) Patching quarterly on a fixed schedule regardless of severity B) Risk-based, timely updates to the platform/frameworks/dependencies C) Patching only after an incident D) Never patching at all, for stability
    Answer: **B** (Proper patch management is risk-based, timely updating of the platform, frameworks, and dependencies according to vulnerability severity.)

30. Why does compatibility testing of patched/updated libraries matter before deployment? A) It doesn't matter, patches are always compatible B) An update can break functionality, causing teams to delay critical security patches C) Required only for mobile apps D) Testing slows development for no benefit
    Answer: **B** (Compatibility must be tested before deploy: broken functionality makes teams delay critical security patches and extends the exploitation window.)

31. Typosquatting attacks on npm/PyPI (e.g., reqeusts instead of requests) are: A) misconfiguration B) a supply chain attack via a malicious similarly-named package C) SQL Injection D) CSRF
    Answer: **B** (Typosquatting (e.g., reqeusts instead of requests) is a supply-chain attack: a malicious similarly named package is installed by mistake instead of the legitimate one.)

32. Which tool, mentioned in OWASP's A03 guidance, is used for SBOM management and tracking? A) sqlmap B) OWASP Dependency-Track C) Burp Suite D) Metasploit
    Answer: **B** (OWASP Dependency-Track is cited in A03 guidance as a tool for SBOM management and continuous dependency vulnerability tracking.)

33. Why is "a CI/CD pipeline with weaker protections than the systems it builds and deploys" considered a sign of A03 exposure? A) It's not a risk B) CI/CD has access to all code and secrets — if it's less protected than prod, it becomes an easier entry point to compromise everything it builds C) CI/CD never stores secrets D) It's unrelated to supply chain
    Answer: **B** (CI/CD has access to code and secrets; if the pipeline is weaker than production, it becomes an easy entry point to compromise everything it builds and deploys.)

34. Which is true about CWE-1395 (Dependency on Vulnerable Third-Party Component)? A) It relates to XSS B) It relates to using a component with a known vulnerability, directly connected to A03 C) It relates to SQL injection D) It relates to authentication issues
    Answer: **B** (CWE-1395 (Dependency on Vulnerable Third-Party Component) describes using a component with a known vulnerability — directly tied to A03.)

35. Per OWASP, who should be able to unilaterally take code from commit to production without independent review? A) The team lead B) No one — separation of duty is required C) A DevOps engineer D) Any senior developer
    Answer: **B** (Per OWASP, no one should unilaterally take code from commit to production without independent review — separation of duty is required.)

36. Why is it recommended to avoid deploying updates simultaneously to the entire infrastructure at once? A) It requires more servers B) If a trusted vendor's update turns out compromised, a staged/canary rollout limits the blast radius before detection C) Simultaneous deployment is always faster D) It doesn't matter for security
    Answer: **B** (Deploying an update fleet-wide at once is risky: if a vendor is compromised, staged/canary rollout limits blast radius until detection.)

37. Reliance on Component That is Not Updateable (CWE-1329) describes the risk of: A) using a component that cannot be updated/patched when a vulnerability is discovered B) using an actively maintained component C) a memory leak D) improper authentication
    Answer: **A** (CWE-1329 — Reliance on Component That is Not Updateable: the risk of using a component that cannot be updated or patched when a vulnerability is found.)

38. Which practice is closest to "Zero Trust" as applied to the supply chain? A) Automatically trust all updates from "known" vendors without verification B) Verify the provenance and signature of every artifact regardless of source C) Trust all open-source libraries without checking D) Disable signature verification to speed up builds
    Answer: **B** (Zero Trust for the supply chain means not trusting a source by default: verify provenance and signature of every artifact regardless of origin.)

39. Which of the following best describes the "recruitment" of a developer's compromised npm token in a campaign like Shai-Hulud? A) The token was used only to read public packages B) An npm token found on a compromised machine was automatically used to publish malicious versions of any package the victim had access to, spreading the worm further C) The token was immediately revoked automatically by npm D) Tokens weren't involved in this attack
    Answer: **B** (In campaigns like Shai-Hulud, a stolen npm token automatically published malicious versions of the victim's packages, "recruiting" the account to spread the worm further.)

40. Why does "reducing attack surface" by removing unused dependencies relate to A03? A) It doesn't, that's only A02 B) Every extra dependency is a potential entry point through its own vulnerabilities, even if its functionality is unused C) Reducing dependencies doesn't affect security D) It's purely a performance concern
    Answer: **B** (Every unused dependency is extra attack surface via its CVEs even if features are unused; removing them reduces A03 risk.)

41. An attack where the attacker gains access to build infrastructure and injects malicious code before artifact signing is called: A) XSS injection B) build/CI-CD pipeline compromise (related to A03/A08) C) session fixation D) CSRF
    Answer: **B** (Injecting malicious code into build infrastructure before artifact signing is a CI/CD pipeline compromise related to A03 (and overlapping A08).)

42. Which of the following is true about the difficulty of detecting supply chain attacks? A) They're always easily caught by antivirus B) They often exploit trust in a legitimate source (vendor/package), so traditional perimeter defenses don't notice them C) Such attacks are impossible when HTTPS is used D) A WAF fully prevents such attacks
    Answer: **B** (Supply-chain attacks exploit trust in a legitimate vendor or package, so traditional perimeter defenses often fail to notice them.)

43. Why should monitoring sources like CVE/NVD/OSV be continuous rather than a one-time check when a component is adopted? A) A one-time check is sufficient forever B) New vulnerabilities in already-used components are discovered constantly after adoption C) NVD updates only once a year D) Continuous monitoring provides no practical benefit
    Answer: **B** (New CVEs in already-adopted components appear continuously, so CVE/NVD/OSV monitoring must be ongoing, not a one-time check at adoption.)

44. Per OWASP 2025 data, category A03 nonetheless has: A) the fewest occurrences in the dataset, but the highest average exploit/impact score of all categories B) the most occurrences and low impact C) zero impact D) the highest number of CWEs
    Answer: **A** (Per OWASP 2025 data, A03 has the fewest dataset occurrences yet the highest average exploit/impact score of all categories.)

45. What's the correct security-team response when a Log4Shell-like vulnerability is found in a production dependency? A) Ignore it if the app is running stably B) Promptly assess exposure (where the component is used), apply a risk-prioritized patch/mitigation, and deploy a temporary virtual patch if needed C) Wait for the scheduled quarterly patch cycle D) Permanently shut down the application
    Answer: **B** (For a Log4Shell-like issue, promptly assess where the component is used, apply a risk-prioritized patch/mitigation, and add a temporary virtual patch if needed.)

46. IDE extensions (e.g., a malicious VS Code extension) as an attack vector fall under A03 because: A) extensions have no file-system access B) extensions are part of the developer toolchain (part of the supply chain) and can steal secrets/code or inject malicious code into projects C) extensions only run in the browser D) they're unrelated to A03 at all
    Answer: **B** (IDE extensions are part of the developer toolchain and supply chain: a malicious extension can steal secrets/code or inject malware into projects, so they fall under A03.)

47. Which is true about artifact provenance per A03 recommendations? A) It doesn't matter where an artifact came from as long as it works B) Provenance lets you trace that an artifact was built from expected source code through an expected, protected build process (e.g., via the SLSA framework) C) Provenance only applies to hardware D) Provenance is an outdated practice
    Answer: **B** (Provenance (e.g., via SLSA) proves an artifact was built from expected source code through an expected, protected build process.)

48. The timeline of the Shai-Hulud attack (infecting 500+ package versions before being stopped) illustrates: A) low propagation speed for supply chain attacks B) the ability of self-propagating supply chain worms to scale rapidly through trust relationships in package registries C) npm's overall ineffectiveness as a platform D) no risk to developers whatsoever
    Answer: **B** (Shai-Hulud infected 500+ package versions before being stopped, showing how registry worms scale rapidly through trust relationships in package ecosystems.)

49. Why has "developers themselves are now prime targets" (per analysis of the Shai-Hulud attack) become a new trend? A) Developers were never targeted before B) Compromising a developer's machine/tokens grants immediate access to many projects and packages they maintain — an efficient lever for a supply chain attack C) Developers are easier to fool than regular users D) It's unrelated to A03
    Answer: **B** (Compromising a developer's machine or tokens grants access to many projects and packages they maintain — an efficient lever for supply-chain attacks.)

50. Which measure is MOST effective against campaigns like Shai-Hulud that exploit registry tokens found on a developer's machine to self-replicate? A) Using longer GitHub passwords B) Short-lived/scoped publish tokens + MFA for publishing + no long-lived tokens stored on developer machines C) Disabling npm entirely D) Using only private registries with zero external dependencies
    Answer: **B** (Against stolen publish tokens, the most effective controls are short-lived/scoped tokens, MFA for publishing, and no long-lived tokens on developer machines.)

---
## A04:2025 — Cryptographic Failures (50 questions)

1. What was the Cryptographic Failures category called before its 2021 renaming? A) Injection B) Sensitive Data Exposure C) Broken Authentication D) XXE
   Answer: **B** (Before the 2021 rename the category was Sensitive Data Exposure (OWASP 2017); 2021/2025 focus on the root cause — Cryptographic Failures.)

2. Why does renaming it to "Cryptographic Failures" better capture the essence of the category? A) Exposure is a symptom, Cryptographic Failure is the root cause leading to exposure B) It's purely a marketing change C) The new name is shorter D) The old name was prohibited
   Answer: **A** ("Exposure" is a symptom (data leaked), while "Cryptographic Failure" is the root cause: weak or missing crypto that leads to that exposure.)

3. Which password-hashing algorithm is considered brute-force-resistant and recommended by OWASP? A) MD5 B) SHA-1 C) Argon2id D) CRC32
   Answer: **C** (Argon2id is a modern memory-hard KDF resistant to GPU/ASIC brute-force; OWASP recommends it (alongside bcrypt/scrypt) for password storage.)

4. ECB (Electronic Codebook) mode is dangerous because: A) it's too slow B) identical plaintext blocks yield identical ciphertext blocks, revealing data patterns C) it's unsupported by modern libraries D) it requires an excessively long key
   Answer: **B** (In ECB mode identical plaintext blocks always produce identical ciphertext blocks, revealing data patterns and structure — the mode is considered insecure.)

5. Which of the following is NOT protection of data, only encoding? A) AES-256 B) Base64 C) bcrypt D) TLS 1.3
   Answer: **B** (Base64 is encoding, not encryption: data is reversible without a key and provides no confidentiality, unlike AES, bcrypt, or TLS.)

6. Why is storing passwords with a fast hash (e.g., plain SHA-256 with no salt or iterations) considered a vulnerability? A) SHA-256 can never be used anywhere B) Fast algorithms let an attacker try billions of password guesses per second in an offline attack (brute-force/rainbow tables) C) SHA-256 is incompatible with databases D) SHA-256 isn't supported over HTTPS
   Answer: **B** (Fast hashes (SHA-256 without salt/iterations) allow billions of offline password guesses per second; passwords need slow salted KDFs.)

7. A salt in password hashing is used to: A) speed up hash computation B) prevent the use of precomputed rainbow tables and identical hashes for users with identical passwords C) encrypt traffic D) generate session tokens
   Answer: **B** (A salt makes each password hash unique: it defeats rainbow tables and prevents revealing identical passwords across users via matching hashes.)

8. A padding oracle attack exploits: A) a weak hashing algorithm B) an information leak through a difference in server responses when handling incorrect padding in block-cipher encryption (e.g., CBC mode) C) lack of HTTPS D) SQL injection
   Answer: **B** (A padding oracle exploits differing server responses to invalid block-cipher padding (often CBC), enabling gradual decryption or forgery of ciphertext.)

9. The average incidence rate for A04:2025 was: A) 0.5% B) 3.80% C) 15% D) 50%
   Answer: **B** (Per OWASP Top 10:2025 data, the average incidence rate for A04 Cryptographic Failures is 3.80%.)

10. Why is "homegrown" (custom) cryptography a bad practice? A) It's always slower B) Crypto algorithms are extremely hard to design securely; unvetted implementations often contain subtle flaws not caught without deep cryptanalysis C) Homegrown crypto is illegal everywhere D) It's unsupported by modern programming languages
    Answer: **B** (Homegrown cryptography almost always hides subtle flaws; secure algorithms need years of analysis — use vetted libraries and standards.)

11. Which protocol/version is NOT recommended by OWASP for protecting data in transit in 2025? A) TLS 1.3 B) TLS 1.2 C) SSL 3.0/TLS 1.0 D) mTLS
    Answer: **C** (SSL 3.0 and TLS 1.0 are obsolete and vulnerable (e.g., POODLE); OWASP recommends TLS 1.2+/1.3, not legacy protocols.)

12. HSTS (HTTP Strict Transport Security) relates to: A) protecting against XSS B) forcing browsers to use HTTPS, preventing downgrade attacks C) encrypting passwords in the DB D) API authorization
    Answer: **B** (HSTS forces the browser to use HTTPS for the site, reducing downgrade attacks and accidental HTTP access to the resource.)

13. Data transmitted via a URL query string (e.g., ?token=secret) is dangerous because: A) URLs can't be used with HTTPS B) URLs are often logged by servers, proxies, and browser history — a token can leak via logs C) URLs don't support Unicode D) URLs have a length limit
    Answer: **B** (Secrets in the query string appear in server/proxy logs, browser history, and Referer headers; tokens can leak without live traffic interception.)

14. Which of the following is a correct cryptographic key-management practice? A) Store keys in source code for easy access B) Use dedicated key management (KMS/HSM) with rotation and separation of keys from data C) Use the same key across all environments (dev/staging/prod) D) Never rotate keys after initial setup
    Answer: **B** (Correct key management uses KMS/HSM, rotation, and separating keys from data; keys must not live next to ciphertext unprotected.)

15. Data that doesn't need protection per the data-minimization principle should: A) always be encrypted "just in case" B) not be collected/stored at all if not needed for the business process C) be stored in plaintext for convenience D) be published openly
    Answer: **B** (Data minimization: if data is not needed for the business process, do not collect or store it — better than encrypting unnecessary data.)

16. An IV (initialization vector) reused across CBC encryption operations leads to: A) increased performance B) information leakage about patterns in the encrypted data, weakening cryptographic strength C) automatic key rotation D) an inability to decrypt the data
    Answer: **B** (Reusing an IV in CBC leaks relationships between plaintext blocks and weakens strength; IVs must be unique (and often unpredictable).)

17. Which of the following is an example of a Cryptographic Failure, not a Broken Access Control issue? A) IDOR via directly changing an ID in the URL B) Storing credit card numbers in the DB unencrypted, in plaintext C) CSRF with no token D) Missing role check on an endpoint
    Answer: **B** (Storing card numbers in the DB in plaintext is a failure of data-at-rest crypto (A04), not an access-control authorization flaw.)

18. Why does disabling caching matter for responses containing sensitive data? A) Caching slows down the server B) Cached data may remain accessible in the browser/intermediate proxies after the session should have ended C) Caches are always automatically encrypted D) It's unrelated to security
    Answer: **B** (Browser and proxy caches can retain sensitive responses after the session ends; caching must be disabled for such responses.)

19. Why does verifying the TLS certificate and trust chain matter? A) Without it, HTTPS won't physically work B) Ignoring certificate errors opens the door to a MITM attack C) Certificates are unrelated to encryption D) Required only for mobile apps
    Answer: **B** (Without verifying the certificate and trust chain, a client accepts an attacker's fake cert — enabling MITM interception and modification.)

20. NIST 800-63b password recommendations, referenced in the context of OWASP A07 but overlapping with A04's storage aspects, emphasize that: A) complexity matters more than length B) length matters more than imposed complexity (special characters), plus checking against compromised-password lists C) passwords don't need to be hashed at all D) MFA isn't needed with long passwords
    Answer: **B** (NIST 800-63B emphasizes password length over forced special-character complexity, plus checks against compromised-password lists.)

21. Which of the following data classes requires protection per applicable regulations (GDPR, PCI DSS, HIPAA)? A) Only passwords B) PII, financial, medical data, credentials, business secrets — depending on jurisdiction and business type C) Only admin data D) Only cloud-stored data
    Answer: **B** (PII, financial and medical data, credentials, and business secrets require protection under GDPR, PCI DSS, HIPAA, and local rules as applicable.)

22. Why does the "encryption vs. encoding" distinction matter for understanding A04? A) It has no practical significance B) Encoding (Base64, URL-encoding) is reversible without a key and does NOT provide confidentiality, unlike encryption C) Encoding is stronger than encryption D) Encoding and encryption are synonyms
    Answer: **B** (Encoding (Base64, URL-encoding) is reversible without a key and gives no confidentiality; A04 requires real encryption/crypto, not obfuscation.)

23. An attacker gains DB access and sees password hashes like $2b$12$... Judging by the format, which algorithm was likely used? A) MD5 B) bcrypt C) plaintext D) Base64
    Answer: **B** (The $2b$12$… prefix is the characteristic bcrypt format (version 2b, cost 12), not MD5, SHA, or Argon2.)

24. What's the correct practice upon discovering a leaked cryptographic key? A) Ignore it unless the leak is publicly confirmed B) Immediately rotate the key, reassess all data encrypted with it, and investigate the scope of compromise C) Wait for the scheduled annual key update D) Remove mentions of the key from logs and keep using the same key
    Answer: **B** (On key leakage, immediately rotate the key, reassess data encrypted with it, and investigate the scope of compromise.)

25. DES and RC4 are considered obsolete algorithms because: A) they're incompatible with modern OSes B) they're cryptographically broken/weak by modern standards and subject to practical attacks C) they're too slow D) they don't support Unicode
    Answer: **B** (DES and RC4 are cryptographically weak/broken by modern standards and subject to practical attacks; they must not be used for new protection.)

26. Data stored "longer than necessary," including backups and logs, is a risk under A04 because: A) it takes up storage space B) it increases the attack surface and the volume of potentially leaked sensitive data upon compromise, even if not actively used C) it doesn't affect security D) it's legally required to keep everything indefinitely
    Answer: **B** (Retaining data longer than needed (logs, backups) grows the volume that leaks on compromise, even if it is not actively used.)

27. Which of the following is NOT a TLS misconfiguration a pentester should check? A) Use of outdated cipher suites B) Missing HSTS C) SQL injection in a login form D) A self-signed certificate in production
    Answer: **C** (SQL injection in a login form is Injection (A05), not a TLS misconfiguration; TLS checks cover protocols, ciphers, certificates, HSTS, etc.)

28. testssl.sh as a tool is used to: A) scan open ports B) analyze a server's TLS/SSL configuration — protocols, cipher suites, certificates C) brute-force passwords D) statically analyze code
    Answer: **B** (testssl.sh analyzes a server's TLS/SSL configuration: supported protocols, cipher suites, certificates, and common weaknesses.)

29. Why is a JWT signed with a weak/predictable HMAC secret a Cryptographic Failure? A) JWTs are never signed B) An attacker can brute-force the secret and forge a valid token with arbitrary claims C) JWT doesn't support signatures at all D) It's not a vulnerability
    Answer: **B** (A weak JWT HMAC secret can be brute-forced offline; the attacker then forges tokens with arbitrary claims (roles, subject) — a classic crypto failure.)

30. The term "Sensitive Data Exposure" in current OWASP 2025 terminology is treated as: A) a separate category with its own number B) a symptom, not a root cause — the actual cause is usually a Cryptographic Failure C) a synonym for XSS D) an outdated name for Injection
    Answer: **B** (In OWASP 2025 terminology Sensitive Data Exposure is a symptom; the root cause is usually a Cryptographic Failure (weak or missing data protection).)

31. Which of the following is a correct measure for protecting personal data at rest, beyond encryption? A) Tokenization/truncation of data where the full value isn't needed by the business logic B) Storing it as plaintext for easier debugging C) Using one shared key for all customers forever D) Not logging anything at all
    Answer: **A** (Beyond encryption, tokenization/truncation is correct: if the full value (e.g., PAN) is not needed, store a token or mask to reduce leak impact.)

32. An attacker intercepts traffic sent over HTTP (not HTTPS) between a client and server. Which OWASP category does this describe? A) Injection B) Cryptographic Failure (data in transit isn't protected) C) Insecure Design D) Logging Failure
    Answer: **B** (Intercepting cleartext HTTP without TLS is unprotected data in transit and falls under A04 Cryptographic Failures.)

33. What does "crypto agility" refer to? A) The system's ability to easily swap an outdated algorithm for a new one without a full architecture rewrite B) The speed of data encryption C) Using only one algorithm forever D) Avoiding encryption libraries
    Answer: **A** (Crypto agility is the ability to swap an outdated algorithm for a new one without rewriting the whole architecture (configurable algorithms/parameters).)

34. Why is a hardcoded encryption algorithm baked directly into the code a bad practice in the A04 context? A) It slows program execution B) It complicates migration when the algorithm is found vulnerable or when future quantum threats emerge C) It doesn't affect security D) It's a PCI DSS requirement
    Answer: **B** (A hardcoded algorithm blocks migration when it is broken or post-quantum needs arise; configurability and crypto agility are required.)

35. Which measure directly relates to protecting data "at rest"? A) HSTS B) Full disk encryption / column-level DB encryption for sensitive fields C) CSP D) SameSite cookie
    Answer: **B** (Data-at-rest protection is full-disk encryption and/or column-level DB encryption for sensitive fields — complementary to TLS in transit.)

36. Which of the following best describes the practical difference between symmetric and asymmetric encryption? A) Asymmetric is always faster B) Symmetric uses one shared key (faster, for bulk data), asymmetric uses a key pair (slower, for key exchange/signing) C) They're identical in speed and purpose D) Symmetric is never used in TLS
    Answer: **B** (Symmetric crypto uses one shared key (fast, bulk data); asymmetric uses a key pair (slower, key exchange and signing).)

37. Per OWASP A04:2025, how many CWEs does the category contain? A) 6 CWEs B) 32 CWEs C) 16 CWEs D) 40 CWEs
    Answer: **B** (Per OWASP A04:2025, the Cryptographic Failures category contains 32 CWEs.)

38. Why does checking password-reset token "predictability" matter cryptographically? A) It doesn't matter B) The token must be generated by a cryptographically strong random number generator with sufficient entropy, or an attacker can guess/predict it C) Tokens should never expire D) Tokens should be short for convenience
    Answer: **B** (Password-reset tokens must come from a CSPRNG with enough entropy; a predictable token lets an attacker take over the account.)

39. The difference between hashing and encryption: A) they're the same thing B) hashing is one-way (for integrity checks/passwords), encryption is reversible with a key (for confidentiality) C) encryption is irreversible, hashing is reversible D) hashing is used only for files
    Answer: **B** (Hashing is one-way (integrity checks/passwords); encryption is reversible with a key and serves confidentiality.)

40. Which of the following poses the greatest risk from an A04 perspective? A) Using TLS 1.3 with modern cipher suites B) Storing credit card numbers in plaintext in application logs C) Using bcrypt for passwords D) Rotating keys once a year per policy
    Answer: **B** (Plaintext card numbers in application logs are a direct leak of sensitive payment data — high A04/PCI DSS risk.)

41. A MITM attack is most effectively prevented by: A) complex user passwords B) properly configured TLS with certificate validation (certificate pinning in mobile apps as an extra measure) C) rate limiting D) CAPTCHA
    Answer: **B** (MITM is best prevented by properly configured TLS with certificate validation; mobile apps may add certificate pinning.)

42. Which of the following illustrates a "crypto failure" rather than a "design flaw" (Insecure Design)? A) Lack of threat modeling for a new feature B) Using MD5 for password hashing in an otherwise reasonably designed system C) Absence of rate limiting in business logic D) Absence of promo-code limit checks
    Answer: **B** (Using MD5 for passwords in an otherwise reasonable system is a crypto-primitive failure (A04), not primarily an Insecure Design threat-modeling gap.)

43. Per OWASP recommendations, sensitive data should be encrypted: A) only at rest B) only in transit C) both at rest AND in transit, using modern proven algorithms D) encryption isn't required if a VPN is used
    Answer: **C** (OWASP requires encrypting sensitive data both at rest and in transit with modern, proven algorithms and protocols.)

44. Which tool/technique is most often used to find hardcoded secrets (API keys, passwords) in source code during a pentest? A) sqlmap B) truffleHog/gitleaks and similar secret scanners + manual grep through commits C) Nikto D) Metasploit
    Answer: **B** (Hardcoded secrets are found with scanners (truffleHog, gitleaks) plus manual grep of commit history — a common pentest technique.)

45. Why is "lack of certificate verification" (e.g., verify=False in Python's requests library) a common code-review finding and a risk? A) It slows down requests B) It completely disables MITM protection for that HTTP client C) It improves performance without risk D) It's always safe when working with self-signed certificates
    Answer: **B** (verify=False (and equivalents) fully disables certificate verification for that HTTP client and removes MITM protection — a critical code-review finding.)

46. Which of the following describes the difference between Confidentiality and Integrity in a cryptography context? A) They're synonyms B) Confidentiality protects against unauthorized reading (encryption), Integrity protects against unauthorized modification (hash/signature/MAC) C) Confidentiality only applies to passwords D) Integrity only applies to network protocols
    Answer: **B** (Confidentiality protects against unauthorized reading (encryption); Integrity protects against unauthorized modification (hash, MAC, signature).)

47. HMAC is used to: A) encrypt data B) verify a message's integrity and authenticity using a secret key C) generate random numbers D) compress data
    Answer: **B** (HMAC verifies message integrity and authenticity with a shared secret key — an authenticated MAC, not encryption.)

48. Is it true that using HTTPS automatically solves all A04 issues? A) Yes, completely B) No — HTTPS only protects data in transit; data at rest, password storage, and key management require separate measures C) Yes, if the certificate is from Let's Encrypt D) No, HTTPS is unrelated to A04 at all
    Answer: **B** (HTTPS only protects data in transit; at-rest data, password storage, key management, and avoiding weak algorithms need separate A04 controls.)

49. Which of the following is an example of correct payment-data storage architecture per A04/PCI DSS principles? A) Storing the full card number in your own DB in plaintext B) Tokenization via a payment processor — the app stores only a token, not the actual card data C) Storing the card number in logs for debugging D) Emailing the card number in plaintext for confirmation
    Answer: **B** (Correct PCI-aligned architecture: tokenize via a payment processor so the app stores only a token, not full PAN/CVV.)

50. Which measure is most effective against an "offline brute-force" attack on a stolen database of password hashes? A) Only increasing the minimum password length on the sign-up page B) Using a slow, resource-intensive salted hash function (Argon2id/bcrypt/scrypt) with an adequate cost factor, rather than a fast hash C) Base64-encoding the password before hashing D) Limiting login attempts via the web form (doesn't affect an offline attack)
    Answer: **B** (Against offline brute-force on stolen hashes, use slow salted KDFs (Argon2id/bcrypt/scrypt) with adequate cost — not fast hashes.)

---
## A05:2025 — Injection (50 questions)

1. How many CWEs are in category A05:2025 — the largest number of any category? A) 16 B) 24 C) 38 D) 40
   Answer: **C** (Per OWASP Top 10:2025, A05 Injection maps the largest set of CWEs — 38 — reflecting the breadth of injection families (SQL, XSS, command, SSTI, and others).)

2. The root cause of the Injection category is: A) a weak password B) the lack of separation between the control plane and data plane when building a query/command (concatenation instead of parameterization) C) lack of HTTPS D) incorrect server configuration
   Answer: **B** (Injection’s root cause is mixing data with control instructions: user input is concatenated into a query/command instead of being parameterized. That lets a payload change the structure or semantics of the operation.)

3. Which type of SQL injection is identified by a difference in server response time? A) UNION-based B) Error-based C) Time-based blind D) Stacked queries
   Answer: **C** (Time-based blind SQL injection is identified by response delay (e.g., SLEEP/WAITFOR) when data and errors are not returned directly. Timing differences confirm the condition executed in the DBMS.)

4. Boolean-based blind SQL Injection is identified through: A) the DBMS error text output B) a difference in the response content/behavior for a true vs. false query condition C) server response time D) HTTP headers
   Answer: **B** (Boolean-based blind SQLi relies on differing response content or behavior for true vs. false conditions, not error text or delays. Those differences let an attacker extract data bit by bit.)

5. Second-order SQL Injection is a situation where: A) the injection fires instantly upon input B) a malicious payload is stored in the DB and fires later when used in a different query C) the injection only works via a second parameter D) the injection requires two users simultaneously
   Answer: **B** (In second-order SQL injection the payload is stored “safely,” then later reused in another query without parameterization and fires there. Validating only the initial input point is not enough.)

6. SSTI (Server-Side Template Injection) most often leads to: A) XSS only B) DoS only C) RCE — injecting into a template engine (Jinja2, Twig, FreeMarker) allows arbitrary code execution on the server D) cookie theft only
   Answer: **C** (SSTI injects into the template engine’s API (Jinja2, Twig, FreeMarker), often yielding server-side RCE rather than mere XSS. It is server-side injection into template control logic.)

7. The payload {{7*7}} in an input field is used to test for: A) SQL Injection B) SSTI (if 49 appears in the response, the template engine is vulnerable) C) XSS D) LDAP Injection
   Answer: **B** (The {{7*7}} payload is a classic SSTI probe: if the response shows 49, the server evaluated the template expression. That differs from mere text reflection.)

8. Reflected XSS differs from Stored XSS in that: A) reflected is permanently saved to the DB B) reflected fires immediately from request parameters and requires the victim to follow a crafted link, while stored persists server-side and hits every visitor of the page C) reflected only works in Internet Explorer D) they're the same thing
   Answer: **B** (Reflected XSS fires immediately from the current request’s parameters and usually needs the victim to open a crafted link. Stored XSS persists server-side and hits later visitors of the page.)

9. DOM-based XSS differs from Reflected/Stored in that: A) it doesn't exist at all B) the vulnerability is entirely client-side, via unsafe JS handling of the DOM, without the server reflecting the payload C) it requires an SQL database D) it only works through cookies
   Answer: **B** (DOM-based XSS is entirely client-side: unsafe JS reads untrusted data and writes it into the DOM even if the server never reflected the payload in HTML. Defend with safe DOM APIs and client-side context-aware encoding.)

10. NoSQL Injection in MongoDB is often exploited via operators such as: A) UNION SELECT B) $where, $ne in JSON parameters C) LDAP filter syntax D) XPath expressions
    Answer: **B** (NoSQL injection in MongoDB often abuses operators such as $ne and $where in JSON parameters to alter query logic. Classic UNION SELECT does not apply here.)

11. OS Command Injection occurs when: A) user input is passed directly into a system call (exec/system/backticks) without sanitization B) an outdated TLS version is used C) rate limiting is absent D) it isn't a real risk
    Answer: **A** (OS command injection occurs when user input is passed into a shell/system API without argument separation and escaping. Shell metacharacters can then launch arbitrary commands.)

12. Parameterized queries (prepared statements) protect against SQL Injection because: A) they encrypt the query B) the DBMS precompiles the query structure separately from the data, so user input can't alter the query's logic C) they speed up query execution D) they require less memory
    Answer: **B** (Prepared statements compile SQL structure separately from parameter values, so input cannot change query syntax. Data stays data rather than part of the control plane.)

13. Context-aware output escaping for XSS means: A) one universal escaping method works for all cases B) the escaping method differs depending on where data is inserted into the DOM (HTML tag, attribute, JS string, URL) C) escaping isn't needed if HTTPS is used D) server-side input validation alone is sufficient
    Answer: **B** (Context-aware XSS encoding picks rules for the insertion site: HTML text, attribute, JS string, or URL each has different dangerous characters. Generic “escape HTML” is often insufficient.)

14. CSP (Content-Security-Policy) reduces XSS risk because: A) it fully eliminates XSS with no other measures needed B) it restricts the sources browsers can execute scripts from, acting as defense-in-depth even when an XSS injection is present C) it encrypts cookies D) it blocks SQL queries
    Answer: **B** (CSP restricts which scripts a browser may load and execute and acts as defense-in-depth even when XSS exists. It does not replace correct output encoding by itself.)

15. CRLF Injection (Header Injection) can lead to: A) SQL injection B) HTTP response splitting and related attacks (e.g., cache poisoning, XSS via headers) C) memory leaks D) DoS via buffer overflow
    Answer: **B** (CRLF/header injection injects line breaks into HTTP headers, enabling response splitting, cache poisoning, and XSS via response rewriting. Validate input and ban CR/LF in header values.)

16. XXE (XML External Entity) is classed as an injection because: A) a malicious XML document defines an external entity that the parser resolves and processes, potentially enabling file reads/SSRF B) it requires a SQL database C) it only works in PDFs D) it's unrelated to injection
    Answer: **A** (XXE is injection via external entity definitions in XML: the parser resolves the entity and may disclose files or trigger SSRF. That is why XXE is classed under Injection.)

17. LDAP Injection exploits: A) improper construction of an LDAP filter from unvalidated user input B) a weakness in TLS C) lack of MFA D) a buffer overflow
    Answer: **A** (LDAP injection abuses building an LDAP filter from unvalidated input, altering search or authentication logic. Escape LDAP special characters and parameterize filters.)

18. Why isn't an ORM 100% protection against injection? A) ORMs are never vulnerable to injection B) With careless use (e.g., raw queries inside an ORM, building filters via string concatenation), an ORM can still be vulnerable C) An ORM completely replaces the database D) An ORM only works with NoSQL
    Answer: **B** (An ORM is not complete protection if you use raw queries, concatenated filters, or native SQL. Misuse again mixes the control plane with data.)

19. UNION-based SQL Injection is used by an attacker to: A) alter a table's structure B) merge the result of a malicious SELECT query with a legitimate query's result to extract data from other tables C) delete a table D) encrypt the database
    Answer: **B** (UNION-based SQLi merges a malicious SELECT with a legitimate query’s result to extract data from other tables. Column count and types must match the original SELECT.)

20. OGNL/SpEL injection (e.g., in Struts2/Spring) belongs to which subtype? A) SQL Injection B) Expression Language / Command Injection, often leading to RCE C) XSS D) CSRF
    Answer: **B** (OGNL/SpEL injection is expression-language injection that often yields RCE in Java stacks (Struts2, Spring). It is EL/command injection, not classic SQL injection.)

21. The impact range for the Injection category in OWASP is described as: A) uniformly low-to-critical across all subtypes B) ranging from high-frequency/low-impact (some XSS) to low-frequency/high-impact (SQLi) C) always critical D) always low
    Answer: **B** (Per OWASP, Injection impact ranges from high-frequency, often lower-impact XSS to lower-frequency, high-impact SQLi/RCE. The category spans both ends of that risk spectrum.)

22. Positive input validation (allow-list) is preferable to negative validation (deny-list/blacklisting special characters) because: A) allow-lists are technically simpler to implement B) an allow-list defines the exact permitted format, while a deny-list can easily be bypassed by new/unforeseen bypass techniques C) deny-lists run faster D) they're equally effective
    Answer: **B** (An allow-list defines the exact permitted input format, while a deny-list is easily bypassed with novel payloads. For injection, positive validation beats negative filtering.)

23. What's the correct test for blind time-based SQL Injection? A) Send a payload like ' OR SLEEP(5)-- - and measure the response delay B) Check the Server header C) Send an extremely long string D) Check the cookie for HttpOnly
    Answer: **A** (A correct time-based blind SQLi test sends a SLEEP/delay payload and measures response time. A clear pause under a true condition confirms injection.)

24. Restricting the application's DB account privileges (read-only where write isn't needed) relates to the principle of: A) defense in depth / least privilege — reduces the impact of a successful injection even if one exists B) unrelated to injection C) required only for NoSQL D) it replaces the need for parameterization
    Answer: **A** (Restricting the app’s DB privileges is least privilege / defense in depth: even a successful injection has limited impact. It does not remove the root cause but reduces damage.)

25. Why is static analysis (SAST) useful for finding injections? A) SAST can automatically fix code B) SAST can detect patterns of user input concatenated into queries/commands during development, before production C) SAST fully replaces pentesting D) SAST only works on compiled code
    Answer: **B** (SAST detects patterns where untrusted input reaches sinks (queries, commands) during development. That helps fix injections before production, when DAST may not yet apply.)

26. The HttpOnly cookie attribute reduces the risk of: A) SQL Injection B) cookie theft via XSS (JS can't read an HttpOnly cookie) C) CSRF D) SSTI
    Answer: **B** (HttpOnly stops JavaScript from reading the cookie, reducing session theft via XSS. It does not prevent XSS itself and does not stop CSRF.)

27. Which of the following is an example of mutation-based XSS (mXSS)? A) The payload is reflected directly, unchanged B) The browser, while parsing/sanitizing HTML, transforms seemingly "safe" input into executable code due to parser quirks C) An SQL UNION query D) An LDAP filter
    Answer: **B** (mXSS occurs when the browser’s HTML parse/sanitize path rewrites seemingly safe markup into executable code. Sanitizers that ignore parser mutations can miss this.)

28. Why does injection via a file upload (e.g., a filename like '; DROP TABLE...) also fall under A05? A) File uploads are unrelated to injection B) File metadata (name, EXIF) is also user input, which can be used in queries/commands without proper sanitization C) It relates only to Broken Access Control D) File uploads are always safe
    Answer: **B** (Filenames, EXIF, and other metadata are still user input; concatenating them into SQL or commands enables injection. Uploads expand the Injection attack surface.)

29. The command-injection payload "; whoami" exploits: A) the lack of shell special-character escaping when passing input to a system call B) a weak TLS setup C) missing CSRF token D) incorrect CORS configuration
    Answer: **A** (The “; whoami” payload abuses shell separators/metacharacters when input is passed to a system call without a safe argument API. Missing escaping lets an extra command run.)

30. The sqlmap tool is used for: A) static code analysis B) automated detection and exploitation of SQL injection C) Wi-Fi network scanning D) TLS certificate analysis
    Answer: **B** (sqlmap automates SQL injection detection and exploitation: fingerprinting, payloads, and data extraction. It is SQLi-focused, not a general XSS scanner.)

31. Which of the following correctly describes stacked queries (batch queries) in SQLi? A) Executing several SQL queries in a row through a single injection point (separated by ;), not always supported by all DBMS/drivers B) The only type of SQL injection C) A type of XSS D) A type of CSRF
    Answer: **A** (Stacked/batch queries execute multiple SQL statements via one injection point (often with “;”), but support depends on the driver/DBMS. Not every stack allows that mode.)

32. Why shouldn't a WAF (Web Application Firewall) be treated as the only defense against injection? A) A WAF fully eliminates the risk on its own B) A WAF is an additional layer (defense-in-depth) but can be bypassed via payload obfuscation; the root defense is parameterization/validation in code C) A WAF has no effect on injections at all D) A WAF removes the need for patching
    Answer: **B** (A WAF is an extra layer and can be bypassed with payload obfuscation; root defense is parameterization, safe APIs, and encoding. A WAF alone does not replace fixing the code.)

33. A Blind XXE attack can be used to exfiltrate data via: A) a DNS/HTTP out-of-band channel (an external DTD sending data to the attacker's server) B) only via direct output in the response C) only via SMTP D) it's impossible without direct output
    Answer: **A** (Blind XXE often exfiltrates data out-of-band via DNS/HTTP to an attacker-controlled external DTD/server. The entity content may never appear in the HTTP response.)

34. Which of the following is an example of an injection into a JavaScript-string context (different escaping requirement than an HTML-tag injection)? A) <script>alert(1)</script> in the page body B) input inserted inside var x = "USER_INPUT"; in an inline script, requiring JS-escaping rather than HTML-escaping C) an SQL UNION SELECT D) an LDAP filter
    Answer: **B** (Insertion into a JS string (var x = "USER_INPUT";) needs JavaScript escaping of quotes/specials, not only HTML entity encoding. Wrong encoding context leaves XSS open.)

35. Why do sandboxed template engines (e.g., restricted Jinja2) reduce SSTI risk? A) They completely remove the possibility of template-syntax injection B) They limit the objects/methods available inside the template, reducing the likelihood of reaching RCE even if injection into the template occurs C) A sandbox has no effect on SSTI D) The template engine must be disabled entirely
    Answer: **B** (A sandboxed/restricted template mode limits available objects and methods, making RCE via SSTI harder. It is defense-in-depth alongside forbidding untrusted templates.)

36. Per OWASP 2025 data, Injection fell from #3 (2021) to #5 (2025) in ranking. The most likely reason: A) injections no longer exist B) improved industry practices (widespread use of ORMs, parameterized queries, automatic framework escaping) reduced frequency, though the category remains significant C) OWASP decided to exclude SQLi from the list D) Injections now fall under A01
    Answer: **B** (Injection fell from #3 (2021) to #5 (2025) largely due to ORMs, prepared statements, and framework auto-escaping. Risk remains, but industry practices improved.)

37. Which of the following is the correct approach to escaping output within an HTML tag attribute (e.g., <div title="USER_INPUT">)? A) HTML entity encoding for the attribute's special characters (", ', <, >, &) B) Server-side regex validation alone is sufficient C) No escaping is needed if HTTPS is used D) Using Base64
    Answer: **A** (Inside an HTML attribute, HTML-entity-encode attribute specials (" ' < > &) to prevent breaking out of the value. Otherwise XSS can escape the attribute context.)

38. Fuzzing input points with special characters (' " ; -- <script> {{7*7}} $(whoami)) during a pentest is used to: A) test performance B) discover potential injection points via anomalous response behavior (errors, delays, payload reflection) C) check TLS D) check cookie flags
    Answer: **B** (Fuzzing with specials (' " ; -- <script> {{7*7}}, etc.) finds injection points via anomalies: errors, delays, reflection. It is discovery, not full exploitation.)

39. Which of the following is true about polyglot payloads in injection testing? A) They only work for SQLi B) They're specifically crafted to simultaneously trigger multiple injection types (XSS+SQLi, etc.) for efficient initial fuzzing C) They're used only for DoS D) They have no practical application
    Answer: **B** (Polyglot payloads are crafted to trigger multiple injection types at once (XSS+SQLi, etc.) to speed testing. They are diagnostic tools, not “safe” input.)

40. An injection into the User-Agent HTTP header, which is then logged and rendered in an admin panel without escaping, is an example of: A) SSRF B) Stored XSS via a nonstandard input point C) CSRF D) LDAP Injection
    Answer: **B** (A User-Agent logged and later rendered in HTML without encoding yields Stored XSS via a nonstandard input point. Any reflected header can be a sink.)

41. Why is the absence of the X-XSS-Protection header now considered a non-issue per current recommendations? A) It never worked B) Modern browsers removed the built-in XSS-auditor due to its own vulnerabilities; the current mitigation is CSP C) It's still mandatory and the primary defense D) It relates to SQLi, not XSS
    Answer: **B** (X-XSS-Protection is obsolete: modern browsers removed the XSS auditor due to its own flaws. Current mitigations are CSP, context-aware encoding, and safe frameworks.)

42. Deserialization-based injection (e.g., Java gadget chains) overlaps with which other OWASP category? A) A02 Misconfiguration B) A08 Software/Data Integrity Failures (insecure deserialization) C) A07 Authentication Failures D) A09 Logging Failures
    Answer: **B** (Insecure deserialization (gadget chains) overlaps A08 Software/Data Integrity Failures, even though the payload injects behavior. In Top 10:2025 it primarily sits in the integrity/deserial class.)

43. Which of the following correctly describes "second-order" (stored) command injection? A) The command executes immediately upon input B) Malicious input is stored (e.g., in a config/DB) and later used in a system call by a different component/process C) No such type exists D) It only works with SQL
    Answer: **B** (Second-order command injection stores malicious input (config/DB), then another component later uses it in a system call. Exploitation is delayed and may hit a different service.)

44. GraphQL injections (e.g., through nested queries for DoS or resolver injection) fall under: A) a separate category outside OWASP B) a subset of Injection (A05), given the specifics of GraphQL as a REST alternative C) exclusively SSRF D) exclusively CSRF
    Answer: **B** (GraphQL injections and related abuse (resolver injection, nested-query DoS) are a subset of Injection (A05) with GraphQL specifics. They are not a separate Top 10 category.)

45. Why is sanitizing markdown/rich-text content (e.g., in blog comments) a frequent source of Stored XSS? A) Markdown is always safe by default B) Improper markdown parser configuration can allow HTML/JS tags through into the final render, bypassing basic protection C) Markdown never renders to HTML D) It's unrelated to XSS
    Answer: **B** (A misconfigured markdown/rich-text parser can allow HTML/JS into the final render, bypassing a “plain text only” assumption. Sanitizing rich content is a common Stored XSS source.)

46. Regex injection (ReDoS — Regular Expression Denial of Service) belongs to a subclass of: A) SQL Injection B) an Injection-class vulnerability leading to DoS through catastrophic backtracking in a poorly optimized regex pattern C) XSS D) CSRF
    Answer: **B** (ReDoS is regex injection/abuse via catastrophic backtracking that causes DoS. It is an injection-class availability issue, not data theft.)

47. Which of the following is the correct defense against Command Injection when reliable input escaping is technically hard to guarantee? A) Using an allow-list of permitted commands/arguments and the language's API instead of invoking a shell (e.g., subprocess with a list of args instead of shell=True) B) Simply increasing logging C) Using longer passwords D) Disabling HTTPS
    Answer: **A** (Against command injection prefer an allow-list of commands/args and shell-less APIs (exec with argument arrays), not filtering “bad” characters. That keeps the control plane out of user strings.)

48. Why does testing injection via cookies/headers matter, not just via form parameters/URLs? A) Cookies and headers are never processed server-side B) Any point where the server reads user input (including cookies, headers, JSON body) is potentially vulnerable if used in a query/command without validation C) Headers can't be tampered with D) Cookies are automatically escaped by the browser
    Answer: **B** (Cookies, headers, and JSON bodies are untrusted inputs just like form fields. If the server uses them in queries/output without protection, injection works there too.)

49. Why does AST-based/semantic code analysis outperform simple regex-based injection scanning? A) It's slower, and thus worse B) It understands code structure (data flow from source to sink) rather than just searching for text patterns, reducing false positives/negatives C) It can't analyze SQL D) It only works on compiled code
    Answer: **B** (AST/semantic analysis tracks data flow from sources to sinks rather than only matching text with regex. That cuts false positives and finds non-obvious injection paths.)

50. Which measure is MOST effective as a single root-cause defense against most Injection subtypes at once? A) Using a WAF as the only measure B) Strict separation of the data plane and control plane at the language API level (parameterization/safe APIs) + context-aware output escaping + positive input validation C) Increasing request logging D) Disabling JavaScript on the client
    Answer: **B** (The most effective root defense is strict data/control-plane separation via parameterization and safe language APIs. Validation and WAFs help but do not replace that separation.)

---
## A06:2025 — Insecure Design (50 questions)

1. What's the key difference between Insecure Design and Security Misconfiguration? A) They're the same thing B) Insecure Design is the absence of a needed control in the architecture itself, even with a flawless implementation; Misconfiguration is a poorly configured, properly designed control C) Insecure Design only applies to passwords D) Misconfiguration can never be fixed with a patch
   Answer: **B** (Insecure Design is a missing control in the architecture even with perfect code; Misconfiguration is bad setup of a control that exists by design. Root causes differ: never designed vs. poorly configured.)

2. Why "can't Insecure Design be fixed with a simple patch"? A) Patches are never released for web apps B) The problem is baked into the architecture/design level and requires rethinking the model, not a targeted code change C) Patches are too expensive D) You can always fix it with one patch
   Answer: **B** (Insecure Design cannot be fixed with a one-line patch: the model/process itself is missing or wrong and needs architectural redesign. A local patch does not invent a control absent from the design.)

3. Threat modeling should be performed: A) after release, if vulnerabilities are found B) at the design phase, before code is written C) only during an annual audit D) it isn't required for web applications
   Answer: **B** (Threat modeling should run in the design phase, before code, so threats and controls shape the architecture. After release you only paper over gaps already baked in.)

4. An example of business logic abuse: A) SQL injection in a search form B) Using a legitimate refund feature repeatedly to obtain funds beyond what was actually paid (endless refund loop) C) A memory leak in a parser D) A weak TLS cipher
   Answer: **B** (An endless refund loop abuses a legitimate refund flow lacking architectural limits/idempotency. That is business-logic abuse, not classic SQLi or weak TLS.)

5. STRIDE is: A) a threat-modeling framework (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege) B) an encryption algorithm C) a DBMS D) a port-scanning tool
   Answer: **A** (STRIDE is a threat-modeling framework: Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation of privilege. It structures threat analysis; it is not an encryption algorithm.)

6. A race condition in business logic (e.g., parallel requests to debit funds) falls under: A) Cryptographic Failure B) Insecure Design — if the architecture doesn't enforce atomicity/locking for critical operations C) Security Misconfiguration D) XSS
   Answer: **B** (A business-logic race (parallel debits) is Insecure Design when architecture omits atomicity and locking. Without design-level sync the code “works” but is abusable.)

7. Why is the lack of a limit on how many times a promo code can be applied an Insecure Design example, not an implementation bug? A) Promo codes are unrelated to design B) The business process design never established this constraint as a requirement, so even a flawless implementation "as intended" remains exploitable C) It's always a Cryptographic Failure D) It only relates to Injection
   Answer: **B** (No limit on promo-code reuse is a requirements/process-design gap: an “as intended” implementation remains exploitable. It is a missing business rule, not a single-line code bug.)

8. Reference architecture and secure design patterns reused across projects help prevent Insecure Design because: A) they speed up compilation B) they build proven protective mechanisms (authentication, rate limiting) into the architecture from the start, rather than as an afterthought C) they're unrelated to security D) they replace the need for testing
   Answer: **B** (Reference architectures and secure design patterns embed proven controls (auth, rate limiting) from day one across projects. Reusing sound architecture reduces Insecure Design risk.)

9. An attack tree in threat modeling is used to: A) visualize possible attack paths from an attacker's goal down to specific techniques B) store passwords C) encrypt data D) build an ER diagram for a database
   Answer: **A** (An attack tree visualizes paths from the attacker’s goal to concrete techniques and steps. That helps prioritize controls during threat modeling.)

10. The Insecure Design category fell from #4 (2021) to #6 (2025) — the most likely reason: A) the vulnerability disappeared completely B) growing industry maturity in applying threat modeling and secure-by-design practices C) OWASP removed most CWEs from the category D) Insecure Design is no longer tested
    Answer: **B** (Insecure Design’s drop from #4 (2021) to #6 (2025) is linked to better threat modeling and secure-by-design maturity. The category remains, but industry more often designs controls in early.)

11. PASTA (Process for Attack Simulation and Threat Analysis) is: A) a programming language B) a threat-modeling methodology focused on business risk C) a hashing algorithm D) a network protocol
    Answer: **B** (PASTA is a threat-modeling methodology focused on business risk and attack simulation. It is an analysis process, not a programming language or port scanner.)

12. Which of the following is an example of abuse-case testing (as opposed to use-case testing)? A) Verifying that the registration form works with valid data B) Verifying what happens if a user tries to register 10,000 accounts in a minute to farm referral bonuses C) Testing UI at different screen resolutions D) Testing performance under normal load
    Answer: **B** (An abuse case tests misuse of a legitimate feature (10,000 signups/min for referrals), not the happy-path use case. Such scenarios reveal business-logic design gaps.)

13. A trust boundary in system architecture is: A) the physical perimeter of a data center B) the point where data/requests cross between levels of differing trust (e.g., from client to server), requiring verification at that point C) a TLS setting D) a firewall rule
    Answer: **B** (A trust boundary is where data/requests cross between different trust levels (client→server) and verification is required. It is an architectural concept, not a data-center fence.)

14. Why should rate limiting be baked into the architecture (Insecure Design concern), rather than bolted on as a "patch" after an incident? A) Patches always work better B) Architecturally embedded rate limiting establishes systemic limits at the user/API/transaction level, rather than a one-off fix for a single observed abuse case C) Rate limiting is unrelated to design D) Rate limiting is only needed for DDoS
    Answer: **B** (Architecturally required rate limiting sets systemic per-user/API/transaction caps, not a one-off patch after an incident. Otherwise abuse cases stay outside the model.)

15. A multi-step business process (e.g., checkout) that doesn't verify the previous step completed legitimately is vulnerable to: A) SQL Injection B) Bypassing the business logic — jumping directly to the final step, skipping checks (e.g., payment) C) XXE D) CSRF exclusively
    Answer: **B** (A multi-step flow that does not verify prior steps lets attackers jump to the end, skipping payment/validation. That is classic business-logic bypass from weak workflow design.)

16. Which of the following is a proper example of a unit/integration test covering a security scenario (not just the happy path)? A) A test that the login form accepts a correct password B) A test that the API returns 403 when attempting to access someone else's resource with a valid but insufficiently privileged token C) A page-load performance test D) A mobile-device support test
    Answer: **B** (A security test expects 403 when accessing another user’s resource with a valid but under-privileged token. It verifies designed authorization, not happy-path login.)

17. The difference between "security control missing" (Insecure Design) and "security control present but misconfigured" (Security Misconfiguration) is best illustrated by: A) A CAPTCHA entirely absent from the registration form's design (Insecure Design) vs. a CAPTCHA present but configured with a test-mode key in production (Misconfiguration) B) It's the same example for both categories C) Both examples belong only to Injection D) Neither example relates to these categories
    Answer: **A** (No CAPTCHA in registration design is Insecure Design; CAPTCHA present with a test key in prod is Misconfiguration. Missing control vs. badly configured existing control.)

18. Segregation of tiers (dividing architecture by trust level and data type) relates to: A) Insecure Design — its absence means the whole system has a single, unisolated attack surface with no separation of critical components B) Cryptographic Failure C) Only network infrastructure, not app design D) It's unrelated to security
    Answer: **A** (Missing tier/trust segmentation is Insecure Design: one unisolated attack surface without separating critical parts. That is architectural, not a crypto algorithm issue.)

19. Which of the following is NOT a business-logic example requiring design-level protection? A) A limit on password-reset requests per hour B) Limiting how much of a limited-stock item one account can buy in a flash sale C) Using bcrypt for password hashing D) Preventing a user from transferring a negative amount of money
    Answer: **C** (Password hashing with bcrypt is a cryptographic practice (A04 Cryptographic Failures), not a business-design gap. It is NOT an Insecure Design example.)

20. A Secure Development Lifecycle (SDL) includes threat modeling: A) only at the final stage before release B) for critical user stories/features at the design stage, before code is written C) only after an incident D) it doesn't include threat modeling at all
    Answer: **B** (In an SDL, threat-model critical user stories/features at design time, before coding. Late pre-release analysis no longer builds controls into the model.)

21. Why is "insufficient segmentation in a multi-tenant SaaS app" (where one customer could theoretically access another's data due to an architectural gap, not just an authorization bug) an example specifically of Insecure Design? A) It's always just IDOR (A01) B) If the data architecture itself doesn't enforce tenant isolation at the model level (e.g., a shared table without strictly enforced tenant_id checks at every layer), this is an architectural problem requiring a data-model redesign, not just a single-endpoint patch C) It's unrelated to security D) It's always solved with a WAF
    Answer: **B** (If a SaaS data model does not enforce tenant isolation (shared DB without mandatory tenant_id), one customer can read another’s data — Insecure Design. A single-query bug is a symptom of architectural root cause.)

22. Which of the following is an example of "insufficient design" for resource limits, rather than an implementation bug? A) A memory leak in a specific function due to a forgotten free() B) The API architecture never limits request size/complexity at all (e.g., arbitrarily deep nested JSON/GraphQL queries), enabling DoS through the design C) A bug in an SQL query D) A weak admin password
    Answer: **B** (An API with no request size/complexity limits (unbounded nested JSON/GraphQL) is insufficient resource-limit design. It enables application-level DoS/resource exhaustion.)

23. Per secure-design principles, critical protective components (authentication, rate limiting) should be implemented: A) from scratch in every module for flexibility B) as reusable services/libraries applied consistently across the entire app C) only in the frontend D) separately by each developer as they see fit
    Answer: **B** (Critical controls (auth, rate limiting) should be reusable services/libraries applied consistently app-wide. Per-module one-offs leave design gaps.)

24. Attack surface analysis at the design stage helps: A) increase performance B) proactively identify every point where the system interacts with untrusted sources and design appropriate protections for them C) replace the need for testing D) has no practical use
    Answer: **B** (Design-stage attack surface analysis finds every interaction with untrusted sources and designs controls early. It is proactive, not post-incident cleanup.)

25. Which of the following is a correct example of protecting against a race condition in business logic at the design level? A) Using a database-level lock/atomic transaction for critical multi-step operations (e.g., debiting a balance) B) Simply increasing the request timeout C) Disabling logging D) Using a longer password
    Answer: **A** (Race-condition defense uses DB locks or atomic transactions for critical multi-step ops (balance debit). Without them parallel requests break business invariants.)

26. The concept of "Trust but verify" relates to Insecure Design in that: A) it means fully waiving checks for "trusted" sources B) modern secure-design principle calls for verifying even internal/trusted sources (akin to Zero Trust), rather than blindly trusting them C) it applies only to external APIs D) it's unrelated to system design
    Answer: **B** (“Trust but verify” / Zero Trust: even “internal” sources need verification — secure design rejects blind trust. Otherwise one compromised component opens everything.)

27. Which of the following is an Insecure Design example in the authentication context, distinct from an Authentication Failure (A07)? A) A user's weak password (A07) B) The architecture doesn't allow for introducing MFA in the future without a full redesign of the authentication system (an architectural limitation) C) No rate limiting on login (A07) D) Using MD5 for the password hash (A04)
    Answer: **B** (An auth architecture that cannot add MFA without a full rewrite is Insecure Design (poor security extensibility). It is about the system model, not merely a weak password.)

28. Why is it important to think through abuse-case scenarios together with the product team, not just the security team? A) The product team is unrelated to security B) Their understanding of business logic and user intent helps identify which legitimate features could be abused for unintended purposes C) The security team always manages fine alone D) It's only required for startups
    Answer: **B** (Product owners know business rules and user intent, so jointly they surface abuse cases of legitimate features. Without business input, threat models miss logic holes.)

29. Which of the following illustrates the difference between "vulnerability" and "missing control" as applied to Insecure Design? A) They're the same concept B) A vulnerability is a specific bug in an existing control's implementation; a missing control is one that should have existed by design but is entirely absent C) A missing control only applies to networking D) A vulnerability only applies to passwords
    Answer: **B** (A vulnerability is a defect in an existing control’s implementation; a missing control was never designed in. Insecure Design is primarily the latter.)

30. Per OWASP, effective secure design requires modeling threats for: A) only external users B) every entity that interacts with the system — including internal users, partners, automated systems/bots C) only administrators D) only mobile clients
    Answer: **B** (Per OWASP, model threats for every entity interacting with the system: users, partners, automation, internal roles. Limiting the model to an external hacker leaves blind spots.)

31. An example of an insufficiently thought-out limit at registration (e.g., no check against mass automated bot registration to farm a referral program) falls under: A) SQL Injection B) Insecure Design / business logic abuse C) Cryptographic Failure D) Security Logging Failure
    Answer: **B** (Registration without limits/checks (mass accounts) is Insecure Design / business-logic abuse. A legitimate feature becomes a fraud and farming tool.)

32. Which of the following is proper practice when a pentest finds an Insecure Design flaw (as opposed to a classic code vulnerability)? A) Simply patch the single endpoint locally and close the ticket B) Escalate to the architecture/product team for a redesign of the process, since a local patch may not cover every bypass variant C) Ignore it if the PoC didn't succeed on the first try D) Automatically lower its severity since it isn't a "classic" vulnerability
    Answer: **B** (An Insecure Design finding in a pentest needs escalation to architecture/product for process redesign; a local patch may not fix the model. Redesign beats a one-line hotfix.)

33. How does a zero-day "design flaw" differ from a zero-day "implementation bug"? A) A design flaw can't be exploited B) A design flaw requires an architecture redesign to fix, rather than a simple code patch, and often affects several components at once C) An implementation bug is never patched D) They're synonyms
    Answer: **B** (A design-flaw zero-day needs architectural change; an implementation bug needs a targeted code patch. Design flaws are usually broader in impact and slower to remediate.)

34. Which of the following relates to "secure design patterns and paved road," as recommended by OWASP? A) Every team reinvents its own authentication implementation from scratch B) Centralized, proven libraries/services (auth-as-a-service, rate-limiting middleware), mandatory for all teams to use C) No standards shared across teams D) Skipping code review
    Answer: **B** (A paved road means centralized proven services (auth-as-a-service, rate-limit middleware) mandatory for teams. Those secure design patterns reduce ad-hoc gaps.)

35. Which of the following is a correct example of defending against "scalping"/limited-item hoarding through design (rather than a post-incident patch)? A) Simply adding a CAPTCHA after the fact, once bots have already bought out the entire stock once B) Building purchase-flow rate limiting per account/IP, behavioral analysis, and per-account item limits into the architecture from the start as business requirements C) Ignoring the problem D) Doubling the item's price
    Answer: **B** (Against scalping: purchase rate limits per account/IP, behavioral signals, and per-account quantity caps in the flow. UI-only “honest user” assumptions fail against bots.)

36. Why is a "single point of failure" for a security control an example of poor design? A) It's unrelated to security B) If the entire security posture relies on one unverifiable mechanism with no supporting/defense-in-depth layers, compromising that single mechanism leads to a complete protection failure C) SPOF is only about availability, not security D) SPOFs are impossible in modern systems
    Answer: **B** (A security single point of failure puts all protection on one unverifiable mechanism with no defense-in-depth. If that point fails or is bypassed, security collapses — poor design.)

37. Which of the following is a correct example of a "fail securely" design for a payment system (overlapping with A10, but established at the A06 stage)? A) When a transaction-limit check fails, allow the transaction by default (fail open) B) When a transaction-limit check fails, deny the transaction by default and log the incident (fail closed) C) Ignore failures D) Automatically retry the transaction without logging
    Answer: **B** (Fail securely: if a transaction-limit check fails, deny by default and log (fail closed), never “allow through.” Otherwise control failure becomes an open door.)

38. Per OWASP, insufficient threat modeling most often manifests as: A) lack of performance testing B) unaccounted-for abuse/attack scenarios at the design stage that are only discovered later via an incident or pentest C) outdated API docs D) lack of CI/CD
    Answer: **B** (Weak threat modeling most often shows up as abuse/attack scenarios missed at design and found only via incident or pentest. Design-stage gaps catch up later.)

39. A business logic flaw example in e-commerce: the ability to apply the same "first purchase -50%" promo code multiple times to different orders from the same user, due to no check of prior usage. This falls under: A) SQL Injection B) Insecure Design (insufficient business-rule enforcement in the architecture) C) XSS D) SSRF
    Answer: **B** (Reusing a “first-order” discount is Insecure Design: business rules are not enforced in the architecture. Need idempotency, usage tracking, and server-side limits.)

40. What's the correct approach to testing for race conditions during a pentest? A) Sending requests strictly sequentially with a delay B) Sending identical requests simultaneously (in parallel) via tools like Burp Turbo Intruder/specialized scripts to minimize network latency between requests C) Testing only via the UI manually with a single request D) Checking the TLS version
    Answer: **B** (Test races by sending identical requests in parallel (Turbo Intruder etc.) and checking invariants (balance, stock). Sequential manual clicks do not reproduce races.)

41. Why should "design review" be a separate stage from "code review" in the SDLC? A) They're the same thing, no separation needed B) Code review checks correctness of an existing design's implementation; design review checks the adequacy of the design itself against architectural threats, before code is written C) Design review isn't required for web apps D) Design review is only done after release
    Answer: **B** (Design review checks whether the model and controls are adequate; code review checks correct implementation of an already chosen design. Different SDLC stages, different questions.)

42. Which of the following is an example of insufficient password-reset process design leading to account takeover? A) Using bcrypt to store the password B) The recovery process relies solely on a secret question with an easily guessable/publicly known answer (e.g., "mother's maiden name"), baked into the architecture with no alternative C) Using HTTPS for the recovery form D) Rate limiting on the login form
    Answer: **B** (Password reset solely via an easily guessed secret question is poor recovery-process design. Use strong tokens, MFA channels, and TTLs—not public “answers.”)

43. Per Insecure Design principles, "excessive client-side trust" manifests when: A) the server fully validates all data independently of the client B) business logic (e.g., calculating an item's price) is partially or fully performed/verified on the client, and the server accepts the client's final value without recalculating it C) the client has no API access D) HTTPS is used
    Answer: **B** (Excessive client-side trust means business logic (price, discounts) is computed/trusted on the client without server enforcement. Attackers control the client; the server must enforce rules.)

44. Which of the following is a correct example of secure multi-tenant SaaS architecture from a secure-design standpoint? A) A shared table with no tenant_id at all B) Strict data isolation built into the architecture (separate schemas/tenant_id as a mandatory, enforced filter at the ORM/middleware level for every request) C) Relying only on UI-level filtering by tenant D) No tenant check at all, "because it's inconvenient for development"
    Answer: **B** (Secure multi-tenant design isolates data architecturally (separate schemas / mandatory enforceable tenant_id). “Hope the developer remembers WHERE” is not a design.)

45. Why does an "insufficiently thought-through" approval workflow — e.g., no check that the approver isn't the same person as the requester (segregation of duties) — fall under Insecure Design? A) It's only relevant to HR processes, not InfoSec B) The lack of an architectural separation between requester and approver roles lets a single compromised or dishonest account approve its own request (e.g., a privilege escalation, a large transfer) C) This can't be prevented architecturally D) It's unrelated to web applications
    Answer: **B** (A workflow without requester/approver separation lets one compromised account complete the whole approval chain. Architectural segregation of duties is a required design control.)

46. Which of the following best describes the "secure by default" approach in the context of Insecure Design? A) All security settings are disabled by default for user convenience B) The system is configured as securely as possible by default, and the user must deliberately weaken protection if needed, rather than the reverse C) Secure by default only applies to passwords D) It's unrelated to design
    Answer: **B** (Secure by default means the system starts as secure as practical; weakening it is a deliberate user/admin act. That design/product principle reduces accidental exposure.)

47. An example of an architectural oversight: a booking system doesn't limit the number of simultaneous "holds" one user can place on seats, allowing the entire inventory to be locked up without any real purchase. This is: A) SQL Injection B) Insecure Design / resource exhaustion via business logic C) XSS D) Broken Authentication
    Answer: **B** (Booking without limits on hanging holds is Insecure Design / resource exhaustion via business logic: inventory can be locked out. Need hold TTLs and per-account caps.)

48. Per OWASP's Insecure Design guidance, "limit resource consumption by user or service" should be applied at the level of: A) only the network firewall B) the application and API architecture — transactions, requests, user actions — not only infrastructure C) only the database D) only the frontend
    Answer: **B** (Per OWASP, resource limits belong in app/API architecture: transactions, requests, user actions—not only infra quotas. Otherwise business-operation abuse remains open.)

49. Why does "trusting a third party without verification" (e.g., automatically accepting a webhook from a partner without checking its signature) fall under Insecure Design? A) Webhooks are always safe B) If the architecture never accounts for verifying the source/signature of incoming webhooks, anyone who learns the URL can forge an event C) It's unrelated to design, it's Injection D) Webhooks aren't used in enterprise systems
    Answer: **B** (Trusting third-party webhooks without signature/source verification is Insecure Design: anyone who knows the URL can inject events. Architecture must require inbound verification.)

50. Which measure MOST comprehensively reduces an organization's overall risk from the Insecure Design category? A) Only regular post-release vulnerability scanning B) Integrating threat modeling and security requirements into the earliest stage of the SDLC (before code is written) as a mandatory process for critical features, plus reusable secure patterns C) Only using antivirus on servers D) Increasing release frequency without changing the process
    Answer: **B** (The broadest reduction of Insecure Design risk is integrating threat modeling and security requirements at the earliest SDLC stage—before code. Late patches do not replace secure-by-design.)

---
## A07:2025 — Authentication Failures (50 questions)

1. What was category A07 called in the 2021 edition? A) Broken Authentication B) Identification and Authentication Failures C) Sensitive Data Exposure D) Security Misconfiguration
   Answer: **B** (In OWASP Top 10:2021 category A07 was named Identification and Authentication Failures; in 2025 it was renamed Authentication Failures while keeping the same rank.)

2. How many CWEs are in category A07:2025? A) 16 B) 24 C) 36 D) 40
   Answer: **C** (In the 2025 edition, A07: Authentication Failures maps to 36 CWEs covering weak identity proofing, brute force, and session management.)

3. Why has the industry "improved" on this category (rank unchanged, but practices improved)? A) Passwords are no longer needed B) Widespread adoption of standardized frameworks (OAuth2/OIDC) and off-the-shelf Identity Providers instead of homegrown authentication C) Authentication is no longer required D) Every site switched to biometrics
   Answer: **B** (A07’s rank stayed the same, but industry practice improved through widespread OAuth2/OIDC and managed Identity Providers instead of custom authentication.)

4. Credential stuffing is an attack where: A) an attacker brute-forces a password by trying characters B) an attacker uses login/password pairs leaked from other services, betting on password reuse by victims C) an attacker intercepts traffic D) an attacker exploits SQL injection
   Answer: **B** (Credential stuffing tries leaked username/password pairs from other breaches, exploiting password reuse, rather than brute-forcing characters against one account.)

5. User enumeration via a difference in error messages ("user not found" vs. "incorrect password") is: A) not a vulnerability B) a vulnerability letting an attacker determine which logins/emails exist in the system for a subsequent targeted attack C) relevant only to XSS D) relevant only to SSRF
   Answer: **B** (Different “user not found” vs “wrong password” messages let attackers enumerate valid logins/emails for targeted stuffing or phishing.)

6. Session fixation is an attack where: A) a session never expires B) the attacker sets a known session ID for the victim before authentication, and the server doesn't change the ID after successful login, letting the attacker reuse that same ID C) the session is encrypted with a weak algorithm D) the session is stored in a cookie without HttpOnly
   Answer: **B** (In session fixation the attacker forces a known session ID on the victim before login; if the server does not regenerate it after authentication, that ID becomes the victim’s session.)

7. Why should the session ID be rotated (regenerated) after a successful login? A) To save server memory B) To prevent session fixation — a session ID known to the attacker before authentication becomes useless C) Not required if HTTPS is used D) Only required once a year
   Answer: **B** (Regenerating the session ID after login invalidates any pre-authentication ID the attacker knew, which prevents session fixation.)

8. NIST 800-63b recommends for password policy: A) mandatory complexity (special characters, digits, uppercase) and a 90-day forced change B) prioritizing length over imposed complexity, checking against compromised-password lists, and dropping periodic forced changes without cause C) a 4-character minimum D) no restrictions at all
   Answer: **B** (NIST 800-63B prioritizes password length, breach-list checks, and no forced periodic rotation without cause—not rigid complexity rules and 90-day changes.)

9. Rate limiting and lockout on the login endpoint protect against: A) SQL Injection B) brute-force and credential-stuffing attacks C) XSS D) SSRF
   Answer: **B** (Login rate limiting and lockout cap attempt volume, which slows or stops brute-force and credential-stuffing attacks.)

10. Why shouldn't a failed-login error message reveal specifically what was wrong (username or password)? A) It doesn't matter B) Revealing it lowers the entropy available to an attacker for user enumeration and credential-stuffing attacks C) Only required for mobile apps D) It prevents users from recovering access
    Answer: **B** (A generic failure message avoids confirming whether an account exists and does not help attackers with user enumeration or stuffing.)

11. MFA (Multi-Factor Authentication) reduces account-compromise risk because: A) it replaces the need for a password entirely B) it requires an additional factor (something the user has/is) that an attacker usually can't obtain from a stolen password alone C) MFA has no effect on security D) MFA only works for administrators
    Answer: **B** (MFA requires something the user has or is, which an attacker with only a stolen password typically cannot supply.)

12. Which of the following is an example of an insecure password-recovery process? A) Emailing a link with a cryptographically strong random token that has a limited lifetime B) A secret question with an easily guessable/public answer (e.g., "favorite color") as the sole recovery factor C) Requiring re-entry of the current password before changing it D) Notifying the user by email of a password change
    Answer: **B** (A secret question with a public or guessable answer as the sole recovery path effectively bypasses strong authentication.)

13. Exposing a session ID in the URL (e.g., ;jsessionid=ABC123) is risky because: A) URLs don't support long strings B) URLs are often saved in browser history, server/proxy logs, and Referer headers — the session ID can leak through these C) URLs can't be used with HTTPS D) A session ID in a URL is automatically encrypted
    Answer: **B** (A session ID in the URL is stored in browser history, proxy/server logs, and Referer headers, creating leakage paths.)

14. PKCE (Proof Key for Code Exchange) in OAuth2 is mandatory for: A) confidential clients with a server-side secret B) public clients (SPAs, mobile apps) that can't safely store a client secret C) server-side applications only D) it's unrelated to OAuth2
    Answer: **B** (PKCE is required for public clients (SPAs, mobile) that cannot hold a client secret securely; it protects the authorization-code flow from code interception.)

15. Missing verification of the state parameter in an OAuth2 authorization code flow makes the app vulnerable to: A) SQL Injection B) a CSRF attack on the OAuth flow (login CSRF) C) XSS D) SSRF
    Answer: **B** (The OAuth state parameter binds the auth request to the callback and prevents login CSRF; without verifying it, an attacker can force their own code.)

16. An open (unvalidated) redirect_uri in an OAuth2 app can be used by an attacker to: A) intercept the authorization code/token by redirecting to an attacker-controlled domain B) encrypt traffic C) increase performance D) it can't be misused this way
    Answer: **A** (An open redirect_uri lets the attacker redirect the authorization code or token to a domain they control and steal access.)

17. Why does an inactivity session timeout matter, especially on shared/public computers? A) It saves server resources B) It shrinks the window during which a session left open by mistake could be used by the next person on the device C) It doesn't matter for security D) Only required for banking apps
    Answer: **B** (An inactivity timeout shrinks the window in which a session left open on a shared device can be abused by the next person.)

18. Default accounts (e.g., admin/admin) left over after installation are a risk that: A) belongs solely to A02 Misconfiguration B) overlaps between A02 (misconfiguration of the installation itself) and A07 (the weakness/predictability of the account itself as an authentication factor) C) belongs solely to Injection D) isn't a risk at all
    Answer: **B** (Default admin/admin accounts are both an installation misconfiguration (A02) and a weak, predictable authentication factor (A07).)

19. Which of the following is a proper defense against credential stuffing besides rate limiting? A) Checking submitted passwords against known-breach databases (e.g., the Have I Been Pwned API) at registration/password change B) Increasing session ID length C) Disabling HTTPS to speed things up D) Using one password for all service accounts
    Answer: **A** (Checking passwords against breach databases (e.g. HIBP) at registration and change blocks already-compromised credentials, complementing rate limiting.)

20. MFA bypass via a race condition is possible when: A) MFA is always invulnerable B) the server doesn't atomically verify that the MFA step has completed, letting parallel requests bypass the second-factor check C) MFA uses TOTP D) MFA uses SMS
    Answer: **B** (If “MFA completed” is not enforced atomically, parallel requests can race past the second-factor gate.)

21. An MFA downgrade attack is a situation where: A) an attacker physically steals the victim's device B) an attacker manipulates the authentication flow to force it to fall back to a less-secure factor (e.g., SMS instead of TOTP) or skip MFA altogether C) MFA runs slower than usual D) no such attack exists
    Answer: **B** (An MFA downgrade manipulates the auth flow so the app falls back to a weaker factor (e.g. SMS) or skips MFA entirely.)

22. Why is storing a session token in localStorage considered less secure than in an HttpOnly cookie? A) localStorage is slower B) localStorage is accessible from JavaScript, making it vulnerable to theft via XSS, whereas an HttpOnly cookie can't be read from JS C) localStorage isn't supported by modern browsers D) There's no security difference
    Answer: **B** (localStorage is readable from JavaScript, so XSS can steal the token; an HttpOnly cookie cannot be read by scripts and resists that theft.)

23. Which of the following is a correct example of authentication architecture when using a third-party Identity Provider (e.g., Auth0/Okta/Keycloak)? A) Building the entire password-storage logic yourself instead of delegating to the IdP B) Delegating credential storage and MFA logic to a trusted, specialized IdP via a standard protocol (OIDC/SAML) C) Storing the IdP user's password in your own DB "as a backup" D) Disabling MFA on the IdP side to simplify things
    Answer: **B** (Sound design delegates credential storage and MFA to a specialized IdP via OIDC/SAML instead of reimplementing password handling in-app.)

24. How does a password-spraying attack differ from classic brute-forcing? A) They're the same thing B) The attacker tries one/a few common passwords against many different accounts (rather than many passwords against one account), to avoid triggering per-account lockout C) Password spraying only works against SSH D) No such technique exists
    Answer: **B** (Password spraying tries few common passwords across many accounts to avoid per-account lockout, unlike brute-forcing one user with many passwords.)

25. Why is a progressive delay on failed login attempts more effective than a hard lockout after N attempts? A) They have the same effect B) A hard lockout can be weaponized by an attacker for a DoS attack against a legitimate user (account lockout DoS), whereas a progressive delay slows brute-forcing without fully blocking the legitimate owner's access C) A lockout is always better D) A delay doesn't affect brute-forcing
    Answer: **B** (Hard lockout can be weaponized as account-lockout DoS; progressive delay slows brute force without fully locking out the legitimate owner.)

26. Which of the following relates to "Identification Failures" (part of the renamed 2025 category)? A) Weak password storage (that's A04) B) Incorrect/predictable generation of unique user identifiers, allowing confusion/impersonation within the system C) SQL injection D) XSS
    Answer: **B** (Identification failures include incorrect or predictable user identifiers that enable confusion or impersonation in the system.)

27. Is building a custom authentication system "from scratch," without using proven libraries, a recommended practice per OWASP? A) Yes, always better B) No — OWASP recommends using proven, off-the-shelf frameworks/libraries/IdPs instead of homegrown implementations, due to the high risk of subtle bugs C) Yes, if the team is experienced D) The recommendation doesn't depend on context
    Answer: **B** (OWASP advises against custom auth from scratch because subtle session/MFA/reset bugs are likely; prefer proven frameworks and IdPs.)

28. How does a Pass-the-Cookie/Pass-the-Token attack differ from stealing a password? A) It's technically impossible B) The attacker steals an already-valid session token/cookie directly (e.g., via malware/XSS), bypassing the need to know the password or re-pass MFA C) It requires physical access D) It only applies to mobile apps
    Answer: **B** (Pass-the-Cookie/Token steals an already-issued valid session token (e.g. via XSS or malware) and skips password and MFA re-entry.)

29. Which of the following is the correct system response to a suspicious login (e.g., from a new region/device)? A) Do nothing B) Additional verification (step-up authentication), notifying the user, possibly a temporary hold pending investigation C) Immediately and permanently block the account with no notification D) Ignore geolocation entirely
    Answer: **B** (Suspicious logins warrant step-up authentication, user notification, and possibly a temporary hold—not silence or a permanent ban without notice.)

30. Why is TOTP (Time-based One-Time Password) more phishing-resistant as an MFA factor than an SMS code? A) TOTP works without internet access B) TOTP is generated locally on the device and isn't transmitted over an interceptable SMS channel vulnerable to SIM-swapping C) TOTP always uses more digits D) There's no resilience difference
    Answer: **B** (TOTP is generated locally on the device and never rides SMS, so it is not exposed to SIM-swap interception the way SMS codes are.)

31. A SIM-swapping attack targets the compromise of: A) TOTP apps B) SMS-based MFA — the attacker ports the victim's phone number to their own SIM card via the carrier C) passwords directly D) biometrics
    Answer: **B** (SIM-swapping ports the victim’s number to the attacker’s SIM via the carrier and compromises SMS-based MFA, not TOTP apps directly.)

32. Which of the following is best practice regarding reusing old passwords at change time? A) Allow reuse without restriction B) Check password history and prevent reuse of recently compromised/previous passwords C) Require a password change every day D) It doesn't matter
    Answer: **B** (Password history and blocking recent or breached passwords stop users from returning to credentials attackers may already know.)

33. Why is WebAuthn/FIDO2 as an authentication method considered more phishing-resistant than a password+SMS combo? A) It's slower B) The cryptographic binding of the key to a specific domain makes it impossible to use the credential on a fake phishing site C) It doesn't require a device D) It's mechanically identical to a password
    Answer: **B** (WebAuthn/FIDO2 cryptographically binds the credential to the site’s origin, so it cannot be replayed on a phishing domain.)

34. Why is "step-up authentication" (additional verification for sensitive actions, even within an already-authenticated session) good practice? A) It slows the user down with no benefit B) Even if the session is compromised, an extra barrier for critical operations (password change, large transfer) reduces the impact of that compromise C) It's unrelated to A07 D) Only required for administrators
    Answer: **B** (Step-up re-verifies identity for sensitive actions so a stolen session alone is not enough for password change or large transfers.)

35. A "broken logout" attack occurs when: A) logout logic is entirely absent B) the client side removes the token locally, but the server-side session/token remains valid (isn't invalidated), letting a previously intercepted token be reused even after "logging out" C) logout runs too fast D) it isn't a vulnerability
    Answer: **B** (Broken logout is when the client drops the token locally but the server never invalidates the session, so a stolen token still works.)

36. What's the correct entropy test for a password-reset token during a pentest? A) Visually checking the token's length B) Generating many tokens and statistically analyzing them for predictability/patterns (e.g., incrementing, time-dependence) C) Checking the color of the reset button D) Checking the TLS version
    Answer: **B** (Reset-token entropy is tested by generating many tokens and analyzing predictability (increments, time dependence), not by eyeballing length.)

37. Per A07 principles, API (machine-to-machine) authentication should use: A) a simple static API key with no rotation, forever B) short-lived tokens (e.g., OAuth2 client credentials flow) with the ability to rotate and revoke C) a user's password passed in a header D) no authentication at all for internal services
    Answer: **B** (Machine-to-machine APIs should use short-lived tokens (e.g. OAuth2 client credentials) with rotation and revocation, not eternal static keys.)

38. Which of the following describes "broken remember-me functionality"? A) Remember-me is always safe B) The long-lived "remember me" token is stored/transmitted insecurely (e.g., predictably generated or not device-bound), enabling account takeover if stolen C) Remember-me isn't a real concept D) It's unrelated to authentication
    Answer: **B** (Broken remember-me means a long-lived, predictable, or non-device-bound token whose theft yields full account takeover.)

39. Why is "login + password with no MFA" for admin panels especially risky? A) Admin panels aren't attack targets B) Compromising the single factor (the admin's password) grants full system control, not just one user's data C) Admin panels are always physically isolated D) MFA isn't technically supported for admin panels
    Answer: **B** (Admin panels without MFA are high impact: one stolen password often yields full system control, not just one user’s data.)

40. Account enumeration via a registration form ("this email is already registered") is a risk because: A) it isn't a vulnerability B) it lets an attacker compile a list of valid emails/logins for a subsequent targeted attack (credential stuffing, phishing) C) it relates only to SQL Injection D) it requires physical access
    Answer: **B** (“Email already registered” enumerates valid addresses for later credential stuffing and phishing.)

41. Which of the following is the correct action upon discovering a user's password in a known-breach database (e.g., via an HIBP integration)? A) Ignore the event B) Proactively notify the user and/or force a password change on next login C) Permanently block the account with no explanation D) Auto-generate a new password and email it in plaintext
    Answer: **B** (If a password appears in a breach list, notify the user and/or force a change on next login—do not ignore it or email a new plaintext password.)

42. A JWT with an excessively long expiration (exp far in the future) and no revocation mechanism is a risk because: A) it isn't a risk when HTTPS is used B) a stolen token remains valid for the rest of its lifetime with no way for the server to invalidate it C) JWT doesn't support exp D) Only relevant for mobile apps
    Answer: **B** (A long-lived JWT without revocation stays valid until exp if stolen; the server cannot promptly cut off access.)

43. Which of the following is a correct strategy for protecting login forms from automated bots without hurting UX for real humans? A) A classic visual CAPTCHA on every attempt for everyone B) A combination of invisible behavioral checks (e.g., honeypot fields, risk scoring based on behavior patterns) with CAPTCHA only when activity looks suspicious C) No protection at all D) Blocking all users after their first mistake
    Answer: **B** (Invisible honeypots and risk scoring with CAPTCHA only on suspicious activity block bots without punishing every human login.)

44. Per OWASP, "Weak Credential Recovery and Forgot Password process" belongs to: A) A02 Misconfiguration B) A07 Authentication Failures, as it's part of the overall identity-confirmation process C) A05 Injection D) A09 Logging Failures
    Answer: **B** (Weak credential recovery is part of proving identity, so OWASP places it under A07 Authentication Failures.)

45. Why CAN a single sign-on point (SSO), when properly implemented, reduce an organization's overall Authentication Failure risk, despite being a "single point of failure"? A) SSO has no effect on security at all B) Centralization lets you consistently enforce strong policies (MFA, anomaly monitoring) across every system at once, instead of scattered, weaker implementations per app C) SSO always reduces security D) SSO replaces the need for encryption
    Answer: **B** (Well-implemented SSO centralizes MFA and anomaly monitoring across apps, reducing scattered weak auth, even though it is a single point of failure.)

46. An attacker who obtains a password hash from a database leak but can't decrypt it directly — what's the most likely next attack? A) SSRF B) An offline brute-force/rainbow-table attack on the hash (also related to A04) C) CSRF D) Clickjacking
    Answer: **B** (With a leaked password hash, the next step is typically offline brute-force or rainbow-table cracking (also overlapping A04 Cryptographic Failures).)

47. Which of the following is best practice regarding "security questions" if an organization is still forced to use them (legacy systems)? A) Use them as the sole account-recovery factor B) Use them only as an additional (not sole) factor, allowing the user to write their own unpredictable question rather than pick from a standard list C) Store answers in plaintext for quick support access D) Make answers mandatory and unchangeable forever
    Answer: **B** (If security questions must remain on legacy systems, use them only as an extra factor with user-written unpredictable questions, never as sole recovery.)

48. Why should pentest testing of "broken authentication" cover the password-reset flow separately from the login flow? A) They're the same thing, no separate testing needed B) The password-reset process often has its own, less-tested vulnerabilities (predictable tokens, missing rate limiting, user enumeration) distinct from the login logic itself C) Password reset is never tested D) Only required for mobile apps
    Answer: **B** (Password-reset flows often have distinct flaws—weak tokens, no rate limit, enumeration—so they must be tested separately from login.)

49. Which of the following is correct behavior when an incorrect MFA code is entered multiple times in a row? A) Allow unlimited attempts B) Apply rate limiting/a temporary lockout on MFA code entry, analogous to password brute-force protection C) Disable MFA after the third failed attempt D) Automatically email the correct code in plaintext
    Answer: **B** (Repeated wrong MFA codes need rate limiting or temporary lockout like password brute force—not unlimited tries or disabling MFA.)

50. Which measure MOST comprehensively reduces an organization's overall Authentication Failure risk? A) Requiring a complex password with mandatory 30-day rotation B) Mandatory MFA (preferably WebAuthn/FIDO2) + delegation to a proven IdP + rate limiting/lockout + short-lived, rotatable, revocable tokens C) Using only long session IDs with no other measures D) Disabling password reset entirely
    Answer: **B** (The strongest A07 posture combines mandatory MFA (preferably WebAuthn/FIDO2), a proven IdP, rate limiting/lockout, and short-lived revocable tokens.)

---
## A08:2025 — Software or Data Integrity Failures (50 questions)

1. The key difference between A08 and A03 (Supply Chain Failures): A) They're the same category B) A08 covers verifying the integrity of a specific artifact/data (a lower level), A03 covers the entire supply chain process/ecosystem C) A08 applies only to databases D) A03 applies only to web applications
   Answer: **B** (A08 is about verifying integrity of a specific artifact or data; A03 covers the whole supply-chain process and ecosystem.)

2. Insecure deserialization is dangerous primarily because: A) it slows down the application B) deserializing untrusted data without validating its structure/type can lead to RCE via building a gadget chain C) it requires more memory D) it's incompatible with JSON
   Answer: **B** (Insecure deserialization of untrusted data without type/structure controls enables gadget chains that lead to remote code execution.)

3. A gadget chain in the context of Java deserialization is: A) a physical device B) a sequence of classes already present in the classpath that, combined during deserialization of a malicious object, results in arbitrary code execution C) an SQL query D) a network protocol
   Answer: **B** (A gadget chain is a sequence of classes already on the classpath that, during malicious deserialization, combine to run arbitrary code.)

4. The ysoserial tool is used to: A) generate SSL certificates B) generate payloads for exploiting insecure deserialization in Java applications C) scan ports D) brute-force passwords
   Answer: **B** (ysoserial generates payloads (gadget chains) used to exploit insecure Java deserialization.)

5. Python's pickle.loads() on untrusted data is dangerous because: A) pickle only works with numbers B) the pickle format can contain instructions executed during deserialization, enabling RCE via a malicious serialized object C) pickle isn't supported in Python 3 D) it's unrelated to security
   Answer: **B** (The pickle format can embed executable instructions, so pickle.loads() on untrusted data enables RCE.)

6. SRI (Subresource Integrity) for third-party CDN scripts protects against: A) SQL Injection B) execution of a tampered/compromised script, since the browser checks the loaded file's hash against the expected one C) XSS via forms D) CSRF
   Answer: **B** (SRI makes the browser compare the CDN script’s hash to the expected value and refuse to run a tampered file.)

7. The integrity attribute on a <script> tag specifies: A) the script's version B) a cryptographic hash of the expected file content, for the browser to verify before executing it C) the file's encoding D) the script's language
   Answer: **B** (The integrity attribute holds a cryptographic hash of the expected content for the browser to verify before script execution.)

8. Which of the following is an example of insufficient integrity checking in an auto-update mechanism? A) Verifying the update's digital signature before installation B) Downloading and installing an update from a CDN without verifying its signature/hash, relying solely on an HTTPS connection C) Using staged rollout D) Logging every update
   Answer: **B** (Fetching auto-updates over HTTPS alone without signature/hash checks does not prove the file was not swapped at the source.)

9. Why doesn't "an HTTPS connection alone" guarantee an update's content integrity? A) HTTPS provides no data protection at all B) HTTPS secures the transport channel (against MITM), but doesn't guarantee the source itself (server/CDN) hasn't been compromised and isn't legitimately serving a malicious file C) HTTPS automatically verifies the file's signature D) It's false; HTTPS fully solves this problem
   Answer: **B** (HTTPS protects the transport from MITM but does not guarantee the origin server/CDN is uncompromised and serving a clean artifact.)

10. .NET BinaryFormatter is considered obsolete and unsafe for deserializing untrusted data because: A) it's too slow B) it's been repeatedly exploited historically via gadget chains for RCE, so Microsoft recommends avoiding it C) it doesn't support Unicode D) it's incompatible with .NET Core
    Answer: **B** (BinaryFormatter has been repeatedly exploited via gadget chains for RCE; Microsoft marks it obsolete and unsafe for untrusted input.)

11. Which of the following is a proper alternative to insecure deserialization when it can't be avoided entirely? A) Using pickle for all data with no restrictions B) Isolating/sandboxing the deserialization process + strict schema validation of structure before deserializing C) Increasing server memory D) Disabling logging
    Answer: **B** (If deserialization cannot be avoided, sandbox the process and accept only data that passes strict schema validation first.)

12. A CI/CD pipeline without integrity control (e.g., ability to unauthorizedly modify a build script) falls under: A) A08, since the compromised build artifact is then trusted downstream B) exclusively A02 C) exclusively A07 D) it's unrelated to integrity at all
    Answer: **A** (Unauthorized CI/CD build-script changes fall under A08 because the compromised build artifact is trusted downstream.)

13. Which of the following describes an attack on the CI/CD chain via injecting a malicious step into the configuration (e.g., a GitHub Actions workflow)? A) SQL Injection B) Software Integrity Failure — a compromised build stage can implant a backdoor into the resulting artifact, which is then treated as trusted C) XSS D) CSRF
    Answer: **B** (A malicious CI workflow step is a Software Integrity Failure: a backdoor can land in the final artifact that others trust.)

14. Using untrusted third-party plugins (e.g., for a CMS) without verifying their origin/signature relates to: A) exclusively A03 (Supply Chain) B) an overlap of A03 and A08 — the choice of source itself (A03) and the lack of integrity verification for the specific plugin at install/update time (A08) C) exclusively A01 D) it isn't a risk
    Answer: **B** (Untrusted CMS plugins without origin/signature checks span A03 (source choice) and A08 (no integrity check at install/update).)

15. Which of the following is true about XML deserialization (e.g., via XStream in Java)? A) XML cannot be vulnerable to insecure deserialization B) Similar to object deserialization, unsafe handling of an XML representation of objects can lead to RCE via gadget chains specific to XML libraries C) XML deserialization is always safe thanks to an XSD schema D) It's unrelated to A08
    Answer: **B** (Unsafe XML object deserialization (e.g. XStream) can yield RCE via library-specific gadget chains, like binary serializers.)

16. A digital signature for verifying the origin of software/an update works via: A) simple hashing without a key B) asymmetric cryptography — the publisher signs with a private key, the recipient verifies with the publisher's public key C) symmetric encryption with a shared password D) Base64 encoding
    Answer: **B** (Software signing uses asymmetric crypto: the publisher signs with a private key; clients verify with the publisher’s public key.)

17. Why is code review before merging into the main branch a measure relevant to A08? A) It speeds up development B) Independent review reduces the risk that a compromised or malicious commit (breaking codebase integrity) reaches production unnoticed C) It's unrelated to integrity D) Only required for open-source projects
    Answer: **B** (Pre-merge code review reduces the chance a malicious or compromised commit breaks codebase integrity unnoticed.)

18. A Java/.NET/PHP deserialization gadget is most often exploited via: A) standard, widely used libraries already in the classpath/dependencies, whose classes can be combined into a chain without needing to add custom code B) only custom, rare libraries C) only built-in language primitives D) it's impossible without access to the app's source code
    Answer: **A** (Deserialization gadgets usually chain classes from common libraries already on the classpath, without custom app code.)

19. Which of the following is a risk specific to the "software update mechanism" (rather than the development process in general)? A) SQL injection in a login form B) Missing signature verification when a client (thick client, IoT device, plugin) fetches and installs an update C) A weak admin password D) Missing CSP
    Answer: **B** (Update-mechanism risk is specifically missing signature verification when a client (desktop, IoT, plugin) installs an update.)

20. Why do isolated (immutable) build environments reduce CI/CD integrity risk? A) They slow builds down B) They prevent persistent compromise of a build agent across builds — each build starts from a clean, known state C) They have no effect on security D) Only required for mobile apps
    Answer: **B** (Immutable isolated build environments start each job from a clean known state, blocking persistent build-agent compromise.)

21. The SLSA (Supply-chain Levels for Software Artifacts) framework relates to: A) an encryption algorithm B) a standard/framework for ensuring verifiable integrity and provenance of software artifacts at every build level C) an authentication protocol D) a programming language
    Answer: **B** (SLSA is a framework of levels for verifiable integrity and provenance of software artifacts across the build chain.)

22. Sigstore/cosign are used for: A) vulnerability scanning B) signing and verifying container images/artifacts to ensure their integrity and provenance C) database encryption D) password generation
    Answer: **B** (Sigstore/cosign sign and verify container images and artifacts to establish integrity and provenance.)

23. Which of the following describes the risk of "unsigned/unverified container images" in a production Kubernetes cluster? A) It's not a risk when using a private registry B) Without signature verification, the cluster can deploy a swapped/compromised image, even one pulled from a repo that appears "correct" by name C) Container images can't technically be swapped D) It only applies to public registries
    Answer: **B** (Without image signature verification, Kubernetes can deploy a swapped image even from a repository that looks correctly named.)

24. Why is insecure deserialization especially dangerous when combined with widely used enterprise Java frameworks? A) Java is slower than other languages B) The abundance of widely distributed libraries in an enterprise app's classpath increases the odds of finding a usable gadget-chain class combination C) Java doesn't support serialization D) Enterprise apps never use serialization
    Answer: **B** (Enterprise Java classpaths are rich with libraries, raising the odds of finding a usable deserialization gadget chain.)

25. What's the correct testing methodology for finding insecure deserialization in a pentest? A) Only fuzzing text input forms B) Identifying endpoints accepting serialized data (by format — Java magic bytes, PHP's O:, Python's pickle opcode), then testing with tools like ysoserial/phpggc while monitoring for code execution (e.g., via an OOB DNS callback) C) Only checking response headers D) Checking the TLS certificate
    Answer: **B** (Pentests find serialized-data endpoints (magic bytes, PHP O:, pickle), probe with ysoserial/phpggc, and detect RCE via OOB (e.g. DNS).)

26. Why should organizations avoid deserializing objects from data sent directly by the client, even if the client is a "trusted" mobile app built by the same organization? A) Mobile apps can't be compromised B) A client app can be decompiled/modified by an attacker (e.g., via reverse engineering + traffic interception), so a client should be treated as an untrusted source by default C) Mobile apps don't support serialization D) It isn't a risk
    Answer: **B** (Client apps can be reverse-engineered and traffic rewritten, so even “our mobile app” is an untrusted source by default.)

27. Which of the following is true about JSON as a data-exchange format in the A08 context? A) JSON is inherently executable, like pickle B) JSON itself contains no executable code (unlike object serialization), reducing (though not eliminating, given parser misconfiguration) integrity-failure risk compared to binary serialization C) JSON is always unsafe D) JSON can't be used to transmit structured data
    Answer: **B** (JSON itself carries no executable code unlike object serializers, reducing integrity risk—though misconfigured parsers can still hurt.)

28. Manifest confusion/dependency confusion (an internal package sharing a name with a public one, but the public one has a higher version) relates to the overlap between: A) A08 and A03 — compromising the integrity of a dependency's source B) exclusively XSS C) exclusively CSRF D) exclusively DoS
    Answer: **A** (Dependency/manifest confusion compromises the dependency source—overlapping supply chain (A03) and artifact integrity (A08).)

29. Why should digital-signature verification happen BEFORE unpacking/using an archive/package's contents, rather than after? A) Order doesn't matter B) Processing unverified content before verifying the signature can itself trigger a parser-level exploit, even if the signature is later found invalid C) Verifying afterward is faster D) Only relevant for ZIP archives
    Answer: **B** (Verify signatures before unpacking: processing untrusted content first can exploit parser bugs even if the signature later fails.)

30. Which of the following is an example of a "software integrity failure" in a mobile app? A) A user's weak password B) The app doesn't verify the integrity of its own code/resources at launch, allowing a modified (patched) version with security checks bypassed to run C) Missing MFA D) Using HTTP instead of HTTPS
    Answer: **B** (A mobile integrity failure is not verifying own code/resources at launch, allowing patched builds that bypass security checks.)

31. Why is object deserialization riskier than parsing a structured text format with an explicit schema (e.g., Protocol Buffers with a strict schema)? A) There's no difference in safety between them B) Object deserialization directly instantiates arbitrary classes found in the data stream, whereas a strict-schema format constrains the set of allowed fields/types in advance C) Protocol Buffers is always slower D) Object serialization is faster, hence safer
    Answer: **B** (Object deserialization instantiates arbitrary classes from the stream; strict-schema formats (e.g. Protobuf) constrain allowed fields and types.)

32. Which of the following describes a "type confusion" attack via polymorphic deserialization (e.g., Jackson with enableDefaultTyping)? A) The attacker specifies an arbitrary class to instantiate via a type field in the JSON, if the library is configured to take the type from the data itself rather than a strict schema B) It's not a risk when using JSON C) It only applies to XML D) It requires physical access
    Answer: **A** (Polymorphic type confusion (e.g. Jackson enableDefaultTyping) trusts a type field in the data, so attackers can instantiate arbitrary classes.)

33. Why is "trust but don't verify" an antipattern relevant to category A08? A) It's a recommended practice B) Blind trust in the source of data/code without cryptographic integrity verification is the essential root cause of Integrity Failures C) It's unrelated to A08 D) Verification is always redundant when HTTPS is used
    Answer: **B** (“Trust but don’t verify” is the root of Integrity Failures: trusting a source without cryptographic integrity checks.)

34. Which of the following is true about npm postinstall scripts in the integrity context? A) Postinstall scripts can't execute arbitrary code B) Postinstall scripts run automatically at package install time and can contain malicious code if the package/its dependency is compromised (overlapping with A03) C) Postinstall scripts always require manual confirmation by default D) It's unrelated to either A03 or A08
    Answer: **B** (npm postinstall scripts run automatically on install and can execute malware if the package is compromised (overlaps A03).)

35. Why is keeping hashes of reference file versions (integrity monitoring / FIM — File Integrity Monitoring) useful for detecting integrity violations in production? A) FIM slows the system down with no benefit B) It allows detecting unauthorized changes to critical files/binaries after the fact, by comparing the current hash to the reference one C) FIM replaces the need for artifact signing D) FIM only applies to network traffic
    Answer: **B** (File Integrity Monitoring compares live hashes of critical files to baselines to detect unauthorized production changes.)

36. Which of the following is a correct example of protecting a release pipeline against a "time-of-check to time-of-use" (TOCTOU) race condition during signature verification? A) Verifying the artifact's signature long before it's actually used/deployed, leaving room for the file to be swapped in between B) Verifying the signature immediately before use, followed instantly by using that exact same verified object with no intervening swap C) TOCTOU is unrelated to integrity D) It requires no special attention
    Answer: **B** (Against TOCTOU, verify the signature immediately before using that same object, with no swap window between check and use.)

37. Per A08 principles, dependencies and files should come: A) from any convenient source, for development speed B) from expected, trusted repositories over a verified/signed channel C) exclusively from the developer's local disk D) with no origin check, as long as a VPN is used
    Answer: **B** (Per A08, dependencies and files should come from expected trusted repositories over verified/signed channels.)

38. Which of the following describes a risk specific to YAML deserialization (e.g., PyYAML's yaml.load() without safe_load)? A) YAML doesn't support objects B) Unsafe YAML loading can allow instantiating arbitrary Python objects from tags like !!python/object, similar to pickle C) YAML is always safe D) YAML only applies to config files, not user data
    Answer: **B** (Unsafe yaml.load() without safe_load can instantiate arbitrary Python objects via !!python/object tags, similar to pickle.)

39. Why is a browser plugin/extension's auto-update mechanism a frequent target for integrity attacks? A) Extensions have no access to user data B) A compromised extension-update channel lets an attacker silently deliver malicious code with broad access to browser data, bypassing app-store review on subsequent "silent" updates C) Extensions are always updated manually D) It's unrelated to A08
    Answer: **B** (A compromised extension update channel silently delivers malware with broad browser access, bypassing store review on later updates.)

40. Which of the following is true about the relationship between Log4Shell (Log4j RCE) and category A08 vs. A03? A) Log4Shell is exclusively an integrity problem, not supply chain B) Log4Shell is an example of a vulnerable component (A03, a known CVE in a dependency), while the exploitation technique itself — via JNDI lookup — demonstrates the broader issue of unsafe deserialization/interpretation of untrusted data (overlapping with A05/A08) C) Log4Shell is unrelated to either category D) Log4Shell relates only to A01
    Answer: **B** (Log4Shell is a vulnerable dependency (A03); JNDI-based abuse of untrusted data also overlaps injection/integrity themes (A05/A08).)

41. Why does the code-signing certificate used to sign software itself require strict protection (in an HSM, with restricted access)? A) It doesn't matter where it's stored B) Compromising the private signing key lets an attacker sign malicious code as legitimate, completely bypassing the integrity-verification mechanism C) Signing certificates can't be stolen D) Only required for open-source software
    Answer: **B** (Compromise of the private code-signing key lets attackers sign malware as legitimate software and fully bypass signature checks.)

42. Which of the following describes a "CI/CD platform trust boundary violation" risk? A) A CI runner used to build several projects from different teams without isolation, letting a potentially compromised build of one project affect another's artifacts through shared runner state B) It's not a risk when using a cloud CI C) It only applies to self-hosted runners D) It's unrelated to integrity
    Answer: **A** (A shared CI runner without isolation is a trust-boundary violation: one compromised build can poison another project’s artifacts.)

43. Why is verifying a checksum (e.g., SHA-256) of a file downloaded from a public mirror insufficient on its own for full integrity assurance (unlike a cryptographic signature)? A) A checksum and a signature offer equivalent assurance B) A checksum without a signature can be recalculated and republished for a tampered file by the very same attacker who compromised the source — a signature requires possession of the publisher's private key, which the attacker doesn't have C) A checksum is always more reliable than a signature D) A checksum is unrelated to integrity
    Answer: **B** (An unsigned checksum can be recomputed for a tampered file by the same attacker; a signature needs the publisher’s private key.)

44. Which of the following describes an "insecure CI/CD trigger" vulnerability (e.g., a workflow triggered on pull_request_target with access to secrets)? A) It allows an external contributor, via a specially crafted PR, to gain access to secrets/execute code in an elevated context via CI, violating the pipeline's integrity B) It isn't a vulnerability C) It only applies to private repositories D) It requires physical access to the CI server
    Answer: **A** (An insecure trigger such as pull_request_target with secrets lets an external PR run code and steal secrets, breaking pipeline integrity.)

45. Per A08 recommendations, is it safer to use a data format with an explicit, constrained schema (JSON Schema, Protobuf) instead of language-specific binary serialization for inter-service communication? A) No difference B) Yes — a schema constrains the set of allowed fields/types, reducing the attack surface compared to arbitrary object instantiation C) Binary serialization is always safer D) The format doesn't matter for integrity
    Answer: **B** (Schema-constrained formats (JSON Schema, Protobuf) limit fields/types and are safer than language-specific binary serialization between services.)

46. Which of the following is the correct response upon discovering that production uses .NET BinaryFormatter to deserialize data received from an external client? A) Leave it as is if there haven't been incidents yet B) Prioritize migrating to a safe alternative (e.g., System.Text.Json with a strict schema) and/or isolating the deserialization process C) Increase logging without changing the code D) Disable only error logging
    Answer: **B** (BinaryFormatter on external client data should be migrated urgently (e.g. System.Text.Json with a strict schema) and/or sandboxed.)

47. Why is a "pull-based" configuration update pattern (an agent itself requests and verifies the signature of a new config from the server) considered safer than an unverified "push-based" pattern? A) Push is always safer B) A pull-based pattern with signature verification on the agent side lets the agent itself reject an unsigned/tampered configuration, whereas an unconditional push relies solely on transport-channel protection C) Push and pull are always equally secure D) It's unrelated to integrity
    Answer: **B** (Pull-based signed config lets the agent reject unsigned/tampered updates; unverified push relies only on transport protection.)

48. Which of the following is an example of a Data Integrity Failure (as opposed to a Software Integrity Failure) in the A08 context? A) RCE via deserialization B) Missing checksum/signature verification for critical business data (e.g., a financial transaction) exchanged between microservices, allowing it to be silently tampered with "in flight" between mutually trusting services C) A user's weak password D) Missing CSP
    Answer: **B** (A Data Integrity Failure is missing checksum/signature on critical business data (e.g. transactions) between services, enabling silent in-flight tampering.)

49. Why is it recommended to maintain an auditable log of all changes to CI/CD configuration (who, when, what was changed)? A) It doesn't matter for integrity B) It enables investigating pipeline-integrity-violation incidents after the fact and detecting unauthorized changes, which also overlaps with A09 (Logging) C) Only required for ISO compliance D) It slows down CI with no benefit
    Answer: **B** (Auditable CI/CD config change logs support investigating integrity incidents and overlap with A09 Logging failures.)

50. Which measure MOST comprehensively reduces an organization's risk from category A08 (Software/Data Integrity Failures)? A) Only antivirus on servers B) Mandatory cryptographic signing of all artifacts/updates + signature verification before use + avoiding unsafe object deserialization of untrusted data in favor of schema-constrained formats + code review before merge C) Increasing release frequency D) Disabling HTTPS to speed up builds
    Answer: **B** (The strongest A08 control set is mandatory artifact signing, verify-before-use, no unsafe object deserialization (prefer schemas), and pre-merge code review.)

---
## A09:2025 — Security Logging & Alerting Failures (50 questions)

1. What was category A09 called in the 2021 edition? A) Security Logging and Monitoring Failures B) Broken Authentication C) Sensitive Data Exposure D) Using Components with Known Vulnerabilities
   Answer: **A** (In OWASP Top 10:2021 category A09 was named Security Logging and Monitoring Failures; the 2025 edition renamed it to stress alerting rather than monitoring alone.)

2. Why did the emphasis shift from "monitoring" to "alerting" in 2025? A) Monitoring is no longer needed B) Logging and monitoring without an actual notification/response (alerting) trigger are useless for timely incident detection C) "Alerting" is an outdated term D) There's no difference between the terms
   Answer: **B** (Logs and passive monitoring alone do not stop attacks: without a notification and response trigger (alerting), incidents are found too late. That is why 2025 emphasizes alerting.)

3. Why is category A09 underrepresented in OWASP's automated test data (it ranks highly mainly via the community survey)? A) The category doesn't technically exist B) It's hard to automatically test for "absence of a log" with a scanner — it requires understanding an organization's architecture/processes C) Logging is unrelated to security D) OWASP doesn't collect any data for this category at all
   Answer: **B** (Scanners struggle to prove a missing log or a dead alert path — that needs architectural and process context. A09 therefore ranks via the community survey more than pure automated test data.)

4. Which events MUST be logged per OWASP's A09 guidance? A) Only successful logins B) Logins (successful and failed), authorization denials, high-severity server errors, and inputs that are clearly malicious payloads C) Only 500 errors D) Nothing, if HTTPS is used
   Answer: **B** (OWASP requires logging auditable security events: successful and failed logins, authorization denials, high-severity server errors, and clearly malicious inputs (e.g. SQLi/XSS payloads).)

5. Which of the following must NOT be logged in plaintext per best practice? A) Event timestamp B) Passwords, tokens, card numbers — sensitive data C) User ID D) IP address
   Answer: **B** (Plaintext passwords, tokens, and card numbers in logs create sensitive-data exposure and violate best practice; log the event and safe context, never secrets.)

6. Log injection (via CRLF sequences in fields that end up in a log) can lead to: A) SQL injection in a DB B) forging log entries — injecting fake lines that distort forensic analysis C) memory leaks D) DoS via buffer overflow
   Answer: **B** (CRLF in user-controlled fields can split a log line and inject forged entries, distorting forensics and hiding the attacker's real activity.)

7. A SIEM (Security Information and Event Management) is used to: A) encrypt data B) centralize, correlate, and analyze logs from multiple sources to detect incidents and drive alerting C) store passwords D) generate certificates
   Answer: **B** (A SIEM centralizes logs from many sources, correlates them, and drives alerting — turning raw records into incident detection.)

8. Why is storing logs only locally on a compromised server a bad practice? A) It takes up a lot of space B) An attacker who gains control of the server can delete/modify local logs, destroying evidence (anti-forensics) C) Local logs are always faster D) It has no bearing on security
   Answer: **B** (Local logs on a compromised host can be deleted or altered by the attacker, destroying evidence; centralization and integrity controls counter that anti-forensic step.)

9. Per an OWASP example, if a DAST scan/pentest doesn't generate noticeable alerts in the monitoring system, this indicates: A) excellent defense against scanners B) a failure of the monitoring/alerting itself — active attacks should be noticed C) excessive logging D) always a misconfigured scanner, not a monitoring problem
   Answer: **B** (Active DAST/pentesting simulates attack traffic; missing noticeable alerts is itself an A09 finding — the system fails to notice real malicious activity.)

10. NIST 800-61r2 is a document dedicated to: A) passwords B) incident response guidance C) encryption D) microservice architecture
    Answer: **B** (NIST SP 800-61r2 is the standard incident-response guidance; OWASP points to it for playbooks and drills under A09.)

11. Why does sufficient context in a log entry (user id, timestamp, IP, trace id) matter for forensics? A) It doesn't matter, just the fact of recording is enough B) Without context, it's impossible to reconstruct the full chain of events in an incident and link disparate log entries into a single picture of an attack C) Context slows the system down with no benefit D) Only required for GDPR compliance
    Answer: **B** (User id, timestamp, IP, and trace id link sparse records into an attack chain; without that context, forensics and an incident timeline are not feasible.)

12. Which of the following is a correct approach to log format for protecting against log injection? A) Free-text format with no escaping B) Structured logging (e.g., JSON) with escaping of user input before it's written C) Logging without timestamps to save space D) Storing logs as HTML for convenient viewing
    Answer: **B** (Structured logs (e.g. JSON) with escaped user input resist CRLF/log injection and make parsing and correlation more reliable.)

13. Why should logs be protected from modification/deletion even by the application's own permissions (append-only/centralized storage)? A) It doesn't matter when HTTPS is used B) If a compromised application process has rights to delete its own logs, an attacker can cover their tracks post-compromise C) Logs are never programmatically deleted D) Only required in the banking sector
    Answer: **B** (If the app process can delete its own logs, post-compromise the attacker covers tracks; use append-only/WORM storage and/or ship logs beyond the app's privileges.)

14. Which of the following is an example of insufficient alerting, even with complete logging in place? A) Logs are collected in a SIEM, but thresholds/rules for automatic anomaly notification (e.g., multiple failed logins) aren't configured B) Logs are retained for 90 days C) Logs include a timestamp D) Logs are structured as JSON
    Answer: **A** (Full SIEM ingestion without alert rules and thresholds is passive storage: anomalies such as brute force never notify anyone in time.)

15. Why might a company fail to detect an active incident for weeks/months given weak A09 practices? A) Incidents are always detected instantly B) Without effective real-time monitoring and alerting, signs of an attack remain unnoticed in logs that were accumulated but never analyzed, until visible damage appears C) It's technically impossible D) Only relevant to small businesses
    Answer: **B** (With weak monitoring and alerting, attack indicators sit in unreviewed logs for weeks or months until damage is obvious — a classic A09 failure.)

16. Which of the following should NOT be logged in plaintext for privacy/security reasons, while the fact of the attempt itself should still be recorded? A) The fact of a failed login attempt (the fact itself — yes, log it) B) The actual password entered during a failed attempt (content of the password — no, don't log it) C) The attacker's IP address D) The timestamp of the attempt
    Answer: **B** (Record the failed-login fact, but never the password that was typed: it is a secret and a leakage/reuse risk.)

17. Playbooks and regular drills for incident response relate to A09 recommendations because: A) they're unrelated to logging directly B) effective response to an incident discovered via logs/alerts requires a pre-rehearsed process, not just the fact of detection C) A playbook replaces the need for logging D) Drills are only required for military organizations
    Answer: **B** (Detection via logs/alerts is useless without a rehearsed IR process; playbooks and drills enable fast, consistent response.)

18. Which of the following is an example of "alert fatigue" that reduces A09's practical effectiveness? A) Too few alerts B) An excessive volume of low-priority/false-positive alerts leads analysts to ignore or miss genuinely critical alerts amid the noise C) Alert fatigue isn't a real problem D) It only applies to small teams
    Answer: **B** (Alert fatigue is when noise from false or low-priority alerts causes analysts to miss truly critical events, undercutting A09's value.)

19. Why does a trace ID / correlation ID that follows a single request across all microservices matter for logging in distributed systems? A) It's unrelated to microservice architecture B) It lets you link scattered logs from different services into a single event chain for one request/transaction during an incident investigation C) A trace ID is only used for performance debugging, not security D) It significantly slows down request processing
    Answer: **B** (A shared correlation/trace ID spans microservices for one request and stitches their logs into a single transactional chain for investigation.)

20. Per OWASP, the application should be able to: A) only passively log events B) detect, escalate, and signal an active attack in real time, not just keep a passive log for later analysis C) log events only once a day in a batch D) disable logging under high load for performance
    Answer: **B** (OWASP expects the application not only to keep a passive log but to detect, escalate, and signal an active attack in real time.)

21. Which of the following is an example of an event that must be logged per OWASP A09, but is often overlooked? A) A successful image upload B) A change to a user's access rights/role by an administrator C) Viewing an FAQ page D) Loading a CSS file
    Answer: **B** (Admin changes to roles/permissions are critical audit events; without logs, privilege abuse and unauthorized elevation are hard to investigate.)

22. Why is centralizing logs (rather than storing them only on the originating server) critical for investigating large-scale incidents spanning multiple systems? A) Centralization doesn't matter B) It allows correlating events across different systems for a complete picture of an attack that spread across the infrastructure C) Centralized logs always take up less space D) Only required for cloud applications
    Answer: **B** (Centralization correlates events across hosts/services and reveals lateral movement and attack scope, which siloed local storage cannot.)

23. Which of the following is the correct approach to a retention policy for security logs? A) Keep logs for exactly 1 day to save space B) Keep them long enough to cover typical incident-detection time (dwell time), balanced against data-retention requirements and storage cost C) Never delete logs at all, without limit D) Retention policy has no bearing on security
    Answer: **B** (Retention must cover typical dwell time until detection while balancing compliance and storage cost — neither forever nor immediate deletion.)

24. An attacker who knows certain actions (e.g., bulk data downloads) aren't logged can use this to: A) it can't be used in an attack B) exfiltrate data undetected, since the absence of logging means the absence of a trail for later investigation C) speed up the attack technically D) bypass TLS
    Answer: **B** (Knowing logging blind spots lets an attacker exfiltrate data with no record, hence no detection trail and no forensics trail.)

25. Why should WAF/IDS alerts be integrated into a common SIEM rather than treated in isolation? A) WAF alerts are unrelated to application logs B) Correlating perimeter/network alerts with application logs gives a fuller picture of an attack and reduces the chance of missing related events C) Integration slows alert processing D) It has no practical significance
    Answer: **B** (Feeding WAF/IDS into the SIEM links perimeter signals with app logs, yields a fuller attack picture, and cuts missed related events.)

26. Which of the following describes the difference between "logging" and "monitoring/alerting" as the category's two parts? A) They're the same concept B) Logging is recording events; monitoring/alerting is actively analyzing those records in (near) real time with notification of significant events C) Alerting doesn't require prior logging D) Monitoring only relates to performance, not security
    Answer: **B** (Logging is recording events; monitoring/alerting is actively analyzing those records in near real time and notifying on significant events.)

27. Per OWASP, effective A09 protection requires an organization to have: A) just the fact that logs exist on disk B) an effective incident-response plan that uses logs/alerts as input for detection, investigation, and response C) only antivirus D) disabled logging to improve performance
    Answer: **B** (Effective A09 includes an IR plan that treats logs and alerts as inputs to detection, investigation, and response, not an end in themselves.)

28. Which of the following is an example of insufficient logging specific to APIs? A) Logging every successful GET request without exception (excessive, but not a risk) B) Not logging authorization denials (403) and rate-limit triggers on API endpoints C) Logging the request timestamp D) Logging the request method
    Answer: **B** (For APIs, logging 403 authorization denials and rate-limit hits is especially important — they often signal probing and API abuse.)

29. Why shouldn't security logs be displayed directly to the end user (e.g., in an error UI)? A) It's just a UI aesthetics requirement B) Exposing internal logging details to an attacker via the UI can give them reconnaissance information about the internal system structure C) It's always safe to show logs to everyone D) It doesn't matter
    Answer: **B** (Exposing security logs or internal details in the UI hands recon data to an attacker; give users a safe, generic message only.)

30. Which of the following is an example of a "false negative" in alerting (the most dangerous error type for A09)? A) An alert fired on legitimate activity (false positive) B) A real attack occurred but didn't generate an alert due to insufficient coverage/thresholds in the detection rules C) An alert fired correctly and on time D) Logs were recorded correctly
    Answer: **B** (A false negative is a real attack with no alert due to gaps in rules/thresholds; for A09 it is worse than noise because the incident is never seen.)

31. Why should logging scope/detail be balanced (not logging absolutely everything indiscriminately)? A) It doesn't matter, more logs are always better B) Excessive, unstructured logging increases noise, hampers analysis, increases storage costs, and can itself create a risk of sensitive-data leakage C) Logging doesn't consume resources D) Balance has no bearing on security
    Answer: **B** (Logging everything creates noise, storage cost, analysis drag, and PII/secret leakage risk; balance detail with purpose.)

32. Which of the following is an example of an event requiring immediate (real-time) alerting, not just later batch analysis? A) Viewing a public blog article B) Multiple consecutive failed login attempts from a single IP within a short window (a sign of brute-forcing) C) A successful profile-picture upload D) A request for a static CSS file
    Answer: **B** (Many failed logins from one IP in a short window signal brute force and need real-time alerting, not deferred batch review.)

33. A honeypot/canary token in the context of logging and alerting is used to: A) encrypt data B) detect unauthorized access/exfiltration by firing when someone interacts with deliberately placed "decoy" data/resources a legitimate user should never touch C) speed up the server D) generate passwords
    Answer: **B** (A honeypot/canary fires when decoy resources that legitimate users never touch are accessed — a high-fidelity signal of unauthorized activity.)

34. Why does "logging the fact of an access denial" (403 Forbidden) matter just as much as logging successful actions? A) Access denials are of no security interest B) Repeated access denials can indicate an active attack attempt (scanning/permission probing) that's important to catch before successful exploitation C) Logging denials slows down the server significantly D) It's sufficient to log only successful actions
    Answer: **B** (Repeated access denials can be permission scanning/probing; logging and alerting on them help catch attacks before successful exploitation.)

35. Which of the following is a correct security-log storage practice for protecting integrity (overlapping with A08)? A) Storing them in a mutable DB with no access control B) Storing them in append-only/WORM (write-once-read-many) storage or with a cryptographic hash chain to detect after-the-fact tampering C) Storing them only in RAM, without persistence D) Security logs don't require integrity protection
    Answer: **B** (Append-only/WORM or hash-chain storage protects log integrity so after-the-fact tampering is detectable, overlapping A08 goals.)

36. Per OWASP, insufficient logging is most often discovered by an organization: A) immediately during development, via unit tests B) after the fact, while investigating an incident that already happened, when the needed data turns out to be missing C) it's never discovered D) via regular press releases
    Answer: **B** (Insufficient logging is most often found after an incident, when investigation data is missing — the classic A09 post-mortem discovery.)

37. Which of the following describes "insufficient granularity" in logging as a problem? A) A log entry contains too much detail B) A log entry records only the fact "an error occurred" without specifying which error, where, or with what parameters — insufficient for investigation C) Granularity doesn't affect a log's usefulness D) Only successful operations need to be logged
    Answer: **B** (Logging only "an error occurred" without type, location, or parameters is useless for investigation — that is insufficient granularity.)

38. Why does integrating threat-intelligence feeds with a SIEM improve alerting effectiveness per current A09 practice? A) Threat intelligence is unrelated to logging B) It lets you automatically match internal logs against known indicators of compromise (IOCs) — IPs, hashes, domains — for faster detection of known threats C) It slows down log processing with no benefit D) Only required for government organizations
    Answer: **B** (Threat-intelligence feeds match logs against known IOCs (IPs, hashes, domains) and speed detection of known threats in the SIEM.)

39. Which of the following is an example of correctly handling sensitive data when logging a form-validation error? A) Logging the user's entered password in plaintext for debugging B) Logging the fact of the validation error and a masked/truncated value (e.g., only the last 4 digits of a card), not the full sensitive value C) Not logging the validation error at all D) Logging only a timestamp with no details
    Answer: **B** (On validation errors, log the fact and masked/truncated values (e.g. card last4), never full secrets.)

40. Why is "Mean Time to Detect" (MTTD) a key effectiveness metric for category A09? A) MTTD is unrelated to logging/alerting B) A low MTTD directly reflects how quickly logging+alerting let an organization notice an incident, which is critical for limiting damage C) MTTD is measured only for infrastructure outages, not security D) MTTD can't be measured
    Answer: **B** (MTTD measures how quickly logging and alerting let you notice an incident; a low MTTD is critical to limiting damage.)

41. Which of the following is a valid example of "insufficient escalation" of a detected alert? A) An alert is generated and instantly routed to an on-call analyst with a clear priority B) An alert is generated but sits in a queue of thousands of unreviewed notifications with no prioritization or response SLA C) An alert fully and automatically remediates the threat with no human involvement D) An alert is logged and analyzed in real time
    Answer: **B** (An alert that sits in a pile of unreviewed notifications without priority or SLA is insufficient escalation: detection without response.)

42. Why is it important for pentesters/a red team to EXPLICITLY document in the report whether their test was noticed by the client's monitoring system? A) It doesn't matter for the report B) It's a direct test of the organization's own A09 effectiveness — independent of whether a "classic" vulnerability was found C) A red team never checks monitoring D) Only relevant to a blue team
    Answer: **B** (Documenting whether monitoring noticed the red team/pentest is a direct A09 effectiveness test, independent of classic vulns found.)

43. Which of the following describes a "log tampering" attack? A) Normally appending new entries to a log B) Deliberately altering or deleting existing log entries by an attacker to hide traces of their activity C) Scheduled log rotation D) Compressing logs to save space
    Answer: **B** (Log tampering is deliberate alteration or deletion of entries by an attacker to hide tracks; log-integrity controls counter it.)

44. Why is storing logs in a separate environment/account isolated from production (e.g., a dedicated AWS account for logs) good practice? A) It has no bearing on security B) If the production system is compromised, isolation reduces the chance that the same compromise also grants the attacker access to the logs themselves for destruction C) Isolation complicates log analysis with no benefit D) Only required to satisfy auditors
    Answer: **B** (Isolating log storage (separate account/environment) reduces the chance that a prod compromise also enables log destruction.)

45. Which of the following is a correct way to test A09's effectiveness during a pentest (beyond just checking that logs exist)? A) Only reviewing logging config files B) Running a controlled attack (with client consent) and checking whether it was detected by the client's monitoring team in a reasonable timeframe (also called a purple team exercise) C) Only port scanning D) Only checking the SIEM version
    Answer: **B** (A09 effectiveness is tested by a consented controlled attack and whether monitoring detects it in a reasonable time — a purple-team exercise.)

46. Why is simply "enabling logging" insufficient without a subsequent analysis process? A) The fact of enabling it is enough B) Logs without regular/automated analysis and configured alerting are just accumulated data with no practical protective value until someone finally reviews them (often too late) C) Logging alone fully solves the detection problem D) Log analysis requires no additional resources
    Answer: **B** (Logging without analysis and alerting is mere data accumulation; protective value appears only with regular or automated processing.)

47. Which of the following is a risk of granting excessive SIEM/log access rights to too broad a group of employees? A) It's not a risk B) It increases the attack surface for insider threat and the likelihood of accidental/deliberate modification or deletion of logs critical to an investigation C) It improves investigation speed linearly with headcount D) It's required to meet every standard
    Answer: **B** (Over-broad SIEM/log access expands insider threat and the risk of accidental or deliberate deletion of investigation-critical records.)

48. Why is "anomaly detection" (detecting deviations from a behavioral baseline) a more advanced alerting approach than simple static threshold rules? A) Anomaly detection is always worse than static rules B) It lets you detect new, previously unknown attack patterns that deviate from normal behavior and aren't covered by predefined static rules C) Anomaly detection isn't used in real SIEMs D) It's unrelated to A09
    Answer: **B** (Anomaly detection catches deviations from a baseline, including novel attack patterns that static rules do not cover.)

49. Which of the following is a correct logging practice when integrating with an external/third-party API (e.g., a payment gateway)? A) Don't log interaction with the third-party API at all B) Log the fact of the request/response (including status, but with masking of sensitive fields like card numbers) to enable investigating integration-related problems/incidents C) Log the full content of requests and responses without masking D) Logging third-party interactions isn't necessary since responsibility lies with the partner
    Answer: **B** (For third-party API calls, log request/response facts and status while masking sensitive fields — otherwise integration incidents cannot be investigated.)

50. Which measure MOST comprehensively reduces an organization's risk from category A09 (Security Logging & Alerting Failures)? A) Only enabling a web server's default logging B) Centralized, structured logging of key security events with sufficient context + SIEM integration with configured alerting thresholds + a rehearsed incident-response playbook + regular purple-team exercises C) Retaining logs indefinitely without analysis D) Disabling alerting to reduce analyst workload
    Answer: **B** (Comprehensive A09 control is centralized structured logging of key security events with context, SIEM thresholds, a rehearsed IR playbook, and regular purple-team exercises.)

---

## A10:2025 — Mishandling of Exceptional Conditions (50 questions)

1. Category A10:2025 is: A) a renaming of A10:2021 SSRF B) an entirely new category, previously partially covered by the vague label "poor code quality" C) an obsolete category removed from the list D) a synonym for Security Misconfiguration
   Answer: **B** (A10:2025 is a new category; related CWEs were previously lumped under vague "poor code quality," not a rename of A10:2021 SSRF.)

2. How many CWEs are in category A10:2025? A) 6 B) 16 C) 24 D) 40
   Answer: **C** (A10:2025 maps to 24 CWEs covering improper handling of exceptional conditions across languages and platforms.)

3. The three failure modes of handling an exceptional condition per A10 are: A) encryption, hashing, encoding B) failing to prevent it, failing to detect it, and reacting incorrectly once it has occurred C) authorization, authentication, auditing D) validation, sanitization, escaping
   Answer: **B** (A10's three failure modes are: failing to prevent the exceptional condition, failing to detect it when it occurs, and reacting incorrectly afterward (e.g. fail open).)

4. CWE-636 "Not Failing Securely (Failing Open)" describes a situation where: A) the system always blocks access on error B) upon failure, the system defaults to ALLOWING the action instead of denying it C) the system doesn't handle errors at all D) it only applies to network protocols
   Answer: **B** (CWE-636 (Failing Open) means on failure the system defaults to allowing the action instead of denying it, violating fail-secure design.)

5. "Fail closed," as opposed to "fail open," means: A) upon failure the system defaults to granting access B) upon failure the system defaults to blocking/denying the action, prioritizing security over availability C) the system never experiences failures D) it only applies to firewalls
   Answer: **B** (Fail closed denies the action on failure, prioritizing security over availability — the opposite of fail open.)

6. An empty catch block (catch (Exception e) {}) in code is risky because: A) it slows down execution B) the exception is "swallowed" with no handling/logging, hiding an exceptional state that could lead to further undetected problems C) it doesn't compile in most languages D) it's not a problem when using try-catch
   Answer: **B** (An empty catch (Exception e) {} swallows the error: the condition is neither detected nor handled — a classic A10 detection failure.)

7. Why is CWE-209/CWE-550 (sensitive-information disclosure via error messages) useful to an attacker? A) It provides no useful information at all B) A DB error's stack trace/details give reconnaissance information for crafting a more precise attack (e.g., a more targeted SQL injection) C) It only relates to XSS D) It requires physical access
   Answer: **B** (CWE-209/550 cover error messages (stacks, versions, paths, SQL) that leak externally and aid recon and precise follow-on attacks.)

8. CWE-476 (NULL Pointer Dereference), as an unhandled exception, can lead to: A) improved performance B) an application crash (DoS), and in some cases, bypassing subsequent validation logic C) automatic data encryption D) improved logging
   Answer: **B** (An exception on an upload path that never frees resources, repeated, exhausts handles/connections/memory — A10 resource-exhaustion DoS.)

9. Why should exceptions be handled at the point where they occur, rather than by a generic catch-all handler higher up the stack? A) It doesn't matter where they're handled B) Handling at the point of occurrence allows a context-specific, meaningful response (log+alert+clear message), whereas a generic catch-all loses that specificity C) A generic catch-all is always better D) Exceptions should only be handled at the end of the program
   Answer: **B** (Partial rollback of a multi-step operation leaves inconsistent state (funds, balances) that attackers can abuse.)

10. Scenario: an attacker interrupts the connection mid-way through a multi-step transaction (debit → credit → log). If the system doesn't fully roll back the operation upon failure, this can lead to: A) improved performance B) a race condition that violates balance integrity (e.g., a debit without a matching credit, or a duplicate credit) C) automatic self-correction by the system D) it isn't a risk
    Answer: **B** (CWE-476 (NULL Pointer Dereference) is using a null without a check, causing crash/DoS or skipping later logic.)

11. Which of the following is an example of "resource exhaustion" via unhandled exceptions leading to DoS? A) A request processed successfully with no errors B) The app catches an exception during file upload but fails to release the resource (file handle/connection) afterward; repeated failures exhaust available resources C) Using HTTPS D) Having a CSP in place
    Answer: **B** (A global catch-all without handling at the origin hides the cause, invites unsafe fallbacks, and blocks correct reaction to the specific failure.)

12. Divide By Zero (CWE-369), as an unhandled arithmetic exception, is an example of: A) SQL Injection B) failing to handle an exceptional condition, capable of causing a crash/DoS if not caught C) Cryptographic Failure D) Broken Access Control
    Answer: **B** (CWE-369 is unhandled divide-by-zero — a class of arithmetic exceptions that must be handled explicitly.)

13. Per OWASP data, category A10, despite a relatively modest average incidence rate, has: A) the fewest CVEs of any category B) a very large total CVE count (3,416) and occurrence count (769k), since it spans a wide range of languages/platforms C) zero occurrences D) relevance to only one programming language
    Answer: **B** (If the authz service fails open, users pass without a permission check — direct access-control bypass via A10.)

14. Why is inconsistent error handling across different modules of the same codebase (no unified strategy) a problem relevant to A10? A) Diversity of approaches improves flexibility with no downside B) Inconsistency makes system behavior under failure unpredictable and complicates centralized error monitoring/alerting C) It's not a problem if each module operates independently D) Diversity is required by some standard
    Answer: **B** (Races in multi-step financial flows under bad concurrency/exception handling enable double-spend and state corruption.)

15. Which of the following is a correct testing methodology for category A10 during a pentest? A) Only checking passwords B) Forcing errors with nonstandard input (invalid Content-Type, interrupted multipart requests, null/empty string/negative numbers/overflow), and analyzing behavior when a dependent service fails C) Only port scanning D) Only checking TLS
    Answer: **B** (A10 testing forces errors with nonstandard input (bad Content-Type, mid-multipart disconnects, null/empty/negative/huge values) and observes system reaction.)

16. An attacker deliberately sends various malformed values into an SQL query to collect the query's structure/schema from differences in DB error messages, for a more precise injection later. This illustrates the overlap between: A) A10 (leakage via error handling) and A05 (Injection) B) A04 and A07 C) A02 and A03 D) A08 and A09
    Answer: **A** (Using differing DB error messages to map schema is an A10 (error-handling leak) and A05 (Injection) overlap for sharper injection.)

17. Why does testing system behavior when a dependent service is unavailable (e.g., an authorization-check service) matter for A10? A) It has no bearing on security B) It needs to be verified that the system chooses fail closed (deny) rather than fail open (grant by default) when a critical security service is unavailable C) Dependent services are never unavailable D) It's only relevant to performance
    Answer: **B** (When the authorization-check service is down, verify fail closed (deny), not fail open (grant by default).)

18. Which of the following is a correct ("fail securely") handling of an error in the authentication system if the MFA-verification service is temporarily unavailable? A) Let the user through without MFA verification (fail open) for convenience B) Deny access until the MFA-verification service is restored (fail closed), logging the incident C) Grant access with no checks whatsoever D) Automatically create a new session with full privileges
    Answer: **B** (If the MFA service is down, fail securely means deny access until it recovers and log the incident, not bypass MFA.)

19. Why is a centralized (application-wide) error-handling strategy preferable to a fragmented one? A) Centralization slows development with no benefit B) A unified strategy guarantees consistent behavior (logging, alerting, defaulting to fail-closed) across the entire application, reducing the chance of missed edge cases C) Centralization always harms performance significantly D) It has no bearing on security
    Answer: **B** (A unified error strategy yields consistent logging, alerting, and default fail-closed behavior app-wide, without per-module gaps.)

20. Which of the following is an example of an attacker abusing a "partial transaction rollback" (partial rollback abuse)? A) An attacker cannot influence transactions B) An attacker deliberately triggers a failure at a specific step of a multi-step operation, knowing the rollback is incomplete, to gain a benefit (e.g., receiving goods without payment being debited) C) It's not a realistic attack scenario D) It only applies to databases without transactions
    Answer: **B** (Partial-rollback abuse: the attacker forces failure at a chosen step knowing rollback is incomplete and profits from the stuck state.)

21. Why does input validation performed BEFORE processing (a preventive measure) relate to A10, not just to A05 Injection? A) Validation relates only to preventing injection B) Validation also prevents the exceptional conditions (edge cases) themselves from arising, which could otherwise lead to unhandled exceptions, regardless of whether it was an injection attempt C) Validation is unrelated to error handling D) A10 doesn't require validation
    Answer: **B** (Input validation prevents exceptional edge cases from arising at all, not only injection payloads — A10's preventive branch.)

22. Which of the following is an example of "rate limiting/resource quotas" as a preventive measure against A10? A) It's unrelated to exception handling B) Limiting resource consumption in advance prevents the exceptional state itself (resource exhaustion) from arising, rather than just correctly handling it afterward C) Rate limiting relates only to A01 D) Rate limiting doesn't affect error handling
    Answer: **B** (Rate limits/quotas prevent resource exhaustion from occurring, rather than only failing "nicely" after exhaustion.)

23. CWE-703/754/755 in category A10 collectively cover: A) encryption vulnerabilities B) general improper handling/checking of exceptional conditions C) SQL-injection vulnerabilities D) network configuration problems
    Answer: **B** (CWE-703/754/755 collectively cover improper checking/handling of exceptional conditions — the core of A10.)

24. Why is "a raw technical stack trace" shown to an end user upon error a specific example of an A10 problem (not just A02)? A) It relates exclusively to A02, with no overlap B) It's simultaneously both a failure of correct exception handling (A10 — what to do when an error occurs) and a failure of error-display configuration (A02) — the categories overlap at this point C) It's unrelated to either category D) It relates only to A08
    Answer: **B** (A raw stack trace to the user is both A10 (unsafe error handling) and A02 (misconfiguration allowing debug detail in prod).)

25. Which of the following is an example of an edge-case value important for testing error handling? A) An ordinary valid field value B) null, an empty string, a negative number, an extremely long string, a value that overflows the data type C) Only positive integers D) Only strings in English
    Answer: **B** (Error-handling edge cases to test include null, empty string, negatives, extreme lengths, and type overflows.)

26. Why is load/stress testing relevant to category A10, not just to performance testing? A) It's unrelated to security at all B) It can reveal resource-exhaustion vulnerabilities arising from an accumulation of unhandled exceptions under load, which may go unnoticed during low-load staging tests C) Load testing fully replaces security testing D) It's unrelated to error handling
    Answer: **B** (Load/stress testing reveals resource exhaustion from accumulating unhandled exceptions under load — an A10 scenario, not only performance.)

27. Which of the following demonstrates "state corruption" via improper handling of an exceptional condition in a multi-step operation? A) All steps complete successfully with no failures B) A failure at an intermediate step (e.g., a network interruption) leaves the system in an inconsistent state unless a full rollback/compensating transaction is provided C) Using HTTPS for every step D) Logging every step
    Answer: **B** (Mid-flow failure without full rollback leaves inconsistent state — state corruption via mishandling exceptional conditions.)

28. Why does OWASP recommend threat modeling and code review specifically focused on error handling? A) Error handling can't be analyzed in advance B) It lets you identify edge cases and incorrect assumptions about failure behavior before they become a production vulnerability C) Threat modeling relates only to A06, with no overlap with A10 D) Code review doesn't reveal error-handling problems
    Answer: **B** (Threat modeling and error-handling code review find bad failure assumptions and edge cases before production.)

29. Which of the following is an example of strict input validation with sanitization as a preventive A10 measure? A) Fully trusting any incoming value without checks B) Checking the type, range, and format of data BEFORE it's used in business logic, rejecting invalid values at the input rather than handling their consequences afterward C) Client-side validation only D) No range check on numeric values
    Answer: **B** (Strict type/range/format checks at the boundary, rejecting invalid values, prevent many A10 exceptional conditions.)

30. Why does "necessary but insufficient" error logging without subsequent alerting partly overlap with the A09 problem, but also relate to A10? A) The categories are entirely independent, with no overlap B) A10 focuses on the system's correct response AT THE MOMENT an exceptional condition occurs (including detection via logging), while A09 covers the subsequent monitoring/alerting process on accumulated logs — they complement each other C) A10 doesn't include logging at all D) Logging relates only to A09
    Answer: **B** (Error logging without alerting overlaps A09, yet A10 centers on the system's correct reaction at the moment the exceptional condition occurs, including detection.)

31. Which of the following is a correct response by an API to a malformed/unexpected request-body format (e.g., XML instead of the expected JSON)? A) Attempt to parse it by any means available, with no restrictions B) Explicitly reject the request with a clear error code (400 Bad Request) without leaking internal parser details, and log the attempt C) Ignore the problem and return 200 OK D) Crash the entire server process
    Answer: **B** (On unexpected body format (XML instead of JSON), the API should return 400 without parser internals and log the attempt.)

32. Why is "unhandled exceptions during third-party API integration" (e.g., a payment gateway timeout) an A10-specific scenario? A) Third-party integrations never fail B) The application must explicitly anticipate and correctly handle scenarios where an external system is unavailable/times out/responds unexpectedly, without leaving the user/data in an undefined state C) Third-party APIs always handle their own errors on the app's behalf D) It's unrelated to exception handling
    Answer: **B** (External API timeouts/failures (payment gateway) are classic A10: handle them explicitly without leaving funds/user in an undefined state.)

33. CWE-234/235 (missing/extra parameters not handled correctly) in the A10 context describes a risk where: A) parameters are always handled correctly by default B) a missing expected parameter or an unexpected extra one isn't explicitly handled, potentially causing unpredictable behavior or a logic bypass C) it only relates to SQL queries D) it only relates to cookies
    Answer: **B** (CWE-234/235: missing or extra parameters without explicit handling cause unpredictable behavior or logic bypass.)

34. Which of the following is an example of "graceful degradation" as a correct architectural pattern for handling a non-critical component's failure? A) When the recommendation engine fails, the entire site becomes unavailable (total outage) B) When a non-critical component (e.g., recommendations) fails, core functionality (viewing a product, checkout) keeps working without it, with explicit, safe feature degradation C) No such pattern exists D) It only applies to database failures
    Answer: **B** (Graceful degradation: if a non-critical component (recommendations) fails, core flows (catalog, checkout) continue with that feature safely off.)

35. Why is "fail open" especially dangerous specifically for security-critical checks (authentication, authorization), but not for non-critical features? A) Fail open is equally dangerous everywhere, with no difference B) For security checks, fail open directly means granting unauthorized access upon failure, whereas for a non-critical feature (e.g., recommendations), degraded functionality creates no security risk C) Fail open never applies to security checks D) It doesn't matter which component failed
    Answer: **B** (Fail open on authn/authz grants unauthorized access on failure; degrading a non-critical feature is fine, failing open security checks is not.)

36. Which of the following is an example of correctly handling buffer/memory overflow in languages without automatic memory management (C/C++)? A) Ignoring array bounds for speed B) Explicit bounds checking before accessing memory, using safe string/buffer functions instead of unsafe ones (strcpy → strncpy and similar) C) Disabling all checks for performance D) Using pointers with no null checks
    Answer: **B** (In C/C++, use bounds checks and safe string/buffer APIs (strncpy and peers) instead of strcpy — correct handling of memory bounds.)

37. Why does an incident where "an attacker deliberately forces a 500 error to get a full stack trace with the framework version" relate to both A10 and A02 simultaneously? A) It relates only to A02 B) A10 concerns the fact that the error wasn't handled "internally" by the app correctly (without leaking details); A02 concerns the fact that the server configuration allows debug information to be displayed in prod at all C) A10 is unrelated to information disclosure D) A02 is unrelated to error handling
    Answer: **B** (Forced 500 with a stack trace: A10 is unsafe error handling (leak); A02 is config allowing debug detail in production.)

38. Which of the following is the correct response to discovering during a pentest that a multi-step financial transaction allows a race condition (double debit under parallel requests)? A) Treat it as a low-priority "just a bug," unrelated to security B) Classify it as a significant vulnerability (overlap of A06 Insecure Design and A10 Mishandling of Exceptional Conditions), recommending atomicity via DB-level locking/transactions C) Ignore it if the PoC only succeeded once out of ten tries D) Report it only if the attack reproduces reliably 100% of the time
    Answer: **B** (A double-debit race is a significant issue at the A06 (Insecure Design) and A10 boundary; fix with atomicity and DB locks/transactions.)

39. Why is it important to test "unexpected input combinations" (e.g., sending conflicting parameters simultaneously) when auditing error handling? A) Such combinations never occur in real traffic B) Unexpected combinations of input data are a frequent source of unhandled edge cases that developers didn't anticipate during normal happy-path testing C) It's sufficient to test one parameter at a time D) It's unrelated to A10
    Answer: **B** (Conflicting or unexpected parameter combinations often expose edge cases missed by happy-path testing.)

40. Which of the following describes the link between A10 and A03 (Supply Chain) when a third-party library itself mishandles exceptions? A) The categories are entirely unrelated B) A third-party dependency vulnerable to mishandling of exceptional conditions (e.g., a library that crashes unsafely on certain input) is simultaneously a supply-chain risk (use of a vulnerable component) and a concrete A10 manifestation at the level of that component C) A10 applies only to an organization's own code D) A03 doesn't overlap with any other category
    Answer: **B** (A library that mishandles exceptions is both A03 (supply-chain/vulnerable component) and concrete A10 at the dependency level.)

41. Per OWASP, which vaguer, more general label were part of these CWEs previously filed under? A) "Broken Cryptography" B) "Poor code quality" C) "Weak Authentication" D) "Unsafe Deserialization"
    Answer: **B** (OWASP previously filed some of these CWEs under vague "poor code quality"; A10 narrows focus to behavior under exceptional conditions.)

42. Which of the following is an example of insufficient handling of an "unexpected null" in an object-oriented language with nullable types? A) An explicit null check before dereferencing an object (Optional/null-check) B) Directly calling a method on an object without a null check, resulting in a NullPointerException and potential crash/DoS C) Using strict typing with no nullable types D) Explicitly handling Optional.empty()
    Answer: **B** (Calling a method without a null check → NullPointerException, crash/DoS — insufficient handling of unexpected null (CWE-476 class).)

43. Why can "an unhandled exception while parsing client-supplied JSON" pose a security risk in addition to an availability (DoS) concern? A) JSON parsing never raises exceptions B) Depending on the implementation, a parsing failure can leave the system in an unpredictable intermediate state, potentially skipping subsequent security checks that expected the parse to succeed first C) JSON parsing is always safe D) It's unrelated to A10
    Answer: **B** (Unhandled JSON parse failure can leave intermediate state and skip security checks that assumed a successful parse — risk beyond mere DoS.)

44. Which of the following is the correct architectural approach to handling a failure of an external authorization service in a microservices architecture? A) A circuit-breaker pattern with fail-closed default behavior — requests requiring authorization are denied, not waved through, when the auth service is unavailable B) Automatically approve all requests when the auth service is unavailable C) Infinite retries with no timeout, blocking the entire processing pipeline D) Fully disabling logging when the auth service fails
    Answer: **A** (When the auth service is down, a circuit breaker with fail-closed denies authorization-required requests rather than waving them through.)

45. Why do "unhandled exceptions in background jobs" (cron/background tasks) pose a risk distinct from synchronous HTTP requests in the A10 context? A) Background jobs never fail B) A failed background job (e.g., a batch payment-processing job) can go unnoticed longer, since there's no immediate user-facing error response, requiring separate monitoring/alerting C) Background jobs are unrelated to the application D) It's no different from handling HTTP requests
    Answer: **B** (Background job/cron failures lack an immediate user-facing error, so they stay unnoticed longer — they need separate monitoring and alerting.)

46. Which of the following is an example of correctly handling a timeout when calling an external payment API, to avoid double-charging on retry? A) Simply retrying the payment request automatically on timeout with no additional checks B) Using an idempotency key for the request, so resubmitting the same request doesn't result in a duplicate charge C) Ignoring the timeout and assuming the payment succeeded D) Immediately rolling back the whole order without checking the status with the payment provider
    Answer: **B** (An idempotency key on payment API calls prevents double charge on timeout retry — correct reaction to that exceptional condition.)

47. Why does "explicitly defining behavior for unreachable/logically impossible states" (e.g., a switch with no default case for an enum) matter during development? A) Such states never arise in practice B) Changes to code/data over time can lead to a previously "impossible" state occurring; explicit handling (including a default case with logging) prevents it from being silently skipped C) It has no bearing on security D) A code comment is sufficient, without actual handling
    Answer: **B** ("Impossible" states become possible as code/data change; a default branch with log/alert prevents silently skipping that case.)

48. Which of the following is the correct approach to handling an exception caused by insufficient file-system permissions (an OS-level error) in an application? A) Allow the operation to proceed, bypassing the check (fail open) B) Deny the operation, return a clear error to the user without leaking the file path, and log the incident with full server-side context C) Crash the entire application process with no logging D) Silently ignore the error and continue as if nothing happened
    Answer: **B** (On file-permission errors: deny, return a safe user message without the path, and log full server-side context.)

49. Why does category A10 logically "close out" the OWASP Top 10:2025 list, covering exceptional conditions that can arise from exploiting ANY of the other nine categories? A) A10 is unrelated to the other categories B) Improper error handling often becomes the final link in exploiting other vulnerabilities (e.g., an injection triggers a DB error → mishandling that error leaks data) — A10 concerns what happens at the system's failure boundary regardless of the root cause C) A10 relates only to DoS attacks D) A10 is never actually tested in practice
    Answer: **B** (A10 closes the Top 10: bad error handling is often the last link when exploiting any prior category (injection → DB error → leak).)

50. Which measure MOST comprehensively reduces an organization's risk from category A10 (Mishandling of Exceptional Conditions)? A) Only increasing timeouts on all requests B) A centralized error-handling strategy (fail closed by default, handling at the point of occurrence, no leakage of internal details) + strict input validation + preventive rate limiting/resource quotas + stress/pentest of edge cases C) Fully removing try-catch blocks for code simplicity D) Logging errors without ever actually handling them
    Answer: **B** (Best A10 reduction: centralized strategy (fail closed, handle at origin, no leaks) plus validation, rate limits/quotas, and stress/pen testing of edge cases.)

---

## Summary

500 questions (10 categories × 50). This format is suitable for importing into Anki/Quizlet (delimiter: the numbered list; the answer is bolded) or as a base question set for interview prep/self-testing.
