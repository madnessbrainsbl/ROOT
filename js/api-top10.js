/* RØOT — OWASP API Security Top 10 (2023) track
 * Original educational summaries + offline mini-labs.
 * Category names/order follow the public OWASP API Security Top 10 project
 * (see THIRD_PARTY.md). Practice UIs and wording are original RØOT material.
 */
const ApiTop10 = (() => {
  const esc = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const numLabel = (id) => { const m = String(id).match(/(\d+)$/); return m ? String(+m[1]).padStart(2,'0') : String(id); };
  const L = (ru, en) => (I18n.lang() === 'en' ? en : ru);

  const INTRO = {
    en: `<p class="theory-lead">The <strong>OWASP API Security Top 10 (2023)</strong> classifies risks specific to APIs (REST/GraphQL/gRPC), not the same list as Web Top 10:2025. In industry reports and bug-bounty programs, <strong>BOLA (API1)</strong> is consistently the most common critical API finding — object-level access control fails more often than fancy crypto bugs. RØOT gives theory + offline simulators — no real backend.</p>
<p>Map loosely: API1/API5 ≈ A01 access control · API7 ≈ SSRF · API8 ≈ misconfig · API2 ≈ auth. Practice only on authorized targets and this offline range.</p>`,
    ru: `<p class="theory-lead"><strong>OWASP API Security Top 10 (2023)</strong> — отдельная таксономия для API (REST/GraphQL/gRPC), не копия Web Top 10:2025. В отраслевых отчётах и bug bounty <strong>BOLA (API1)</strong> стабильно №1 среди критичных API-находок: object-level authz ломается чаще, чем «красивая» криптография. В RØOT: теория + offline-симуляторы, без реального backend.</p>
<p>Грубый маппинг: API1/API5 ≈ A01 · API7 ≈ SSRF · API8 ≈ misconfig · API2 ≈ auth. Только authorized targets и этот offline range.</p>`,
  };

  const ITEMS = [
    {
      id: 'API1',
      title_en: 'Broken Object Level Authorization',
      title_ru: 'Нарушение авторизации на уровне объекта (BOLA)',
      risk: 'CRITICAL',
      cwe: 'CWE-639',
      theory_en: `<h3>What breaks</h3>
<p><strong>Broken Object Level Authorization (BOLA)</strong> — also known as IDOR in older web terminology — happens when an API authenticates the caller but does <em>not</em> verify that this identity may read or change the specific object named in the request. Typical surfaces: path params (<code>/api/v1/orders/{id}</code>), query filters (<code>?accountId=</code>), body fields, or GraphQL node IDs. Sequential or predictable IDs make discovery easy; UUIDs only hide objects — they do not replace authorization.</p>
<p>Impact ranges from reading another user’s invoices or messages to changing or deleting records, exporting PII, or abusing multi-tenant SaaS isolation. Horizontal privilege (user A → user B data) is the classic form; vertical privilege appears when object IDs reach admin-only resources.</p>
<h3>Real-world / known patterns</h3>
<ul>
<li>Mobile banking and fintech APIs: classic bug-bounty pattern of swapping <code>accountId</code> / <code>transactionId</code> after login.</li>
<li>Social / Graph-style APIs: Facebook Graph and similar platforms historically faced IDOR-class object access issues when object IDs were guessable or leaked.</li>
<li>Ride-sharing, health, and IoT backends: public writeups repeatedly show “logged-in but no ownership check” on receipts, trips, devices, and medical records.</li>
</ul>
<h3>How to practice / test (authorized only)</h3>
<ul>
<li><strong>Offline lab:</strong> as user 2, request invoice IDs belonging to user 1 (hint id <code>1001</code>) and observe whether data is returned without an ownership check.</li>
<li><strong>Generic pentest:</strong> create two sessions; collect object IDs from one; replay with the other token. Test path, body, GraphQL variables, and bulk endpoints.</li>
<li>Try list→detail consistency, export/download endpoints, and “share link” or PDF generators that re-fetch by id.</li>
<li>Never test against production accounts you do not own; stay inside scope and this offline range for practice.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Server-side authorization on <strong>every</strong> object access: resolve the object, then check ownership / tenant / role before returning or mutating.</li>
<li>Prefer opaque IDs and avoid trusting client-supplied <code>user_id</code>; derive the subject from the session/token.</li>
<li>Centralize checks (policy middleware, ABAC, repository-layer guards); add automated tests that assert cross-user denial.</li>
<li>Log and alert on repeated cross-tenant id probes; do not leak existence differences if policy requires it.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API1 Broken Object Level Authorization</strong> (most frequently reported API risk).</li>
<li>BOLA/IDOR class: typical of bug-bounty reports on mobile banking and multi-tenant SaaS object endpoints.</li>
<li>Graph API / social IDOR-class issues: publicly discussed object-id access control failures (e.g. Facebook Graph historical research patterns).</li>
</ul>`,
      theory_ru: `<h3>Что ломается</h3>
<p><strong>Broken Object Level Authorization (BOLA)</strong> — в старой web-терминологии IDOR — возникает, когда API аутентифицирует caller, но <em>не</em> проверяет, что эта личность может читать или менять конкретный объект из запроса. Типичные поверхности: path (<code>/api/v1/orders/{id}</code>), query (<code>?accountId=</code>), body, GraphQL node id. Sequential/предсказуемые id упрощают discovery; UUID лишь скрывают объекты — они <strong>не</strong> заменяют authorization.</p>
<p>Импакт: чужие счета и сообщения, изменение/удаление записей, выгрузка PII, поломка multi-tenant isolation. Горизонтальный privilege (user A → данные user B) — классика; вертикальный — когда id ведёт к admin-only ресурсам.</p>
<h3>Реальный мир / известные паттерны</h3>
<ul>
<li>Mobile banking и fintech API: классика bug bounty — подмена <code>accountId</code> / <code>transactionId</code> после login.</li>
<li>Social / Graph API: у Facebook Graph и похожих платформ исторически обсуждались IDOR-class проблемы доступа по object id.</li>
<li>Ride-sharing, health, IoT: публичные writeup’ы снова и снова показывают «залогинен, но ownership не проверен» на trips, devices, medical records.</li>
</ul>
<h3>Как практиковать / тестировать (только authorized)</h3>
<ul>
<li><strong>Offline lab:</strong> как user 2 запроси invoice id user 1 (hint <code>1001</code>) и проверь, вернётся ли объект без ownership check.</li>
<li><strong>Generic pentest:</strong> две сессии; id из одной — replay токеном другой. Path, body, GraphQL variables, bulk endpoints.</li>
<li>List→detail, export/download, «share link» / PDF, которые снова тянут объект по id.</li>
<li>Не тестируй чужие production-аккаунты; оставайся в scope и в этом offline range.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Server-side authz на <strong>каждый</strong> object access: resolve → ownership/tenant/role → ответ или mutate.</li>
<li>Opaque id; не доверять client <code>user_id</code> — subject из session/token.</li>
<li>Централизовать checks (middleware, ABAC, repository); автотесты на cross-user deny.</li>
<li>Логи/алерты на cross-tenant probe; при необходимости не светить existence.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API1 Broken Object Level Authorization</strong> (самый частый critical API-риск).</li>
<li>Класс BOLA/IDOR: типичные bug-bounty отчёты по mobile banking и multi-tenant SaaS.</li>
<li>Graph API / social IDOR-class: публично обсуждавшиеся сбои object-level access (паттерны Facebook Graph research).</li>
</ul>`,
      practice: 'bola',
      flag: 'FLAG{api1_bola_object_authz}',
      points: 10,
    },
    {
      id: 'API2',
      title_en: 'Broken Authentication',
      title_ru: 'Сломанная аутентификация',
      risk: 'CRITICAL',
      cwe: 'CWE-287',
      theory_en: `<h3>What breaks</h3>
<p><strong>Broken Authentication</strong> covers flaws in how APIs issue, validate, store, and revoke credentials and tokens. Common failures: long-lived or never-expiring access tokens; predictable or weak secrets; missing lockout/rate limits enabling credential stuffing; JWT with <code>alg=none</code>, weak HMAC secrets, or key confusion; API keys in query strings or mobile binaries; broken password-reset and OTP flows; accepting tokens without audience/issuer checks.</p>
<p>Unlike BOLA (authorized user, wrong object), here the attacker aims to <em>become</em> a legitimate principal or stay authenticated longer than intended.</p>
<h3>Real-world / known patterns</h3>
<ul>
<li>Credential stuffing against login and token endpoints is a dominant real-world API abuse pattern (leaked password lists + no adaptive throttling).</li>
<li>JWT misconfiguration class: public research and CTF material repeatedly demonstrate <code>none</code> algorithm, kid injection, and weak shared secrets on microservices.</li>
<li>OAuth/OIDC pitfalls: open redirects, token leakage via referrer/logs, refresh tokens without rotation — classic of mobile and SPA API designs.</li>
</ul>
<h3>How to practice / test (authorized only)</h3>
<ul>
<li><strong>Offline lab:</strong> try weak <code>client_secret</code> values (<code>password</code>, <code>secret</code>, <code>changeme</code>) against the simulated token endpoint.</li>
<li><strong>Generic pentest:</strong> observe rate limits on login/token; test password spray carefully within scope; decode JWTs and check alg, exp, aud, iss; replay expired/revoked tokens.</li>
<li>Hunt tokens in URL query, HTML/JS, redirect chains, and verbose error bodies; review reset/OTP for enumeration and reuse.</li>
<li>Cross-link with the JWT Workshop track for deeper token attacks — only on authorized targets.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Short-lived access tokens + rotating refresh tokens; server-side revocation list or introspection for sensitive APIs.</li>
<li>Strong secret management; enforce JWT alg allowlist (prefer asymmetric); validate <code>iss</code>/<code>aud</code>/<code>exp</code>/<code>nbf</code>.</li>
<li>Adaptive rate limiting, lockout/step-up, MFA for high-risk operations; block credential stuffing with device/IP signals.</li>
<li>Never put secrets or long-lived keys in URLs; use Authorization headers and secure storage on clients.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API2 Broken Authentication</strong>.</li>
<li>Credential stuffing class: widely documented large-scale abuse of login/token APIs without proper throttling.</li>
<li>JWT/OAuth misconfig class: public research and HackerOne-style reports on weak secrets, <code>alg=none</code>, and token leakage.</li>
</ul>`,
      theory_ru: `<h3>Что ломается</h3>
<p><strong>Broken Authentication</strong> — сбои в выдаче, проверке, хранении и отзыве credentials/tokens. Типично: вечные access tokens; слабые secrets; нет lockout/rate limit → credential stuffing; JWT с <code>alg=none</code>, слабым HMAC или key confusion; API keys в query/mobile binary; сломанный password-reset/OTP; токены без проверки audience/issuer.</p>
<p>В отличие от BOLA (уже authorized, но не тот object), здесь цель — <em>стать</em> легитимным principal или жить дольше intended session.</p>
<h3>Реальный мир / известные паттерны</h3>
<ul>
<li>Credential stuffing на login/token endpoints — доминирующий real-world abuse (слитые пароли + нет adaptive throttling).</li>
<li>Класс JWT misconfig: public research и CTF снова показывают <code>none</code>, kid injection, weak shared secrets в microservices.</li>
<li>OAuth/OIDC pitfalls: open redirect, утечка token через referrer/logs, refresh без rotation — классика mobile/SPA API.</li>
</ul>
<h3>Как практиковать / тестировать (только authorized)</h3>
<ul>
<li><strong>Offline lab:</strong> слабые <code>client_secret</code> (<code>password</code>, <code>secret</code>, <code>changeme</code>) на симулированном token endpoint.</li>
<li><strong>Generic pentest:</strong> rate limit на login/token; password spray только в scope; decode JWT (alg, exp, aud, iss); replay expired/revoked.</li>
<li>Токены в query, HTML/JS, redirect chain, verbose errors; reset/OTP — enumeration и reuse.</li>
<li>См. JWT Workshop для углубления — только authorized targets.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Короткие access tokens + rotating refresh; revocation/introspection для sensitive API.</li>
<li>Secret management; allowlist alg (лучше asymmetric); validate <code>iss</code>/<code>aud</code>/<code>exp</code>/<code>nbf</code>.</li>
<li>Adaptive rate limit, lockout/step-up, MFA; anti-stuffing по device/IP signals.</li>
<li>Секреты не в URL; Authorization header и secure storage на клиенте.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API2 Broken Authentication</strong>.</li>
<li>Credential stuffing: массовый abuse login/token API без throttling (широко документирован).</li>
<li>JWT/OAuth misconfig: public research и HackerOne-style отчёты о weak secrets, <code>alg=none</code>, token leakage.</li>
</ul>`,
      practice: 'auth',
      flag: 'FLAG{api2_broken_auth_token}',
      points: 10,
    },
    {
      id: 'API3',
      title_en: 'Broken Object Property Level Authorization',
      title_ru: 'Нарушение авторизации на уровне свойств объекта',
      risk: 'HIGH',
      cwe: 'CWE-915',
      theory_en: `<h3>What breaks</h3>
<p><strong>Broken Object Property Level Authorization</strong> sits between BOLA and BFLA: the user may access the object, but not every <em>property</em>. Two faces: <strong>mass assignment</strong> (client writes sensitive fields such as <code>role</code>, <code>isAdmin</code>, <code>price</code>, <code>balance</code> on POST/PATCH) and <strong>excessive data exposure</strong> (API returns internal fields like <code>ssn</code>, <code>isInternal</code>, hashed secrets, or cost markup that the UI simply “hides”).</p>
<p>Frameworks that bind JSON straight to ORM models make this especially common: extra properties are accepted silently if the server does not allowlist inputs and shape responses per role.</p>
<h3>Real-world / known patterns</h3>
<ul>
<li>Uber-style and similar mass-assignment patterns: public discussions of privilege fields accepted from client JSON in ride/profile APIs (class of bug, not a single CVE narrative).</li>
<li>Rails/ASP.NET/Node “bind the whole body” anti-patterns repeatedly appear in bug-bounty writeups as role/price elevation.</li>
<li>Mobile apps that strip fields in the UI while the API still returns full user or order objects — classic excessive exposure.</li>
</ul>
<h3>How to practice / test (authorized only)</h3>
<ul>
<li><strong>Offline lab:</strong> PATCH profile JSON and inject <code>"role":"admin"</code> (or similar) beyond the intended name field.</li>
<li><strong>Generic pentest:</strong> compare documented schema vs actual response; add unexpected properties; fuzz nested objects; check GraphQL field suggestions and introspection.</li>
<li>Diff list vs detail vs admin responses; look for hidden financial, PII, or feature-flag properties.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Server-side allowlist of writable properties; never bind raw request bodies to persistence models.</li>
<li>Separate request/response DTOs per use case and role; omit sensitive fields by default.</li>
<li>Authorization checks at property level for privileged attributes; schema validation (OpenAPI/JSON Schema) enforced at the gateway or app layer.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API3 Broken Object Property Level Authorization</strong>.</li>
<li>Mass assignment class: Uber-style / framework auto-bind privilege elevation patterns in public research.</li>
<li>Excessive data exposure: mobile API responses shipping full objects while UI hides fields — common bug-bounty theme.</li>
</ul>`,
      theory_ru: `<h3>Что ломается</h3>
<p><strong>Broken Object Property Level Authorization</strong> — между BOLA и BFLA: доступ к объекту есть, но не ко всем <em>свойствам</em>. Две стороны: <strong>mass assignment</strong> (клиент пишет <code>role</code>, <code>isAdmin</code>, <code>price</code>, <code>balance</code> в POST/PATCH) и <strong>excessive data exposure</strong> (API отдаёт <code>ssn</code>, <code>isInternal</code>, hash secrets, markup — UI лишь «прячет»).</p>
<p>Особенно часто, когда JSON напрямую биндится в ORM: лишние поля принимаются, если нет allowlist входа и DTO по ролям на выходе.</p>
<h3>Реальный мир / известные паттерны</h3>
<ul>
<li>Uber-style mass assignment: публичные обсуждения privilege-полей из client JSON в ride/profile API (класс бага, не один CVE-нарратив).</li>
<li>Rails/ASP.NET/Node «bind whole body» — частый bug-bounty сюжет elevation role/price.</li>
<li>Mobile apps: UI скрывает поля, API отдаёт полный user/order — classic excessive exposure.</li>
</ul>
<h3>Как практиковать / тестировать (только authorized)</h3>
<ul>
<li><strong>Offline lab:</strong> PATCH profile и inject <code>"role":"admin"</code> сверх name.</li>
<li><strong>Generic pentest:</strong> schema vs real response; unexpected properties; nested objects; GraphQL suggestions/introspection.</li>
<li>Diff list vs detail vs admin; ищи financial/PII/feature-flag поля.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Allowlist writable properties; не биндить raw body в persistence model.</li>
<li>Отдельные request/response DTO по use case и роли; sensitive fields omit by default.</li>
<li>Property-level authz; schema validation (OpenAPI/JSON Schema) на gateway или app.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API3 Broken Object Property Level Authorization</strong>.</li>
<li>Mass assignment: Uber-style / framework auto-bind elevation в public research.</li>
<li>Excessive data exposure: mobile API отдаёт full objects при «скрытом» UI — частая bug-bounty тема.</li>
</ul>`,
      practice: 'mass',
      flag: 'FLAG{api3_mass_assignment}',
      points: 10,
    },
    {
      id: 'API4',
      title_en: 'Unrestricted Resource Consumption',
      title_ru: 'Неограниченное потребление ресурсов',
      risk: 'HIGH',
      cwe: 'CWE-770',
      theory_en: `<h3>What breaks</h3>
<p><strong>Unrestricted Resource Consumption</strong> means the API lets a client consume CPU, memory, bandwidth, storage, or paid third-party quota without meaningful bounds. Examples: no or weak rate limits; <code>limit=999999</code> pagination; nested GraphQL queries that explode joins; batch endpoints without max items; file uploads without size/type caps; SMS/email/ML inference endpoints that bill per call; unbounded zip/PDF generation.</p>
<p>Outcome is not only classical DoS: cloud bills and partner API costs can spike (economic denial of sustainability).</p>
<h3>Real-world / known patterns</h3>
<ul>
<li>Public cloud cost-abuse stories: attackers trigger expensive SMS, translation, or AI inference APIs via open or weakly keyed endpoints.</li>
<li>GraphQL “query of death” / alias batching patterns widely documented in security research.</li>
<li>Export and report APIs that accept arbitrary date ranges or full-table dumps without pagination caps — classic of enterprise bug bounty.</li>
</ul>
<h3>How to practice / test (authorized only)</h3>
<ul>
<li><strong>Offline lab:</strong> fire a burst of requests (≥50) and see if the simulator ever returns 429 — here unlimited consumption wins the flag.</li>
<li><strong>Generic pentest:</strong> raise page size, nest GraphQL, flood batch/import, probe upload limits; watch latency and error rates (within scope, avoid real production harm).</li>
<li>Map which endpoints hit paid providers and try amplification with minimal client work.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Per-IP, per-user, and per-API-key rate limits; soft and hard quotas with clear 429 semantics.</li>
<li>Max page size, max batch length, GraphQL depth/complexity/cost analysis, timeouts and circuit breakers.</li>
<li>Upload size/MIME checks; async jobs with queue limits; budget alerts on cloud spend for sensitive integrations.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API4 Unrestricted Resource Consumption</strong>.</li>
<li>GraphQL complexity / alias abuse class: public research on “query of death” patterns.</li>
<li>Cloud cost abuse: SMS/email/AI inference endpoints without quotas — documented economic DoS class.</li>
</ul>`,
      theory_ru: `<h3>Что ломается</h3>
<p><strong>Unrestricted Resource Consumption</strong> — API позволяет без разумных границ тратить CPU, память, bandwidth, storage или платные third-party квоты. Примеры: нет/слабый rate limit; <code>limit=999999</code>; nested GraphQL «взрыв» joins; batch без max items; upload без size/type; SMS/email/ML inference «за клик»; безграничная генерация zip/PDF.</p>
<p>Итог — не только classical DoS: облачный счёт и partner API costs (economic denial of sustainability).</p>
<h3>Реальный мир / известные паттерны</h3>
<ul>
<li>Cloud cost-abuse: дорогие SMS, translation, AI inference через открытые/слабо ключённые endpoints.</li>
<li>GraphQL «query of death» / alias batching — широко в security research.</li>
<li>Export/report API с произвольными date ranges или full dump без pagination — enterprise bug bounty classic.</li>
</ul>
<h3>Как практиковать / тестировать (только authorized)</h3>
<ul>
<li><strong>Offline lab:</strong> burst ≥50 запросов; если нет 429 — unrestricted consumption → flag.</li>
<li><strong>Generic pentest:</strong> page size, nest GraphQL, batch/import flood, upload limits; latency/errors (в scope, без вреда production).</li>
<li>Карта endpoints на paid providers; amplification с минимальной работой клиента.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Rate limits per-IP/user/API-key; soft/hard quotas и понятный 429.</li>
<li>Max page size, max batch, GraphQL depth/complexity/cost, timeouts, circuit breakers.</li>
<li>Upload size/MIME; async jobs с лимитами очереди; budget alerts на cloud spend.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API4 Unrestricted Resource Consumption</strong>.</li>
<li>GraphQL complexity / alias abuse: public research «query of death».</li>
<li>Cloud cost abuse: SMS/email/AI inference без квот — economic DoS class.</li>
</ul>`,
      practice: 'rate',
      flag: 'FLAG{api4_rate_limit_bypass}',
      points: 8,
    },
    {
      id: 'API5',
      title_en: 'Broken Function Level Authorization',
      title_ru: 'Нарушение авторизации на уровне функций (BFLA)',
      risk: 'CRITICAL',
      cwe: 'CWE-285',
      theory_en: `<h3>What breaks</h3>
<p><strong>Broken Function Level Authorization (BFLA)</strong> is about <em>operations</em>, not single objects: a regular user can invoke admin or privileged functions — create users, export all data, change system config, hit <code>DELETE</code> where only <code>GET</code> was intended, or call <code>/internal</code> and <code>/admin</code> routes that the mobile app never shows. Unlike BOLA, the issue is “can this role call this function at all?”</p>
<p>Root causes: authorization only on the UI; missing checks on HTTP methods; different microservices with inconsistent RBAC; debug routes left enabled; GraphQL mutations exposed without role guards.</p>
<h3>Real-world / known patterns</h3>
<ul>
<li>Classic bug-bounty pattern: force-browse <code>/api/admin/*</code>, <code>/v1/management</code>, or alternate HTTP verbs after discovering paths in JS bundles or Swagger.</li>
<li>Privilege escalation via “hidden” admin APIs that rely on obscurity (no network ACL, only “security through UI”).</li>
<li>Partner/reseller portals where lower-tier roles still reach higher-tier report or provisioning endpoints.</li>
</ul>
<h3>How to practice / test (authorized only)</h3>
<ul>
<li><strong>Offline lab:</strong> with a user-role session, call paths such as <code>/api/admin/users</code> or export endpoints and see if they succeed.</li>
<li><strong>Generic pentest:</strong> map all verbs and routes from docs, clients, and gateway logs; replay privileged calls with low-privilege tokens; test role claims in JWT without server re-validation.</li>
<li>Try method override headers, version prefixes, and host-based admin APIs only within written scope.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Deny-by-default RBAC/ABAC on every sensitive operation server-side; never rely on client UI hiding.</li>
<li>Central policy engine; explicit role matrix; automated tests that low roles receive 403 on admin functions.</li>
<li>Network segmentation for true admin planes; remove debug/internal routes from public gateways.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API5 Broken Function Level Authorization</strong>.</li>
<li>Admin path force-browse class: typical HackerOne/Bugcrowd reports on <code>/admin</code> APIs reachable with user tokens.</li>
<li>Inconsistent microservice RBAC: public writeups where one service enforces roles and a sibling service does not.</li>
</ul>`,
      theory_ru: `<h3>Что ломается</h3>
<p><strong>Broken Function Level Authorization (BFLA)</strong> — про <em>операции</em>, не один object: обычный user вызывает admin/privileged functions — создать users, export all, system config, <code>DELETE</code> вместо <code>GET</code>, <code>/internal</code> и <code>/admin</code>, которых mobile app не показывает. В отличие от BOLA вопрос: «может ли эта роль вызвать функцию вообще?»</p>
<p>Причины: authz только в UI; нет checks на HTTP methods; разный RBAC в microservices; debug routes; GraphQL mutations без role guards.</p>
<h3>Реальный мир / известные паттерны</h3>
<ul>
<li>Bug-bounty classic: force-browse <code>/api/admin/*</code>, <code>/v1/management</code>, alternate verbs после discovery в JS/Swagger.</li>
<li>Privilege escalation через «скрытые» admin API (security through obscurity/UI).</li>
<li>Partner/reseller порталы: lower-tier роли доходят до higher-tier report/provisioning.</li>
</ul>
<h3>Как практиковать / тестировать (только authorized)</h3>
<ul>
<li><strong>Offline lab:</strong> user-role session → <code>/api/admin/users</code> или export; успех = BFLA.</li>
<li><strong>Generic pentest:</strong> карта verbs/routes из docs/clients/logs; replay privileged calls low-priv token; JWT role claims без server re-check.</li>
<li>Method override, version prefixes, host-based admin — только в written scope.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Deny-by-default RBAC/ABAC на каждую sensitive operation; не полагаться на UI.</li>
<li>Central policy; role matrix; автотесты 403 для low roles на admin functions.</li>
<li>Сегментация admin plane; убрать debug/internal с public gateway.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API5 Broken Function Level Authorization</strong>.</li>
<li>Admin force-browse: типичные HackerOne/Bugcrowd отчёты о <code>/admin</code> API с user token.</li>
<li>Несогласованный RBAC microservices: writeup’ы, где один сервис проверяет роли, соседний — нет.</li>
</ul>`,
      practice: 'bfla',
      flag: 'FLAG{api5_bfla_admin}',
      points: 10,
    },
    {
      id: 'API6',
      title_en: 'Unrestricted Access to Sensitive Business Flows',
      title_ru: 'Неограниченный доступ к чувствительным бизнес-потокам',
      risk: 'HIGH',
      cwe: 'CWE-841',
      theory_en: `<h3>What breaks</h3>
<p><strong>Unrestricted Access to Sensitive Business Flows</strong> targets legitimate, working endpoints that implement high-value business processes — ticket purchase, coupon redeem, referral rewards, voting, reservation, passwordless login spam — but lack anti-automation and fair-use controls. Auth may be correct and rate limits per second weak or absent; the business logic still allows bots to exhaust inventory, farm bonuses, or distort markets.</p>
<p>This is not pure technical DoS (API4) and not classic BOLA: the “bug” is missing product-level abuse prevention on flows that must remain available to humans.</p>
<h3>Real-world / known patterns</h3>
<ul>
<li>Concert/ticket scalping bots: widely reported automation against purchase and hold APIs.</li>
<li>Coupon, cashback, and referral abuse: multi-account farming documented across e-commerce and fintech bounty programs.</li>
<li>Limited drops (sneakers, GPUs, NFT mint-style flows): public discussions of scripted checkout APIs bypassing soft client checks.</li>
</ul>
<h3>How to practice / test (authorized only)</h3>
<ul>
<li><strong>Offline lab:</strong> redeem a coupon many times (≥20) without progressive friction — if all succeed, the business flow is unrestricted.</li>
<li><strong>Generic pentest:</strong> script multi-step flows; parallelize holds/checkouts; create many accounts if in scope; measure whether risk signals kick in.</li>
<li>Identify “money or inventory” steps and test idempotency, one-time tokens, and concurrency races — carefully, without real fraud.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Per-account and per-payment-method caps; device binding; progressive delays and CAPTCHA/step-up on risk scores.</li>
<li>Server-side inventory locks, one-time redeem tokens, strong identity proofing for high-value flows.</li>
<li>Fraud/risk engines: velocity rules, graph analysis of accounts, anomaly alerts — layered with technical rate limits.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API6 Unrestricted Access to Sensitive Business Flows</strong>.</li>
<li>Ticket scalping / bot checkout class: public reporting on automated purchase APIs.</li>
<li>Coupon &amp; referral farming: recurring e-commerce/fintech bug-bounty and fraud-ops theme.</li>
</ul>`,
      theory_ru: `<h3>Что ломается</h3>
<p><strong>Unrestricted Access to Sensitive Business Flows</strong> — легитимные high-value процессы (покупка билета, redeem купона, referral, голосование, reservation, spam passwordless login) без anti-automation и fair-use. Auth может быть «правильным», rate limit слабым: боты выгребают inventory, фармят бонусы, искажают рынок.</p>
<p>Это не pure technical DoS (API4) и не классический BOLA: «баг» — отсутствие product-level abuse prevention на flow, который должен оставаться доступен людям.</p>
<h3>Реальный мир / известные паттерны</h3>
<ul>
<li>Concert/ticket scalping bots: широко освещаемая автоматизация purchase/hold API.</li>
<li>Coupon, cashback, referral abuse: multi-account farming в e-commerce/fintech bounty.</li>
<li>Limited drops (sneakers, GPU, NFT mint-style): scripted checkout, обход soft client checks.</li>
</ul>
<h3>Как практиковать / тестировать (только authorized)</h3>
<ul>
<li><strong>Offline lab:</strong> redeem купона ≥20 раз без friction — если всё accepted, flow unrestricted.</li>
<li><strong>Generic pentest:</strong> скрипт multi-step; параллельные hold/checkout; multi-account в scope; риск-сигналы.</li>
<li>Шаги «деньги/inventory»: idempotency, one-time tokens, concurrency races — без real fraud.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Caps per account/payment method; device binding; progressive delay и CAPTCHA/step-up по risk score.</li>
<li>Server-side inventory locks, one-time redeem, strong identity для high-value flows.</li>
<li>Fraud/risk engine: velocity, graph accounts, anomaly alerts + technical rate limits.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API6 Unrestricted Access to Sensitive Business Flows</strong>.</li>
<li>Ticket scalping / bot checkout: публичные материалы об automated purchase API.</li>
<li>Coupon &amp; referral farming: повторяющаяся тема e-commerce/fintech bounty и fraud-ops.</li>
</ul>`,
      practice: 'flow',
      flag: 'FLAG{api6_business_flow}',
      points: 8,
    },
    {
      id: 'API7',
      title_en: 'Server Side Request Forgery',
      title_ru: 'Подделка серверных запросов (SSRF)',
      risk: 'HIGH',
      cwe: 'CWE-918',
      theory_en: `<h3>What breaks</h3>
<p><strong>Server-Side Request Forgery (SSRF)</strong> in APIs appears when a feature accepts a URL or host (webhook, import-from-URL, preview, avatar fetch, PDF renderer, integration callback) and the <em>server</em> performs the HTTP(S) request. Attackers point it at internal networks, cloud metadata endpoints such as <code>http://169.254.169.254/</code>, localhost admin panels, or secondary cloud services.</p>
<p>API gateways and microservices increase blast radius: one “fetch URL” helper can reach Kubernetes/Docker internal DNS, Redis, or IMDS credentials that never face the public Internet.</p>
<h3>Real-world / known patterns</h3>
<ul>
<li>Capital One–class cloud SSRF to instance metadata: publicly analyzed case of SSRF-style access leading to cloud credential abuse (educational reference for the pattern).</li>
<li>Webhook and “import URL” endpoints in SaaS: frequent bug-bounty SSRF class against internal hosts and link-local addresses.</li>
<li>PDF/image converters and URL preview bots: classic secondary SSRF vectors documented across research blogs.</li>
</ul>
<h3>How to practice / test (authorized only)</h3>
<ul>
<li><strong>Offline lab:</strong> submit the IMDS-style URL <code>http://169.254.169.254/latest/meta-data/</code> (or lab equivalent) to the webhook fetcher and observe internal response simulation.</li>
<li><strong>Generic pentest:</strong> try loopback, RFC1918, link-local, DNS rebinding, redirect chains, alternate IP encodings; only on authorized systems.</li>
<li>Map all server-side fetch features from OpenAPI and client code; treat file:// and gopher-like schemes as high risk if parsers allow them.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Allowlist destination hosts/schemes; block link-local, loopback, private ranges after DNS resolution (not only string filters).</li>
<li>Disable or tightly control redirects; enforce timeouts and response size limits; network egress policies from app pods.</li>
<li>Cloud: require IMDSv2 (session tokens), restrict metadata hop limits; prefer signed uploads over server fetch-from-URL where possible.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API7 Server Side Request Forgery</strong>.</li>
<li>Capital One–class SSRF → cloud metadata credential pattern (public post-incident analyses).</li>
<li>Webhook/import-URL SSRF class: recurring SaaS bug-bounty theme against 169.254.169.254 and internal hosts.</li>
</ul>`,
      theory_ru: `<h3>Что ломается</h3>
<p><strong>Server-Side Request Forgery (SSRF)</strong> в API — когда фича принимает URL/host (webhook, import-from-URL, preview, avatar, PDF renderer, callback), а <em>сервер</em> сам ходит по HTTP(S). Атакующий целится во internal networks, cloud metadata <code>http://169.254.169.254/</code>, localhost admin, secondary cloud services.</p>
<p>Gateway и microservices увеличивают blast radius: один helper «fetch URL» достаёт Kubernetes/Docker DNS, Redis или IMDS credentials, которых нет в public Internet.</p>
<h3>Реальный мир / известные паттерны</h3>
<ul>
<li>Capital One–class cloud SSRF к instance metadata: публично разобранный кейс SSRF-style доступа и abuse cloud credentials (учебный паттерн).</li>
<li>Webhook и «import URL» в SaaS: частый bug-bounty SSRF на internal hosts и link-local.</li>
<li>PDF/image converters и URL preview bots: классические secondary SSRF в research blogs.</li>
</ul>
<h3>Как практиковать / тестировать (только authorized)</h3>
<ul>
<li><strong>Offline lab:</strong> IMDS-style URL <code>http://169.254.169.254/latest/meta-data/</code> в webhook fetcher — симуляция internal response.</li>
<li><strong>Generic pentest:</strong> loopback, RFC1918, link-local, DNS rebinding, redirect chains, alternate IP encodings — только authorized.</li>
<li>Карта server-side fetch из OpenAPI/client code; file:// и gopher-like schemes — high risk.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Allowlist hosts/schemes; block link-local/loopback/private <strong>после</strong> DNS resolve (не только string filter).</li>
<li>Контроль redirects; timeouts и size limits; egress policies из app pods.</li>
<li>Cloud: IMDSv2, hop limit; предпочитать signed upload вместо server fetch-from-URL.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API7 Server Side Request Forgery</strong>.</li>
<li>Capital One–class SSRF → cloud metadata credentials (public post-incident analyses).</li>
<li>Webhook/import-URL SSRF: recurring SaaS bug-bounty тема к 169.254.169.254 и internal hosts.</li>
</ul>`,
      practice: 'ssrf',
      flag: 'FLAG{api7_ssrf_metadata}',
      points: 10,
    },
    {
      id: 'API8',
      title_en: 'Security Misconfiguration',
      title_ru: 'Неправильная конфигурация безопасности',
      risk: 'HIGH',
      cwe: 'CWE-16',
      theory_en: `<h3>What breaks</h3>
<p><strong>Security Misconfiguration</strong> for APIs includes unsafe defaults and incomplete hardening across gateways, frameworks, and runtimes: open or wildcard CORS; verbose stack traces and debug modes in production; unauthenticated Swagger/OpenAPI/GraphQL playgrounds; default credentials and sample API keys; unnecessary HTTP methods (TRACE, OPTIONS abuse); missing security headers; overly broad cloud IAM on the API service account; TLS/cipher weakness at the edge.</p>
<p>Misconfiguration often multiplies other risks: open docs reveal all BOLA targets; verbose errors leak internal hosts for SSRF pivots.</p>
<h3>Real-world / known patterns</h3>
<ul>
<li>Open Swagger/OpenAPI and GraphQL playgrounds on the public Internet — extremely common reconnaissance finding.</li>
<li>Wildcard CORS with credentialed requests enabling cross-origin token abuse patterns discussed in public research.</li>
<li>Default keys and debug endpoints left from scaffolds (Spring, Express generators, cloud quickstarts).</li>
</ul>
<h3>How to practice / test (authorized only)</h3>
<ul>
<li><strong>Offline lab:</strong> request paths like <code>/swagger.json</code> without auth and observe whether full API inventory is exposed.</li>
<li><strong>Generic pentest:</strong> probe docs paths (<code>/swagger</code>, <code>/api-docs</code>, <code>/graphql</code>), CORS preflights, error verbosity, default creds on staging hosts in scope, security headers, and HTTP method matrices.</li>
<li>Review gateway and K8s ingress configs for open management ports and debug sidecars.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Harden API gateway: deny by default, explicit CORS origins, disable unused methods, enforce TLS.</li>
<li>Authenticate and network-restrict documentation and playgrounds; strip stack traces in production.</li>
<li>Rotate default secrets; least-privilege service accounts; configuration baselines and automated CIS-style checks in CI.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API8 Security Misconfiguration</strong>.</li>
<li>Open Swagger / unauthenticated API docs: ubiquitous public recon and bug-bounty finding.</li>
<li>Wildcard CORS + credentials class: publicly discussed browser-based API abuse patterns.</li>
</ul>`,
      theory_ru: `<h3>Что ломается</h3>
<p><strong>Security Misconfiguration</strong> для API — небезопасные defaults и неполный hardening gateway/frameworks/runtime: open/wildcard CORS; stack traces и debug в production; Swagger/OpenAPI/GraphQL playground без auth; default credentials и sample keys; лишние HTTP methods (TRACE); нет security headers; слишком широкий cloud IAM; слабый TLS на edge.</p>
<p>Misconfig умножает другие риски: open docs показывают цели BOLA; verbose errors светят internal hosts для SSRF.</p>
<h3>Реальный мир / известные паттерны</h3>
<ul>
<li>Открытые Swagger/OpenAPI и GraphQL playground в public Internet — крайне частый recon finding.</li>
<li>Wildcard CORS с credentials — cross-origin abuse паттерны в public research.</li>
<li>Default keys и debug endpoints из scaffolds (Spring, Express, cloud quickstarts).</li>
</ul>
<h3>Как практиковать / тестировать (только authorized)</h3>
<ul>
<li><strong>Offline lab:</strong> <code>/swagger.json</code> без auth — полная inventory API?</li>
<li><strong>Generic pentest:</strong> docs paths, CORS preflight, error verbosity, default creds на staging в scope, headers, method matrix.</li>
<li>Gateway/K8s ingress: open management ports, debug sidecars.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Харденинг gateway: deny by default, explicit CORS, disable unused methods, TLS.</li>
<li>Auth + network restrict на docs/playground; без stack traces в production.</li>
<li>Ротация default secrets; least-privilege SA; baselines и CIS-style checks в CI.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API8 Security Misconfiguration</strong>.</li>
<li>Open Swagger / unauthenticated API docs: ubiquitous recon и bug-bounty finding.</li>
<li>Wildcard CORS + credentials: публично обсуждаемые browser-based API abuse patterns.</li>
</ul>`,
      practice: 'misconfig',
      flag: 'FLAG{api8_swagger_open}',
      points: 8,
    },
    {
      id: 'API9',
      title_en: 'Improper Inventory Management',
      title_ru: 'Некорректное управление инвентарём API',
      risk: 'MEDIUM',
      cwe: 'CWE-1059',
      theory_en: `<h3>What breaks</h3>
<p><strong>Improper Inventory Management</strong> means the organization does not know which APIs, versions, and hosts are live. Shadow and zombie APIs (undocumented microservices, forgotten <code>/v1</code> after <code>/v2</code> rollout, staging hosts on the public Internet, partner-only endpoints reused broadly) stay unpatched while the “official” surface is hardened. Attackers discover old paths via historical JS, DNS, certificates, and gateway misroutes.</p>
<p>Without inventory you cannot consistently apply authz, logging, or rate limits — every other OWASP API category fails in the dark.</p>
<h3>Real-world / known patterns</h3>
<ul>
<li>Shadow <code>/v1</code> APIs left online after security fixes only landed on <code>/v2</code> — classic post-incident and bounty pattern.</li>
<li>Parler API scraping discussions: public commentary on poorly controlled, highly enumerable API surfaces and data harvest at scale (inventory + exposure class).</li>
<li>Forgotten staging/debug hosts and “temporary” admin APIs discovered via certificate transparency and subdomain recon.</li>
</ul>
<h3>How to practice / test (authorized only)</h3>
<ul>
<li><strong>Offline lab:</strong> compare documented current routes with a still-live legacy <code>/v1</code> path that retains weaker controls.</li>
<li><strong>Generic pentest:</strong> version fuzzing (<code>/v1</code>…<code>/v3</code>), alternate hosts, historical mobile app traffic, OpenAPI drift vs live behavior; map shadow routes within scope.</li>
<li>Cross-check gateway configs, service mesh inventories, and cloud load balancers for orphan targets.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Authoritative API inventory and schema registry; every endpoint owned and versioned.</li>
<li>Deprecation policy with hard sunsets; force traffic through a single controlled gateway.</li>
<li>Continuous discovery (traffic analysis, code scan, external recon of your own assets); retire zombies quickly.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API9 Improper Inventory Management</strong>.</li>
<li>Shadow/zombie <code>/v1</code> vs patched <code>/v2</code> class: recurring public bounty theme.</li>
<li>Parler-style mass API enumeration/scraping discussions: uncontrolled API surface + weak inventory/exposure controls.</li>
</ul>`,
      theory_ru: `<h3>Что ломается</h3>
<p><strong>Improper Inventory Management</strong> — организация не знает, какие API, версии и hosts живы. Shadow/zombie API (undocumented microservices, забытый <code>/v1</code> после <code>/v2</code>, staging в public Internet, partner endpoints «на всех») остаются unpatched, пока «официальная» поверхность hardened. Атакующие находят старые path через historical JS, DNS, certificates, gateway misroutes.</p>
<p>Без inventory нельзя стабильно применять authz, logging, rate limits — остальные категории OWASP API ломаются «в темноте».</p>
<h3>Реальный мир / известные паттерны</h3>
<ul>
<li>Shadow <code>/v1</code> online, фиксы только на <code>/v2</code> — classic post-incident и bounty.</li>
<li>Parler API scraping: публичные обсуждения слабо контролируемой enumerable API-поверхности и mass harvest (inventory + exposure class).</li>
<li>Forgotten staging/debug и «временные» admin API через CT logs и subdomain recon.</li>
</ul>
<h3>Как практиковать / тестировать (только authorized)</h3>
<ul>
<li><strong>Offline lab:</strong> documented routes vs live legacy <code>/v1</code> со слабыми controls.</li>
<li><strong>Generic pentest:</strong> version fuzz (<code>/v1</code>…<code>/v3</code>), alternate hosts, traffic старых mobile apps, OpenAPI drift; shadow routes в scope.</li>
<li>Сверка gateway, service mesh inventory, cloud LB на orphan targets.</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Authoritative inventory + schema registry; каждый endpoint с owner и version.</li>
<li>Deprecation policy с hard sunset; весь traffic через controlled gateway.</li>
<li>Continuous discovery (traffic, code scan, external recon своих assets); быстрый retire zombies.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API9 Improper Inventory Management</strong>.</li>
<li>Shadow/zombie <code>/v1</code> vs patched <code>/v2</code>: recurring public bounty theme.</li>
<li>Parler-style mass enumeration/scraping: uncontrolled surface + weak inventory/exposure.</li>
</ul>`,
      practice: 'inventory',
      flag: 'FLAG{api9_shadow_v1}',
      points: 8,
    },
    {
      id: 'API10',
      title_en: 'Unsafe Consumption of APIs',
      title_ru: 'Небезопасное потребление внешних API',
      risk: 'MEDIUM',
      cwe: 'CWE-20',
      theory_en: `<h3>What breaks</h3>
<p><strong>Unsafe Consumption of APIs</strong> flips the trust model: <em>your</em> service is the client of third-party or partner APIs and treats their responses as fully trusted. Risks include injecting upstream JSON/XML into SQL, HTML, or commands; following malicious redirects; accepting oversized or unexpected schemas; storing unvalidated files; weak TLS validation to the integration; and cascading failures when a dependency is compromised or spoofed.</p>
<p>Supply-chain style API abuse and compromised SaaS integrations turn “we only call trusted vendors” into an incident inside your perimeter.</p>
<h3>Real-world / known patterns</h3>
<ul>
<li>Third-party widget/API compromise: public incidents where integrated services delivered malicious payloads to consumers who rendered them unsafely.</li>
<li>Webhook and partner feed injection: attackers who control or MITM an upstream shape responses that break parsers or trigger SSRF/XSS downstream.</li>
<li>Blind trust of payment, KYC, or shipping callback bodies without signature verification — recurring fintech/e-commerce finding class.</li>
</ul>
<h3>How to practice / test (authorized only)</h3>
<ul>
<li><strong>Offline lab:</strong> feed the consumer a malicious or oversized partner-style payload and see whether it is validated or blindly processed (lab simulation).</li>
<li><strong>Generic pentest / design review:</strong> map outbound integrations; try schema deviations, unexpected types, redirect targets, and content-type confusion on staging doubles; verify signature and mTLS requirements.</li>
<li>Chaos: timeout and error handling — do failures fail closed with safe defaults?</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Treat all upstream data as untrusted: schema validation, size limits, allowlists, output encoding before use in SQL/HTML/commands.</li>
<li>Enforce TLS correctly; consider certificate pinning or mTLS for critical partners; verify webhook signatures and timestamps.</li>
<li>Timeouts, circuit breakers, least-privilege credentials per integration; monitor anomalous upstream content.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API10 Unsafe Consumption of APIs</strong>.</li>
<li>Compromised third-party script/API class: public supply-chain incidents affecting consumers who trusted integrations.</li>
<li>Unsigned webhook/callback consumption: common fintech &amp; e-commerce vulnerability class in public writeups.</li>
</ul>`,
      theory_ru: `<h3>Что ломается</h3>
<p><strong>Unsafe Consumption of APIs</strong> переворачивает trust model: <em>ваш</em> сервис — клиент third-party/partner API и слепо доверяет ответам. Риски: upstream JSON/XML → SQL/HTML/commands; malicious redirects; oversized/unexpected schema; unvalidated files; слабая TLS-проверка; cascade, когда dependency скомпрометирован или spoofed.</p>
<p>Supply-chain API abuse и компрометация SaaS-интеграций превращают «мы ходим только к trusted vendors» в инцидент внутри периметра.</p>
<h3>Реальный мир / известные паттерны</h3>
<ul>
<li>Compromise third-party widget/API: публичные инциденты, где интеграция отдавала malicious payload потребителям без safe render.</li>
<li>Webhook и partner feed injection: control/MITM upstream → parser break, SSRF/XSS downstream.</li>
<li>Слепое доверие payment/KYC/shipping callback без signature — recurring fintech/e-commerce class.</li>
</ul>
<h3>Как практиковать / тестировать (только authorized)</h3>
<ul>
<li><strong>Offline lab:</strong> malicious/oversized partner-style payload — validate или blind process (симуляция).</li>
<li><strong>Generic pentest / design review:</strong> карта outbound integrations; schema deviations, unexpected types, redirects, content-type confusion на staging doubles; signature/mTLS.</li>
<li>Chaos: timeout/errors — fail closed с safe defaults?</li>
</ul>
<h3>Fix / mitigations</h3>
<ul>
<li>Upstream = untrusted: schema validation, size limits, allowlists, output encoding перед SQL/HTML/commands.</li>
<li>Корректный TLS; pin/mTLS для critical partners; verify webhook signatures и timestamps.</li>
<li>Timeouts, circuit breakers, least-privilege creds per integration; мониторинг anomalous upstream content.</li>
</ul>
<h3>Live cases / public references</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API10 Unsafe Consumption of APIs</strong>.</li>
<li>Compromised third-party script/API: public supply-chain incidents для доверчивых consumers.</li>
<li>Unsigned webhook/callback: common fintech &amp; e-commerce class в public writeups.</li>
</ul>`,
      practice: 'consume',
      flag: 'FLAG{api10_unsafe_consume}',
      points: 8,
    },
  ];

  function capture(id) {
    const it = ITEMS.find(x => x.id === id);
    if (!it) return;
    if (Store.hasChallenge(id)) {
      UI.toast(I18n.t('flagGot') + ': ' + it.flag, 'ok');
      return;
    }
    Store.setChallengeFlag(id, it.flag);
    UI.toast(I18n.t('flagCaptured') + ': ' + it.flag, 'ok');
    UI.route('api10', id);
  }

  function renderHub() {
    const en = I18n.lang() === 'en';
    return `
      <div class="hero">
        <div class="row mb8">
          <span class="tag tc">OWASP API</span>
          <span class="tag tb">2023</span>
          <span class="tag tm">offline sims</span>
        </div>
        <h1>${en ? 'API Security Top 10' : 'API Security Top 10'}</h1>
        <div class="theory">${en ? INTRO.en : INTRO.ru}</div>
        <div class="stat-grid">
          <div class="stat"><div class="n" style="color:var(--red)">10</div><div class="l">01–10</div></div>
          <div class="stat"><div class="n" style="color:var(--grn)">${ITEMS.filter(i => Store.hasChallenge(i.id)).length}</div><div class="l">${en?'Solved':'Решено'}</div></div>
          <div class="stat"><div class="n" style="color:var(--yel)">≈A01</div><div class="l">BOLA/BFLA</div></div>
          <div class="stat"><div class="n" style="color:var(--blu)">REST</div><div class="l">sim labs</div></div>
        </div>
      </div>
      <div class="g2">
        ${ITEMS.map(it => {
          const done = Store.hasChallenge(it.id);
          return `<button type="button" class="mod-card" style="text-align:left;width:100%;font:inherit;color:inherit;cursor:pointer"
            onclick="UI.route('api10','${it.id}')">
            <div class="top">
              <span class="code">${esc(numLabel(it.id))}</span>
              ${done ? '<span class="tag tm">✓</span>' : ''}
            </div>
            <h3>${esc(en ? it.title_en : it.title_ru)}</h3>
            <p class="small muted">${esc(it.cwe)}</p>
          </button>`;
        }).join('')}
      </div>`;
  }

  function practiceUI(it) {
    const en = I18n.lang() === 'en';
    const id = it.id;
    const p = it.practice;
    if (p === 'bola') {
      return `<div class="lab-frame"><div class="lab-chrome"><div class="dots"><span class="dot r"></span><span class="dot y"></span><span class="dot g"></span></div>
        <div class="url">GET /api/v1/invoices/{id}</div></div><div class="lab-body">
        <h3>BOLA lab</h3>
        <p class="muted">${en?'You are user 2. Try invoice ids.':'Ты user 2. Перебери invoice id.'}</p>
        <div class="field"><label>invoice id</label><input id="api-id" value="2002"></div>
        <button class="btn btnp" onclick="ApiTop10.tryBola('${id}')">GET</button>
        <div id="api-out"></div>
        <p class="muted small mt8">Hint: try <code class="inline">1001</code></p>
      </div></div>`;
    }
    if (p === 'auth') {
      return `<div class="lab-frame"><div class="lab-chrome"><div class="url">POST /oauth/token</div></div><div class="lab-body">
        <h3>${en?'Weak API token':'Слабый API token'}</h3>
        <div class="field"><label>client_secret</label><input id="api-sec" value="password"></div>
        <button class="btn btnp" onclick="ApiTop10.tryAuth('${id}')">token</button>
        <div id="api-out"></div>
        <p class="muted small mt8">lab secrets: password / secret / changeme</p>
      </div></div>`;
    }
    if (p === 'mass') {
      return `<div class="lab-frame"><div class="lab-chrome"><div class="url">PATCH /api/users/me</div></div><div class="lab-body">
        <h3>Mass assignment</h3>
        <div class="field"><label>JSON body</label>
          <textarea id="api-json" rows="4">{"name":"alice","role":"user"}</textarea></div>
        <button class="btn btnp" onclick="ApiTop10.tryMass('${id}')">PATCH</button>
        <div id="api-out"></div>
        <p class="muted small mt8">try <code class="inline">"role":"admin"</code></p>
      </div></div>`;
    }
    if (p === 'rate') {
      return `<div class="lab-frame"><div class="lab-body">
        <h3>${en?'No rate limit':'Нет rate limit'}</h3>
        <div class="field"><label>${en?'Burst requests':'Пачка запросов'}</label>
          <input id="api-n" type="number" value="5" min="1" max="500"></div>
        <button class="btn btnp" onclick="ApiTop10.tryRate('${id}')">fire</button>
        <div id="api-out"></div>
        <p class="muted small mt8">≥ 50 without 429 → flag</p>
      </div></div>`;
    }
    if (p === 'bfla') {
      return `<div class="lab-frame"><div class="lab-chrome"><div class="url">role=user session</div></div><div class="lab-body">
        <h3>BFLA</h3>
        <div class="field"><label>path</label>
          <select id="api-path">
            <option value="/api/me">/api/me</option>
            <option value="/api/admin/users">/api/admin/users</option>
            <option value="/api/v1/export">/api/v1/export</option>
          </select></div>
        <button class="btn btnp" onclick="ApiTop10.tryBfla('${id}')">GET</button>
        <div id="api-out"></div>
      </div></div>`;
    }
    if (p === 'flow') {
      return `<div class="lab-frame"><div class="lab-body">
        <h3>${en?'Coupon redeem spam':'Спам redeem купона'}</h3>
        <div class="field"><label>redeems</label><input id="api-n" type="number" value="1" min="1" max="100"></div>
        <button class="btn btnp" onclick="ApiTop10.tryFlow('${id}')">redeem</button>
        <div id="api-out"></div>
        <p class="muted small">≥ 20 redeems accepted → business flow abuse</p>
      </div></div>`;
    }
    if (p === 'ssrf') {
      return `<div class="lab-frame"><div class="lab-body">
        <h3>SSRF webhook</h3>
        <div class="field"><label>url</label><input id="api-url" value="http://example.com"></div>
        <button class="btn" onclick="document.getElementById('api-url').value='http://169.254.169.254/latest/meta-data/'">IMDS</button>
        <button class="btn btnp" onclick="ApiTop10.trySsrf('${id}')">fetch</button>
        <div id="api-out"></div>
      </div></div>`;
    }
    if (p === 'misconfig') {
      return `<div class="lab-frame"><div class="lab-body">
        <h3>Open API docs</h3>
        <div class="field"><label>path</label>
          <select id="api-path">
            <option value="/health">/health</option>
            <option value="/swagger.json">/swagger.json</option>
            <option value="/graphql">/graphql</option>
          </select></div>
        <button class="btn btnp" onclick="ApiTop10.tryMisc('${id}')">GET</button>
        <div id="api-out"></div>
      </div></div>`;
    }
    if (p === 'inventory') {
      return `<div class="lab-frame"><div class="lab-body">
        <h3>${en?'Old API version':'Старая версия API'}</h3>
        <div class="field"><label>version</label>
          <select id="api-ver"><option value="v2">/v2/users</option><option value="v1">/v1/users</option></select></div>
        <button class="btn btnp" onclick="ApiTop10.tryInv('${id}')">GET</button>
        <div id="api-out"></div>
        <p class="muted small">v1 still returns password hashes</p>
      </div></div>`;
    }
    return `<div class="lab-frame"><div class="lab-body">
      <h3>${en?'Unsafe upstream JSON':'Небезопасный upstream JSON'}</h3>
      <div class="field"><label>upstream body</label>
        <textarea id="api-up" rows="3">{"name":"ok","html":"&lt;img src=x onerror=alert(1)&gt;"}</textarea></div>
      <button class="btn btnp" onclick="ApiTop10.tryConsume('${id}')">import</button>
      <div id="api-out"></div>
      <p class="muted small">include script/onerror in upstream field</p>
    </div></div>`;
  }

  function out(msg, ok) {
    const el = document.getElementById('api-out');
    if (el) el.innerHTML = `<div class="resp ${ok?'ok':'err'}">${msg}</div>`;
  }

  function tryBola(id) {
    const v = document.getElementById('api-id')?.value;
    if (v === '1001' || v === '1') {
      out('200 OK — invoice of user 1 (admin) leaked to user 2\nFLAG path open', true);
      capture(id);
    } else out('200 — your own invoice only', false);
  }
  function tryAuth(id) {
    const s = document.getElementById('api-sec')?.value || '';
    if (/^(password|secret|changeme)$/i.test(s)) {
      out('{"access_token":"eyJlab...","token_type":"bearer"}', true);
      capture(id);
    } else out('401 invalid_client', false);
  }
  function tryMass(id) {
    const j = document.getElementById('api-json')?.value || '';
    if (/role\s*"?\s*:\s*"?admin/i.test(j)) {
      out('200 {"role":"admin"} — mass assignment accepted', true);
      capture(id);
    } else out('200 {"role":"user"} — try setting role', false);
  }
  function tryRate(id) {
    const n = +document.getElementById('api-n')?.value;
    if (n >= 50) { out(`Accepted ${n} requests, 0×429 — unrestricted consumption`, true); capture(id); }
    else out(`n=${n} still under noisy threshold; try ≥50`, false);
  }
  function tryBfla(id) {
    const p = document.getElementById('api-path')?.value;
    if (/admin/i.test(p)) { out('200 admin user list (role=user session!)', true); capture(id); }
    else out('200 profile — try admin path', false);
  }
  function tryFlow(id) {
    const n = +document.getElementById('api-n')?.value;
    if (n >= 20) { out(`${n} coupon redeems OK — no anti-automation`, true); capture(id); }
    else out(`${n} redeems ok; spam more (≥20)`, false);
  }
  function trySsrf(id) {
    const u = document.getElementById('api-url')?.value || '';
    if (/169\.254|metadata|127\.0\.0\.1|localhost/i.test(u)) {
      out(`Server fetched ${esc(u)}\nami-id / credentials path visible`, true);
      capture(id);
    } else out('Fetched external URL only', false);
  }
  function tryMisc(id) {
    const p = document.getElementById('api-path')?.value;
    if (/swagger|openapi/i.test(p)) {
      out('200 swagger.json — full unauthenticated schema + internal hosts', true);
      capture(id);
    } else out('200 ok — try swagger path', false);
  }
  function tryInv(id) {
    const v = document.getElementById('api-ver')?.value;
    if (v === 'v1') {
      out('200 /v1/users — includes password_hash fields (shadow API)', true);
      capture(id);
    } else out('200 /v2/users — sanitized DTO', false);
  }
  function tryConsume(id) {
    const u = document.getElementById('api-up')?.value || '';
    if (/onerror|script|javascript:/i.test(u)) {
      out('Upstream HTML reflected into UI without sanitization', true);
      capture(id);
    } else out('Import ok — inject XSS-like field from partner API', false);
  }

  function renderItem(id) {
    const it = ITEMS.find(x => x.id === id);
    if (!it) return `<div class="card"><div class="cb">Not found</div></div>`;
    const en = I18n.lang() === 'en';
    const done = Store.hasChallenge(id);
    return `
      <div class="lab-page">
        <div class="row mb12">
          <button class="btn" onclick="UI.route('apihub')">← API Top 10</button>
          <button class="btn" onclick="UI.route('lab','A01')">${en?'Related web A01':'Связанный A01'}</button>
        </div>
        <div class="card lab-card">
          <div class="ch lab-header">
            <div class="lab-title">
              <span class="lab-code">${esc(numLabel(it.id))}</span>
              <div>
                <h2>${esc(en ? it.title_en : it.title_ru)}</h2>
                <div class="lab-sub">${esc(it.cwe)}</div>
              </div>
            </div>
            ${done ? '<span class="tag tm">FLAG ✓</span>' : ''}
          </div>
          <div class="tabs" id="api-tabs">
            <button class="tab active" data-tab="theory">${en?'Theory':'Теория'}</button>
            <button class="tab" data-tab="lab">${en?'Practice':'Практика'}</button>
          </div>
          <div class="tabpane active" id="tp-theory">
            <div class="theory-wrap">
              <div class="theory">${en ? it.theory_en : it.theory_ru}</div>
              <aside class="theory-meta">
                <div class="meta-block"><div class="meta-label">CWE</div><div class="meta-line">${esc(it.cwe)}</div></div>
              </aside>
            </div>
          </div>
          <div class="tabpane" id="tp-lab">
            <div class="goal">
              <strong>${en?'Offline API simulator':'Offline API-симулятор'}</strong>
              <div class="flag-hint">${en?'No real network. Capture the flag when the check passes.':'Без сети. Флаг при успешной проверке.'}</div>
            </div>
            ${practiceUI(it)}
            <div id="api-flag">${done?`<div class="flag-box"><div class="flabel">${I18n.t('yourFlag')}</div><div class="fval">${esc(it.flag)}</div></div>`:''}</div>
          </div>
        </div>
      </div>`;
  }

  function bindTabs() {
    document.querySelectorAll('#api-tabs .tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('#api-tabs .tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('#tp-theory,#tp-lab').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('tp-' + tab.dataset.tab)?.classList.add('active');
      });
    });
  }

  return {
    renderHub, renderItem, bindTabs, ITEMS,
    tryBola, tryAuth, tryMass, tryRate, tryBfla, tryFlow, trySsrf, tryMisc, tryInv, tryConsume,
  };
})();
