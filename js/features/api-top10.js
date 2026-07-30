/* RØOT — OWASP API Security Top 10 (2023) track
 * Original educational summaries + offline mini-labs.
 * Category names/order follow the public OWASP API Security Top 10 project
 * (see README.md). Practice UIs and wording are original RØOT material.
 */
const ApiTop10 = (() => {
  const esc = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const numLabel = (id) => { const m = String(id).match(/(\d+)$/); return m ? String(+m[1]).padStart(2,'0') : String(id); };
  const L = (ru, en) => (I18n.lang() === 'en' ? en : ru);

  const INTRO = {
    en: `<p class="theory-lead"><strong>OWASP API Security Top 10 (2023)</strong> describes ten common and high-impact API risk categories: authorization and authentication failures, unrestricted resource consumption, abuse of sensitive business flows, SSRF, security misconfiguration and poor API inventory management.</p>
<p>This section explains each category, shows a vulnerable scenario and provides a small local exercise. Use it as a starting point, not a complete checklist: an assessment must still account for the API's architecture, roles, data and business logic.</p>`,
    ru: `<p class="theory-lead"><strong>OWASP API Security Top 10 (2023)</strong> описывает десять распространённых и опасных классов рисков API: ошибки авторизации и аутентификации, неограниченное потребление ресурсов, злоупотребление критичными бизнес-процессами, SSRF, ошибки конфигурации и отсутствие полного реестра API.</p>
<p>Раздел объясняет каждую категорию, показывает уязвимый сценарий и предлагает небольшое локальное упражнение. Используйте его как отправную точку, а не как полный чек-лист: при проверке необходимо учитывать архитектуру, роли, данные и бизнес-логику конкретного API.</p>`,
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
<p><strong>Нарушение контроля доступа к объекту (BOLA)</strong>, в старой веб-терминологии IDOR, возникает, когда API опознаёт вызывающего, но <em>не</em> проверяет, вправе ли он читать или менять именно этот объект. Идентификатор приходит в пути (<code>/api/v1/orders/{id}</code>), в строке запроса (<code>?accountId=</code>), в теле или как узел GraphQL. Последовательные и предсказуемые идентификаторы облегчают перебор, а UUID лишь прячут объекты — проверку прав они <strong>не</strong> заменяют.</p>
<p>Последствия: чужие счета и переписка, правка и удаление записей, выгрузка персональных данных, разрушение изоляции между арендаторами. Горизонтальный случай — пользователь A читает данные пользователя B; вертикальный — идентификатор ведёт к ресурсу, доступному только администратору.</p>
<h3>Как это выглядит в жизни</h3>
<ul>
<li>Мобильный банк и финтех: классика bug bounty — подмена <code>accountId</code> или <code>transactionId</code> сразу после входа.</li>
<li>Социальные и графовые API: у Facebook Graph и похожих платформ исторически разбирали проблемы доступа по идентификатору объекта.</li>
<li>Такси, медицина, умные устройства: публичные разборы раз за разом показывают «вошёл, но принадлежность не проверена» на поездках, устройствах и медицинских картах.</li>
</ul>
<h3>Как практиковать и тестировать (только с разрешения)</h3>
<ul>
<li><strong>Учебный стенд:</strong> под вторым пользователем запросите счёт первого (подсказка — <code>1001</code>) и посмотрите, вернётся ли объект без проверки принадлежности.</li>
<li><strong>Обычный пентест:</strong> заведите две сессии и повторите идентификатор из одной под токеном другой — в пути, в теле, в переменных GraphQL и в пакетных методах.</li>
<li>Проверьте переходы «список → карточка», выгрузку и скачивание, ссылки «поделиться» и печать в PDF: они часто заново достают объект по идентификатору.</li>
<li>Чужие боевые учётные записи не трогайте — работайте в согласованных границах и на этом локальном полигоне.</li>
</ul>
<h3>Как чинить</h3>
<ul>
<li>Проверка прав на сервере при <strong>каждом</strong> обращении к объекту: найти объект, сверить владельца, арендатора и роль, и только потом отдать или изменить.</li>
<li>Непрозрачные идентификаторы; не доверять полю <code>user_id</code> от клиента — субъект берут из сессии или токена.</li>
<li>Единая точка проверки: middleware, политики или слой доступа к данным. Автотесты должны подтверждать отказ при обращении к чужому объекту.</li>
<li>Журналы и оповещения о переборе чужих идентификаторов; при необходимости не раскрывать даже факт существования объекта.</li>
</ul>
<h3>Источники и разборы</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API1 Broken Object Level Authorization</strong>, самый частый критический риск для API.</li>
<li>Класс BOLA/IDOR: типовые отчёты bug bounty по мобильным банкам и многоарендным сервисам.</li>
<li>Графовые и социальные API: публично разобранные сбои проверки прав на уровне объекта.</li>
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
<p><strong>Нарушение аутентификации</strong> — сбои при выдаче, проверке, хранении и отзыве учётных данных и токенов. Типичное: вечные токены доступа; слабые секреты; нет блокировки и ограничения частоты, отсюда подстановка утёкших паролей; JWT с <code>alg=none</code>, слабым HMAC или подменой ключа; ключи API в строке запроса и внутри мобильной сборки; сломанные восстановление пароля и одноразовые коды; токены без проверки получателя и издателя.</p>
<p>В отличие от BOLA, где нарушитель уже вошёл, но лезет не в свой объект, здесь цель другая — <em>стать</em> легитимным пользователем или прожить дольше, чем задумано сессией.</p>
<h3>Как это выглядит в жизни</h3>
<ul>
<li>Подстановка утёкших паролей на методах входа и выдачи токенов — самое массовое злоупотребление на практике: чужие базы паролей плюс отсутствие адаптивного торможения.</li>
<li>Ошибки настройки JWT: исследования и задачи CTF раз за разом показывают <code>none</code>, подмену идентификатора ключа и слабые общие секреты между сервисами.</li>
<li>Ловушки OAuth и OIDC: открытые перенаправления, утечка токена через реферер и журналы, обновление без смены токена — классика мобильных и одностраничных приложений.</li>
</ul>
<h3>Как практиковать и тестировать (только с разрешения)</h3>
<ul>
<li><strong>Учебный стенд:</strong> слабые значения <code>client_secret</code> — <code>password</code>, <code>secret</code>, <code>changeme</code> — на имитации метода выдачи токена.</li>
<li><strong>Обычный пентест:</strong> проверьте ограничение частоты на входе и выдаче токенов; подбор одного пароля к множеству учёток — только в границах работ; разберите JWT по полям <code>alg</code>, <code>exp</code>, <code>aud</code>, <code>iss</code>; повторите просроченный и отозванный токен.</li>
<li>Ищите токены в строке запроса, в HTML и JavaScript, в цепочке перенаправлений и в подробных сообщениях об ошибках; у восстановления пароля и одноразовых кодов — перебор и повторное использование.</li>
<li>Для углубления есть практикум по JWT — только на разрешённых целях.</li>
</ul>
<h3>Как чинить</h3>
<ul>
<li>Короткоживущие токены доступа и сменяемые токены обновления; отзыв и проверка состояния токена для чувствительных методов.</li>
<li>Хранилище секретов; разрешённый список алгоритмов, лучше асимметричных; обязательная проверка <code>iss</code>, <code>aud</code>, <code>exp</code>, <code>nbf</code>.</li>
<li>Адаптивное ограничение частоты, блокировка и дополнительное подтверждение, многофакторная аутентификация; защита от подстановки паролей по признакам устройства и адреса.</li>
<li>Секреты не в адресе: заголовок <code>Authorization</code> и защищённое хранилище на клиенте.</li>
</ul>
<h3>Источники и разборы</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API2 Broken Authentication</strong>.</li>
<li>Подстановка утёкших паролей: массовое злоупотребление методами входа без торможения, задокументировано многократно.</li>
<li>Ошибки настройки JWT и OAuth: исследования и отчёты bug bounty о слабых секретах, <code>alg=none</code> и утечке токенов.</li>
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
<p><strong>Нарушение контроля доступа к свойствам объекта</strong> находится между BOLA и BFLA: к самому объекту доступ есть, а вот не ко всем его <em>полям</em>. Сторон две. Первая — массовое присваивание: клиент дописывает <code>role</code>, <code>isAdmin</code>, <code>price</code> или <code>balance</code> в запрос на создание или изменение. Вторая — избыточная выдача: API возвращает номер документа, внутренние флаги, хеши секретов и наценку, а интерфейс их просто не показывает.</p>
<p>Особенно часто это случается, когда пришедший JSON напрямую отображается в модель хранения: лишние поля принимаются, если на входе нет разрешённого списка, а на выходе — отдельного представления под роль.</p>
<h3>Как это выглядит в жизни</h3>
<ul>
<li>Массовое присваивание в сервисах заказа поездок: публичные разборы того, как привилегированные поля попадали в модель прямо из клиентского JSON. Это класс дефекта, а не одна конкретная уязвимость.</li>
<li>Привязка всего тела запроса в Rails, ASP.NET и Node — частый сюжет отчётов о повышении роли или подмене цены.</li>
<li>Мобильные приложения: интерфейс прячет поля, а API отдаёт пользователя или заказ целиком — типичная избыточная выдача.</li>
</ul>
<h3>Как практиковать и тестировать (только с разрешения)</h3>
<ul>
<li><strong>Учебный стенд:</strong> измените профиль и добавьте к имени поле <code>"role":"admin"</code>.</li>
<li><strong>Обычный пентест:</strong> сверьте схему с реальным ответом, ищите непредусмотренные поля и вложенные объекты, используйте подсказки и интроспекцию GraphQL.</li>
<li>Сравните между собой ответы списка, карточки и админского метода; ищите финансовые поля, персональные данные и флаги функций.</li>
</ul>
<h3>Как чинить</h3>
<ul>
<li>Разрешённый список изменяемых полей; не отображать сырое тело запроса прямо в модель хранения.</li>
<li>Отдельные представления запроса и ответа под сценарий и роль; чувствительные поля по умолчанию не выдавать.</li>
<li>Проверка прав на уровне поля; валидация по схеме OpenAPI или JSON Schema на шлюзе либо в приложении.</li>
</ul>
<h3>Источники и разборы</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API3 Broken Object Property Level Authorization</strong>.</li>
<li>Массовое присваивание: публичные исследования о повышении прав через автоматическую привязку полей во фреймворках.</li>
<li>Избыточная выдача: мобильный API возвращает объекты целиком при «спрятанном» интерфейсе — частая тема bug bounty.</li>
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
<p><strong>Неограниченное потребление ресурсов</strong> — это когда API даёт без разумных пределов тратить процессор, память, канал, дисковое место или платные квоты внешних сервисов. Примеры: ограничения частоты нет или оно слабое; проходит <code>limit=999999</code>; вложенный запрос GraphQL раздувает соединения таблиц; пакетная операция без предела количества; загрузка файлов без ограничения размера и типа; отправка SMS, писем или запуск модели «по нажатию»; неограниченная сборка архивов и PDF.</p>
<p>Итог не сводится к отказу в обслуживании: приходит счёт от облака и от партнёрских API. Это называют экономическим отказом в обслуживании.</p>
<h3>Как это выглядит в жизни</h3>
<ul>
<li>Раскрутка облачного счёта: дорогие SMS, перевод текста и запросы к моделям через открытые или слабо защищённые ключом методы.</li>
<li>«Запрос смерти» в GraphQL и пакетирование через псевдонимы полей — хорошо изучено в исследованиях.</li>
<li>Выгрузки и отчёты с произвольным диапазоном дат или полным дампом без постраничности — классика корпоративных программ bug bounty.</li>
</ul>
<h3>Как практиковать и тестировать (только с разрешения)</h3>
<ul>
<li><strong>Учебный стенд:</strong> отправьте залпом полсотни запросов. Если ответа 429 так и нет — потребление не ограничено, флаг ваш.</li>
<li><strong>Обычный пентест:</strong> размер страницы, вложенность GraphQL, поток пакетных операций и импорта, пределы загрузки файлов; следите за задержкой и ошибками, не вредя боевой среде и не выходя за границы работ.</li>
<li>Составьте карту методов, которые дёргают платных поставщиков, и найдите те, где малое действие клиента вызывает большую работу сервера.</li>
</ul>
<h3>Как чинить</h3>
<ul>
<li>Ограничение частоты по адресу, пользователю и ключу; мягкие и жёсткие квоты и внятный ответ 429.</li>
<li>Предельный размер страницы и пакета, ограничение глубины и стоимости запроса GraphQL, таймауты, размыкатели цепи.</li>
<li>Пределы размера и типа загружаемых файлов; фоновые задачи с ограничением очереди; оповещения о превышении бюджета в облаке.</li>
</ul>
<h3>Источники и разборы</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API4 Unrestricted Resource Consumption</strong>.</li>
<li>Сложность запросов и злоупотребление псевдонимами в GraphQL: публичные исследования «запроса смерти».</li>
<li>Раскрутка облачного счёта: SMS, письма и запросы к моделям без квот — экономический отказ в обслуживании.</li>
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
<p><strong>Нарушение контроля доступа к функции (BFLA)</strong> — это про <em>операции</em>, а не про отдельный объект: обычный пользователь вызывает привилегированные действия. Создать пользователя, выгрузить всё, поменять настройки системы, отправить <code>DELETE</code> вместо <code>GET</code>, зайти на <code>/internal</code> и <code>/admin</code>, которых нет в мобильном приложении. В отличие от BOLA вопрос ставится иначе: вправе ли эта роль вызывать функцию вообще?</p>
<p>Причины: права проверяются только в интерфейсе; нет проверки метода HTTP; разные сервисы понимают роли по-разному; остались отладочные маршруты; изменяющие операции GraphQL без проверки роли.</p>
<h3>Как это выглядит в жизни</h3>
<ul>
<li>Классика bug bounty: прямое обращение к <code>/api/admin/*</code> и <code>/v1/management</code>, перебор методов после того, как маршруты нашлись в JavaScript или в описании API.</li>
<li>Повышение прав через «скрытые» административные методы — защита сокрытием и надежда на интерфейс.</li>
<li>Партнёрские и дилерские порталы: младшие роли дотягиваются до отчётов и выделения ресурсов, положенных старшим.</li>
</ul>
<h3>Как практиковать и тестировать (только с разрешения)</h3>
<ul>
<li><strong>Учебный стенд:</strong> из сессии обычного пользователя обратитесь к <code>/api/admin/users</code> или к выгрузке. Получилось — это BFLA.</li>
<li><strong>Обычный пентест:</strong> соберите карту маршрутов и методов из документации, клиентов и журналов; повторите привилегированные вызовы под токеном с низкими правами; проверьте, не берёт ли сервер роль прямо из JWT без собственной проверки.</li>
<li>Подмена метода, префиксы версий, административный доступ по отдельному имени узла — только в письменно согласованных границах.</li>
</ul>
<h3>Как чинить</h3>
<ul>
<li>Запрет по умолчанию на каждую чувствительную операцию, права по ролям или атрибутам; на интерфейс не полагаться.</li>
<li>Единая политика и матрица ролей; автотесты, подтверждающие ответ 403 для младших ролей на административных функциях.</li>
<li>Отделить административный контур; убрать отладочные и внутренние маршруты с публичного шлюза.</li>
</ul>
<h3>Источники и разборы</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API5 Broken Function Level Authorization</strong>.</li>
<li>Прямое обращение к административным маршрутам: типовые отчёты о доступе к <code>/admin</code> под обычным токеном.</li>
<li>Рассогласованные роли между сервисами: разборы, где один сервис проверяет права, а соседний нет.</li>
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
<p><strong>Неограниченный доступ к ценным бизнес-процессам</strong> — это законные операции, на которых зарабатывают: покупка билета, погашение купона, приглашение друга, голосование, бронирование, вход по одноразовой ссылке. Защиты от автоматизации и правил честного использования у них нет. Аутентификация при этом может работать безупречно, а ограничение частоты запросов — почти отсутствовать: боты вычерпывают остатки товара, фармят бонусы и искажают рынок.</p>
<p>Это не отказ в обслуживании из API4 и не классический обход контроля доступа. Дефект в другом: у процесса, который обязан оставаться открытым для людей, нет продуктовой защиты от злоупотребления.</p>
<h3>Как это выглядит в жизни</h3>
<ul>
<li>Перекупщики билетов: автоматизация покупки и удержания мест, о которой много писали в прессе.</li>
<li>Злоупотребление купонами, кешбэком и реферальными программами: массовая регистрация учётных записей в электронной торговле и финтехе.</li>
<li>Ограниченные тиражи — кроссовки, видеокарты, выпуск токенов: скриптованное оформление заказа в обход проверок на стороне клиента.</li>
</ul>
<h3>Как практиковать и тестировать (только с разрешения)</h3>
<ul>
<li><strong>Учебный стенд:</strong> погасите купон двадцать раз подряд. Если система не сопротивляется ни разу — процесс не защищён.</li>
<li><strong>Обычный пентест:</strong> скрипт на несколько шагов; параллельные удержание и оформление; несколько учётных записей, если это в границах работ; наблюдение за сигналами риска.</li>
<li>На шагах с деньгами и остатками проверяют идемпотентность, одноразовые токены и гонки при одновременных запросах — без настоящего мошенничества.</li>
</ul>
<h3>Как чинить</h3>
<ul>
<li>Лимиты на учётную запись и способ оплаты, привязка к устройству, нарастающая задержка и капча или дополнительное подтверждение по уровню риска.</li>
<li>Резервирование остатков на сервере, одноразовое погашение, усиленная проверка личности для дорогих операций.</li>
<li>Антифрод-движок: скорость действий, связи между учётными записями, оповещения об аномалиях — вместе с техническим ограничением частоты запросов.</li>
</ul>
<h3>Источники и разборы</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API6 Unrestricted Access to Sensitive Business Flows</strong>.</li>
<li>Перекупка билетов и ботовое оформление заказов: открытые материалы об автоматизации покупок через API.</li>
<li>Фарм купонов и рефералов: постоянная тема отчётов bug bounty и служб противодействия мошенничеству в торговле и финтехе.</li>
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
<p><strong>Подделка запроса со стороны сервера (SSRF)</strong> в API возникает там, где функция принимает адрес или имя узла — вебхук, импорт по ссылке, предпросмотр, аватар, сборка PDF, обратный вызов, — а по сети идёт <em>сам сервер</em>. Нарушитель целится во внутренние сети, в метаданные облака по адресу <code>http://169.254.169.254/</code>, в административные интерфейсы на локальном узле и в соседние облачные службы.</p>
<p>Шлюз и микросервисы расширяют радиус поражения: одна вспомогательная функция «сходи по ссылке» дотягивается до внутренних имён Kubernetes и Docker, до Redis или до учётных данных из службы метаданных, которых из интернета не видно.</p>
<h3>Как это выглядит в жизни</h3>
<ul>
<li>Инцидент уровня Capital One: публично разобранный доступ к метаданным виртуальной машины и злоупотребление добытыми облачными учётными данными — хрестоматийный пример.</li>
<li>Вебхуки и импорт по ссылке в облачных сервисах: частая находка bug bounty с выходом на внутренние узлы и служебные адреса.</li>
<li>Конвертеры PDF и картинок, боты предпросмотра ссылок: классический косвенный SSRF из исследовательских блогов.</li>
</ul>
<h3>Как практиковать и тестировать (только с разрешения)</h3>
<ul>
<li><strong>Учебный стенд:</strong> подставьте адрес службы метаданных <code>http://169.254.169.254/latest/meta-data/</code> в загрузчик вебхука — стенд имитирует внутренний ответ.</li>
<li><strong>Обычный пентест:</strong> локальная петля, частные диапазоны, служебные адреса, повторное разрешение имени, цепочки перенаправлений, необычные записи IP-адреса — только с разрешения.</li>
<li>Соберите карту серверных запросов по описанию API и коду клиента; схемы вроде <code>file://</code> особенно опасны.</li>
</ul>
<h3>Как чинить</h3>
<ul>
<li>Разрешённый список узлов и схем; служебные, локальные и частные адреса блокировать <strong>после</strong> разрешения имени, а не строковым фильтром.</li>
<li>Контроль перенаправлений, таймауты и пределы размера ответа, правила исходящего трафика из подов приложения.</li>
<li>В облаке — вторая версия службы метаданных с ограничением числа переходов; вместо загрузки сервером по ссылке лучше подписанная загрузка от клиента.</li>
</ul>
<h3>Источники и разборы</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API7 Server Side Request Forgery</strong>.</li>
<li>Инцидент уровня Capital One: SSRF привёл к облачным учётным данным из метаданных, есть публичные разборы.</li>
<li>SSRF через вебхуки и импорт по ссылке: постоянная тема отчётов по облачным сервисам с обращениями к 169.254.169.254 и внутренним узлам.</li>
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
<p><strong>Небезопасная конфигурация</strong> для API — это опасные значения по умолчанию и недоделанное укрепление шлюза, фреймворка и среды выполнения: открытый или подстановочный CORS; трассировки стека и отладка в боевой среде; интерактивная документация и песочница GraphQL без аутентификации; учётные данные и ключи из примеров; лишние методы HTTP вроде <code>TRACE</code>; отсутствие заголовков безопасности; чрезмерно широкие облачные права; слабый TLS на границе.</p>
<p>Такие огрехи умножают остальные риски: открытая документация показывает цели для BOLA, а подробные ошибки выдают внутренние узлы для SSRF.</p>
<h3>Как это выглядит в жизни</h3>
<ul>
<li>Открытые в интернете описание API и песочница GraphQL — крайне частая находка на этапе разведки.</li>
<li>Подстановочный CORS вместе с передачей учётных данных — разобранные в исследованиях сценарии межсайтового злоупотребления.</li>
<li>Ключи по умолчанию и отладочные методы из шаблонов проектов: Spring, Express, быстрые старты облачных провайдеров.</li>
</ul>
<h3>Как практиковать и тестировать (только с разрешения)</h3>
<ul>
<li><strong>Учебный стенд:</strong> откройте <code>/swagger.json</code> без аутентификации — получится ли полная опись API?</li>
<li><strong>Обычный пентест:</strong> пути к документации, предварительные запросы CORS, подробность ошибок, учётные данные по умолчанию на предпродакшене в границах работ, заголовки, матрица допустимых методов.</li>
<li>Шлюз и точка входа Kubernetes: открытые управляющие порты, отладочные контейнеры рядом с приложением.</li>
</ul>
<h3>Как чинить</h3>
<ul>
<li>Укрепление шлюза: запрет по умолчанию, явно перечисленные источники для CORS, отключение неиспользуемых методов, TLS.</li>
<li>Аутентификация и сетевые ограничения на документацию и песочницу; никаких трассировок стека в боевой среде.</li>
<li>Смена секретов из шаблонов; служебные учётные записи с минимальными правами; эталонные конфигурации и проверки уровня CIS в конвейере сборки.</li>
</ul>
<h3>Источники и разборы</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API8 Security Misconfiguration</strong>.</li>
<li>Открытая документация API без аутентификации: повсеместная находка при разведке и в bug bounty.</li>
<li>Подстановочный CORS вместе с учётными данными: публично разобранные сценарии злоупотребления API из браузера.</li>
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
<p><strong>Отсутствие учёта API</strong> — организация не знает, какие интерфейсы, версии и узлы ещё живы. Теневые и заброшенные API — недокументированные сервисы, забытый <code>/v1</code> после выхода <code>/v2</code>, предпродакшен в открытом интернете, партнёрские методы «для всех сразу» — остаются без обновлений, пока «официальную» поверхность укрепляют. Старые пути находят по историческим версиям JavaScript, записям DNS, журналам выданных сертификатов и ошибкам маршрутизации на шлюзе.</p>
<p>Без учёта нельзя последовательно применять ни проверку прав, ни журналирование, ни ограничение частоты: остальные категории списка OWASP ломаются вслепую.</p>
<h3>Как это выглядит в жизни</h3>
<ul>
<li>Теневой <code>/v1</code> продолжает работать, а исправления выходят только для <code>/v2</code> — классика разборов инцидентов и отчётов bug bounty.</li>
<li>Массовая выгрузка данных из Parler: публично обсуждавшийся случай слабо контролируемой и легко перебираемой поверхности API.</li>
<li>Забытые предпродакшен и отладка, «временные» административные методы — находятся по журналам прозрачности сертификатов и перебору поддоменов.</li>
</ul>
<h3>Как практиковать и тестировать (только с разрешения)</h3>
<ul>
<li><strong>Учебный стенд:</strong> сравните описанные маршруты с работающим устаревшим <code>/v1</code>, где проверки слабее.</li>
<li><strong>Обычный пентест:</strong> перебор версий от <code>/v1</code> до <code>/v3</code>, альтернативные имена узлов, трафик старых версий мобильного приложения, расхождение описания API с реальностью; теневые маршруты — в границах работ.</li>
<li>Сверьте шлюз, реестр сервисной сети и облачные балансировщики на предмет целей, оставшихся без хозяина.</li>
</ul>
<h3>Как чинить</h3>
<ul>
<li>Единый достоверный реестр и хранилище схем; у каждого метода есть владелец и версия.</li>
<li>Правила вывода версий из эксплуатации с жёсткой датой отключения; весь трафик — через контролируемый шлюз.</li>
<li>Постоянный поиск новых точек: по трафику, по коду, внешней разведкой собственных активов; заброшенное отключать быстро.</li>
</ul>
<h3>Источники и разборы</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API9 Improper Inventory Management</strong>.</li>
<li>Теневой <code>/v1</code> против исправленного <code>/v2</code>: постоянная тема публичных отчётов.</li>
<li>Массовый перебор и выгрузка данных как в случае Parler: неконтролируемая поверхность и отсутствие учёта.</li>
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
<p><strong>Небезопасное потребление чужих API</strong> переворачивает модель доверия: теперь <em>ваш</em> сервис выступает клиентом стороннего или партнёрского интерфейса и слепо верит ответам. Риски: пришедший сверху JSON или XML попадает в SQL-запрос, в разметку страницы или в команду; вредоносные перенаправления; ответ непредусмотренного размера или структуры; файлы без проверки; слабая проверка TLS; и цепная реакция, когда поставщик скомпрометирован или подменён.</p>
<p>Злоупотребления в цепочке поставки и взлом облачных интеграций превращают убеждение «мы ходим только к проверенным поставщикам» в инцидент уже внутри периметра.</p>
<h3>Как это выглядит в жизни</h3>
<ul>
<li>Взлом стороннего виджета или API: публичные инциденты, где интеграция раздавала потребителям вредоносное содержимое, а те выводили его без экранирования.</li>
<li>Внедрение через вебхуки и партнёрские ленты: захват или перехват канала ломает разбор ответа и приводит к SSRF или XSS уже у получателя.</li>
<li>Слепое доверие обратным вызовам об оплате, проверке личности и доставке без подписи — повторяющийся класс в финтехе и торговле.</li>
</ul>
<h3>Как практиковать и тестировать (только с разрешения)</h3>
<ul>
<li><strong>Учебный стенд:</strong> подайте вредоносный или чрезмерно большой партнёрский ответ и посмотрите, проверит его сервис или обработает вслепую.</li>
<li><strong>Пентест и разбор архитектуры:</strong> составьте карту исходящих интеграций; на двойниках предпродакшена проверьте отклонения от схемы, неожиданные типы, перенаправления и подмену типа содержимого; убедитесь в наличии подписи или взаимного TLS.</li>
<li>Устройте отказ: при таймауте и ошибках сервис должен закрываться в безопасное состояние.</li>
</ul>
<h3>Как чинить</h3>
<ul>
<li>Ответ поставщика — недоверенные данные: проверка по схеме, пределы размера, разрешённые списки, экранирование перед подстановкой в SQL, разметку и команды.</li>
<li>Корректная проверка TLS; закрепление сертификата или взаимный TLS для критичных партнёров; проверка подписи и метки времени у вебхуков.</li>
<li>Таймауты, размыкатели цепи, отдельные учётные данные с минимальными правами на каждую интеграцию; наблюдение за аномальным содержимым от поставщика.</li>
</ul>
<h3>Источники и разборы</h3>
<ul>
<li>OWASP API Security Top 10:2023 — <strong>API10 Unsafe Consumption of APIs</strong>.</li>
<li>Взломанный сторонний скрипт или API: публичные инциденты в цепочке поставки, ударившие по доверчивым потребителям.</li>
<li>Вебхуки и обратные вызовы без подписи: распространённый класс в финтехе и торговле по публичным разборам.</li>
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
      <div class="lab-page">
      ${Owasp.tabs('api')}
      <div data-watermark="API" class="hero">
        <div class="row mb8">
          <span class="tag tc">OWASP API</span>
          <span class="tag tb">2023</span>
          <span class="tag tm">${en ? 'local labs' : 'локальные упражнения'}</span>
        </div>
        <h1>${en ? 'API Security Top 10' : 'API Security Top 10'}</h1>
        <div class="theory">${en ? INTRO.en : INTRO.ru}</div>
        <div class="stat-grid">
          <div class="stat"><div class="n" style="color:var(--red)">10</div><div class="l">${en ? 'risk categories' : 'категорий риска'}</div></div>
          <div class="stat"><div class="n" style="color:var(--grn)">${ITEMS.filter(i => Store.hasChallenge(i.id)).length}</div><div class="l">${en ? 'exercises solved' : 'упражнений решено'}</div></div>
          <div class="stat"><div class="n" style="color:var(--yel)">2023</div><div class="l">${en ? 'current edition' : 'текущая редакция'}</div></div>
          <div class="stat"><div class="n" style="color:var(--blu)">LOCAL</div><div class="l">${en ? 'safe practice' : 'безопасная практика'}</div></div>
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
      </div>
      ${Owasp.sourceBlock('https://owasp.org/API-Security/', 'Official OWASP API Security Top 10', 'Официальный сайт OWASP API Security Top 10')}
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
        ${Owasp.sourceBlock('https://owasp.org/API-Security/', 'Official OWASP API Security Top 10', 'Официальный сайт OWASP API Security Top 10')}
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
