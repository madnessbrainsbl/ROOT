/* Russian labels and explanatory text for the middle payload-library cohort. */
(() => {
  const CATEGORIES = [
    'SSTI',
    'Log4Shell',
    'Open Redirect',
    'CRLF / Headers',
    'NoSQL',
    '403 Bypass / access control',
    'API Key Leaks',
    'Account Takeover',
    'Backup Files Exposure',
    'CORS Misconfiguration',
    'CSS Injection',
    'CSV Injection',
    'CVE Exploits',
    'Clickjacking',
    'Client Side Path Traversal',
    'Cross-Site Request Forgery',
    'DNS Rebinding',
    'DOM Clobbering',
    'Denial of Service',
    'Dependency Confusion',
    'Encoding Transformations',
    'External Variable Modification',
    'File Inclusion',
  ];

  const EXACT_TITLES = {
    'Jinja math': 'Jinja — вычисление',
    'Jinja config': 'Jinja — конфигурация',
    'Freemarker exec': 'Freemarker — выполнение команды',
    'ERB system': 'ERB — вызов system',
    'Probe ${{}}': 'Пробник ${{}}',
    'lower obfuscation': 'Обфускация через lower',
    'env USER': 'Переменная окружения USER',
    '::- obfuscation': 'Обфускация через ::-',
    'User-Agent header': 'Заголовок User-Agent',
    'JSON field': 'Поле JSON',
    backslash: 'Обратная косая черта',
    '@ confusion': 'Неоднозначность с @',
    'encoded @': 'Закодированный @',
    'data URI': 'Схема data URI',
    'subdomain lookalike': 'Похожий поддомен',
    'Set-Cookie inject': 'Внедрение Set-Cookie',
    'Location inject': 'Внедрение Location',
    'raw CRLF': 'CRLF без кодирования',
    'Unicode CRLF': 'CRLF через Unicode',
    'Host override': 'Подмена Host',
    '$ne null': '$ne со значением null',
    '$gt empty': '$gt с пустым значением',
    'form $ne': '$ne в форме',
    'JSON $or login': 'Вход через $or в JSON',
    'regex password': 'Подбор пароля через regex',
    '$where sleep': 'Задержка через $where',
    '$in array': 'Массив $in',
    'form $gt': '$gt в форме',
    'regex extract': 'Извлечение через regex',
    'trailing slash': 'Завершающий слеш',
    case: 'Изменение регистра',
    'double slash': 'Двойной слеш',
    '%2e path': 'Путь с %2e',
    'Referer spoof': 'Подмена Referer',
    'Response Manipulation': 'Подмена ответа',
    Prevention: 'Предотвращение',
    Practice: 'Практика',
    'Fork Bomb (Linux)': 'Fork bomb (Linux)',
    'Jinja2 - bypassing the _ and dot filter': 'Jinja2 — обход фильтра _ и точки',
    'SpEL / Java EL - detection and RCE': 'SpEL / Java EL — обнаружение и RCE',
    'ERB - detection and RCE': 'ERB — обнаружение и RCE',
    'Redirect methods: path and JavaScript': 'Способы редиректа: путь и JavaScript',
    'Common query parameters for a redirect': 'Типовые query-параметры редиректа',
    'Protocol-relative (//) and "http" bypass': 'Относительный протокол (//) и обход фильтра "http"',
    'Basic redirects to an external host': 'Базовые редиректы на внешний хост',
    'Subdomain/subfolder as the trusted domain': 'Поддомен/папка как доверенный домен',
    'The @ character - the real host comes after @ (RFC 1738)': 'Символ @ — настоящий хост находится после @ (RFC 1738)',
    'The ? character - the browser treats it as /?': 'Символ ? — браузер трактует его как /?',
    'Whitelist domain + @ / # / & / \\ before the real host': 'Домен из белого списка + @ / # / & / \\ перед настоящим хостом',
    'Backslash tricks - bypass of the "//" filter': 'Трюки с обратным слешем — обход фильтра "//"',
    'Triple/multiple slash + path-traversal suffix': 'Тройной/множественный слеш + суффикс path traversal',
    'Encoded TAB (%09) inside the host': 'Закодированная табуляция (%09) внутри хоста',
    'URL-encode the whole payload - bypass of keyword filters': 'URL-кодирование всего payload — обход фильтров по ключевым словам',
    'Ideographic dot %E3%80%82 - bypass of the "." filter': 'Идеографическая точка %E3%80%82 — обход фильтра "."',
    'Null byte %00 - bypass of a blacklist filter': 'Нулевой байт %00 — обход чёрного списка',
    'Host/Split Unicode Normalization': 'Unicode-нормализация Host/Split',
    'CRLF to bypass the "javascript" filter': 'CRLF для обхода фильтра "javascript"',
    'javascript: scheme - XSS via redirect': 'Схема javascript: — XSS через редирект',
    'javascript: with obfuscation (CRLF, escape, octal/unicode)': 'javascript: с обфускацией (CRLF, escape, octal/unicode)',
    'Whitelist bypass with @ and %2f.. suffix (for Intruder)': 'Обход белого списка через @ и суффикс %2f.. (для Intruder)',
    'XSS via CRLF': 'XSS через CRLF',
    'Open redirect via CRLF (Location)': 'Открытый редирект через CRLF (Location)',
    'XSS - disable X-XSS-Protection and inject svg': 'XSS — отключение X-XSS-Protection и внедрение svg',
    'CR/LF encoding variants (for bypassing filters)': 'Варианты кодирования CR/LF для обхода фильтров',
    'Guessing the username via $in': 'Подбор имени пользователя через $in',
    'Determining the value length via $regex': 'Определение длины значения через $regex',
    'Character-by-character extraction via $regex (form-urlencoded)': 'Посимвольное извлечение через $regex (form-urlencoded)',
    'Character-by-character extraction via $regex (JSON)': 'Посимвольное извлечение через $regex (JSON)',
    'Regex match on a field via this (with %00)': 'Regex-сопоставление поля через this (с %00)',
    '$or / $comment and insertion via mapReduce': '$or / $comment и внедрение через mapReduce',
    'Delay via sleep() and a busy-loop in $where': 'Задержка через sleep() и цикл активного ожидания в $where',
    'Removing a pre-condition via key duplication': 'Удаление предварительного условия через дублирование ключа',
    'Auto-fuzzing mutations with ffuf': 'Автофаззинг мутаций через ffuf',
    'IP headers — bypassing "localhost / internal only"': 'IP-заголовки — обход ограничения "localhost / internal only"',
    'Editing a cookie via machineKey (if ViewState is disabled)': 'Изменение cookie через machineKey (если ViewState отключён)',
    'Injecting an email via a parameter (parameter pollution / cc / separators)': 'Внедрение email через параметр (parameter pollution / cc / разделители)',
    'IDOR in the password-change API - example request': 'IDOR в API смены пароля — пример запроса',
    'Reset-token leakage in the response body': 'Утечка токена сброса в теле ответа',
    '2FA bypass via Force Browsing': 'Обход 2FA через принудительный переход',
    'PoC - stealing the response via XHR (hosted on evil.com)': 'PoC — кража ответа через XHR (размещён на evil.com)',
    'PoC - HTML page with an Exploit button': 'PoC — HTML-страница с кнопкой Exploit',
    'XSS on a whitelisted domain → launch a CORS payload': 'XSS на доверенном домене → запуск CORS-payload',
    'Trusted prefix - any prefix before example.com passes': 'Доверенный префикс — принимается любой префикс перед example.com',
    'Exact value match (PIN / known value)': 'Точное совпадение значения (PIN / известное значение)',
    'Character presence oracle via unicode-range': 'Оракул наличия символа через unicode-range',
    'Blind CSS Exfiltration via @import': 'Слепой вывод данных через CSS и @import',
    'Extracting an attribute via attr() + image-set': 'Извлечение атрибута через attr() + image-set',
    'Target HTML for attr() exfiltration': 'Целевой HTML для вывода данных через attr()',
    'Launching calc via DDE (basic variants)': 'Запуск calc через DDE (базовые варианты)',
    'Blind formula injection / exfiltration via IMPORTXML': 'Слепая инъекция формул / вывод данных через IMPORTXML',
    'Shellshock - RCE via User-Agent (CGI)': 'Shellshock — RCE через User-Agent (CGI)',
    'CVE-2025-4123: 3 encoded traversal payloads (redirect / XSS / SSRF)': 'CVE-2025-4123: три закодированных payload обхода пути (редирект / XSS / SSRF)',
    'Execution - hidden form with prefilled fields': 'Выполнение — скрытая форма с заполненными полями',
    'Execution - submit function on click': 'Выполнение — вызов submit по клику',
    '204 No Content - bypass without a prompt (stub page)': '204 No Content — обход без диалога (страница-заглушка)',
    'Disabling JavaScript - restricted frame (IE) and sandbox': 'Отключение JavaScript — ограниченный frame (IE) и sandbox',
    'IE8 XSS filter - inducing a false positive': 'XSS-фильтр IE8 — вызов ложного срабатывания',
    'JSON POST - autosubmit form (bypassing browser defenses)': 'JSON POST — автоотправка формы (обход защиты браузера)',
    'Note on simple vs complex request': 'Примечание о простых и сложных запросах',
    'Example attack with Singularity of Origin': 'Пример атаки через Singularity of Origin',
    'Clobbering x.y via id + name (DOM collection)': 'Подмена x.y через id + name (DOM-коллекция)',
    'Clobbering document.getElementById() via <html>/<body>': 'Подмена document.getElementById() через <html>/<body>',
    'Clobbering x.username and x.password (URL parsing of href)': 'Подмена x.username и x.password (разбор URL из href)',
    'Clobbering a value via href (Firefox only)': 'Подмена значения через href (только Firefox)',
    'Clobbering x.xyz via base href (Chrome only)': 'Подмена x.xyz через base href (только Chrome)',
    'DOMPurify bypass via the cid: protocol (double quote is not encoded)': 'Обход DOMPurify через протокол cid: (двойная кавычка не кодируется)',
    'Disabling the trick via COLLATE utf8mb4_0900_as_cs': 'Отключение трюка через COLLATE utf8mb4_0900_as_cs',
    'Exploitation - swapping $page for LFI': 'Эксплуатация — подмена $page для LFI',
    'Bypassing recursive stripping of ../ (....// and //)': 'Обход рекурсивного удаления ../ (....// и //)',
    'php://filter - chaining via | or /': 'php://filter — объединение цепочек через | или /',
    'Download source via base64 (curl)': 'Скачивание исходного кода через base64 (curl)',
    'Ready-made filter chain for <?php phpinfo();?>': 'Готовая цепочка фильтров для <?php phpinfo();?>',
    'PHAR deserialization - vulnerable class with a magic method': 'PHAR-десериализация — уязвимый класс с magic method',
    'lightyear - blind file read primitive': 'lightyear — примитив слепого чтения файла',
    'SSH auth.log - poisoning via the username': 'SSH auth.log — отравление через имя пользователя',
    'Mail log - poisoning via SMTP': 'Почтовый журнал — отравление через SMTP',
    '/proc/self/environ - poisoning via User-Agent': '/proc/self/environ — отравление через User-Agent',
    'PHP sessions - inject code and include the session file': 'PHP-сессии — внедрение кода и подключение файла сессии',
    'Race condition - brute-force /tmp/php* during upload': 'Race condition — перебор /tmp/php* во время загрузки',
    'Remote File Inclusion - basic inclusion by URL': 'Remote File Inclusion — базовое подключение по URL',
    'RFI - Null Byte and Double Encoding': 'RFI — нулевой байт и двойное кодирование',
    'Bypassing allow_url_include via SMB (Windows)': 'Обход allow_url_include через SMB (Windows)',
    'Linux - /etc/shadow and private SSH keys': 'Linux — /etc/shadow и приватные SSH-ключи',
    'Windows - SAM and SYSTEM for extracting hashes': 'Windows — SAM и SYSTEM для извлечения хешей',
  };

  const TITLE_RULES = [
    ['What it is and where to look', 'Что это такое и где искать'],
    ['Where to look and how to test', 'Где искать и как проверять'],
    ['Where to look for', 'Где искать'],
    ['Where it applies', 'Где применимо'],
    ['Where web.config / machine.config live', 'Где находятся web.config / machine.config'],
    ['Where to look for impact', 'Где искать влияние'],
    ['Common query parameters for a redirect', 'Типовые query-параметры редиректа'],
    ['Common tags to test for', 'Типовые теги для проверки'],
    ['Common names and paths', 'Типовые имена и пути'],
    ['Exploitation conditions', 'Условия эксплуатации'],
    ['Vulnerable response', 'Уязвимый ответ'],
    ['Vulnerable example', 'Уязвимый пример'],
    ['Vulnerable code', 'Уязвимый код'],
    ['Example request', 'Пример запроса'],
    ['example request', 'пример запроса'],
    ['Example regex patterns', 'Примеры регулярных выражений'],
    ['example and claims', 'пример и claims'],
    ['exploitation example', 'пример эксплуатации'],
    ['real-world example', 'пример из реальной практики'],
    ['basic variants', 'базовые варианты'],
    ['Basic variants', 'Базовые варианты'],
    ['Basic redirects', 'Базовые редиректы'],
    ['Basic PoC', 'Базовый PoC'],
    ['Quick check', 'Быстрая проверка'],
    ['Minimal operator probes', 'Минимальные пробники операторов'],
    ['Math probe', 'Математический пробник'],
    ['Error-based probe', 'Пробник по ошибке'],
    ['Polyglot - trigger an error when SSTI is present', 'Полиглот — вызвать ошибку при наличии SSTI'],
    ['Redirect methods', 'Способы редиректа'],
    ['Protocol-relative', 'Относительный протокол'],
    ['trusted domain', 'доверенного домена'],
    ['Trusted prefix', 'Доверенный префикс'],
    ['Whitelist domain', 'Домен из белого списка'],
    ['whitelist domain', 'доменом из белого списка'],
    ['whitelist', 'белого списка'],
    ['Whitelist', 'Белый список'],
    ['the real host comes after', 'настоящий хост находится после'],
    ['the browser treats it as', 'браузер трактует его как'],
    ['Backslash tricks', 'Трюки с обратным слешем'],
    ['Encoded backslash', 'Закодированный обратный слеш'],
    ['Triple/multiple slash', 'Тройной/множественный слеш'],
    ['Encoded TAB', 'Закодированная табуляция'],
    ['URL-encode the whole payload', 'URL-кодирование всего payload'],
    ['Ideographic dot', 'Идеографическая точка'],
    ['Null byte', 'Нулевой байт'],
    ['Null Byte', 'Нулевой байт'],
    ['Unicode characters that normalize to', 'Unicode-символы, нормализующиеся в'],
    ['Host in non-standard IP notations', 'Хост в нестандартных форматах IP'],
    ['IP notations with', 'Форматы IP с'],
    ['Multi-parameter payload', 'Payload с несколькими параметрами'],
    ['bypass of', 'обход'],
    ['bypassing', 'обход'],
    ['Bypassing', 'Обход'],
    ['Bypass', 'Обход'],
    ['injection', 'инъекция'],
    ['Injection', 'Инъекция'],
    ['inject', 'внедрение'],
    ['Injecting', 'Внедрение'],
    ['reflection of', 'отражение'],
    ['stealing the response', 'кража ответа'],
    ['hosted on', 'размещён на'],
    ['sandboxed iframe', 'iframe в sandbox'],
    ['allowed', 'разрешён'],
    ['reading an internal API', 'чтение внутреннего API'],
    ['Unescaped dot in the regex', 'Неэкранированная точка в regex'],
    ['any letter instead of the dot', 'любая буква вместо точки'],
    ['Detection and exfiltration channels', 'Каналы обнаружения и вывода данных'],
    ['Attribute selectors', 'Селекторы атрибутов'],
    ['the basis of the technique', 'основа техники'],
    ['Exfiltration via', 'Вывод данных через'],
    ['Exact value match', 'Точное совпадение значения'],
    ['styling a parent based on a child', 'стилизация родителя по дочернему элементу'],
    ['Hidden inputs', 'Скрытые input-элементы'],
    ['styling a neighboring element', 'стилизация соседнего элемента'],
    ['Character presence oracle', 'Оракул наличия символа'],
    ['Leaking a CSRF token character by character', 'Посимвольная утечка CSRF-токена'],
    ['Extracting an attribute', 'Извлечение атрибута'],
    ['Target HTML', 'Целевой HTML'],
    ["Request on the attacker's server", 'Запрос на сервере атакующего'],
    ['launch and payload', 'запуск и payload'],
    ['A nuance with the hyphen in the source', 'Нюанс с дефисом в исходных данных'],
    ['Launching calc', 'Запуск calc'],
    ['How a DDE payload is structured', 'Как устроен DDE-payload'],
    ['download & execute', 'загрузка и выполнение'],
    ['instead of', 'вместо'],
    ['Prefix obfuscation and command chaining', 'Обфускация префикса и цепочка команд'],
    ['functions for requesting remote URLs', 'функции запроса удалённых URL'],
    ['Blind formula injection', 'Слепая инъекция формул'],
    ['exploitation via header', 'эксплуатация через заголовок'],
    ['unauth deserialization', 'RCE через десериализацию без аутентификации'],
    ['unauth RCE probe', 'пробник RCE без аутентификации'],
    ['JS execution on PDF render', 'выполнение JS при рендеринге PDF'],
    ['PoC generator', 'генератор PoC'],
    ['client-side traversal', 'обход пути на клиенте'],
    ['encoded traversal payloads', 'закодированные payload обхода пути'],
    ['transparent overlay', 'прозрачное наложение'],
    ['Invisible iframe', 'Невидимый iframe'],
    ['zero dimensions, no border', 'нулевые размеры, без рамки'],
    ['Hidden form', 'Скрытая форма'],
    ['Visible button over a hidden form', 'Видимая кнопка поверх скрытой формы'],
    ['Execution -', 'Выполнение —'],
    ['Execution via', 'Выполнение через'],
    ['cancelling frame-busting', 'отмена frame-busting'],
    ['with a prompt', 'с диалогом'],
    ['without a prompt', 'без диалога'],
    ["attacker's page", 'страница атакующего'],
    ['Disabling JavaScript', 'Отключение JavaScript'],
    ['restricted frame', 'ограниченный frame'],
    ['code that XSS filters break', 'код, который ломают XSS-фильтры'],
    ['inducing a false positive', 'вызов ложного срабатывания'],
    ['targeted script disabling', 'точечное отключение скрипта'],
    ['meta tag', 'meta-тег'],
    ['Challenge - dissecting a vulnerable snippet', 'Задача — разбор уязвимого фрагмента'],
    ['with user action', 'с действием пользователя'],
    ['without user action', 'без действия пользователя'],
    ['autosubmit', 'автоматическая отправка'],
    ['with file upload', 'с загрузкой файла'],
    ['simple request', 'простой запрос'],
    ['complex request', 'сложный запрос'],
    ['bypassing browser defenses', 'обход защиты браузера'],
    ['Note on simple vs complex request', 'Примечание о простых и сложных запросах'],
    ['is checked only when the header is present', 'проверяется только при наличии заголовка'],
    ['Broken Referer validation', 'Некорректная проверка Referer'],
    ['Tools for', 'Инструменты для'],
    ['Example attack', 'Пример атаки'],
    ['dig example', 'пример с dig'],
    ['an HTML injection without scripts is needed', 'нужна HTML-инъекция без скриптов'],
    ['Clobbering', 'Подмена'],
    ['DOM collection', 'DOM-коллекция'],
    ['levels of nesting', 'уровня вложенности'],
    ['more than 3 levels', 'более трёх уровней'],
    ['nested iframe', 'вложенный iframe'],
    ['URL parsing of href', 'разбор URL из href'],
    ['Chrome only', 'только Chrome'],
    ['Firefox only', 'только Firefox'],
    ['double quote is not encoded', 'двойная кавычка не кодируется'],
    ['Account lockout DoS', 'DoS через блокировку аккаунта'],
    ['XML bomb', 'XML-бомба'],
    ['deeply nested queries', 'глубоко вложенные запросы'],
    ['Other exhaustion vectors', 'Другие векторы истощения ресурсов'],
    ['the execution primitive', 'примитив выполнения'],
    ['finding dependency confusion', 'поиска dependency confusion'],
    ['Checking normalization in all forms', 'Проверка всех форм нормализации'],
    ['treats similar characters as equal', 'считает похожие символы одинаковыми'],
    ['Disabling the trick', 'Отключение трюка'],
    ['Encoding and decoding', 'Кодирование и декодирование'],
    ['authentication bypass', 'обход аутентификации'],
    ['controlling the include path', 'управление путём подключения'],
    ['swapping', 'подмена'],
    ['Overwriting', 'Перезапись'],
    ['Protection', 'Защита'],
    ['detection', 'обнаружение'],
    ['Detection', 'Обнаружение'],
    ['file read', 'чтение файла'],
    ['File read', 'Чтение файла'],
    ['leaks', 'утечки'],
    ['universal', 'универсальный вариант'],
    ['modern versions', 'современных версиях'],
    ['sandbox escape', 'выход из sandbox'],
    ['via import', 'через import'],
    ['shortest', 'кратчайший'],
    ['classic', 'классический'],
    ['if __builtins__ is filtered', 'если __builtins__ отфильтрован'],
    ['bypassing the _ and dot filter', 'обход фильтра _ и точки'],
    ['vulnerable versions', 'уязвимые версии'],
    ['listing', 'список'],
    ['Header', 'Заголовок'],
    ['field', 'поле'],
    ['Set-Cookie injection', 'Внедрение Set-Cookie'],
    ['Session Fixation', 'Фиксация сессии'],
    ['forcing your own cookie', 'навязывание собственного cookie'],
    ['Open redirect', 'Открытый редирект'],
    ['Phishing', 'Фишинг'],
    ['rewrite the response body', 'подмена тела ответа'],
    ['disable X-XSS-Protection', 'отключение X-XSS-Protection'],
    ['via UTF-8 characters', 'через UTF-8-символы'],
    ['stripping in Firefox', 'удаление в Firefox'],
    ['Payload made of UTF-8 characters', 'Payload из UTF-8-символов'],
    ['The same payload in URL encoding', 'Тот же payload в URL-кодировке'],
    ['encoding variants', 'варианты кодирования'],
    ['for bypassing filters', 'для обхода фильтров'],
    ['Practice -', 'Практика —'],
    ['Operator injection into search', 'Инъекция оператора в поиск'],
    ['example of the vulnerability', 'пример уязвимости'],
    ['Login bypass via operators', 'Обход входа через операторы'],
    ['Guessing the username', 'Подбор имени пользователя'],
    ['Determining the value length', 'Определение длины значения'],
    ['Character-by-character extraction', 'Посимвольное извлечение'],
    ['Blind script', 'Скрипт слепого извлечения'],
    ['with a JSON body', 'с телом JSON'],
    ['with a urlencoded body', 'с urlencoded-телом'],
    ['conditions', 'условия'],
    ['always true', 'всегда истинно'],
    ['closing the string and a JS expression', 'закрытие строки и JS-выражение'],
    ['Regex match on a field', 'Regex-сопоставление поля'],
    ['insertion via mapReduce', 'внедрение через mapReduce'],
    ['Delay via', 'Задержка через'],
    ['busy-loop', 'цикл активного ожидания'],
    ['Removing a pre-condition', 'Удаление предварительного условия'],
    ['key duplication', 'дублирование ключа'],
    ['When and how 403/401 is bypassed', 'Когда и как обходятся 403/401'],
    ['Top techniques', 'Основные техники'],
    ['using /admin as an example', 'на примере /admin'],
    ['copy and try', 'копируйте и проверяйте'],
    ['Auto-fuzzing mutations', 'Автофаззинг мутаций'],
    ['access to a hidden path', 'доступ к скрытому пути'],
    ['How X-Original-URL / X-Rewrite-URL work', 'Как работают X-Original-URL / X-Rewrite-URL'],
    ['IP headers', 'IP-заголовки'],
    ['Changing the HTTP method and version', 'Изменение HTTP-метода и версии'],
    ['Automating the 403 bypass', 'Автоматизация обхода 403'],
    ['Signs of a bypass and nuances', 'Признаки обхода и нюансы'],
    ['checking a token across many APIs', 'проверка токена во множестве API'],
    ['scan a GitHub organization', 'сканирование организации GitHub'],
    ['scan a repository with issues and PRs', 'сканирование репозитория с issues и PR'],
    ['scan a Docker image', 'сканирование Docker-образа'],
    ['Validation example', 'Пример проверки'],
    ['element format', 'формат элемента'],
    ['example (from Microsoft docs)', 'пример из документации Microsoft'],
    ['Guessing a known machineKey', 'Подбор известного machineKey'],
    ['Known machineKey wordlists', 'Словари известных machineKey'],
    ['Decoding ViewState', 'Декодирование ViewState'],
    ['MAC disabled', 'MAC отключён'],
    ['MAC enabled, encryption disabled', 'MAC включён, шифрование отключено'],
    ['extract the key', 'извлечение ключа'],
    ['generate ViewState', 'создание ViewState'],
    ['MAC and encryption enabled', 'MAC и шифрование включены'],
    ['notes', 'примечания'],
    ['remove __VIEWSTATEENCRYPTED', 'удаление __VIEWSTATEENCRYPTED'],
    ['Editing a cookie', 'Изменение cookie'],
    ['if ViewState is disabled', 'если ViewState отключён'],
    ['what to do with a leaked one', 'что делать с утёкшим ключом'],
    ['validate + billable call + data leak', 'проверка + платный вызов + утечка данных'],
    ['referrer / app restriction', 'ограничения referrer / приложения'],
    ['Password Reset Poisoning', 'Отравление сброса пароля'],
    ['via the Host header', 'через заголовок Host'],
    ['parameter pollution / cc / separators', 'загрязнение параметров / cc / разделители'],
    ['password-change API', 'API смены пароля'],
    ['Reset-token leakage', 'Утечка токена сброса'],
    ['via Unicode normalization', 'через нормализацию Unicode'],
    ['via HTTP Request Smuggling', 'через HTTP Request Smuggling'],
    ['final request', 'итоговый запрос'],
    ['2FA bypass', 'Обход 2FA'],
    ['Force Browsing', 'принудительный переход'],
    ['via an array', 'через массив'],
    ['Exposed backups and source files', 'Открытые резервные копии и исходники'],
    ['Fuzzing backup files', 'Фаззинг резервных файлов'],
    ['Tell source disclosure from a normal page', 'Как отличить выдачу исходника от обычной страницы'],
    ['Wayback and nuclei for backups', 'Wayback и nuclei для поиска резервных копий'],
    ['CSPT to XSS', 'CSPT в XSS'],
    ['with a POST sink', 'с POST-приёмником'],
    ['via "../"', 'через "../"'],
    ['form-urlencoded', 'form-urlencoded'],
    ['JSON body', 'тело JSON'],
    ['Source disclosure', 'Раскрытие исходного кода'],
    ['Vulnerable example in PHP', 'Уязвимый пример на PHP'],
    ['Basic /etc/passwd read via traversal', 'Базовое чтение /etc/passwd через traversal'],
    ['truncating the extension', 'обрезание расширения'],
    ['Double Encoding', 'Двойное кодирование'],
    ['overlong encoding', 'избыточное кодирование'],
    ['Path Truncation', 'Обрезание пути'],
    ['PHP cuts paths', 'PHP обрезает пути'],
    ['recursive stripping', 'рекурсивное удаление'],
    ['reading source', 'чтение исходного кода'],
    ['part of the name is case-insensitive', 'часть имени не зависит от регистра'],
    ['chain with compression for large files', 'цепочка со сжатием для больших файлов'],
    ['chaining', 'объединение цепочек'],
    ['Download source', 'Скачивание исходного кода'],
    ['generating a chain', 'создание цепочки'],
    ['Ready-made filter chain', 'Готовая цепочка фильтров'],
    ['custom chain for command execution', 'собственная цепочка для выполнения команды'],
    ['webshell in base64', 'webshell в base64'],
    ['direct command execution', 'прямое выполнение команды'],
    ['code in the POST body', 'код в теле POST'],
    ['webshell inside an archive', 'webshell внутри архива'],
    ['archive structure with a backdoor', 'структура архива с бэкдором'],
    ['build and include', 'сборка и подключение'],
    ['deserialization', 'десериализация'],
    ['vulnerable class with a magic method', 'уязвимый класс с magic method'],
    ['building the archive with an object in meta-data', 'создание архива с объектом в метаданных'],
    ['JPG magic bytes in the stub', 'magic bytes JPG в stub'],
    ['auto file leak', 'автоматическая утечка файла'],
    ['wrap file contents with a prefix/suffix', 'оборачивание содержимого файла префиксом/суффиксом'],
    ['vulnerable target code', 'уязвимый код цели'],
    ['blind file read primitive', 'примитив слепого чтения файла'],
    ['Including web/service log files', 'Подключение журналов веб-сервисов'],
    ['poisoning', 'отравление'],
    ['brute-forcing descriptors of uploaded files', 'перебор дескрипторов загруженных файлов'],
    ['useful pseudo-files', 'полезные псевдофайлы'],
    ['path to the session file', 'путь к файлу сессии'],
    ['inject code and include the session file', 'внедрение кода и подключение файла сессии'],
    ['Self-inclusion of an uploaded file', 'Подключение загруженного файла'],
    ['Race condition - brute-force', 'Race condition — перебор'],
    ['wildcard for the temp file', 'маска для временного файла'],
    ['leaking the upload temp file name', 'утечка имени временного файла загрузки'],
    ['basic inclusion by URL', 'базовое подключение по URL'],
    ['private SSH keys', 'приватные SSH-ключи'],
    ['extracting hashes', 'извлечение хешей'],
  ];

  function translateTitle(title) {
    if (EXACT_TITLES[title]) return EXACT_TITLES[title];
    return TITLE_RULES.reduce(
      (result, [source, translated]) => result.replaceAll(source, translated),
      title,
    ).replaceAll(' - ', ' — ');
  }

  const titles = {};
  for (const category of CATEGORIES) {
    const items = DATA.PAYLOADS?.[category] || [];
    titles[category] = Object.fromEntries(
      items.map((item) => [item.t, translateTitle(item.t)]),
    );
  }

  const lines = {
    '• Generated PDFs, invoices, and emails are almost always template-based.':
      '• Сгенерированные PDF, счета и письма почти всегда основаны на шаблонах.',
    '• Name/greeting fields, template previews, email subjects and bodies, custom messages.':
      '• Поля имени и приветствия, предпросмотр шаблонов, темы и тела писем, пользовательские сообщения.',
    '• Any input that is later rendered back to the user.':
      '• Любой ввод, который позднее рендерится обратно пользователю.',
    '• Start with {{7*7}} and ${7*7}; if it evaluates, identify the engine and escalate to RCE.':
      '• Начните с {{7*7}} и ${7*7}; если выражение вычисляется, определите движок и переходите к проверке RCE.',
    '⚠ On Smarty 3.1+ {system} is blocked by the Security Policy and {php} was removed — see the working escape in the card below.':
      '⚠ В Smarty 3.1+ {system} блокируется Security Policy, а {php} удалён — рабочий выход из sandbox приведён в следующей карточке.',
    'On Smarty 3.1+ the default Security Policy blocks {system} and {php} was removed — you need to escape via static methods / native tags:':
      'В Smarty 3.1+ стандартная Security Policy блокирует {system}, а {php} удалён — требуется выход через статические методы или встроенные теги:',
    'Write a webshell via a static method (the classic sandbox escape):':
      'Запись webshell через статический метод (классический выход из sandbox):',
    'Sandbox escape via template_object (CVE-2021-26119, Smarty < 3.1.39):':
      'Выход из sandbox через template_object (CVE-2021-26119, Smarty < 3.1.39):',
    'Injection into {math} (CVE-2021-29454, < 3.1.42 / 4.0.2):':
      'Инъекция в {math} (CVE-2021-29454, версии < 3.1.42 / 4.0.2):',
    'Version: {$smarty.version}. Fix: Smarty >= 4.x with an up-to-date Security Policy; do not let the user control the template body.':
      'Версия: {$smarty.version}. Исправление: Smarty >= 4.x с актуальной Security Policy; не позволяйте пользователю управлять телом шаблона.',
    'If ${...} did not work, try #{...} *{...} @{...} ~{...}':
      'Если ${...} не сработало, попробуйте #{...} *{...} @{...} ~{...}',
    '# Trusted domain as a folder/path prefix (the host stays yours):':
      '# Доверенный домен как префикс папки/пути (хост остаётся вашим):',
    '# All variants below = 216.58.214.206':
      '# Все варианты ниже соответствуют 216.58.214.206',
    'If input of the form':
      'Если ввод вида',
    'The attacker has forced their own cookie onto the victim (session fixation).':
      'Атакующий навязал жертве собственный cookie (фиксация сессии).',
    'The simplest way to exploit CRLF is to append a new page body (phishing or arbitrary JS).':
      'Простейшая эксплуатация CRLF — добавить новое тело страницы для фишинга или выполнения произвольного JS.',
    'Requested URL:': 'Запрошенный URL:',
    'Resulting HTTP response:': 'Итоговый HTTP-ответ:',
    '• Login forms are the most frequent vector (authentication bypass via $ne / $gt / $regex).':
      '• Формы входа — самый частый вектор (обход аутентификации через $ne / $gt / $regex).',
    '• Search fields and filters (price, category) - mix in an operator instead of a value.':
      '• Поля поиска и фильтры (цена, категория) — подставьте оператор вместо значения.',
    '• Parameters in the URL and in the JSON POST body - try both [$ne]= in form-urlencoded and {"$ne": ...} in JSON.':
      '• Параметры URL и JSON-тела POST — проверьте и [$ne]= в form-urlencoded, и {"$ne": ...} в JSON.',
    '• No visible response - switch to blind: boolean via $regex or timing via $where/sleep.':
      '• Нет видимого ответа — переходите к blind-проверке: boolean через $regex или задержка через $where/sleep.',
    '• It helps to know whether the query travels as JSON or as form-urlencoded - the injection syntax differs.':
      '• Важно определить формат запроса: синтаксис инъекции для JSON и form-urlencoded различается.',
    '// Vulnerable code: user input goes straight into the value':
      '// Уязвимый код: пользовательский ввод напрямую попадает в значение',
    '// The attacker substitutes an operator instead of the value:':
      '// Атакующий подставляет оператор вместо значения:',
    '// The resulting query returns ALL products with price > 0 (data leak):':
      '// Итоговый запрос возвращает ВСЕ товары с ценой > 0 (утечка данных):',
    "Note: server-side JavaScript ($where, mapReduce, $function/$accumulator) is ENABLED by default on self-hosted mongod (javascriptEnabled=true); usually disabled on managed clouds (Atlas) and with --noscripting. On 4.4+ $function/$accumulator provide an alternative to $where in aggregation.":
      'Примечание: серверный JavaScript ($where, mapReduce, $function/$accumulator) по умолчанию ВКЛЮЧЁН в self-hosted mongod (javascriptEnabled=true), но обычно отключён в managed-cloud (Atlas) и с --noscripting. В версиях 4.4+ альтернативой $where в aggregation служат $function/$accumulator.',
    '// In MongoDB, when a key is duplicated in a document, the LAST occurrence wins.':
      '// В MongoDB при дублировании ключа в документе побеждает ПОСЛЕДНЕЕ значение.',
    '// The resulting value of "id" will be "100":':
      '// Итоговым значением "id" будет "100":',
    'How to test: take a protected path (returns 403), run mutations and headers through it, WATCH for a change in the response code/size (ffuf -mc all -ac). Not every 403 can be broken: a genuine server-side ACL or a client-side redirect cannot be bypassed this way.':
      'Как проверять: возьмите защищённый путь с ответом 403, примените к нему мутации и заголовки и СЛЕДИТЕ за изменением кода/размера ответа (ffuf -mc all -ac). Не каждый 403 обходится: настоящую серверную ACL или клиентский редирект таким способом не сломать.',
    '# Full mutation lists are already in this toolkit (⌘K): 403_url_payloads.txt (236 of them),':
      '# Полные списки мутаций уже есть в toolkit (⌘K): 403_url_payloads.txt (236 вариантов),',
    '# and in SecLists: /usr/share/seclists/Fuzzing/403/403.md (77 from @jhaddix).':
      '# а также в SecLists: /usr/share/seclists/Fuzzing/403/403.md (77 вариантов от @jhaddix).',
    '# mutation at the tail of the path': '# мутация в конце пути',
    '# mutation at the start of the path': '# мутация в начале пути',
    '# -ac auto-calibrates the baseline, -mc all shows all codes — look for a response with a code/size':
      '# -ac автоматически калибрует baseline, -mc all показывает все коды — ищите ответ с другим кодом/размером',
    '# different from the original 403 (often 200/302/401).':
      '# относительно исходного 403 (часто 200/302/401).',
    'Request-URI: /admin': 'Запрашиваемый URI: /admin',
    'The request goes to an allowed path (for example "/"), but the front-end (Symfony, some Nginx/IIS configs, a number of proxies) routes by the value of the X-Original-URL / X-Rewrite-URL header. The proxy ACL checked "/" (allowed) -> let it through, and the application served /admin.':
      'Запрос идёт к разрешённому пути (например, "/"), но front-end (Symfony, некоторые конфигурации Nginx/IIS и прокси) маршрутизирует его по X-Original-URL / X-Rewrite-URL. ACL прокси проверяет "/" и пропускает запрос, после чего приложение отдаёт /admin.',
    '# The full list of 42 headers is in the toolkit (⌘K): 403_header_payloads.txt.':
      '# Полный список из 42 заголовков находится в toolkit (⌘K): 403_header_payloads.txt.',
    '# The ACL is often set only on GET — try other methods':
      '# ACL часто настроена только для GET — попробуйте другие методы',
    '# An arbitrary/junk method (some servers treat it as GET)':
      '# Произвольный метод (некоторые серверы обрабатывают его как GET)',
    '# Method override headers': '# Заголовки подмены HTTP-метода',
    '# Downgrade the protocol version (Host-based routing/ACL may break)':
      '# Понижение версии протокола (маршрутизация/ACL по Host может сломаться)',
    '# nomore403 (Go) — paths + methods + headers automatically':
      '# nomore403 (Go) — автоматическая проверка путей, методов и заголовков',
    '# byp4xx — verbs / headers / path-mutations in one run':
      '# byp4xx — методы, заголовки и мутации пути за один запуск',
    '# bypass-url-parser (laluka) — maximum URL mutations':
      '# bypass-url-parser (laluka) — максимальный набор URL-мутаций',
    '# ffuf with the toolkit\'s ready-made lists (⌘K: 403_url_payloads.txt / 403_header_payloads.txt)':
      '# ffuf с готовыми списками toolkit (⌘K: 403_url_payloads.txt / 403_header_payloads.txt)',
    '• Success = a response with a code/size different from the reference 403 (usually 200/302/401, or a different Content-Length).':
      '• Успех — ответ с кодом/размером, отличным от эталонного 403 (обычно 200/302/401 или другой Content-Length).',
    '• Combine: path + header + method at once (a combination often works, not a single one).':
      '• Комбинируйте путь + заголовок + метод: часто срабатывает именно сочетание.',
    '• If the 403 is from a WAF (Cloudflare/Akamai/Imperva in the Server/headers) — that is a different story (WAF bypass), not a backend ACL.':
      '• Если 403 выдаёт WAF (Cloudflare/Akamai/Imperva в Server/заголовках), это обход WAF, а не backend ACL.',
    '• Hit the backend/origin IP or an internal port directly, bypassing the proxy, if the address is known.':
      '• Если адрес известен, обратитесь напрямую к backend/origin IP или внутреннему порту в обход прокси.',
    '• Try both /path and /path/ — behavior is often different.':
      '• Проверяйте и /path, и /path/ — поведение часто различается.',
    '• Double encoding (%252e, %252f) goes through where single encoding is cut by the proxy.':
      '• Двойное кодирование (%252e, %252f) иногда проходит там, где прокси отсекает одинарное.',
    'If __VIEWSTATEGENERATOR is absent but the application runs on .NET Framework <= 4.0, you can specify the application root (for example --apppath="/testaspx/").':
      'Если __VIEWSTATEGENERATOR отсутствует, но приложение работает на .NET Framework <= 4.0, можно указать корень приложения (например, --apppath="/testaspx/").',
    '• .NET Framework < 4.5 - ASP.NET still accepts an unencrypted __VIEWSTATE if you remove the __VIEWSTATEENCRYPTED parameter from the request.':
      '• .NET Framework < 4.5 — ASP.NET принимает незашифрованный __VIEWSTATE, если удалить из запроса параметр __VIEWSTATEENCRYPTED.',
    '• .NET Framework > 4.5 - the machineKey has the compatibilityMode="Framework45" property.':
      '• .NET Framework > 4.5 — machineKey имеет свойство compatibilityMode="Framework45".',
    '# Validate (service-agnostic, preferred - does not depend on a model name):':
      '# Проверка без привязки к сервису (предпочтительно, не зависит от имени модели):',
    '# Billable LLM call (PoC of unauthorized paid use). Use a CURRENT model from ListModels: names churn (gemini-1.5/2.0-flash already 404).':
      '# Платный вызов LLM (PoC несанкционированного расходования средств). Используйте АКТУАЛЬНУЮ модель из ListModels: имена меняются.',
    '# Leak another project\'s private assets:':
      '# Утечка приватных ресурсов другого проекта:',
    '# Maps billing abuse (priciest - Directions / DistanceMatrix / Places / Geocode):':
      '# Злоупотребление биллингом Maps (самые дорогие: Directions / DistanceMatrix / Places / Geocode):',
    '# A single 200 is a sufficient PoC. Do NOT loop it, to avoid running up the victim\'s bill.':
      '# Одного ответа 200 достаточно для PoC. НЕ запускайте запрос в цикле, чтобы не увеличивать счёт жертвы.',
    '# Bypass an HTTP-referrer restriction: supply the allowed Referer (the domain where you found the key, or its *.wildcard).':
      '# Обход ограничения HTTP-referrer: передайте разрешённый Referer (домен, где найден ключ, или его *.wildcard).',
    '# For the Maps JavaScript API also add Origin:':
      '# Для Maps JavaScript API также добавьте Origin:',
    '# Bypass an application restriction (Android): forge package + signing-cert SHA1.':
      '# Обход ограничения приложения (Android): подмените package + SHA1 сертификата подписи.',
    '# iOS: forge the bundle id (Info.plist CFBundleIdentifier):':
      '# iOS: подмените bundle id (Info.plist CFBundleIdentifier):',
    '# Only an IP restriction cannot be bypassed with a header.':
      '# Только ограничение по IP нельзя обойти заголовком.',
    'If the backend builds the absolute email URL from the Host header, the victim\'s token will be sent to your domain.':
      'Если backend строит абсолютный URL письма из заголовка Host, токен жертвы будет отправлен на ваш домен.',
    'When processing Unicode input (case mapping or normalization), unexpected behavior is possible: different characters collapse into one and two accounts are treated as "the same".':
      'При обработке Unicode (смене регистра или нормализации) разные символы могут схлопнуться в один, и две учётные записи будут считаться одинаковыми.',
    'Tools: Unisub (finding Unicode characters that collapse into the desired character) and the Unicode pentester cheatsheet (a list of suitable characters for a specific platform).':
      'Инструменты: Unisub для поиска схлопывающихся Unicode-символов и Unicode pentester cheatsheet со списками для конкретных платформ.',
    'If the response has `"success":false`, change it to `"success":true`.':
      'Если ответ содержит `"success":false`, замените значение на `"success":true`.',
    'The client may trust the flag from the response and let you through when the response is tampered with in a proxy.':
      'Клиент может доверять флагу из ответа и пропустить пользователя после подмены ответа в прокси.',
    'If with 2FA enabled the login redirects to `/2fa/verify`, while without 2FA it goes straight to `/my-account`, try manually navigating to `/my-account` instead of `/2fa/verify` to skip verification.':
      'Если с 2FA вход ведёт на `/2fa/verify`, а без 2FA — сразу на `/my-account`, попробуйте вручную открыть `/my-account` и пропустить проверку.',
    '# 1) Clusterbomb: known files x suffixes (two fuzz points)':
      '# 1) Clusterbomb: известные файлы × суффиксы (две точки фаззинга)',
    '# 2) Archive/dump of the whole project in the root':
      '# 2) Архив/дамп всего проекта в корне',
    '# 3) feroxbuster with auto-appended extensions':
      '# 3) feroxbuster с автоматическим добавлением расширений',
    '# 4) point check on a found path':
      '# 4) Точечная проверка найденного пути',
    '# -ac (auto-calibrate) filters \'soft 200s\' (custom 404s). For .swp:':
      '# -ac (auto-calibrate) отфильтровывает soft 200 (кастомные 404). Для .swp:',
    "The goal is not '200 OK', it is 'the server returned SOURCE instead of executing it'. Signs:":
      'Цель — не просто `200 OK`, а выдача сервером ИСХОДНОГО КОДА вместо его выполнения. Признаки:',
    '• `Content-Type: text/plain` (or `application/octet-stream`) on something normally served as html.':
      '• `Content-Type: text/plain` (или `application/octet-stream`) у ресурса, который обычно отдаётся как HTML.',
    '• Code visible in the body: `<?php`, `<?=`, `$_GET[`, `$_POST[`, `define(\'DB_`, `DB_PASSWORD`, `\'password\' =>`, DB connection strings.':
      '• В теле виден код: `<?php`, `<?=`, `$_GET[`, `$_POST[`, `define(\'DB_`, `DB_PASSWORD`, `\'password\' =>`, строки подключения к БД.',
    '• Response size clearly differs from the normal page of the same name.':
      '• Размер ответа явно отличается от обычной страницы с тем же именем.',
    '# Historical backups from the web archive (see Commands -> Recon -> Wayback CDX)':
      '# Исторические копии из веб-архива (см. Commands -> Recon -> Wayback CDX)',
    '# nuclei: ready templates for backup files and dumps':
      '# nuclei: готовые шаблоны для резервных файлов и дампов',
    '# gobuster pattern-mode: substitute the domain into archive name templates':
      '# gobuster pattern-mode: подстановка домена в шаблоны имён архивов',
    '# Note: downloading someone\'s full DB dump out of scope is risky -':
      '# Внимание: скачивать чужой полный дамп БД вне scope рискованно —',
    '# confirm minimally (header/first bytes), clear a full pull against program rules.':
      '# подтвердите утечку минимально (заголовки/первые байты), полную загрузку согласуйте с правилами программы.',
    '• Do not keep backups and dumps in the webroot; back up outside DocumentRoot.':
      '• Не храните резервные копии и дампы в webroot; сохраняйте их вне DocumentRoot.',
    '• Clean editor swap files on prod (`.*.swp`); do not edit files directly on production.':
      '• Удаляйте swap-файлы редакторов на production (`.*.swp`); не редактируйте файлы прямо на сервере.',
    '• Do not ship `.env`/`config.*.dist` with real secrets into a public folder.':
      '• Не помещайте `.env`/`config.*.dist` с реальными секретами в публичный каталог.',
    '• Monitor 200 responses on typical backup paths (a rare but precise leak signal).':
      '• Отслеживайте ответы 200 на типовых путях резервных копий — это редкий, но точный сигнал утечки.',
    "The attacker's request (Burp) adds its own Origin:":
      'Запрос атакующего (Burp) добавляет собственный Origin:',
    "The victim's response is vulnerable if at the same time:":
      'Ответ жертвы уязвим при одновременном выполнении условий:',
    'Exploited via attacker code in an iframe with the data: scheme - with it the browser sends the request with the null origin:':
      'Эксплуатация через код атакующего в iframe со схемой data: — браузер отправляет запрос с Origin null:',
    'If the application implements a strict whitelist of allowed origins, the payloads above will not work. But if there is an XSS on a trusted (whitelisted) origin, you can inject the CORS exploit there and carry out the attack again - the request will now originate from a trusted Origin:':
      'При строгом белом списке Origin предыдущие payload не сработают. Но XSS на доверенном Origin позволяет разместить CORS-эксплойт там: запрос будет исходить из разрешённого Origin.',
    'The server uses a regex where the dot is not escaped: for example `^api.example.com$` instead of `^api\\.example.com$`. Then the dot can be replaced with any letter and you gain access from a third-party domain - the Origin https://apiiexample.com passes the check:':
      'Сервер использует regex с неэкранированной точкой: `^api.example.com$` вместо `^api\\.example.com$`. Точку можно заменить любой буквой: Origin https://apiiexample.com пройдёт проверку.',
    '/* a hidden input does not render -> style the first VISIBLE following sibling via + */':
      '/* скрытый input не рендерится -> стилизуем первый ВИДИМЫЙ соседний элемент через + */',
    '• cmd - the name of the DDE server application that the client (Excel) contacts.':
      '• cmd — имя DDE server application, к которому обращается клиент Excel.',
    '• /C calc - the command / file name being passed (here calc.exe).':
      '• /C calc — передаваемая команда/имя файла (здесь calc.exe).',
    '• !A0 - the item name, the unit of data the server returns to the client on request.':
      '• !A0 — имя элемента, единица данных, которую сервер возвращает клиенту.',
    '# Bypass middleware (for example an authorization check) on a protected route.':
      '# Обход middleware (например, проверки авторизации) на защищённом маршруте.',
    '# The header convinces Next.js the request already passed middleware, so it is skipped.':
      '# Заголовок убеждает Next.js, что запрос уже прошёл middleware, поэтому проверка пропускается.',
    '# Any Next-Action value works; deserialization runs BEFORE action validation.':
      '# Подойдёт любое значение Next-Action: десериализация выполняется ДО проверки action.',
    '# Detect: a DNS/HTTP hit on your Collaborator = confirmed unauth RCE.':
      '# Обнаружение: DNS/HTTP-запрос на Collaborator подтверждает RCE без аутентификации.',
    '# Core: the 6th FontMatrix element is a PDF string that breaks out into the Function body.':
      '# Суть: шестой элемент FontMatrix — строка PDF, позволяющая выйти в тело Function.',
    '# Escaping rule: write every literal ( and ) in the JS as \\( and \\); exactly one trailing unescaped ) closes the PDF string.':
      '# Правило экранирования: каждую ( и ) в JS записывайте как \\( и \\); строку PDF закрывает ровно одна неэкранированная ) в конце.',
    '• State-changing actions performed in one click: "Delete account", "Confirm transfer", "Make public", "Add administrator", "Change email/password".':
      '• Изменяющие состояние действия в один клик: удаление аккаунта, подтверждение перевода, публикация, добавление администратора, смена email/пароля.',
    '• OAuth confirmation buttons / granting privileges to an application.':
      '• Кнопки подтверждения OAuth / выдачи приложению привилегий.',
    '• Likes, follows, reposts, votes - for inflation.':
      '• Лайки, подписки, репосты и голоса — для накрутки.',
    '• Forms whose values can be prefilled via URL parameters, leaving the user only to "submit" them with a click.':
      '• Формы, значения которых заполняются через URL-параметры: пользователю остаётся только нажать submit.',
    '//application/json is not allowed in a simple request. text/plain is the default':
      '// application/json запрещён в простом запросе; по умолчанию используется text/plain',
    '//You will probably want to also try one or both of these':
      '// Также стоит попробовать один или оба варианта:',
    '// this input will send : {"role":admin,"other":"="}':
      '// этот input отправит: {"role":admin,"other":"="}',
    'The server validates the Referer only if it is sent. Suppress sending the Referer entirely, and the check is skipped:':
      'Сервер проверяет Referer только при его наличии. Полностью запретите отправку Referer — проверка будет пропущена:',
    'If the server checks only a substring (the domain appears somewhere in the Referer), bypass the naive check. Place the expected domain in your own URL - as a subdomain or as a parameter:':
      'Если сервер ищет лишь подстроку домена в Referer, обойдите наивную проверку: поместите ожидаемый домен в собственный URL как поддомен или параметр.',
    'Note           SameSite is not a substitute for a CSRF token: with any of these vectors you still need the token.':
      'Примечание: SameSite не заменяет CSRF-токен; при любом из этих векторов токен всё равно необходим.',
    '• nccgroup/singularity (Singularity of Origin) - a framework for DNS rebinding attacks. https://github.com/nccgroup/singularity':
      '• nccgroup/singularity (Singularity of Origin) — фреймворк для атак DNS rebinding. https://github.com/nccgroup/singularity',
    '• rebind.it - a web client for Singularity of Origin. http://rebind.it/':
      '• rebind.it — веб-клиент для Singularity of Origin. http://rebind.it/',
    '• taviso/rbndr - a simple DNS rebinding service. https://github.com/taviso/rbndr':
      '• taviso/rbndr — простой сервис DNS rebinding. https://github.com/taviso/rbndr',
    'Exploitation requires any HTML injection on the page (not full-fledged JS).':
      'Для эксплуатации достаточно любой HTML-инъекции на странице; полноценный JS не требуется.',
    'The classic scenario: a filter/sanitizer strips <script> and event handlers but lets through "harmless" tags (a, form, input, iframe, base, img...).':
      'Классический сценарий: фильтр удаляет <script> и event handlers, но пропускает «безопасные» теги (a, form, input, iframe, base, img...).',
    "The goal is to slip in elements with the right id/name so that the page's script reads a controlled value from them (a sink of the form x, x.y, x.y.value, etc.).":
      'Цель — внедрить элементы с нужными id/name, чтобы скрипт страницы прочитал подконтрольное значение (sink вида x, x.y, x.y.value и т. п.).',
    '// Payload': '// Payload',
    '// Sink': '// Sink',
    '// Payloads': '// Payload',
    '// Code runs through npm lifecycle scripts at INSTALL time.':
      '// Код выполняется через npm lifecycle scripts во время УСТАНОВКИ.',
    '// Publish to the public npm a package with the private name and a version above any internal one:':
      '// Опубликуйте в публичном npm пакет с приватным именем и версией выше любой внутренней:',
    '// the victim\'s npm install (often in CI) -> callback. Bonus: a misconfigured .npmrc/scoped registry resolves @org to public npm.':
      '// npm install у жертвы (часто в CI) -> callback. При неверной настройке .npmrc/scoped registry резолвит @org в публичный npm.',
    'The PHP functions extract($_GET/$_POST), import_request_variables(), parse_str() and register_globals import user input into the current variables.':
      'PHP-функции extract($_GET/$_POST), import_request_variables(), parse_str() и register_globals импортируют пользовательский ввод в текущие переменные.',
    'Attack:': 'Атака:',
    'Note: as of PHP 8.1.0, writing to the entire $GLOBALS array is no longer supported.':
      'Примечание: начиная с PHP 8.1.0 перезапись всего массива $GLOBALS не поддерживается.',
    '• LFI (Local File Inclusion) - a local file is included; may lead to code execution.':
      '• LFI (Local File Inclusion) — подключается локальный файл; это может привести к выполнению кода.',
    '• RFI (Remote File Inclusion) - a remote file is included by URL.':
      '• RFI (Remote File Inclusion) — удалённый файл подключается по URL.',
    '• Path Traversal differs from File Inclusion: traversal gives you file read, while inclusion leads to arbitrary code execution.':
      '• Path Traversal отличается от File Inclusion: traversal даёт чтение файла, а inclusion может привести к выполнению произвольного кода.',
    '• Look in parameters like ?page=, ?file=, ?template=, ?include=, ?lang= - anything that looks like a file name or path.':
      '• Ищите параметры ?page=, ?file=, ?template=, ?include=, ?lang= и всё похожее на имя файла или путь.',
    '• Start with ../../../etc/passwd (Linux) or ..\\..\\..\\windows\\win.ini (Windows); if it works - escalate to RCE via wrappers, log poisoning, upload.':
      '• Начните с ../../../etc/passwd (Linux) или ..\\..\\..\\windows\\win.ini (Windows); при успехе проверяйте переход к RCE через wrappers, log poisoning или upload.',
    '# multiple base64 decodes:': '# многократное декодирование base64:',
    '# deflate + base64encode (useful for exfiltration with a limited character set):':
      '# deflate + base64encode (полезно для вывода данных при ограниченном наборе символов):',
    '# vulnerable file: index.php': '# уязвимый файл: index.php',
    '# vulnerable parameter: file': '# уязвимый параметр: file',
    '# executed command: id': '# выполняемая команда: id',
    '# executed PHP code: <?=`$_GET[0]`;;?>': '# выполняемый PHP-код: <?=`$_GET[0]`;;?>',
    '# 1) create the payload': '# 1) создать payload',
    '# 2) pack it and disguise it as an image': '# 2) упаковать и замаскировать под изображение',
    '# 3) include it (%23 = #)': '# 3) подключить его (%23 = #)',
    '# build (phar.readonly=0 required)': '# сборка (требуется phar.readonly=0)',
    '# include a file inside the archive': '# подключить файл внутри архива',
    '// Does NOT work on PHP 8+ (phar deserialization removed).':
      '// НЕ работает на PHP 8+ (PHAR-десериализация удалена).',
    '// Triggered by any file operation (include, file_get_contents,':
      '// Срабатывает при любой файловой операции (include, file_get_contents,',
    '// create new Phar': '// создать новый Phar',
    '// add object of any class as meta data': '// добавить объект любого класса в метаданные',
    '// disguise the phar as a JPG: magic bytes \\xff\\xd8\\xff':
      '// замаскировать phar под JPG: magic bytes \\xff\\xd8\\xff',
    '// then trigger:': '// затем вызвать:',
    '# oracle: HTTP 500 or response time': '# оракул: HTTP 500 или время ответа',
    '# ambionics/wrapwrap - generates a php://filter chain that adds a prefix and suffix':
      '# ambionics/wrapwrap — создаёт цепочку php://filter, добавляющую префикс и суффикс',
    '# target: {"message":"<file contents>"}': '# цель: {"message":"<содержимое файла>"}',
    '# logs escape double quotes - use single quotes in PHP strings':
      '# журналы экранируют двойные кавычки — используйте одинарные кавычки в PHP-строках',
    '# then request the log via LFI and execute the command':
      '# затем запросить журнал через LFI и выполнить команду',
    '# log in over SSH with PHP code in the username':
      '# войти по SSH с PHP-кодом в имени пользователя',
    '# then include the log': '# затем подключить журнал',
    '# or with a single command:': '# либо одной командой:',
    '# then include /var/log/mail': '# затем подключить /var/log/mail',
    '# 1) upload many shells (for example 100)': '# 1) загрузить много shell-файлов (например, 100)',
    '# 2) include /proc/$PID/fd/$FD ($PID and $FD are brute-forced)':
      '# 2) подключить /proc/$PID/fd/$FD ($PID и $FD перебираются)',
    'Check whether the site uses PHPSESSID:': 'Проверьте, использует ли сайт PHPSESSID:',
    'The session file lives in one of:': 'Файл сессии находится в одном из путей:',
    'Contents (you can see the values you control):':
      'Содержимое (видны подконтрольные вам значения):',
    '# 1) write PHP code into the session via a controlled field':
      '# 1) записать PHP-код в сессию через подконтрольное поле',
    '# 2) include the session file via LFI': '# 2) подключить файл сессии через LFI',
    '# pearcmd.php is installed by default in every php Docker image':
      '# pearcmd.php по умолчанию установлен в каждом Docker-образе php',
    '# at /usr/local/lib/php/pearcmd.php; register_argc_argv=On is required':
      '# путь /usr/local/lib/php/pearcmd.php; требуется register_argc_argv=On',
    '# Method 1: config-create': '# Способ 1: config-create',
    '# Method 2: man_dir': '# Способ 2: man_dir',
    '# Method 3: download (network access required)': '# Способ 3: download (требуется доступ к сети)',
    '# Method 4: install (network access required); exec.php -> /tmp/pear/download/exec.php':
      '# Способ 4: install (требуется доступ к сети); exec.php -> /tmp/pear/download/exec.php',
    '# if you can upload a file - inject a shell into it (e.g. <?php system($_GET[\'c\']); ?>)':
      '# если файл можно загрузить — внедрите в него shell (например, <?php system($_GET[\'c\']); ?>)',
    '# to keep the file valid, hide the code in the metadata of an image/doc/pdf':
      '# чтобы файл оставался валидным, спрячьте код в метаданных изображения/doc/pdf',
    '# Windows only. FindFirstFile allows masks in LFI paths:':
      '# Только Windows. FindFirstFile допускает маски в путях LFI:',
    '#   << like *   (any sequence of characters)': '#   << как *   (любая последовательность символов)',
    '#   >  like ?   (a single character)': '#   >  как ?   (один символ)',
    '# The uploaded file lands in C:\\Windows\\Temp\\ with a name php[A-F0-9]{4}.tmp.':
      '# Загруженный файл попадает в C:\\Windows\\Temp\\ с именем php[A-F0-9]{4}.tmp.',
    '# Brute-force 65536 names or use a wildcard:': '# Переберите 65536 имён или используйте маску:',
    'The iconv wrapper triggers an OOB in glibc (CVE-2024-2961), then LFI reads /proc/self/maps and downloads the glibc binary. RCE is achieved by exploiting the zend_mm_heap structure: free() is remapped to system via custom_heap._free.':
      'Wrapper iconv вызывает OOB в glibc (CVE-2024-2961), затем LFI читает /proc/self/maps и загружает бинарник glibc. RCE достигается через структуру zend_mm_heap: free() переназначается на system через custom_heap._free.',
    'Requirements:': 'Требования:',
    '• access to the convert.iconv, zlib.inflate, dechunk filters':
      '• доступ к фильтрам convert.iconv, zlib.inflate и dechunk',
    'Exploit: ambionics/cnext-exploits.': 'Эксплойт: ambionics/cnext-exploits.',
    '# does not work by default: in PHP 5 allow_url_include is off.':
      '# по умолчанию не работает: в PHP 5 allow_url_include отключён.',
    '# Most of the LFI filter bypasses apply to RFI as well.':
      '# Большинство обходов фильтров LFI применимы и к RFI.',
    'When allow_url_include and allow_url_fopen = Off, on Windows you can still include a remote file over smb:':
      'Когда allow_url_include и allow_url_fopen отключены, в Windows всё ещё можно подключить удалённый файл по SMB:',
    '# extract /etc/shadow and crack the hashes -> log in over SSH':
      '# извлечь /etc/shadow и подобрать хеши -> войти по SSH',
    '# or read the private key: identify the user from /etc/passwd,':
      '# либо прочитать приватный ключ: определить пользователя по /etc/passwd,',
    '# then read /<HOME>/.ssh/id_rsa for each user with a home directory':
      '# затем прочитать /<HOME>/.ssh/id_rsa у каждого пользователя с домашним каталогом',
    '# then: samdump2 SYSTEM SAM > hashes.txt -> crack with hashcat/john or Pass-The-Hash':
      '# затем: samdump2 SYSTEM SAM > hashes.txt -> подбор через hashcat/john или Pass-The-Hash',
  };

  DATA.PAYLOAD_TITLES_RU ||= {};
  for (const [category, categoryTitles] of Object.entries(titles)) {
    Object.assign(DATA.PAYLOAD_TITLES_RU[category] ||= {}, categoryTitles);
  }
  Object.assign(DATA.PAYLOAD_LINES_RU ||= {}, lines);
})();
