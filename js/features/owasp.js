/* Unified OWASP hub and ASVS 5.0 overview. */
const Owasp = (() => {
  const esc = (s) => String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

  const CHAPTERS = [
    ['V1', 'Encoding and Sanitization', 'Кодировка и нейтрализация', 'Canonical input, contextual output encoding, injection prevention and safe deserialization.', 'Канонизация ввода, контекстное кодирование вывода, защита от инъекций и безопасная десериализация.'],
    ['V2', 'Validation and Business Logic', 'Валидация и бизнес-логика', 'Trusted validation, workflow integrity, transaction safety and anti-automation controls.', 'Доверенная валидация, целостность процессов, безопасность транзакций и защита от автоматизации.'],
    ['V3', 'Web Frontend Security', 'Безопасность веб-интерфейса', 'Browser controls, cookies, security headers, origin separation and external resources.', 'Браузерные контроли, cookies, security headers, разделение источников и внешние ресурсы.'],
    ['V4', 'API and Web Service', 'API и веб-сервисы', 'HTTP message handling, GraphQL, WebSocket and service-specific safeguards.', 'Обработка HTTP-сообщений, GraphQL, WebSocket и контроли веб-сервисов.'],
    ['V5', 'File Handling', 'Работа с файлами', 'Upload validation, safe storage, archive processing and controlled downloads.', 'Проверка загрузок, безопасное хранение, обработка архивов и контролируемое скачивание.'],
    ['V6', 'Authentication', 'Аутентификация', 'Passwords, MFA, recovery, identity providers and authentication lifecycle.', 'Пароли, MFA, восстановление, провайдеры идентификации и жизненный цикл аутентификации.'],
    ['V7', 'Session Management', 'Управление сессиями', 'Session creation, rotation, timeout, termination and abuse resistance.', 'Создание, ротация, таймаут, завершение сессий и защита от злоупотреблений.'],
    ['V8', 'Authorization', 'Авторизация', 'Function, object and field-level access control with trusted enforcement.', 'Контроль доступа к функциям, объектам и полям с проверкой на доверенной стороне.'],
    ['V9', 'Self-contained Tokens', 'Автономные токены', 'Secure validation, claims, algorithms and lifecycle for signed or encrypted tokens.', 'Безопасная проверка, claims, алгоритмы и жизненный цикл подписанных или зашифрованных токенов.'],
    ['V10', 'OAuth and OIDC', 'OAuth и OIDC', 'Client, authorization server and resource server controls for OAuth/OIDC flows.', 'Контроли клиентов, серверов авторизации и ресурсов в потоках OAuth/OIDC.'],
    ['V11', 'Cryptography', 'Криптография', 'Approved algorithms, key management, randomness and password storage.', 'Надёжные алгоритмы, управление ключами, случайность и хранение паролей.'],
    ['V12', 'Secure Communication', 'Безопасная коммуникация', 'TLS configuration, certificate validation and protected service connections.', 'Настройка TLS, проверка сертификатов и защищённые соединения между сервисами.'],
    ['V13', 'Configuration', 'Конфигурация', 'Secure defaults, dependency hygiene, deployment configuration and exposed surfaces.', 'Безопасные настройки, зависимости, конфигурация развёртывания и открытая поверхность.'],
    ['V14', 'Data Protection', 'Защита информации', 'Data classification, retention, privacy, caching and sensitive-data handling.', 'Классификация, хранение, приватность, кэширование и обработка чувствительных данных.'],
    ['V15', 'Secure Coding and Architecture', 'Безопасная разработка и архитектура', 'Security architecture, trusted components, concurrency and defensive implementation.', 'Архитектура безопасности, доверенные компоненты, конкурентность и защитная реализация.'],
    ['V16', 'Security Logging and Error Handling', 'Журналирование и обработка ошибок', 'Useful security events, protected logs, alerting and safe failure behavior.', 'Полезные события безопасности, защищённые логи, оповещения и безопасная обработка сбоев.'],
    ['V17', 'WebRTC', 'WebRTC', 'Signaling, media, peer identity and deployment controls specific to WebRTC.', 'Сигналинг, медиа, идентификация узлов и контроли развёртывания WebRTC.'],
  ];

  function tabs(active) {
    const en = I18n.lang() === 'en';
    const items = [
      ['overview', 'owasp', null, 'Overview'],
      ['web', 'webtop10', null, 'Web Top 10'],
      ['api', 'apihub', null, 'API Top 10'],
      ['llm', 'llmhub', null, 'LLM Top 10'],
      ['asvs', 'asvs', null, 'ASVS 5.0'],
      ['wstg', 'framework', 'wstg', 'WSTG 4.2'],
      ['samm', 'framework', 'samm', 'SAMM'],
      ['masvs', 'framework', 'masvs-mastg', 'MASVS/MASTG'],
      ['llmsvs', 'framework', 'llmsvs', 'LLMSVS'],
    ];
    return `<nav class="owasp-tabs" aria-label="${en ? 'OWASP sections' : 'Разделы OWASP'}">
      ${items.map(([id, route, arg, label]) => `<button type="button" class="owasp-tab ${active === id ? 'active' : ''}"
        data-route="${route}"${arg ? ` data-arg="${arg}"` : ''} aria-current="${active === id ? 'page' : 'false'}">${esc(label)}</button>`).join('')}
    </nav>`;
  }

  function sourceBlock(url, labelEn, labelRu) {
    const en = I18n.lang() === 'en';
    return `<section class="card owasp-sources">
      <div class="ch"><h2>${en ? 'Sources' : 'Источники'}</h2></div>
      <div class="cb row"><a class="btn" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(en ? labelEn : labelRu)}</a></div>
    </section>`;
  }

  function renderHub() {
    const en = I18n.lang() === 'en';
    const cards = [
      ['webtop10', null, 'Web Top 10', en ? '10 major web application risk categories with theory, browser labs, fixes and quizzes.' : '10 основных категорий рисков веб-приложений: теория, браузерные лабы, исправления и тесты.', '10 categories'],
      ['apihub', null, 'API Security Top 10:2023', en ? 'API-specific risks with compact explanations and offline simulations.' : 'Риски, характерные для API: краткая теория и offline-симуляции.', '10 risks'],
      ['llmhub', null, 'LLM Top 10', en ? 'LLM application risks and practical security mappings.' : 'Риски LLM-приложений и практические security-маппинги.', '10 risks'],
      ['asvs', null, 'ASVS 5.0.0', en ? 'A verification baseline for requirements, architecture, development, testing and procurement.' : 'База проверяемых требований для архитектуры, разработки, тестирования и закупок.', '345 requirements'],
      ['framework', 'wstg', 'WSTG 4.2', en ? 'Stable web security testing methodology: how to verify application controls.' : 'Стабильная методика web security testing: как проверять контроли приложения.', 'testing guide'],
      ['framework', 'samm', 'OWASP SAMM', en ? 'Maturity assessment and roadmap for an organization-wide AppSec program.' : 'Оценка зрелости и roadmap AppSec-программы организации.', 'maturity model'],
      ['framework', 'masvs-mastg', 'MASVS / MASTG', en ? 'Mobile application verification requirements and testing guidance.' : 'Требования и методика проверки безопасности mobile-приложений.', 'mobile'],
      ['framework', 'llmsvs', 'LLMSVS', en ? 'Testable security requirements for LLM systems.' : 'Проверяемые security-требования для LLM-систем.', 'AI verification'],
    ];
    return `<div class="lab-page owasp-page">
      ${tabs('overview')}
      <div data-watermark="OWASP" class="hero">
        <div class="row mb8"><span class="tag tc">OWASP</span><span class="tag tm">RØOT map</span></div>
        <h1>${en ? 'OWASP workspace' : 'Раздел OWASP'}</h1>
        <p>${en ? 'Risk awareness, hands-on practice and verification standards in one place. Pick the view that matches the job.' : 'Риски, практические лаборатории и стандарты проверки в одном месте. Выберите раздел под текущую задачу.'}</p>
      </div>
      <div class="owasp-project-grid">
        ${cards.map(([route, arg, title, body, meta]) => `<article class="owasp-project-card" data-route="${route}"${arg ? ` data-arg="${arg}"` : ''} role="link" tabindex="0">
          <div class="owasp-project-meta">${esc(meta)}</div>
          <h2>${esc(title)}</h2>
          <p>${esc(body)}</p>
        </article>`).join('')}
      </div>
    </div>`;
  }

  function renderAsvs() {
    const en = I18n.lang() === 'en';
    const pdf = `https://github.com/OWASP/ASVS/raw/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_${en ? 'en' : 'ru'}.pdf`;
    return `<div class="lab-page asvs-page">
      ${tabs('asvs')}
      <div data-watermark="ASVS" class="hero">
        <div class="row mb8"><span class="tag tc">OWASP</span><span class="tag tb">ASVS 5.0.0</span><span class="tag tm">stable</span></div>
        <h1>Application Security Verification Standard</h1>
        <p>${en ? 'ASVS turns broad security goals into testable application requirements. Use versioned identifiers such as v5.0.0-1.2.5 in tickets, reports and contracts.' : 'ASVS превращает общие цели безопасности в проверяемые требования к приложению. В задачах, отчётах и договорах используйте версионированные идентификаторы вида v5.0.0-1.2.5.'}</p>
        <div class="row asvs-actions">
          <a class="btn btnp" href="${pdf}" target="_blank" rel="noopener">${en ? 'Open official PDF' : 'Открыть официальный PDF'}</a>
          <a class="btn" href="https://owasp.org/www-project-application-security-verification-standard/" target="_blank" rel="noopener">OWASP project</a>
        </div>
      </div>

      <div class="asvs-levels">
        <div class="asvs-level"><strong>L1</strong><span>${en ? 'Baseline controls for every application' : 'Базовые контроли для любого приложения'}</span><small>70 ${en ? 'requirements' : 'требований'}</small></div>
        <div class="asvs-level"><strong>L2</strong><span>${en ? 'Most applications handling valuable data' : 'Большинство приложений с ценными данными'}</span><small>253 ${en ? 'cumulative requirements' : 'требования суммарно'}</small></div>
        <div class="asvs-level"><strong>L3</strong><span>${en ? 'High-value and high-assurance systems' : 'Критичные системы с высокой гарантией'}</span><small>345 ${en ? 'cumulative requirements' : 'требований суммарно'}</small></div>
      </div>

      <div class="card mb12">
        <div class="ch"><h2>${en ? 'How to use ASVS' : 'Как использовать ASVS'}</h2></div>
        <div class="cb theory">
          <ol>
            <li>${en ? 'Choose a target level from the application risk and business impact.' : 'Выберите целевой уровень по риску приложения и влиянию на бизнес.'}</li>
            <li>${en ? 'Mark every applicable requirement as pass, fail, not applicable, or not tested, with evidence.' : 'Для каждого применимого требования укажите pass, fail, not applicable или not tested и приложите доказательства.'}</li>
            <li>${en ? 'Reference the ASVS version and requirement ID in findings and acceptance criteria.' : 'Указывайте версию ASVS и ID требования в находках и критериях приёмки.'}</li>
          </ol>
          <p class="muted small">${en ? 'ASVS is a verification standard, not a claim that a product is automatically secure.' : 'ASVS — стандарт проверки, а не автоматическая гарантия безопасности продукта.'}</p>
        </div>
      </div>

      <h2 class="top10-grid-title">${en ? '17 verification chapters' : '17 глав проверки'}</h2>
      <div class="asvs-chapter-grid">
        ${CHAPTERS.map(([id, titleEn, titleRu, bodyEn, bodyRu]) => `<article class="asvs-chapter">
          <span class="lab-code">${esc(id)}</span>
          <h3>${esc(en ? titleEn : titleRu)}</h3>
          <p>${esc(en ? bodyEn : bodyRu)}</p>
        </article>`).join('')}
      </div>
      <p class="asvs-source muted small">${en ? 'Based on OWASP ASVS 5.0.0 chapter structure. Official standard: CC BY-SA 4.0. Always verify requirements against the linked release.' : 'Основано на структуре глав OWASP ASVS 5.0.0. Официальный стандарт: CC BY-SA 4.0. Проверяйте требования по указанному релизу.'}</p>
    </div>`;
  }

  return { tabs, sourceBlock, renderHub, renderAsvs, CHAPTERS };
})();
