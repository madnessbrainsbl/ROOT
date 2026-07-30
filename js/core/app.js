/* App shell, router, module pages — bilingual */
const UI = (() => {
  let routeName = 'home';
  let routeArg = null;
  const navGroupOpen = { owasp: false, frameworks: false };
  const OWASP_FRAMEWORK_IDS = new Set(['wstg', 'samm', 'masvs-mastg', 'llmsvs']);
  const NAV_GROUP_STATE_KEY = 'root_nav_groups';

  const HASH_ROUTES = {
    owasp: 'owasp',
    web: 'webtop10',
    lab: 'lab',
    api: 'apihub',
    llm: 'llmhub',
    asvs: 'asvs',
    frameworks: 'frameworks',
    cves: 'zerodays',
    kev: 'zeroday',
    cve: 'cve9',
    tools: 'tools',
    tool: 'tool',
    commands: 'commands',
    reports: 'reports',
    progress: 'progress',
    scoreboard: 'scoreboard',
    sql: 'sqlexplorer',
  };

  function parseHash(hash = location.hash) {
    const parts = String(hash).replace(/^#\/?/, '').split('/').filter(Boolean);
    if (!parts.length || !HASH_ROUTES[parts[0]]) return null;
    let name = HASH_ROUTES[parts[0]];
    let arg = null;
    try { arg = parts[1] ? decodeURIComponent(parts[1]) : null; }
    catch (_) { return null; }
    if (parts[0] === 'api' && arg) name = 'api10';
    if (parts[0] === 'llm' && arg) name = 'llm10';
    if (parts[0] === 'frameworks' && arg) name = 'framework';
    return [name, arg];
  }

  function routeHash(name, arg) {
    const names = {
      owasp: 'owasp', webtop10: 'web', lab: 'lab', apihub: 'api', api10: 'api',
      llmhub: 'llm', llm10: 'llm', asvs: 'asvs', zerodays: 'cves', zeroday: 'kev',
      frameworks: 'frameworks', framework: 'frameworks',
      cve9: 'cve', tools: 'tools', tool: 'tool', commands: 'commands',
      reports: 'reports', progress: 'progress', scoreboard: 'scoreboard',
      sqlexplorer: 'sql', sql: 'sql',
    };
    const segment = names[name] || 'lab';
    return `#/${segment}${arg ? `/${encodeURIComponent(arg)}` : ''}`;
  }

  function syncHash(name, arg, replace) {
    const hash = routeHash(name, arg);
    if (location.hash === hash) return;
    const url = location.pathname + location.search + hash;
    history[replace ? 'replaceState' : 'pushState'](null, '', url);
  }

  function activeNavGroup(name, arg) {
    const owaspRoute = ['owasp', 'webtop10', 'lab', 'apihub', 'api10', 'llmhub', 'llm10', 'asvs'].includes(name)
      || (name === 'framework' && OWASP_FRAMEWORK_IDS.has(arg));
    if (owaspRoute) return 'owasp';
    if (name === 'frameworks' || name === 'framework') return 'frameworks';
    return null;
  }

  function restoreNavGroups() {
    const raw = sessionStorage.getItem(NAV_GROUP_STATE_KEY);
    if (!raw) return;
    try {
      const saved = JSON.parse(raw);
      if (!saved || typeof saved !== 'object') return;
      Object.keys(navGroupOpen).forEach(group => {
        if (typeof saved[group] === 'boolean') navGroupOpen[group] = saved[group];
      });
    } catch (_) {
      sessionStorage.removeItem(NAV_GROUP_STATE_KEY);
    }
  }

  function persistNavGroups() {
    sessionStorage.setItem(NAV_GROUP_STATE_KEY, JSON.stringify(navGroupOpen));
  }

  function syncNavGroups(name, arg) {
    const active = activeNavGroup(name, arg);
    if (active && !navGroupOpen[active]) {
      navGroupOpen[active] = true;
      persistNavGroups();
    }
  }

  const esc = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  function toast(msg, type = 'ok') {
    const el = document.getElementById('toast');
    el.textContent = msg;
    el.className = 'show ' + type;
    clearTimeout(toast._t);
    toast._t = setTimeout(() => { el.className = ''; }, 2800);
  }

  /** Bottom SQL terminal panel. force: true=open, false=close, omit=toggle. */
  function openTerm(force) {
    const term = document.getElementById('term');
    if (!term) {
      // no panel in DOM — show explorer page
      route('sqlexplorer');
      return;
    }
    if (force === true) term.classList.add('open');
    else if (force === false) term.classList.remove('open');
    else term.classList.toggle('open');
    const open = term.classList.contains('open');
    document.body.classList.toggle('term-open', open);
    try {
      const st = Store.get();
      st.termOpen = open;
      Store.save();
    } catch (_) {}
    if (open && typeof SqlLab !== 'undefined') {
      SqlLab.updateTabs();
      SqlLab.buildSchema();
      const ta = document.getElementById('tsql');
      if (ta && !ta.value.trim()) {
        ta.value = 'SELECT name FROM sqlite_master WHERE type=\'table\' ORDER BY name;';
      }
      setTimeout(() => ta?.focus(), 50);
    }
  }

  function openSqlExplorer() {
    route('sqlexplorer');
  }


  function modTitle(m) {
    return I18n.lang() === 'en' ? m.name : m.nameRu;
  }

  const OWASP_TOP10_2025 = [
    { code: 'A01', legacyCode: 'A01', challengeIds: ['a01-idor-order', 'a01-mass-enum', 'a01-vert-priv', 'a10-imds', 'a10-localhost'], name: 'Broken Access Control', nameRu: 'Нарушение контроля доступа', blurb: { en: 'IDOR, privilege escalation, SSRF and path traversal caused by broken authorization.', ru: 'IDOR, повышение привилегий, SSRF и обход каталогов из-за ошибок контроля доступа.' } },
    { code: 'A02', legacyCode: 'A05', name: 'Security Misconfiguration', nameRu: 'Ошибки конфигурации безопасности', blurb: { en: 'Debug mode, default credentials, exposed storage and overly detailed errors.', ru: 'Режим отладки, стандартные пароли, открытые хранилища и подробные сообщения об ошибках.' } },
    { code: 'A03', legacyCode: 'A06', name: 'Software Supply Chain Failures', nameRu: 'Сбои цепочки поставки ПО', blurb: { en: 'Vulnerable dependencies, Log4Shell, compromised build pipelines and missing SBOMs.', ru: 'Уязвимые зависимости, Log4Shell, компрометация CI/CD и отсутствие SBOM.' } },
    { code: 'A04', legacyCode: 'A02', name: 'Cryptographic Failures', nameRu: 'Криптографические сбои', blurb: { en: 'Weak hashes, MD5, JWT alg=none and plaintext secrets.', ru: 'Слабые хеши, MD5, JWT с alg=none и секреты в открытом виде.' } },
    { code: 'A05', legacyCode: 'A03', name: 'Injection', nameRu: 'Инъекции', blurb: { en: 'SQL injection, XSS and OS command injection: data becomes code.', ru: 'SQL-инъекции, XSS и внедрение команд ОС: данные превращаются в код.' } },
    { code: 'A06', legacyCode: 'A04', name: 'Insecure Design', nameRu: 'Небезопасный дизайн', blurb: { en: 'Weak OTP flows, security questions and business-logic failures.', ru: 'Слабые OTP, контрольные вопросы и ошибки бизнес-логики.' } },
    { code: 'A07', legacyCode: 'A07', name: 'Authentication Failures', nameRu: 'Сбои аутентификации', blurb: { en: 'Credential stuffing, weak sessions, missing MFA and predictable cookies.', ru: 'Подстановка учётных данных, слабые сессии, отсутствие MFA и предсказуемые файлы cookie.' } },
    { code: 'A08', legacyCode: 'A08', name: 'Software or Data Integrity Failures', nameRu: 'Сбои целостности ПО и данных', blurb: { en: 'Unsafe deserialization, unsigned updates and compromised CI/CD.', ru: 'Небезопасная десериализация, неподписанные обновления и компрометация CI/CD.' } },
    { code: 'A09', legacyCode: 'A09', name: 'Security Logging and Alerting Failures', nameRu: 'Сбои журналирования и оповещения', blurb: { en: 'Missing audit logs or alerting lets attacks go unnoticed and secrets leak into logs.', ru: 'Отсутствие журналов аудита и оповещений оставляет атаки незамеченными, а секреты попадают в логи.' } },
    { code: 'A10', legacyCode: 'A10', challengeIds: ['a10-fail-open'], name: 'Mishandling of Exceptional Conditions', nameRu: 'Некорректная обработка нештатных условий', blurb: { en: 'Fail-open behavior, incomplete rollback and unsafe error handling.', ru: 'Fail-open, неполный откат операций и небезопасная обработка ошибок.' } },
  ];

  const OWASP_TOP10_2017 = { A01: 'A05', A02: 'A06', A03: 'A09', A04: 'A03', A05: 'A01', A06: '—', A07: 'A02', A08: 'A08', A09: 'A10', A10: '—' };

  function categoryForLab(code) {
    return OWASP_TOP10_2025.find(category => category.code === code) || null;
  }

  function moduleForCategory(category) {
    return category ? DATA.MODS.find(module => module.code === category.legacyCode) : null;
  }

  function categoryTitle(category) {
    return I18n.lang() === 'en' ? category.name : category.nameRu;
  }

  function categoryChallenges(category, module) {
    return category.challengeIds
      ? category.challengeIds.map(id => CHALLENGES.byId(id)).filter(Boolean)
      : CHALLENGES.byCode(module.code);
  }

  function categoryChallengeProgress(category, module) {
    const challenges = categoryChallenges(category, module);
    return { done: challenges.filter(challenge => Store.hasChallenge(challenge.id)).length, total: challenges.length };
  }

  function categoryStatus(progress) {
    if (!progress.done) return 'none';
    return progress.done === progress.total ? 'done' : 'partial';
  }

  function crumbTrail(name, arg) {
    const en = I18n.lang() === 'en';
    const t = (a, b) => (en ? a : b);
    const mod = code => (DATA.MODS || []).find(m => m.code === code);
    const fw = id => (typeof SecurityFrameworks !== 'undefined'
      ? SecurityFrameworks.ITEMS.find(i => i.id === id) : null);
    const fwGroup = id => (typeof SecurityFrameworks !== 'undefined'
      ? SecurityFrameworks.GROUPS.find(g => g.items.includes(id)) : null);

    const owasp = [t('OWASP', 'OWASP')];
    switch (name) {
      case 'owasp': return [...owasp, 'Overview'];
      case 'webtop10': return [...owasp, I18n.t('webTop10Nav')];
      case 'lab': {
        const category = categoryForLab(arg);
        return [...owasp, I18n.t('webTop10Nav'), category ? `${category.code} ${en ? category.name : category.nameRu}` : arg];
      }
      case 'apihub': return [...owasp, I18n.t('apiNav')];
      case 'api10': return [...owasp, I18n.t('apiNav'), arg];
      case 'llmhub': return [...owasp, I18n.t('llmNav')];
      case 'llm10': return [...owasp, I18n.t('llmNav'), arg];
      case 'asvs': return [...owasp, I18n.t('asvsNav')];
      case 'frameworks': return [I18n.t('frameworksNav'), t('Lifecycle map', 'Карта жизненного цикла')];
      case 'framework': {
        const item = fw(arg);
        const group = fwGroup(arg);
        const underOwasp = ['wstg', 'samm', 'masvs-mastg', 'llmsvs'].includes(arg);
        const trail = [underOwasp ? I18n.t('owaspNav') : I18n.t('frameworksNav')];
        if (group && !underOwasp) trail.push(en ? group.title_en : group.title_ru);
        const label = item ? (en ? item.title_en : item.title_ru) : arg;
        trail.push(underOwasp ? String(label).replace(/^OWASP\s+/, '') : label);
        return trail;
      }
      case 'zerodays': return [t('Zero-Day / KEV', 'Zero-Day / KEV')];
      case 'zeroday': case 'cve9': return [t('Zero-Day / KEV', 'Zero-Day / KEV'), arg];
      case 'tools': return [I18n.t('toolkit'), I18n.t('toolsNav')];
      case 'tool': {
        const row = (typeof Tools !== 'undefined' ? Tools.allSecTools() : [])
          .find(x => x.id === arg);
        return [I18n.t('toolkit'), I18n.t('toolsNav'), row ? row.name : arg];
      }
      case 'commands': return [I18n.t('toolkit'), I18n.t('cmdsNav')];
      case 'reports': return [I18n.t('toolkit'), I18n.t('reports')];
      case 'progress': return [t('Progress', 'Прогресс')];
      case 'sqlexplorer': return [I18n.t('sqlLab')];
      default: return [];
    }
  }

  function paintCrumbs() {
    const el = document.getElementById('crumbs');
    if (!el) return;
    const trail = crumbTrail(routeName, routeArg).filter(Boolean);
    el.innerHTML = trail
      .map((part, i) => `<span class="${i === trail.length - 1 ? 'crumb-now' : 'crumb'}">${esc(part)}</span>`)
      .join('<span class="crumb-sep" aria-hidden="true">/</span>');
  }

  function paintChrome() {
    document.documentElement.lang = I18n.lang();
    const set = (sel, text) => {
      const el = document.querySelector(sel);
      if (el) el.textContent = text;
    };
    set('[data-i18n="toolkit"]', I18n.t('toolkit'));
    set('[data-i18n="toolsNav"]', I18n.t('toolsNav'));
    set('[data-i18n="cmdsNav"]', I18n.t('cmdsNav'));
    set('[data-i18n="reports"]', I18n.t('reports'));
    set('[data-i18n="zeroDays"]', I18n.t('zeroDays'));
    set('[data-i18n="apiNav"]', I18n.t('apiNav'));
    set('[data-i18n="llmNav"]', I18n.t('llmNav'));

    const isEn = I18n.lang() === 'en';
    document.getElementById('lang-ru')?.classList.toggle('active', !isEn);
    document.getElementById('lang-en')?.classList.toggle('active', isEn);
    const termTitle = document.getElementById('term-title');
    if (termTitle) termTitle.textContent = isEn ? 'SQL terminal' : 'SQL-терминал';
    if (typeof SqlLab !== 'undefined' && SqlLab.updateTabs) SqlLab.updateTabs();
    paintCrumbs();
  }

  function setLang(lang) {
    if (lang !== 'ru' && lang !== 'en') return;
    if (I18n.lang() === lang) return;
    I18n.setLang(lang);
    paintChrome();
    refreshNav();
    // Stay on the same page + scroll (do not jump to home / top)
    route(routeName, routeArg, { keepScroll: true });
  }

  function switchLang() {
    I18n.toggle();
    paintChrome();
    refreshNav();
    route(routeName, routeArg, { keepScroll: true });
    toast(I18n.lang() === 'en' ? 'Language: English' : 'Язык: Русский', 'ok');
  }

  function refreshNav() {
    paintCrumbs();
    const nav = document.getElementById('navlist');
    if (!nav) return;

    const webActive = routeName === 'webtop10' || routeName === 'theory2025' || routeName === 'lab';
    const apiActive = routeName === 'apihub' || routeName === 'api10';
    const llmActive = routeName === 'llmhub' || routeName === 'llm10';
    const asvsActive = routeName === 'asvs';
    const owaspActive = routeName === 'owasp' || webActive || apiActive || llmActive || asvsActive
      || (routeName === 'framework' && OWASP_FRAMEWORK_IDS.has(routeArg));
    const frameworksActive = routeName === 'frameworks'
      || (routeName === 'framework' && !OWASP_FRAMEWORK_IDS.has(routeArg));
    const navEn = I18n.lang() === 'en';
    const byLabel = (a, b) => a.label.localeCompare(b.label, navEn ? 'en' : 'ru', { sensitivity: 'base' });
    const frameworkById = id => SecurityFrameworks.ITEMS.find(item => item.id === id);
    const frameworkTitle = item => (navEn ? item.title_en : item.title_ru) || item.title_en;
    const frameworkLink = (item, short) => {
      const active = routeName === 'framework' && routeArg === item.id;
      const label = short ? (item.code || frameworkTitle(item)) : frameworkTitle(item);
      return `<div class="ni ni-child ${active ? 'active' : ''}" data-nav="framework-${item.id}"
        data-route="framework" data-arg="${item.id}" role="button" tabindex="0">
        <span class="nn">${esc(label)}</span><span class="nd"></span>
      </div>`;
    };
    const owaspKids = [
      { label: I18n.t('webTop10Nav'), html: `<div class="ni ni-child ${webActive ? 'active' : ''}" data-nav="webtop10" data-route="webtop10" role="button" tabindex="0"><span class="nn">${I18n.t('webTop10Nav')}</span><span class="nd"></span></div>` },
      { label: I18n.t('apiNav'), html: `<div class="ni ni-child ${apiActive ? 'active' : ''}" data-nav="apihub" data-route="apihub" role="button" tabindex="0"><span class="nn">${I18n.t('apiNav')}</span><span class="nd"></span></div>` },
      { label: I18n.t('llmNav'), html: `<div class="ni ni-child ${llmActive ? 'active' : ''}" data-nav="llmhub" data-route="llmhub" role="button" tabindex="0"><span class="nn">${I18n.t('llmNav')}</span><span class="nd"></span></div>` },
      { label: I18n.t('asvsNav'), html: `<div class="ni ni-child ${asvsActive ? 'active' : ''}" data-nav="asvs" data-route="asvs" role="button" tabindex="0"><span class="nn">${I18n.t('asvsNav')}</span><span class="nd"></span></div>` },
      ...(typeof SecurityFrameworks === 'undefined' ? [] : [...OWASP_FRAMEWORK_IDS]
        .map(frameworkById).filter(Boolean).map(item => ({ label: item.code, html: frameworkLink(item, true) }))),
    ].sort(byLabel).map(item => item.html).join('');
    const frameworkKids = typeof SecurityFrameworks === 'undefined' ? '' : SecurityFrameworks.GROUPS
      .map(group => ({ group, label: (navEn ? group.title_en : group.title_ru) || group.title_en }))
      .sort(byLabel).map(({ group, label }) => {
      const items = group.items.map(frameworkById).filter(Boolean)
        .sort((a, b) => frameworkTitle(a).localeCompare(frameworkTitle(b), navEn ? 'en' : 'ru', { sensitivity: 'base' }));
      const active = items.some(item => routeName === 'framework' && routeArg === item.id);
      return `<details class="nav-subgroup"${active ? ' open' : ''}>
        <summary>${esc(label)}</summary>
        <div>${items.map(item => frameworkLink(item)).join('')}</div>
      </details>`;
    }).join('');
    nav.innerHTML = `
      <div class="nav-group ${navGroupOpen.owasp ? 'open' : ''}" id="nav-owasp">
        <div class="ni ni-parent ${owaspActive ? 'active' : ''}" data-nav="owasp" data-nav-toggle="owasp"
             role="button" tabindex="0" aria-expanded="${navGroupOpen.owasp}">
          <span class="nn">${I18n.t('owaspNav')}</span>
          <span class="nav-chevron">${navGroupOpen.owasp ? '▾' : '▸'}</span>
        </div>
        <div class="nav-children">
          <div class="ni ni-child ${routeName === 'owasp' ? 'active' : ''}" data-nav="owasp-home" data-route="owasp" role="button" tabindex="0">
            <span class="nn">${I18n.t('owaspOverview')}</span><span class="nd"></span>
          </div>
          ${owaspKids}
        </div>
      </div>
      <div class="nsep"></div>
      <div class="nav-group ${navGroupOpen.frameworks ? 'open' : ''}" id="nav-frameworks">
        <div class="ni ni-parent ${frameworksActive ? 'active' : ''}" data-nav="frameworks" data-nav-toggle="frameworks"
             role="button" tabindex="0" aria-expanded="${navGroupOpen.frameworks}">
          <span class="nn">${I18n.t('frameworksNav')}</span>
          <span class="nav-chevron">${navGroupOpen.frameworks ? '▾' : '▸'}</span>
        </div>
        <div class="nav-children">
          <div class="ni ni-child ${routeName === 'frameworks' ? 'active' : ''}" data-nav="frameworks-home" data-route="frameworks" role="button" tabindex="0">
            <span class="nn">${I18n.t('frameworksOverview')}</span><span class="nd"></span>
          </div>
          ${frameworkKids}
        </div>
      </div>`;
  }

  function toggleNavGroup(name) {
    if (!(name in navGroupOpen)) return;
    navGroupOpen[name] = !navGroupOpen[name];
    persistNavGroups();
    refreshNav();
  }

  /** Optional hub page (cards) — opened only if needed; labs open via sidebar A01–A10 */
  function renderWebTop10() {
    const lang = I18n.lang();
    const cards = OWASP_TOP10_2025.map(category => {
      const m = moduleForCategory(category);
      if (!m) return '';
      const cp = categoryChallengeProgress(category, m);
      const qp = Store.quizProgress(m.code);
      const st = categoryStatus(cp);
      const blurb = I18n.pick(category.blurb);
      const stLabel = st === 'done'
        ? (lang === 'en' ? 'Done' : 'Готово')
        : st === 'partial'
          ? (lang === 'en' ? 'In progress' : 'В процессе')
          : (lang === 'en' ? 'Not started' : 'Не начато');
      return `
        <a class="top10-card" href="#/lab/${category.code}" data-route="lab" data-arg="${category.code}">
          <div class="top10-card-head">
            <span class="lab-code">${category.code}</span>
          </div>
          <h3 class="top10-card-title">${esc(categoryTitle(category))}</h3>
          <div class="top10-card-meta muted small">${esc(stLabel)}</div>
          <p class="top10-card-blurb">${esc(blurb)}</p>
          <div class="top10-card-stats">
            <span>${I18n.t('tabLab')}: ${cp.done}/${cp.total}</span>
            <span>${I18n.t('tabQuiz')}: ${qp.answered}/${qp.total || 50}</span>
          </div>
        </a>`;
    }).join('');

    return `
      <div class="lab-page webtop10-page">
        ${Owasp.tabs('web')}
        <div data-watermark="TOP 10" class="hero">
          <h1>${I18n.t('webTop10Title')}</h1>
          <p>${I18n.t('webTop10Desc')}</p>
        </div>
        <div class="top10-grid">${cards}</div>
        ${Owasp.sourceBlock('https://owasp.org/Top10/2025/', 'Official OWASP Top 10:2025', 'Официальный сайт OWASP Top 10:2025')}
      </div>`;
  }

  function renderScoreboard() {
    const stats = Store.stats(DATA.MODS);
    return `
      <div data-watermark="SCORE" class="hero">
        <h1>${I18n.t('scoreboard')}</h1>
        <p>${I18n.t('scoreboardDesc')}</p>
        <div class="stat-grid">
          <div class="stat"><div class="n" style="color:var(--grn)">${stats.challenges}/${stats.challengesTotal}</div><div class="l">${I18n.t('statFlags')}</div></div>
          <div class="stat"><div class="n" style="color:var(--pur)">${stats.challengesTotal ? Math.round(stats.challenges/stats.challengesTotal*100) : 0}%</div><div class="l">${I18n.t('completion')}</div></div>
          <div class="stat"><div class="n" style="color:var(--blu)">${stats.done}/${stats.total}</div><div class="l">${I18n.t('modDone')}</div></div>
        </div>
      </div>
      ${OWASP_TOP10_2025.map(category => {
        const m = moduleForCategory(category);
        if (!m) return '';
        const list = categoryChallenges(category, m);
        const cp = categoryChallengeProgress(category, m);
        return `<div class="card mb12">
          <div class="ch">
            <span class="lab-code" style="margin-right:8px">${category.code}</span>
            <h2>${esc(categoryTitle(category))}</h2>
            <span class="tag tb">${cp.done}/${cp.total}</span>
            <button class="btn btns" style="margin-left:auto" onclick="UI.route('lab','${category.code}')">${I18n.t('openLab')}</button>
          </div>
          <div class="cb">
            <table class="score-table">
              <thead><tr>
                <th>${I18n.t('challenge')}</th>
                <th>${I18n.t('status')}</th>
              </tr></thead>
              <tbody>
                ${list.map(c => {
                  const done = Store.hasChallenge(c.id);
                  return `<tr class="${done ? 'done' : ''}" onclick="UI.route('lab','${category.code}');setTimeout(()=>Labs.selectChallenge('${m.code}','${c.id}'),50)" style="cursor:pointer">
                    <td><strong>${esc(I18n.pick(c.title))}</strong><div class="small muted">${esc(c.id)}</div></td>
                    <td>${done ? '<span class="tag tm">✓</span>' : '<span class="tag th">—</span>'}</td>
                  </tr>`;
                }).join('')}
              </tbody>
            </table>
          </div>
        </div>`;
      }).join('')}`;
  }

  /** Preserve Theory/Lab/Fix/Quiz across language switch (same lab) */
  let activeLabTab = (() => {
    try {
      const t = sessionStorage.getItem('zd_lab_tab');
      if (['theory', 'lab', 'fix', 'quiz'].includes(t)) return t;
    } catch (_) {}
    return 'theory';
  })();

  function persistLabTab() {
    try { sessionStorage.setItem('zd_lab_tab', activeLabTab); } catch (_) {}
  }
  /** Requested tab when opening a lab from the hub */
  let pendingLabTab = null;

  function openLabTab(code, tab) {
    pendingLabTab = tab || 'theory';
    route('lab', code);
  }

  function quizTabBadge(code) {
    const prog = Store.quizProgress(code);
    const total = prog.total || 0;
    if (!total) return '';
    if (prog.done) return `<span class="quiz-count done">✓</span>`;
    if (prog.answered > 0) return `<span class="quiz-count">${prog.answered}/${total}</span>`;
    return `<span class="quiz-count">${total}</span>`;
  }

  /** Category content: Theory / Lab / Fix / Quiz (used inside Web Top 10 shell) */
  function renderLabBody(code) {
    const category = categoryForLab(code);
    const m = moduleForCategory(category);
    if (!category || !m) return '<p>Module not found</p>';
    const legacyCode = m.code;
    const cp = categoryChallengeProgress(category, m);
    const hasFlag = cp.done > 0;
    const qp = Store.quizProgress(legacyCode);
    const tab = ['theory', 'lab', 'fix', 'quiz'].includes(activeLabTab) ? activeLabTab : 'theory';

    let theoryHtml = '';
    if (typeof THEORY_2025 !== 'undefined' && THEORY_2025.byLab[legacyCode]) {
      theoryHtml = THEORY_2025.forLab(legacyCode, I18n.lang());
    } else {
      // THEORY_2025.byLab covers A01–A10; this is the short summary carried on
      // the module itself, used only if a new module ships without theory yet.
      theoryHtml = I18n.pick(m.theory);
    }

    const categoryIndex = OWASP_TOP10_2025.indexOf(category);
    const prevCode = OWASP_TOP10_2025[categoryIndex - 1]?.code || null;
    const nextCode = OWASP_TOP10_2025[categoryIndex + 1]?.code || null;

    return `
      <div class="lab-page">
      <div class="card lab-card">
        <div class="ch lab-header">
          <div class="lab-title">
            <span class="lab-code">${category.code}</span>
            <h2 class="lab-heading">${esc(categoryTitle(category))}</h2>
          </div>
          <div class="row lab-header-actions">
            ${cp.done >= cp.total ? '<span class="tag tm">CLEAR</span>' : hasFlag ? '<span class="tag th">IN PROGRESS</span>' : ''}
            ${qp.done ? `<span class="tag tm">${I18n.t('quizDoneBadge')}</span>` : ''}
          </div>
        </div>
        <div class="tabs" id="lab-tabs" role="tablist">
          <button type="button" class="tab ${tab === 'theory' ? 'active' : ''}" role="tab" data-tab="theory" aria-selected="${tab === 'theory'}">${I18n.t('tabTheory')}</button>
          <button type="button" class="tab ${tab === 'lab' ? 'active' : ''}" role="tab" data-tab="lab" aria-selected="${tab === 'lab'}">${I18n.t('tabLab')}</button>
          <button type="button" class="tab ${tab === 'fix' ? 'active' : ''}" role="tab" data-tab="fix" aria-selected="${tab === 'fix'}">${I18n.t('tabFix')}</button>
          <button type="button" class="tab tab-quiz ${tab === 'quiz' ? 'active' : ''}" role="tab" data-tab="quiz" aria-selected="${tab === 'quiz'}">${I18n.t('tabQuiz')} ${quizTabBadge(code)}</button>
        </div>
        <div class="tabpane ${tab === 'theory' ? 'active' : ''}" id="tp-theory" role="tabpanel">
          <div class="theory-wrap">
            <div class="theory">${theoryHtml}</div>
            <aside class="theory-meta">
              <div class="meta-block">
                <div class="meta-label">${I18n.t('cweLabel')}</div>
                <div class="meta-tags">${m.cwe.map(c => `<code class="inline">${c}</code>`).join('')}</div>
              </div>
              <div class="meta-block">
                <div class="meta-label">${I18n.t('owaspMap')}</div>
                <div class="meta-line">2017: <strong>${OWASP_TOP10_2017[category.code]}</strong></div>
                <div class="meta-line">2021: <strong>${category.code === 'A10' ? '—' : m.owasp2021}</strong></div>
                <div class="meta-line">2025: <strong>${category.code}</strong></div>
              </div>

            </aside>
          </div>
        </div>
        <div class="tabpane ${tab === 'lab' ? 'active' : ''}" id="tp-lab" role="tabpanel">
          <p class="muted small mb12">${I18n.t('goalFlag')} ${I18n.t('flagHint')}</p>
          ${Labs.render(legacyCode, category.challengeIds)}
        </div>
        <div class="tabpane ${tab === 'fix' ? 'active' : ''}" id="tp-fix" role="tabpanel">
          <div class="code-cmp">
            <div class="code-block bad"><div class="ctitle">${I18n.t('vulnerable')}</div><pre>${esc(m.vulnCode)}</pre></div>
            <div class="code-block good"><div class="ctitle">${I18n.t('secure')}</div><pre>${esc(m.fixCode)}</pre></div>
          </div>
        </div>
        <div class="tabpane ${tab === 'quiz' ? 'active' : ''}" id="tp-quiz" role="tabpanel">
          <div class="quiz-shell" id="quiz-root" data-code="${legacyCode}">${renderQuizView(legacyCode)}</div>
        </div>
      </div>
      <div class="row lab-footer">
        ${prevCode
          ? `<button type="button" class="btn" onclick="UI.route('lab','${prevCode}')">← ${prevCode}</button>`
          : `<span></span>`}
        <button type="button" class="btn" onclick="Tools.openChainsForOwasp('${category.code}')">${I18n.t('relatedChains')}</button>
        ${nextCode
          ? `<button type="button" class="btn btnp" onclick="UI.route('lab','${nextCode}')">${nextCode} →</button>`
          : `<span></span>`}
      </div>
      ${Owasp.sourceBlock('https://owasp.org/Top10/2025/', 'Official OWASP Top 10:2025', 'Официальный сайт OWASP Top 10:2025')}
      </div>`;
  }

  function renderLab(code) {
    return renderLabBody(code);
  }

  /** In-session cursor: which question index is shown (or total = results) */
  const quizCursor = {};

  function quizExplain(q) {
    if (!q) return I18n.t('quizEmptyWhy');
    const raw = (I18n.pick(q.e) || '').trim();
    if (raw) return raw;
    return I18n.t('quizEmptyWhy');
  }

  function quizFirstOpenIndex(code) {
    const m = DATA.MODS.find(x => x.code === code);
    if (!m || !m.quiz) return 0;
    const total = m.quiz.length;
    const st = Store.get().quiz[code] || { answered: {} };
    for (let i = 0; i < total; i++) {
      if (st.answered == null || st.answered[i] == null) return i;
    }
    return total; // all answered → results
  }

  function renderQuizView(code) {
    const m = DATA.MODS.find(x => x.code === code);
    if (!m || !m.quiz || !m.quiz.length) {
      return `<p class="muted">${I18n.lang() === 'en' ? 'No questions.' : 'Нет вопросов.'}</p>`;
    }
    const total = m.quiz.length;
    if (quizCursor[code] == null) quizCursor[code] = quizFirstOpenIndex(code);
    let qi = quizCursor[code];
    if (qi < 0) qi = 0;
    if (qi > total) qi = total;
    quizCursor[code] = qi;

    const prog = Store.quizProgress(code);
    const pct = total ? Math.round((prog.answered / total) * 100) : 0;
    // Advance the bar as you move through questions (not only after answers land)
    const barPct = qi >= total ? 100 : Math.max(pct, Math.round((qi / total) * 100));

    if (qi >= total) {
      const right = prog.score;
      const wrong = Math.max(0, prog.answered - right);
      const scorePct = total ? Math.round((right / total) * 100) : 0;
      return `
        <div class="quiz-results">
          <h3>${I18n.t('quizResults')} — ${esc(code)}</h3>
          <p class="muted small">${esc(I18n.t('quizScore'))}</p>
          <div class="quiz-score-ring" style="--p:${scorePct}" aria-label="${scorePct}%">${scorePct}%</div>
          <div class="quiz-stats">
            <div class="quiz-stat good"><b>${right}</b><span>${I18n.t('quizRight')}</span></div>
            <div class="quiz-stat bad"><b>${wrong}</b><span>${I18n.t('quizIncorrect')}</span></div>
            <div class="quiz-stat"><b>${total}</b><span>${I18n.t('quizTotal')}</span></div>
          </div>
          <div class="quiz-actions" style="justify-content:center">
            <button type="button" class="btn btnp" onclick="UI.quizRestart('${code}')">${I18n.t('quizRetry')}</button>
          </div>
        </div>`;
    }

    const q = m.quiz[qi];
    if (!q || !Array.isArray(q.opts) || !q.opts.length) {
      return `<p class="muted">Q${qi + 1}: invalid data</p>
        <div class="quiz-actions">
          <button type="button" class="btn btnp" onclick="UI.quizNext('${code}')">${I18n.t('quizNext')} →</button>
        </div>`;
    }

    const st = Store.get().quiz[code] || { answered: {}, selected: {} };
    const revealed = st.answered && st.answered[qi] != null;
    const selected = revealed ? st.selected?.[qi] : null;
    const isOk = revealed ? !!st.answered[qi] : null;
    const ansIdx = Number(q.ans);
    const correctText = (ansIdx >= 0 && ansIdx < q.opts.length) ? I18n.pick(q.opts[ansIdx]) : '';
    const yourText = (selected != null && q.opts[selected] != null) ? I18n.pick(q.opts[selected]) : '';

    const optsHtml = q.opts.map((o, oi) => {
      let cls = 'qo';
      if (revealed) {
        if (oi === ansIdx) cls += ' ok';
        else if (oi === selected && selected !== ansIdx) cls += ' bad';
        else cls += ' dim';
      }
      const dis = revealed ? 'disabled' : '';
      const click = revealed ? '' : `onclick="UI.ansQuiz('${code}',${qi},${oi})"`;
      return `<button type="button" class="${cls}" ${dis} ${click}>
        <span class="qo-letter">${String.fromCharCode(65 + oi)}</span>
        <span class="qo-text">${esc(I18n.pick(o))}</span>
      </button>`;
    }).join('');

    let feedback = '';
    if (revealed) {
      const panel = isOk ? 'ok-panel' : 'bad-panel';
      const title = isOk ? I18n.t('quizCorrect') : I18n.t('quizWrong');
      feedback = `
        <div class="qe show ${panel}" role="status">
          <div class="qe-title">${esc(title)}</div>
          ${!isOk ? `<div class="qe-line"><span>${esc(I18n.t('quizYourAnswer'))}:</span> ${esc(yourText)}</div>` : ''}
          <div class="qe-line"><span>${esc(I18n.t('quizCorrectAnswer'))}:</span> <strong>${esc(correctText)}</strong></div>
          <div class="qe-why"><strong>${esc(I18n.t('quizWhy'))}:</strong> ${esc(quizExplain(q))}</div>
        </div>`;
    }

    const isLast = qi >= total - 1;
    const nextLabel = isLast ? I18n.t('quizFinish') : I18n.t('quizNext');
    const actions = revealed
      ? `<div class="quiz-actions">
           <button type="button" class="btn btnp" onclick="UI.quizNext('${code}')">${esc(nextLabel)} →</button>
         </div>`
      : '';

    return `
      <div class="quiz-intro-line">${esc(I18n.t('quizOneAtATime'))}</div>
      <div class="quiz-head">
        <div class="quiz-meta">
          ${I18n.t('quizProgress')}: <strong>${qi + 1}</strong> ${I18n.t('quizOf')} <strong>${total}</strong>
          · ${I18n.t('quizRight')}: <strong>${prog.score}</strong>
          · ${I18n.t('quizIncorrect')}: <strong>${Math.max(0, prog.answered - prog.score)}</strong>
        </div>
        <div class="quiz-meta"><strong>${pct}%</strong></div>
      </div>
      <div class="quiz-bar" role="progressbar" aria-valuenow="${prog.answered}" aria-valuemin="0" aria-valuemax="${total}">
        <i style="width:${barPct}%"></i>
      </div>
      <div class="qq" id="qq-${code}-${qi}">
        <div class="qt">${qi + 1}. ${esc(I18n.pick(q.q))}</div>
        <div class="qo-list" role="group" aria-label="${esc(I18n.t('tabQuiz'))}">
          ${optsHtml}
        </div>
        ${feedback}
        ${actions}
      </div>`;
  }

  function paintQuiz(code) {
    const root = document.getElementById('quiz-root');
    if (!root) return;
    root.innerHTML = renderQuizView(code);
    const quizTab = document.querySelector('#lab-tabs .tab[data-tab="quiz"]');
    if (quizTab) quizTab.innerHTML = `${I18n.t('tabQuiz')} ${quizTabBadge(code)}`;
  }

  function ansQuiz(code, qi, sel) {
    const m = DATA.MODS.find(x => x.code === code);
    if (!m || !m.quiz || !m.quiz[qi]) return;
    const q = m.quiz[qi];
    Store.markQuiz(code, qi, Number(sel) === Number(q.ans), sel);
    quizCursor[code] = qi;
    activeLabTab = 'quiz';
    paintQuiz(code);
    requestAnimationFrame(() => {
      document.querySelector('#quiz-root .qe.show')?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    });
    refreshNav();
  }

  function quizNext(code) {
    const m = DATA.MODS.find(x => x.code === code);
    if (!m || !m.quiz) return;
    const total = m.quiz.length;
    const cur = quizCursor[code] == null ? quizFirstOpenIndex(code) : quizCursor[code];
    quizCursor[code] = Math.min(cur + 1, total);
    activeLabTab = 'quiz';
    paintQuiz(code);
    document.getElementById('quiz-root')?.scrollIntoView({ block: 'start', behavior: 'smooth' });
  }

  function quizRestart(code) {
    Store.resetQuiz(code);
    quizCursor[code] = 0;
    activeLabTab = 'quiz';
    paintQuiz(code);
    refreshNav();
  }

  function bindLabTabs() {
    const tabsRoot = document.getElementById('lab-tabs');
    if (!tabsRoot) return;
    tabsRoot.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', () => activateLabTab(tab.dataset.tab));
    });
  }

  function activateLabTab(name) {
    const allowed = ['theory', 'lab', 'fix', 'quiz'];
    if (!allowed.includes(name)) return;
    activeLabTab = name;
    persistLabTab();
    const tabsRoot = document.getElementById('lab-tabs');
    if (!tabsRoot) return;
    tabsRoot.querySelectorAll('.tab').forEach(t => {
      const on = t.dataset.tab === name;
      t.classList.toggle('active', on);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    const card = tabsRoot.closest('.lab-card') || document;
    card.querySelectorAll('.tabpane').forEach(p => {
      p.classList.toggle('active', p.id === 'tp-' + name);
    });
    if (name === 'quiz') {
      const root = document.getElementById('quiz-root');
      const code = root?.dataset?.code;
      if (code) paintQuiz(code);
    }
  }

  function route(name, arg, opts) {
    if (name === 'theory2025') name = 'webtop10';
    opts = opts || {};
    const main = document.getElementById('main');
    const prevScroll = main ? main.scrollTop : 0;

    if (name === 'lab' && arg && arg !== routeArg) {
      activeLabTab = pendingLabTab || 'theory';
      pendingLabTab = null;
      persistLabTab();
    }

    routeName = name;
    // keep 0 / false if ever used; only null/undefined → null
    routeArg = (arg === undefined || arg === null || arg === '') ? null : arg;
    syncNavGroups(routeName, routeArg);
    sessionStorage.setItem('zd_route', JSON.stringify([routeName, routeArg]));
    if (!opts.fromHistory) syncHash(routeName, routeArg, opts.replaceHash || opts.keepScroll);
    // Don't force-close sidebar on pure language re-render
    if (!opts.keepScroll) {
      document.body.classList.remove('sidebar-open');
      document.getElementById('menu-toggle')?.setAttribute('aria-expanded', 'false');
    }
    refreshNav();

    document.querySelectorAll('[data-nav]').forEach(el => {
      const nav = el.dataset.nav;
      el.classList.toggle('active',
        nav === name
        || (['owasp', 'webtop10', 'lab', 'apihub', 'api10', 'llmhub', 'llm10', 'asvs'].includes(name) && nav === 'owasp')
        || (name === 'owasp' && nav === 'owasp-home')
        || (name === 'lab' && nav === 'webtop10')
        || (['frameworks', 'framework'].includes(name) && nav === 'frameworks')
        || (name === 'frameworks' && nav === 'frameworks-home')
        || (name === 'framework' && nav === `framework-${routeArg}`)
        || (name === 'zeroday' && nav === 'zerodays')
        || (name === 'tool' && nav === 'tools')
        || (name === 'api10' && nav === 'apihub')
        || (name === 'llm10' && nav === 'llmhub')
        || (['payloads', 'cmds', 'chains', 'jwt', 'kuber', 'commands'].includes(name) && nav === 'commands'));
    });

    if (name === 'owasp') main.innerHTML = Owasp.renderHub();
    else if (name === 'lab') {
      main.innerHTML = renderLab(arg);
      bindLabTabs();
      // re-activate saved lab tab after re-render (lang switch)
      if (activeLabTab && activeLabTab !== 'theory') {
        try { activateLabTab(activeLabTab); } catch (_) {}
      }
    }
    else if (name === 'webtop10') main.innerHTML = renderWebTop10();
    else if (name === 'scoreboard') main.innerHTML = renderScoreboard();
    else if (name === 'apihub') main.innerHTML = ApiTop10.renderHub();
    else if (name === 'api10') {
      main.innerHTML = ApiTop10.renderItem(arg);
      ApiTop10.bindTabs();
    }
    else if (name === 'llmhub') main.innerHTML = LlmTop10.renderHub();
    else if (name === 'llm10') {
      main.innerHTML = LlmTop10.renderHub();
      LlmTop10.openArea(arg);
    }
    else if (name === 'asvs') main.innerHTML = Owasp.renderAsvs();
    else if (name === 'frameworks') main.innerHTML = SecurityFrameworks.renderHub();
    else if (name === 'framework') main.innerHTML = SecurityFrameworks.renderItem(arg);
    else if (name === 'zerodays') {
      main.innerHTML = ZeroDays.renderHub();
      ZeroDays.bindHub?.();
    }
    else if (name === 'zeroday') {
      main.innerHTML = ZeroDays.renderItem(arg);
      ZeroDays.bindTabs?.();
    }
    else if (name === 'cve9') {
      if (typeof CvesCvss9 !== 'undefined') CvesCvss9.renderItem(arg).then(html => { main.innerHTML = html; });
    }
    else if (name === 'sqlexplorer' || name === 'sql') {
      main.innerHTML = SqlLab.renderExplorer();
      SqlLab.updateTabs();
      SqlLab.buildSchema();
    }
    else if (name === 'tools') main.innerHTML = Tools.renderToolsCatalog();
    else if (name === 'tool') {
      if (typeof Tools !== 'undefined' && Tools.renderToolPage) Tools.renderToolPage(arg);
      else if (typeof Tools !== 'undefined' && Tools.showTool) Tools.showTool(arg, { skipRoute: true });
    }
    // Legacy routes → unified Commands workspace
    else if (name === 'payloads') { route('commands', 'payloads', opts); return; }
    else if (name === 'cmds') { route('commands', 'builder', opts); return; }
    else if (name === 'chains') { route('commands', 'chains', opts); return; }
    else if (name === 'jwt') { route('commands', 'jwt', opts); return; }
    else if (name === 'kuber') { route('commands', 'kuber', opts); return; }
    else if (name === 'commands') {
      main.innerHTML = Tools.renderCommandsHub(arg || 'payloads');
      Tools.mountCommandsHub?.(arg || 'payloads');
    }
    else if (name === 'reports') {
      main.innerHTML = Tools.renderReports();
      Tools.mountReports?.();
    }
    else if (name === 'progress') main.innerHTML = Tools.renderProgress();
    else {
      // Unknown route — only fall back when not a keepScroll re-paint
      if (opts.keepScroll && routeName) {
        /* stay put as best-effort */
      } else {
        route('lab', 'A01');
        return;
      }
    }

    if (opts.keepScroll) {
      // restore after layout
      requestAnimationFrame(() => {
        if (main) main.scrollTop = prevScroll;
      });
    } else {
      main.scrollTop = 0;
      Array.from(main.children).forEach(el => el.classList.add('page-in'));
    }
  }

  /* persist & restore scroll position across reloads */
  function saveScroll() { sessionStorage.setItem('zd_scrollY', window.scrollY); }
  function restoreScroll() {
    const y = sessionStorage.getItem('zd_scrollY');
    if (y) setTimeout(() => window.scrollTo(0, +y), 50);
  }

  async function boot() {
    Store.migrateFlags();
    restoreNavGroups();
    document.documentElement.lang = I18n.lang();
    paintChrome();
    refreshNav();

    bindShell();

    // URL wins over session state so routes can be shared.
    const hashRoute = parseHash();
    const lastRoute = (() => {
      try {
        const r = JSON.parse(sessionStorage.getItem('zd_route'));
        return r && r[0] ? r : null;
      } catch (_) { return null; }
    })();

    document.getElementById('main').innerHTML =
      `<div class="root-spin-wrap"><div class="root-spinner"></div></div>`;
    try {
      await SqlLab.init();
      if (typeof ZeroDays !== 'undefined') ZeroDays.seedSql();
      if (typeof SqlLab !== 'undefined' && SqlLab.seedSecToolsCatalog) {
        SqlLab.seedSecToolsCatalog();
        SqlLab.persist();
      }
    } catch (e) {
      // SQL seed can fail — still restore last page, don't force A01
      console.warn(e);
    }
    paintChrome();
    if (hashRoute) route(hashRoute[0], hashRoute[1], { fromHistory: true });
    else if (lastRoute) route(lastRoute[0], lastRoute[1], { replaceHash: true });
    else route('lab', 'A01', { replaceHash: true });
    restoreScroll();
  }

  function bindShell() {
    document.addEventListener('click', event => {
      const menu = event.target.closest('#menu-toggle');
      if (menu) {
        const open = document.body.classList.toggle('sidebar-open');
        menu.setAttribute('aria-expanded', String(open));
        return;
      }
      const language = event.target.closest('[data-lang]');
      if (language) { setLang(language.dataset.lang); return; }
      const navToggle = event.target.closest('[data-nav-toggle]');
      if (navToggle) { toggleNavGroup(navToggle.dataset.navToggle); return; }
      const hashLink = event.target.closest('a[href^="#/"]');
      if (hashLink) {
        const target = parseHash(hashLink.getAttribute('href'));
        if (target) {
          event.preventDefault();
          route(target[0], target[1]);
          return;
        }
      }
      const routeTarget = event.target.closest('[data-route]');
      if (routeTarget) {
        event.preventDefault();
        route(routeTarget.dataset.route, routeTarget.dataset.arg);
        return;
      }
      const database = event.target.closest('[data-sql-db]');
      if (database) { SqlLab.switchDB(database.dataset.sqlDb); return; }
      if (event.target.closest('#term-close')) { openTerm(false); return; }
      const sqlAction = event.target.closest('[data-sql-action]')?.dataset.sqlAction;
      if (sqlAction === 'history-next') SqlLab.histNav(1);
      else if (sqlAction === 'history-previous') SqlLab.histNav(-1);
      else if (sqlAction === 'clear') SqlLab.clearOut();
      else if (sqlAction === 'run') SqlLab.runQ();
    });
    document.addEventListener('keydown', event => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      const navToggle = event.target.closest('[data-nav-toggle]');
      if (navToggle) {
        event.preventDefault();
        toggleNavGroup(navToggle.dataset.navToggle);
        return;
      }
      const target = event.target.closest('[data-route]');
      if (!target) return;
      event.preventDefault();
      route(target.dataset.route, target.dataset.arg);
    });
    const routeFromLocation = () => {
      const target = parseHash();
      if (target) route(target[0], target[1], { fromHistory: true });
    };
    window.addEventListener('popstate', routeFromLocation);
    window.addEventListener('hashchange', routeFromLocation);
  }

  window.addEventListener('beforeunload', saveScroll);

  return {
    boot, route, toast, openTerm, openSqlExplorer, refreshNav,
    ansQuiz, quizNext, quizRestart, activateLabTab, openLabTab,
    switchLang, setLang, paintChrome, parseHash, routeHash,
  };
})();

document.addEventListener('DOMContentLoaded', () => UI.boot());


// Ctrl/Cmd+Enter runs SQL when terminal focused
document.addEventListener('keydown', (e) => {
  if (!(e.ctrlKey || e.metaKey) || e.key !== 'Enter') return;
  const ta = document.getElementById('tsql');
  if (!ta || document.activeElement !== ta) return;
  e.preventDefault();
  if (typeof SqlLab !== 'undefined') SqlLab.runQ();
});
