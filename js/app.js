/* App shell, router, module pages — bilingual */
const UI = (() => {
  let routeName = 'home';
  let routeArg = null;

  const HASH_ROUTES = {
    web: 'webtop10',
    lab: 'lab',
    api: 'apihub',
    llm: 'llmhub',
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
    return [name, arg];
  }

  function routeHash(name, arg) {
    const names = {
      webtop10: 'web', lab: 'lab', apihub: 'api', api10: 'api',
      llmhub: 'llm', llm10: 'llm', zerodays: 'cves', zeroday: 'kev',
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
    history[replace ? 'replaceState' : 'pushState'](null, '', hash);
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

  /** Sidebar expand state for Web / API / LLM Top 10 */
  let webTop10Expanded = false;
  let apiTop10Expanded = false;
  let llmTop10Expanded = false;

  function setNavGroupOpen(groupId, open) {
    const group = document.getElementById(groupId);
    if (!group) return false;
    group.classList.toggle('open', open);
    const chev = group.querySelector('.nav-chevron');
    if (chev) chev.textContent = open ? '▾' : '▸';
    const parent = group.querySelector('.ni-parent');
    if (parent) parent.setAttribute('aria-expanded', open ? 'true' : 'false');
    const kids = group.querySelector('.nav-children');
    if (kids) {
      if (open) kids.removeAttribute('hidden');
      else kids.setAttribute('hidden', '');
    }
    return true;
  }

  function toggleWebTop10Nav(ev) {
    if (ev) { ev.preventDefault(); ev.stopPropagation(); }
    webTop10Expanded = !webTop10Expanded;
    if (!setNavGroupOpen('nav-webtop10', webTop10Expanded)) refreshNav();
  }

  function toggleApiTop10Nav(ev) {
    if (ev) { ev.preventDefault(); ev.stopPropagation(); }
    apiTop10Expanded = !apiTop10Expanded;
    if (!setNavGroupOpen('nav-apitop10', apiTop10Expanded)) refreshNav();
  }

  function toggleLlmTop10Nav(ev) {
    if (ev) { ev.preventDefault(); ev.stopPropagation(); }
    llmTop10Expanded = !llmTop10Expanded;
    if (!setNavGroupOpen('nav-llmtop10', llmTop10Expanded)) refreshNav();
  }

  function refreshNav() {
    const nav = document.getElementById('navlist');
    if (!nav) return;

    const onLab = routeName === 'lab';
    const onWebHub = routeName === 'webtop10' || routeName === 'theory2025';
    const onApiHub = routeName === 'apihub';
    const onApiItem = routeName === 'api10';
    const onLlmHub = routeName === 'llmhub';
    const onLlmItem = routeName === 'llm10';

    // Green circle = currently selected only (not historical progress)
    // Display numbers as 01…10 (no API/LLM prefix in UI)
    const pad2 = (id) => {
      const m = String(id).match(/(\d+)$/);
      return m ? String(+m[1]).padStart(2, '0') : esc(id);
    };

    const webKids = DATA.MODS.map(m => {
      const active = onLab && routeArg === m.code;
      return `<div class="ni ni-child ${active ? 'active' : ''}"
        onclick="event.stopPropagation();UI.route('lab','${m.code}')">
        <span class="nc">${m.code}</span>
        <span class="nn">${esc(modTitle(m))}</span>
        <span class="nd ${active ? 'on' : ''}"></span>
      </div>`;
    }).join('');

    let apiKids = '';
    if (typeof ApiTop10 !== 'undefined' && ApiTop10.ITEMS) {
      const en = I18n.lang() === 'en';
      apiKids = ApiTop10.ITEMS.map(it => {
        const active = onApiItem && routeArg === it.id;
        const title = en ? it.title_en : it.title_ru;
        return `<div class="ni ni-child ${active ? 'active' : ''}"
          onclick="event.stopPropagation();UI.route('api10','${it.id}')">
          <span class="nc">${pad2(it.id)}</span>
          <span class="nn">${esc(title)}</span>
          <span class="nd ${active ? 'on' : ''}"></span>
        </div>`;
      }).join('');
    }

    let llmKids = '';
    if (typeof LlmTop10 !== 'undefined' && LlmTop10.ITEMS) {
      const en = I18n.lang() === 'en';
      llmKids = LlmTop10.ITEMS.map(it => {
        const active = onLlmItem && routeArg === it.id;
        const title = en ? it.title_en : it.title_ru;
        return `<div class="ni ni-child ${active ? 'active' : ''}"
          onclick="event.stopPropagation();UI.route('llm10','${it.id}')">
          <span class="nc">${pad2(it.id)}</span>
          <span class="nn">${esc(title)}</span>
          <span class="nd ${active ? 'on' : ''}"></span>
        </div>`;
      }).join('');
    }

    nav.innerHTML = `
      <div class="nav-group ${webTop10Expanded ? 'open' : ''}" id="nav-webtop10">
        <div class="ni ni-parent ${onWebHub ? 'active' : ''}" data-nav="webtop10"
             role="button" tabindex="0" aria-expanded="${webTop10Expanded ? 'true' : 'false'}"
             onclick="UI.toggleWebTop10Nav(event)"
             onkeydown="if(event.key==='Enter'||event.key===' '){UI.toggleWebTop10Nav(event)}">
          <span class="icon ic-doc"></span>
          <span class="nn">${I18n.t('webTop10Nav')}</span>
          <span class="nav-chevron" aria-hidden="true">${webTop10Expanded ? '▾' : '▸'}</span>
        </div>
        <div class="nav-children" ${webTop10Expanded ? '' : 'hidden'}>${webKids}</div>
      </div>
      <div class="nav-group ${apiTop10Expanded ? 'open' : ''}" id="nav-apitop10">
        <div class="ni ni-parent ${onApiHub ? 'active' : ''}" data-nav="apihub"
             role="button" tabindex="0" aria-expanded="${apiTop10Expanded ? 'true' : 'false'}"
             onclick="UI.toggleApiTop10Nav(event)"
             onkeydown="if(event.key==='Enter'||event.key===' '){UI.toggleApiTop10Nav(event)}">
          <span class="icon ic-doc"></span>
          <span class="nn">${I18n.t('apiNav')}</span>
          <span class="nav-chevron" aria-hidden="true">${apiTop10Expanded ? '▾' : '▸'}</span>
        </div>
        <div class="nav-children" ${apiTop10Expanded ? '' : 'hidden'}>${apiKids}</div>
      </div>
      <div class="nav-group ${llmTop10Expanded ? 'open' : ''}" id="nav-llmtop10">
        <div class="ni ni-parent ${onLlmHub || onLlmItem ? 'active' : ''}" data-nav="llmhub"
             role="button" tabindex="0" aria-expanded="${llmTop10Expanded ? 'true' : 'false'}"
             onclick="UI.toggleLlmTop10Nav(event)"
             onkeydown="if(event.key==='Enter'||event.key===' '){UI.toggleLlmTop10Nav(event)}">
          <span class="icon ic-doc"></span>
          <span class="nn">${I18n.t('llmNav')}</span>
          <span class="nav-chevron" aria-hidden="true">${llmTop10Expanded ? '▾' : '▸'}</span>
        </div>
        <div class="nav-children" ${llmTop10Expanded ? '' : 'hidden'}>${llmKids}</div>
      </div>`;
  }

  /** Optional hub page (cards) — opened only if needed; labs open via sidebar A01–A10 */
  function renderWebTop10() {
    const lang = I18n.lang();
    const intro = (typeof THEORY_2025 !== 'undefined' && THEORY_2025.intro)
      ? THEORY_2025.pick(THEORY_2025.intro, lang)
      : '';
    const cards = DATA.MODS.map(m => {
      const cp = Store.moduleChallengeProgress(m.code);
      const qp = Store.quizProgress(m.code);
      const st = Store.moduleStatus(m.code);
      const blurb = I18n.pick(m.blurb || { ru: '', en: '' });
      const stLabel = st === 'done'
        ? (lang === 'en' ? 'Done' : 'Готово')
        : st === 'partial'
          ? (lang === 'en' ? 'In progress' : 'В процессе')
          : (lang === 'en' ? 'Not started' : 'Не начато');
      return `
        <article class="top10-card" onclick="UI.route('lab','${m.code}')">
          <div class="top10-card-head">
            <span class="lab-code">${m.code}</span>
          </div>
          <h3 class="top10-card-title">${esc(modTitle(m))}</h3>
          <div class="top10-card-meta muted small">${esc(stLabel)}</div>
          <p class="top10-card-blurb">${esc(blurb)}</p>
          <div class="top10-card-stats">
            <span>${I18n.t('tabLab')}: ${cp.done}/${cp.total}</span>
            <span>${I18n.t('tabQuiz')}: ${qp.answered}/${qp.total || 50}</span>
          </div>
          <div class="top10-card-actions" onclick="event.stopPropagation()">
            <button type="button" class="btn btnp btns" onclick="UI.route('lab','${m.code}')">${I18n.t('openCategory')}</button>
          </div>
        </article>`;
    }).join('');

    return `
      <div class="lab-page webtop10-page">
        <div class="hero">
          <h1>${I18n.t('webTop10Title')}</h1>
          <p>${I18n.t('webTop10Desc')}</p>
        </div>
        ${intro ? `<div class="card mb12"><div class="cb theory">${intro}</div></div>` : ''}
        <h2 class="top10-grid-title">${I18n.t('webTop10GridTitle')}</h2>
        <div class="top10-grid">${cards}</div>
      </div>`;
  }

  function renderTheory2025() {
    return renderWebTop10();
  }

  function renderScoreboard() {
    const stats = Store.stats(DATA.MODS);
    return `
      <div class="hero">
        <h1>${I18n.t('scoreboard')}</h1>
        <p>${I18n.t('scoreboardDesc')}</p>
        <div class="stat-grid">
          <div class="stat"><div class="n" style="color:var(--grn)">${stats.challenges}/${stats.challengesTotal}</div><div class="l">${I18n.t('statFlags')}</div></div>
          <div class="stat"><div class="n" style="color:var(--pur)">${stats.challengesTotal ? Math.round(stats.challenges/stats.challengesTotal*100) : 0}%</div><div class="l">${I18n.t('completion')}</div></div>
          <div class="stat"><div class="n" style="color:var(--blu)">${stats.done}/${stats.total}</div><div class="l">${I18n.t('modDone')}</div></div>
        </div>
      </div>
      ${DATA.MODS.map(m => {
        const list = CHALLENGES.byCode(m.code);
        const cp = Store.moduleChallengeProgress(m.code);
        return `<div class="card mb12">
          <div class="ch">
            <span class="lab-code" style="margin-right:8px">${m.code}</span>
            <h2>${esc(modTitle(m))}</h2>
            <span class="tag tb">${cp.done}/${cp.total}</span>
            <button class="btn btns" style="margin-left:auto" onclick="UI.route('lab','${m.code}')">${I18n.t('openLab')}</button>
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
                  return `<tr class="${done ? 'done' : ''}" onclick="UI.route('lab','${m.code}');setTimeout(()=>Labs.selectChallenge('${m.code}','${c.id}'),50)" style="cursor:pointer">
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
    webTop10Expanded = true;
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
    const m = DATA.MODS.find(x => x.code === code);
    if (!m) return '<p>Module not found</p>';
    const hasFlag = Store.hasFlag(code);
    const cp = Store.moduleChallengeProgress(code);
    const qp = Store.quizProgress(code);
    const tab = ['theory', 'lab', 'fix', 'quiz'].includes(activeLabTab) ? activeLabTab : 'theory';

    let theoryHtml = '';
    const map2025 = (typeof THEORY_2025 !== 'undefined' && THEORY_2025.mapLabTo2025)
      ? THEORY_2025.mapLabTo2025[code] : m.owasp2025;
    if (typeof THEORY_2025 !== 'undefined' && THEORY_2025.byLab[code]) {
      theoryHtml = THEORY_2025.forLab(code, I18n.lang());
    } else if (typeof THEORY !== 'undefined' && THEORY[code]) {
      theoryHtml = I18n.pick(THEORY[code]);
    } else {
      theoryHtml = I18n.pick(m.theory);
    }

    const prevCode = code !== 'A01' ? `A${String(+code.slice(1) - 1).padStart(2, '0')}` : null;
    const nextCode = code !== 'A10' ? `A${String(+code.slice(1) + 1).padStart(2, '0')}` : null;

    return `
      <div class="lab-page">
      <div class="card lab-card">
        <div class="ch lab-header">
          <div class="lab-title">
            <span class="lab-code">${m.code}</span>
            <h2 class="lab-heading">${esc(modTitle(m))}</h2>
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
                <div class="meta-line">2021: <strong>${m.owasp2021}</strong></div>
                <div class="meta-line">2025: <strong>${map2025 || m.owasp2025}</strong></div>
              </div>

            </aside>
          </div>
        </div>
        <div class="tabpane ${tab === 'lab' ? 'active' : ''}" id="tp-lab" role="tabpanel">
          <p class="muted small mb12">${I18n.t('goalFlag')} ${I18n.t('flagHint')}</p>
          ${Labs.render(code)}
        </div>
        <div class="tabpane ${tab === 'fix' ? 'active' : ''}" id="tp-fix" role="tabpanel">
          <div class="code-cmp">
            <div class="code-block bad"><div class="ctitle">${I18n.t('vulnerable')}</div><pre>${esc(m.vulnCode)}</pre></div>
            <div class="code-block good"><div class="ctitle">${I18n.t('secure')}</div><pre>${esc(m.fixCode)}</pre></div>
          </div>
        </div>
        <div class="tabpane ${tab === 'quiz' ? 'active' : ''}" id="tp-quiz" role="tabpanel">
          <div class="quiz-shell" id="quiz-root" data-code="${code}">${renderQuizView(code)}</div>
        </div>
      </div>
      <div class="row lab-footer">
        ${prevCode
          ? `<button type="button" class="btn" onclick="UI.route('lab','${prevCode}')">← ${prevCode}</button>`
          : `<span></span>`}
        <button type="button" class="btn" onclick="Tools.openChainsForOwasp('${code}')">${I18n.t('relatedChains')}</button>
        ${nextCode
          ? `<button type="button" class="btn btnp" onclick="UI.route('lab','${nextCode}')">${nextCode} →</button>`
          : `<span></span>`}
      </div>
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
      webTop10Expanded = true;
    }
    if (name === 'api10' || name === 'apihub') {
      apiTop10Expanded = true;
    }
    if (name === 'llm10' || name === 'llmhub') {
      llmTop10Expanded = true;
    }

    routeName = name;
    // keep 0 / false if ever used; only null/undefined → null
    routeArg = (arg === undefined || arg === null || arg === '') ? null : arg;
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
        || (name === 'zeroday' && nav === 'zerodays')
        || (name === 'tool' && nav === 'tools')
        || (name === 'api10' && nav === 'apihub')
        || (name === 'llm10' && nav === 'llmhub')
        || (['payloads', 'cmds', 'chains', 'jwt', 'kuber', 'commands'].includes(name) && nav === 'commands'));
    });

    if (name === 'lab') {
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
      main.innerHTML = LlmTop10.renderItem(arg);
      LlmTop10.bindTabs?.();
    }
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
      const routeTarget = event.target.closest('[data-route]');
      if (routeTarget) { route(routeTarget.dataset.route, routeTarget.dataset.arg); return; }
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
      const target = event.target.closest('[data-route]');
      if (!target) return;
      event.preventDefault();
      route(target.dataset.route, target.dataset.arg);
    });
    window.addEventListener('popstate', () => {
      const target = parseHash();
      if (target) route(target[0], target[1], { fromHistory: true });
    });
  }

  window.addEventListener('beforeunload', saveScroll);

  return {
    boot, route, toast, openTerm, openSqlExplorer, refreshNav,
    ansQuiz, quizNext, quizRestart, activateLabTab, openLabTab,
    toggleWebTop10Nav, toggleApiTop10Nav, toggleLlmTop10Nav,
    switchLang, setLang, paintChrome, parseHash, routeHash,
  };
})();

document.addEventListener('DOMContentLoaded', () => UI.boot());

// Matrix binary rain in header
(function () {
  const hdr = document.getElementById('hdr');
  if (!hdr) return;
  hdr.style.position = 'relative';

  const cv = document.createElement('canvas');
  cv.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;pointer-events:none;opacity:.13;';
  hdr.insertBefore(cv, hdr.firstChild);

  const ctx = cv.getContext('2d');
  const FS = 11;
  let drops = [];

  function resize() {
    const w = hdr.offsetWidth, h = hdr.offsetHeight;
    if (!w || !h) return;
    cv.width = w; cv.height = h;
    const cols = Math.floor(w / FS);
    // start drops at random positions across full height — looks already running on reload
    drops = Array.from({length: cols}, () => Math.random() * (h / FS));
  }

  resize();
  new ResizeObserver(resize).observe(hdr);

  function tick() {
    ctx.fillStyle = 'rgba(13,13,13,.18)';
    ctx.fillRect(0, 0, cv.width, cv.height);
    ctx.fillStyle = '#ef4444';
    ctx.font = FS + 'px "JetBrains Mono",monospace';

    for (let i = 0; i < drops.length; i++) {
      ctx.fillText(Math.random() < .5 ? '0' : '1', i * FS, drops[i] * FS);
      drops[i] += .35;
      if (drops[i] * FS > cv.height) drops[i] = 0;
    }
  }

  setInterval(tick, 55);
}());

// Ctrl/Cmd+Enter runs SQL when terminal focused
document.addEventListener('keydown', (e) => {
  if (!(e.ctrlKey || e.metaKey) || e.key !== 'Enter') return;
  const ta = document.getElementById('tsql');
  if (!ta || document.activeElement !== ta) return;
  e.preventDefault();
  if (typeof SqlLab !== 'undefined') SqlLab.runQ();
});
