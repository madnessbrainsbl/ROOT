/* RØOT toolkit: sec_tools catalog, payloads, chains, reports */
const Tools = (() => {
  const esc = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

  function copy(text) {
    const t = String(text ?? '');
    if (!t) return;
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(t).then(
        () => UI.toast(I18n.t('copied'), 'ok'),
        () => UI.toast(I18n.t('copyFail'), 'err')
      );
    } else {
      try {
        const ta = document.createElement('textarea');
        ta.value = t;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        UI.toast(I18n.t('copied'), 'ok');
      } catch (_) {
        UI.toast(I18n.t('copyFail'), 'err');
      }
    }
  }

  /** Copy from base64 data attribute (safe for quotes / XSS payloads in HTML). */
  function copyFromB64(el) {
    try {
      const b64 = el?.getAttribute?.('data-cmd-b64') || '';
      const text = decodeURIComponent(escape(atob(b64)));
      copy(text);
    } catch (_) {
      UI.toast(I18n.t('copyFail'), 'err');
    }
  }

  /**
   * Command box + copy icon (Attack Chains, Kuber, etc.).
   * Uses base64 data-attr — never put raw command into HTML attributes.
   */
  function cmdBlockHtml(cmd, opts) {
    const o = opts || {};
    const text = String(cmd ?? '');
    const en = I18n.lang() === 'en';
    const label = o.label || (en ? 'Copy' : 'Копировать');
    let b64 = '';
    try {
      b64 = btoa(unescape(encodeURIComponent(text)));
    } catch (_) {
      b64 = '';
    }
    return `<div class="cmd-block">
      <button type="button" class="btn cmd-copy-btn" data-cmd-b64="${b64}"
        title="${esc(label)}" aria-label="${esc(label)}"
        onclick="event.stopPropagation();Tools.copyFromB64(this)">⎘</button>
      <div class="cmd">${esc(text)}</div>
    </div>`;
  }

  /** All tools from SQLite sec_tools (fallback: TOOLS_CATALOG JS) */
  function allSecTools() {
    if (typeof SqlLab !== 'undefined' && SqlLab.ready) {
      const rows = SqlLab.query(`SELECT * FROM sec_tools ORDER BY CASE track
        WHEN 'offensive' THEN 0 WHEN 'appsec' THEN 1 WHEN 'devsecops' THEN 2
        WHEN 'mobile' THEN 3 ELSE 4 END, code IS NULL, code, name`);
      if (rows.length) return rows;
    }
    return (typeof TOOLS_CATALOG !== 'undefined' && TOOLS_CATALOG.items) ? TOOLS_CATALOG.items : [];
  }

  function trackLabel(track, en) {
    const m = {
      offensive: 'Offensive Security',
      mobile: en ? 'Mobile' : 'Mobile',
      appsec: en ? 'AppSec stack' : 'AppSec',
      devsecops: en ? 'DevSecOps' : 'DevSecOps',
    };
    return m[track] || track;
  }

  function catLabel(cat, en) {
    const m = {
      design: en ? 'Design & threat modeling' : 'Design & threat modeling',
      'code-review': en ? 'Code review' : 'Проверка кода',
      'ai-code': en ? 'AI code scanning' : 'AI-анализ кода',
      sast: 'SAST',
      sca: 'SCA',
      'attack-surface': en ? 'Attack-surface mapping' : 'Карта поверхности атаки',
      'passive-osint': en ? 'Passive OSINT' : 'Пассивный OSINT',
      'domain-discovery': en ? 'Domain & subdomain discovery' : 'Домены и поддомены',
      'cloud-identity-recon': en ? 'Cloud & identity recon' : 'Облачная и identity-разведка',
      'network-discovery': en ? 'Network & service discovery' : 'Сеть и сервисы',
      fingerprinting: en ? 'Technology fingerprinting' : 'Определение технологий',
      'internal-recon': en ? 'Internal network recon' : 'Внутренняя сетевая разведка',
      'traffic-analysis': en ? 'Traffic analysis' : 'Анализ трафика',
      'credential-utilities': en ? 'Credential utilities' : 'Работа со словарями',
      'http-probing': en ? 'HTTP probing' : 'Проверка HTTP-сервисов',
      screenshots: en ? 'Screenshots' : 'Снимки экранов',
      'web-crawling': en ? 'Web crawling' : 'Обход веб-приложений',
      'url-collection': en ? 'URL collection' : 'Сбор URL',
      'content-discovery': en ? 'Content discovery' : 'Поиск каталогов и контента',
      'parameter-discovery': en ? 'Parameter discovery' : 'Поиск параметров',
      'vulnerability-discovery': en ? 'Vulnerability discovery' : 'Поиск уязвимостей',
      'exploitation-validation': en ? 'Exploitation & validation' : 'Эксплуатация и проверка',
      'post-exploitation': en ? 'Post-exploitation' : 'Постэксплуатация',
      'reporting-retest': en ? 'Reporting & retest' : 'Отчёт и повторная проверка',
       'dependency-management': en ? 'Dependency management' : 'Управление зависимостями',
       'appsec-platform': en ? 'Application security platforms' : 'Платформы AppSec',
       secrets: en ? 'Secret scanners' : 'Secret scanners',
      'secret-scanning': en ? 'Secret scanning' : 'Поиск утёкших секретов',
      iac: en ? 'IaC scanning' : 'IaC scanning',
      precommit: en ? 'Pre-commit hooks' : 'Pre-commit hooks',
      container: en ? 'Container scanning' : 'Container scanning',
      sbom: 'SBOM',
      signing: en ? 'Artifact signing' : 'Artifact signing',
      policy: en ? 'Policy-as-code' : 'Policy-as-code',
      admission: en ? 'Admission controllers' : 'Admission controllers',
      cicd: en ? 'CI/CD security' : 'CI/CD security',
      dast: 'DAST',
      api: en ? 'API security' : 'API security',
      cspm: 'CSPM',
      runtime: 'Runtime',
      waf: 'WAF',
      k8s: 'Kubernetes',
      kubernetes: 'Kubernetes',
      chaos: en ? 'Chaos engineering' : 'Хаос-инжиниринг',
      'secrets-mgmt': en ? 'Secrets management' : 'Управление секретами',
      'supply-chain': en ? 'Supply chain' : 'Supply chain',
      network: en ? 'Network' : 'Сеть',
      fuzzing: en ? 'Fuzzing' : 'Fuzzing',
      cloud: en ? 'Cloud security' : 'Cloud security',
      observability: en ? 'Monitoring & observability' : 'Мониторинг и наблюдаемость',
      'edr-xdr': 'EDR / XDR',
      siem: 'SIEM / SOAR',
      'threat-intel': en ? 'Threat intelligence' : 'Аналитика угроз',
      'detection-engineering': en ? 'Detection engineering' : 'Разработка детектов',
      ndr: 'NDR',
      'threat-hunting': en ? 'Threat hunting' : 'Поиск угроз',
      dfir: 'DFIR',
      identity: en ? 'Identity security' : 'Безопасность идентификации',
      iam: 'IAM / PAM',
      'ai-security': en ? 'AI security' : 'Безопасность AI',
      proxy: en ? 'Intercepting proxies' : 'Перехватывающие прокси',
      exploitation: en ? 'Exploitation' : 'Эксплуатация',
      'reverse-engineering': en ? 'Reverse engineering' : 'Реверс-инжиниринг',
      mobile: en ? 'Platforms & device tooling' : 'Платформы и работа с устройствами',
      aspm: 'ASPM',
      iast: 'IAST',
      rasp: 'RASP',
      misc: en ? 'Other' : 'Прочее',
      osint: 'OSINT',
      recon: en ? 'Reconnaissance' : 'Разведка',
      'api-discovery': en ? 'API discovery' : 'Поиск API',
      'vuln-scan': en ? 'Vulnerability scanners' : 'Сканеры уязвимостей',
      cms: en ? 'CMS scanners' : 'Сканеры CMS',
      'web-vuln': en ? 'Web vulnerabilities' : 'Веб-уязвимости',
      injection: en ? 'Injection' : 'Инъекции',
      sqli: 'SQLi',
      xss: 'XSS',
      ssti: 'SSTI',
      ssrf: 'SSRF',
      jwt: en ? 'JWT attacks' : 'Атаки на JWT',
      'prototype-pollution': en ? 'Prototype pollution' : 'Prototype pollution',
      'http-smuggling': en ? 'HTTP request smuggling' : 'HTTP request smuggling',
      'cache-poisoning': en ? 'Cache poisoning' : 'Отравление кэша',
      evasion: en ? 'WAF evasion' : 'Обход WAF',
      delivery: en ? 'Delivery & payloads' : 'Доставка и payload',
      c2: en ? 'Command & control' : 'Command & control',
      persistence: en ? 'Persistence' : 'Закрепление',
      'privilege-escalation': en ? 'Privilege escalation' : 'Повышение привилегий',
      'credential-access': en ? 'Credential access' : 'Доступ к учётным данным',
      'lateral-movement': en ? 'Lateral movement' : 'Боковое перемещение',
      'defense-evasion': en ? 'Defense evasion' : 'Обход защиты',
      exfiltration: en ? 'Exfiltration' : 'Вывод данных',
      'active-directory': 'Active Directory',
      redteam: en ? 'Red team frameworks' : 'Red team фреймворки',
    };
    return m[cat] || cat;
  }

  const TOOLS_STATE_KEY = 'root_tools_catalog_state';
  const _expandedTracks = new Set();
  const _expandedCats = new Set();
  let _trackFilter = '*';
  let _q = '';

  function saveToolsState() {
    sessionStorage.setItem(TOOLS_STATE_KEY, JSON.stringify({
      track: _trackFilter, q: _q,
      tracks: [..._expandedTracks], categories: [..._expandedCats],
    }));
  }

  function restoreToolsState() {
    try {
      const state = JSON.parse(sessionStorage.getItem(TOOLS_STATE_KEY));
      if (!state || typeof state !== 'object') return;
      _trackFilter = typeof state.track === 'string' ? state.track : '*';
      _q = typeof state.q === 'string' ? state.q : '';
      _expandedTracks.clear();
      _expandedCats.clear();
      (Array.isArray(state.tracks) ? state.tracks : []).forEach(track => _expandedTracks.add(track));
      (Array.isArray(state.categories) ? state.categories : []).forEach(category => _expandedCats.add(category));
    } catch (_) {}
  }

  function renderToolsCatalog() {
    const en = I18n.lang() === 'en';
    restoreToolsState();
    const list = allSecTools();
    const tracks = ['offensive', 'appsec', 'devsecops', 'mobile'].filter(tr =>
      list.some(t => t.track === tr)
    );
    // any extra tracks from data
    list.forEach(t => {
      if (t.track && !tracks.includes(t.track)) tracks.push(t.track);
    });
    tracks.sort((a, b) => trackLabel(a, en).localeCompare(trackLabel(b, en), en ? 'en' : 'ru', { sensitivity: 'base' }));
    if (_trackFilter !== '*' && !tracks.includes(_trackFilter)) _trackFilter = '*';
    const byTrack = {};
    list.forEach(t => {
      const k = t.track || 'other';
      if (!byTrack[k]) byTrack[k] = [];
      byTrack[k].push(t);
    });
    return `
      <div class="lab-page tools-page">
        <div data-watermark="TOOLS" class="hero tools-hero">
          <h1>${en ? 'Tools' : 'Инструменты'}</h1>
          <p class="tools-hero-desc">${en
            ? 'Catalog of security tools by track. Expand a group, open a tool for description and install notes.'
            : 'Каталог security-инструментов по направлениям. Раскрой группу, открой инструмент — описание и установка.'}</p>
          <div class="tools-search-wrap">
            <input id="tools-q" class="tools-search" type="search" value="${esc(_q)}" placeholder="${en ? 'Filter: name, tag, mitre…' : 'Фильтр: name, tag, mitre…'}"
              oninput="Tools.filterTools(this.value)" autocomplete="off">
          </div>
          <div class="tools-track-chips" id="tools-track-chips">
            <button type="button" class="chip ${_trackFilter === '*' ? 'active' : ''}" data-track="*" onclick="Tools.filterTrack(this,'*')">${en ? 'All' : 'Все'}</button>
            ${tracks.map(tr => `<button type="button" class="chip ${_trackFilter === tr ? 'active' : ''}" data-track="${esc(tr)}" onclick="Tools.filterTrack(this,'${esc(tr)}')">${esc(trackLabel(tr, en))} (${(byTrack[tr] || []).length})</button>`).join('')}
          </div>
        </div>
        <div id="tools-list" class="tools-list">
          ${renderToolsGroups(byTrack, en, _trackFilter, _q)}
        </div>
      </div>`;
  }

  const CATEGORIZED_TRACKS = new Set(['offensive', 'appsec', 'devsecops', 'mobile']);
  const OFFENSIVE_PHASE_ORDER = [
    'passive-osint', 'domain-discovery', 'cloud-identity-recon', 'network-discovery', 'fingerprinting', 'internal-recon', 'traffic-analysis', 'credential-utilities',
    'http-probing', 'screenshots', 'web-crawling', 'url-collection', 'content-discovery', 'parameter-discovery', 'api-discovery', 'attack-surface',
    'recon', 'vulnerability-discovery', 'exploitation-validation', 'post-exploitation', 'reporting-retest',
  ];

  const sortToolsByName = (tools, en) => [...tools].sort((a, b) =>
    String(a.name || a.id).localeCompare(String(b.name || b.id), en ? 'en' : 'ru', {
      sensitivity: 'base', numeric: true,
    })
  );

  function toggleTrackGroup(track) {
    const el = document.querySelector(`.tools-group[data-track="${track.replace(/"/g, '')}"]`);
    if (!el) return;
    const collapsed = el.classList.toggle('collapsed');
    if (collapsed) _expandedTracks.delete(track);
    else _expandedTracks.add(track);
    saveToolsState();
    const chev = el.querySelector(':scope > .tools-group-head .tools-chevron');
    if (chev) chev.textContent = collapsed ? '▸' : '▾';
  }

  function toggleCat(track, cat) {
    const key = track + ':' + cat;
    const selected = _expandedCats.has(key);
    [..._expandedCats].forEach(openKey => {
      if (openKey.startsWith(track + ':')) _expandedCats.delete(openKey);
    });
    if (!selected) _expandedCats.add(key);
    saveToolsState();
    refreshToolsList();
  }

  function renderCategorizedBody(track, rows, en) {
    const byCat = {};
    rows.forEach(t => {
      const c = (t.category || 'other').toLowerCase();
      if (!byCat[c]) byCat[c] = [];
      byCat[c].push(t);
    });
    const keys = Object.keys(byCat).sort((a, b) => {
      if (track === 'offensive') {
        return OFFENSIVE_PHASE_ORDER.indexOf(a) - OFFENSIVE_PHASE_ORDER.indexOf(b);
      }
      return catLabel(a, en).localeCompare(catLabel(b, en), en ? 'en' : 'ru', { sensitivity: 'base' });
    });
    const selected = keys.find(cat => _expandedCats.has(track + ':' + cat));
    const categories = `<div class="tools-cats-grid">${keys.map(cat => {
      const list = sortToolsByName(byCat[cat], en);
      const active = selected === cat;
      return `<div class="tools-cat ${active ? 'selected' : ''}" data-cat="${esc(cat)}">
        <div class="tools-cat-head" role="button" tabindex="0"
          onclick="event.stopPropagation();Tools.toggleCat('${esc(track)}','${esc(cat)}')"
          onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();Tools.toggleCat('${esc(track)}','${esc(cat)}')}">
          <span class="tools-chevron" aria-hidden="true">${active ? '▾' : '▸'}</span>
          <strong class="tools-cat-title">${esc(catLabel(cat, en))}</strong>
        </div>
      </div>`;
    }).join('')}</div>`;
    if (!selected) return categories;
    const list = sortToolsByName(byCat[selected], en);
    return `${categories}<section class="tools-cat-results">
      <div class="tools-grid">${list.map(t => toolCard(t, en)).join('')}</div>
    </section>`;
  }

  function renderToolsGroups(byTrack, en, trackFilter, q) {
    const ql = (q || '').toLowerCase().trim();
    const keys = Object.keys(byTrack).sort((a, b) =>
      trackLabel(a, en).localeCompare(trackLabel(b, en), en ? 'en' : 'ru', { sensitivity: 'base' })
    );
    let html = '';
    keys.forEach(tr => {
      if (trackFilter && trackFilter !== '*' && tr !== trackFilter) return;
      let rows = byTrack[tr] || [];
      if (ql) {
        rows = rows.filter(t => {
          const blob = [t.name,t.id,t.category,t.mitre,t.tags,t.desc_en,t.desc_ru,t.code].join(' ').toLowerCase();
          return blob.includes(ql);
        });
      }
      rows = sortToolsByName(rows, en);
      if (!rows.length) return;
      const singleTrack = trackFilter && trackFilter !== '*';
      // A selected track reveals its category navigator, not every tool card.
      const forceOpenTrack = singleTrack || !!ql;
      const collapsed = forceOpenTrack ? false : !_expandedTracks.has(tr);
      const body = CATEGORIZED_TRACKS.has(tr) && !ql
        ? renderCategorizedBody(tr, rows, en)
        : `<div class="tools-grid">${rows.map(t => toolCard(t, en)).join('')}</div>`;
      const subtitle = (() => {
        if (!CATEGORIZED_TRACKS.has(tr)) return '';
        const counts = {};
        rows.forEach(t => { counts[t.category] = (counts[t.category] || 0) + 1; });
        const top = Object.entries(counts)
          .sort(([a], [b]) => catLabel(a, en).localeCompare(catLabel(b, en), en ? 'en' : 'ru', { sensitivity: 'base' }))
          .slice(0, 4)
          .map(([cat]) => catLabel(cat, en));
        if (!top.length) return '';
        const more = Object.keys(counts).length > top.length ? ' · …' : '';
        return `<span class="tools-group-sub muted">${esc(top.join(' · ') + more)}</span>`;
      })();
      const header = singleTrack ? '' : `<div class="ch tools-group-head" role="button" tabindex="0"
          onclick="Tools.toggleTrackGroup('${esc(tr)}')"
          onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();Tools.toggleTrackGroup('${esc(tr)}')}">
          <span class="tools-chevron" aria-hidden="true">${collapsed ? '▸' : '▾'}</span>
          <div class="tools-group-titles">
            <h2>${esc(trackLabel(tr, en))}</h2>
            ${subtitle}
          </div>
        </div>`;
      html += `<div class="${singleTrack ? 'tools-group tools-group-single' : 'card tools-group'} ${collapsed ? 'collapsed' : ''}" data-track="${esc(tr)}">
        ${header}
        <div class="${singleTrack ? '' : 'cb '}tools-group-body">${body}</div>
      </div>`;
    });
    return html || `<div class="card"><div class="cb muted">${en ? 'No matches' : 'Нет совпадений'}</div></div>`;
  }

  function toolCard(t, en) {
    const desc = en ? (t.desc_en || '') : (t.desc_ru || t.desc_en || '');
    const short = desc.length > 220 ? desc.slice(0, 220) + '…' : desc;
    const mitre = t.mitre ? `<span class="tag tm">${esc(t.mitre)}</span>` : '';
    return `<article class="tool-card" role="button" tabindex="0"
      onclick="Tools.showTool('${esc(t.id)}')"
      onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();Tools.showTool('${esc(t.id)}')}">
      <div class="tool-top">
        <strong class="tool-name">${esc(t.name)}</strong>
      </div>
      <div class="tool-meta">
        <span class="tag th">${esc(catLabel(t.category || '—', en))}</span>
        ${t.track ? `<span class="tag tb">${esc(trackLabel(t.track, en))}</span>` : ''}
        ${mitre}
      </div>
      <p class="tool-desc">${esc(short)}</p>
    </article>`;
  }

  function paraHtml(text) {
    return esc(text || '').split(/\n+/).filter(Boolean).map(p => `<p>${p}</p>`).join('') || '<p class="muted">—</p>';
  }

  /** Open tool via router so language switch stays on the same tool page */
  function showTool(id, opts) {
    opts = opts || {};
    if (!opts.skipRoute && typeof UI !== 'undefined' && UI.route) {
      UI.route('tool', id);
      return;
    }
    renderToolPage(id);
  }

  function renderToolPage(id) {
    const en = I18n.lang() === 'en';
    let t = null;
    if (typeof SqlLab !== 'undefined' && SqlLab.ready) {
      const rows = SqlLab.query('SELECT * FROM sec_tools WHERE id = ?', [id]);
      t = rows[0];
    }
    if (!t && typeof TOOLS_CATALOG !== 'undefined') {
      t = TOOLS_CATALOG.items.find(x => x.id === id);
    }
    if (!t) { UI.toast('Not found', 'err'); return; }
    const desc = en ? (t.desc_en || '') : (t.desc_ru || t.desc_en || '');
    const usage = en ? (t.usage_en || '') : (t.usage_ru || t.usage_en || '');
    const main = document.getElementById('main');
    main.innerHTML = `
      <div class="lab-page">
        <div class="row mb12">
          <button class="btn" onclick="UI.route('tools')">← ${en ? 'All tools' : 'Все инструменты'}</button>
        </div>
        <div class="card">
          <div class="ch">
            <h2>${esc(t.name)}</h2>
            <div class="row tool-detail-tags">
              ${t.track ? `<span class="tag th">${esc(trackLabel(t.track, en))}</span>` : ''}
              ${t.mitre ? `<span class="tag tc">ATT&CK: ${esc(t.mitre)}</span>` : ''}
            </div>
          </div>
          <div class="cb tool-detail">
            <section class="tool-detail-section">
              <h3>${en ? 'What it is' : 'Что это'}</h3>
              ${paraHtml(desc)}
            </section>
            <section class="tool-detail-section">
              <h3>${en ? 'How it is used' : 'Как применяют'}</h3>
              ${paraHtml(usage)}
            </section>
            ${t.example ? `<section class="tool-detail-section"><h3>${en ? 'Example' : 'Пример'}</h3><div class="ebox"><code>${esc(t.example)}</code></div></section>` : ''}
            <section class="tool-detail-section">
              <h3>${en ? 'Install / links' : 'Установка / ссылки'}</h3>
              <ul>
                ${t.url ? `<li><strong>URL:</strong> <a href="${esc(t.url)}" target="_blank" rel="noopener">${esc(t.url)}</a></li>` : ''}
                <li><strong>${en ? 'Install' : 'Установка'}:</strong> <code class="inline">${esc(t.install_method || t.install || '—')}</code></li>
              </ul>
            </section>
          </div>
        </div>
      </div>`;
  }

  function filterTrack(el, track) {
    _trackFilter = track || '*';
    saveToolsState();
    document.querySelectorAll('#tools-track-chips .chip').forEach(c => c.classList.remove('active'));
    if (el) el.classList.add('active');
    refreshToolsList();
  }

  function filterTools(q) {
    _q = q || '';
    saveToolsState();
    refreshToolsList();
  }

  function refreshToolsList() {
    const en = I18n.lang() === 'en';
    const list = allSecTools();
    const byTrack = {};
    list.forEach(t => {
      const k = t.track || 'other';
      if (!byTrack[k]) byTrack[k] = [];
      byTrack[k].push(t);
    });
    const el = document.getElementById('tools-list');
    if (el) el.innerHTML = renderToolsGroups(byTrack, en, _trackFilter, _q);
  }

  /** Deep UI state surviving language re-renders + page reload (sessionStorage) */
  const HUB_SS_KEY = 'zd_hub_state';
  const _hubState = {
    payGid: null,
    payCat: null,
    chainGid: null,
    chainId: null,
    reportKey: null,
    /** Command builder (keep across setLang re-paint) */
    cmdToolId: null,
    cmdTarget: '10.10.10.5',
    /** { [toolId]: string[] of checked flag tokens } */
    cmdFlags: {},
    /** Kuber */
    kuberToolId: null,
  };
  const _chainFilter = { domain: '*', level: '*', query: '' };

  function loadHubState() {
    try {
      const o = JSON.parse(sessionStorage.getItem(HUB_SS_KEY) || '{}');
      if (!o || typeof o !== 'object') return;
      if (o.payGid != null) _hubState.payGid = o.payGid;
      if (o.payCat != null) _hubState.payCat = o.payCat;
      if (o.chainGid != null) _hubState.chainGid = o.chainGid;
      if (o.chainId != null) _hubState.chainId = o.chainId;
      if (o.reportKey != null) _hubState.reportKey = o.reportKey;
      if (o.cmdToolId != null) _hubState.cmdToolId = o.cmdToolId;
      if (o.cmdTarget != null) _hubState.cmdTarget = o.cmdTarget;
      if (o.cmdFlags && typeof o.cmdFlags === 'object') _hubState.cmdFlags = o.cmdFlags;
      if (o.kuberToolId != null) _hubState.kuberToolId = o.kuberToolId;
      if (o.kuberFlags && typeof o.kuberFlags === 'object' && typeof _kuberState !== 'undefined') {
        /* applied after _kuberState exists via applyKuberPersist */
      }
      _hubState._kuberFlagsSaved = o.kuberFlags || null;
    } catch (_) {}
  }

  function saveHubState() {
    try {
      const kuberFlags = (typeof _kuberState !== 'undefined' && _kuberState.flags)
        ? _kuberState.flags
        : (_hubState._kuberFlagsSaved || {});
      sessionStorage.setItem(HUB_SS_KEY, JSON.stringify({
        payGid: _hubState.payGid,
        payCat: _hubState.payCat,
        chainGid: _hubState.chainGid,
        chainId: _hubState.chainId,
        reportKey: _hubState.reportKey,
        cmdToolId: _hubState.cmdToolId,
        cmdTarget: _hubState.cmdTarget,
        cmdFlags: _hubState.cmdFlags,
        kuberToolId: _hubState.kuberToolId || (typeof _kuberState !== 'undefined' ? _kuberState.toolId : null),
        kuberFlags: kuberFlags,
      }));
    } catch (_) {}
  }

  loadHubState();

  /** Unified hub: Payloads + command builder + chains + Kuber */
  function renderCommandsHub(tab) {
    const t = ['payloads', 'builder', 'chains', 'kuber'].includes(tab) ? tab : 'payloads';
    const tabs = [
      ['payloads', I18n.t('cmdTabPayloads')],
      ['builder', I18n.t('cmdTabBuilder')],
      ['chains', I18n.t('cmdTabChains')],
      ['kuber', I18n.t('cmdTabKuber')],
    ];
    return `
      <div class="lab-page">
        <div class="tabs" id="cmd-hub-tabs" role="tablist" style="margin-top:12px">
          ${tabs.map(([id, label]) =>
            `<button type="button" class="tab ${t === id ? 'active' : ''}" data-cmd-tab="${id}"
              onclick="UI.route('commands','${id}')">${esc(label)}</button>`
          ).join('')}
        </div>
        <div id="cmd-hub-body"></div>
      </div>`;
  }

  function mountCommandsHub(tab) {
    const t = ['payloads', 'builder', 'chains', 'kuber'].includes(tab) ? tab : 'payloads';
    const body = document.getElementById('cmd-hub-body');
    if (!body) return;
    if (t === 'payloads') {
      body.innerHTML = renderPayloadsInner();
      mountPayloads();
    } else if (t === 'builder') {
      body.innerHTML = renderCmdBuilder();
      mountCmdBuilder();
    } else if (t === 'chains') {
      body.innerHTML = renderChains();
      mountChains();
    } else if (t === 'kuber') {
      body.innerHTML = renderKuber();
      mountKuber();
    }
  }

  /** Bilingual helper: M() objects or plain strings */
  function kPick(v) {
    if (v == null) return '';
    if (typeof I18n !== 'undefined' && I18n.pick) return I18n.pick(v);
    if (typeof v === 'string') return v;
    return v.ru || v.en || '';
  }

  function renderKuber() {
    const data = (typeof DATA !== 'undefined' && DATA.KUBER_DATA) ? DATA.KUBER_DATA : {};
    const tools = data.tools || [];
    const attacks = data.attacks || [];
    const en = I18n.lang() === 'en';
    const toolChips = tools.map(t =>
      `<button type="button" class="chip" data-ktool="${esc(t.id)}" onclick="Tools.selectKuberTool(this,'${esc(t.id)}')">${esc(t.name)}</button>`
    ).join('');
    const attackCards = attacks.map(a => {
      const steps = Array.isArray(a.steps) ? a.steps : [];
      const stepsHtml = steps.map((s, i) => {
        const title = kPick(s.t);
        const cmd = typeof s.c === 'string' ? s.c : kPick(s.c);
        return `<div class="chain-step">
          <h4>${i + 1}. ${esc(title)}</h4>
          ${cmdBlockHtml(cmd)}
        </div>`;
      }).join('');
      return `<div class="card mb12">
        <div class="ch" style="flex-wrap:wrap;gap:8px">
          <h2 style="font-size:15px;margin:0">${esc(kPick(a.title))}</h2>
        </div>
        <div class="cb">${stepsHtml || `<p class="muted">${en ? 'No steps' : 'Нет шагов'}</p>`}</div>
      </div>`;
    }).join('');
    return `
      <div class="lab-page">
        <div class="card mb12">
          <div class="ch"><h2 style="font-size:16px;margin:0">${en ? 'K8s tools' : 'Инструменты K8s'}</h2></div>
          <div class="cb">
            <div class="row" id="kuber-tool-chips" style="flex-wrap:wrap;gap:6px">${toolChips}</div>
            <div id="kuber-panel" style="margin-top:12px"></div>
          </div>
        </div>
        <div style="margin-top:8px">
          <h2 style="font-size:16px;margin:0 0 10px">${en ? 'Attack scenarios' : 'Сценарии атак'}</h2>
          <div id="kuber-attacks">${attackCards || `<p class="muted">${en ? 'No scenarios' : 'Нет сценариев'}</p>`}</div>
        </div>
      </div>`;
  }

  function mountKuber() {
    const state = _kuberState;
    if (state.toolId) {
      const chip = document.querySelector(`[data-ktool="${state.toolId}"]`);
      if (chip) {
        chip.classList.add('active');
        renderKuberPanel(state.toolId);
      }
    }
  }

  const _kuberState = { toolId: null, flags: {} };
  // restore kuber selection after reload
  if (_hubState.kuberToolId) _kuberState.toolId = _hubState.kuberToolId;
  if (_hubState._kuberFlagsSaved && typeof _hubState._kuberFlagsSaved === 'object') {
    _kuberState.flags = _hubState._kuberFlagsSaved;
  }

  function ensureKuberDefaults(tool) {
    if (!tool || !tool.id) return;
    if (!_kuberState.flags[tool.id]) {
      _kuberState.flags[tool.id] = (tool.flags || []).filter(f => f.def).map(f => f.id);
    }
  }

  function renderKuberPanel(id) {
    const tools = (DATA.KUBER_DATA && DATA.KUBER_DATA.tools) || [];
    const tool = tools.find(t => t.id === id);
    const panel = document.getElementById('kuber-panel');
    if (!tool || !panel) return;
    const en = I18n.lang() === 'en';
    ensureKuberDefaults(tool);
    const checked = _kuberState.flags[id] || [];
    const flagHtml = (tool.flags || []).map(f => {
      const cid = `kf-${tool.id}-${f.id}`;
      const isChecked = checked.includes(f.id);
      return `<label class="check-row" style="display:flex;align-items:flex-start;gap:8px;padding:4px 0">
        <input type="checkbox" id="${esc(cid)}" data-fid="${esc(f.id)}" ${isChecked ? 'checked' : ''}
          onchange="Tools.kuberToggleFlag('${esc(tool.id)}','${esc(f.id)}')">
        <span><code class="inline">${esc(f.flag || '')}</code>
          <span class="muted small"> — ${esc(kPick(f.help))}</span></span>
      </label>`;
    }).join('');
    const selectedFlags = checked.map(fid => {
      const f = (tool.flags || []).find(fl => fl.id === fid);
      return f ? (f.flag || '') : '';
    }).filter(Boolean).join(' ');
    const baseCmd = tool.base || tool.name;
    const fullCmd = (baseCmd + (selectedFlags ? ' ' + selectedFlags : '')).trim();
    const noteHtml = tool.note
      ? `<div class="ebox info" style="margin-top:8px;font-size:0.9em">${esc(kPick(tool.note))}</div>`
      : '';
    panel.innerHTML = `
      <div class="card" style="margin:0;border:1px solid var(--bdr)">
        <div class="ch"><h2 style="font-size:15px;margin:0">${esc(tool.name)}</h2>
          <span class="tag tb">K8s</span></div>
        <div class="cb">
          <p class="muted mb12">${esc(kPick(tool.desc))}</p>
          <div class="cmd-flags" id="kuber-flags">${flagHtml || `<p class="muted">${en ? 'No flags' : 'Нет флагов'}</p>`}</div>
          ${noteHtml}
          <div class="field mt12"><label>${en ? 'Assembled command' : 'Собранная команда'}</label>
            <textarea id="kuber-cmd" rows="3" readonly>${esc(fullCmd)}</textarea></div>
          <div class="row mt8" style="gap:8px">
            <button type="button" class="btn btnp" onclick="Tools.kuberRebuild('${esc(tool.id)}')">${en ? 'Rebuild' : 'Собрать'}</button>
            <button type="button" class="btn" onclick="Tools.kuberCopy()">${I18n.t('copy') || (en ? 'Copy' : 'Копировать')}</button>
          </div>
        </div>
      </div>`;
  }

  function kuberToggleFlag(tid, fid) {
    if (!_kuberState.flags[tid]) _kuberState.flags[tid] = [];
    const arr = _kuberState.flags[tid];
    const idx = arr.indexOf(fid);
    if (idx > -1) arr.splice(idx, 1);
    else arr.push(fid);
    renderKuberPanel(tid);
    saveHubState();
  }

  function kuberRebuild(id) {
    renderKuberPanel(id);
  }

  function kuberCopy() {
    const inp = document.getElementById('kuber-cmd');
    if (!inp) return;
    const v = inp.value || '';
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(v).then(() => UI.toast?.(I18n.lang() === 'en' ? 'Copied' : 'Скопировано', 'ok')).catch(() => {
        inp.select(); document.execCommand('copy');
      });
    } else {
      inp.select(); document.execCommand('copy');
    }
  }

  function selectKuberTool(el, id) {
    document.querySelectorAll('[data-ktool]').forEach(c => c.classList.remove('active'));
    if (el) el.classList.add('active');
    _kuberState.toolId = id;
    _hubState.kuberToolId = id;
    const tool = ((DATA.KUBER_DATA && DATA.KUBER_DATA.tools) || []).find(t => t.id === id);
    ensureKuberDefaults(tool);
    renderKuberPanel(id);
    saveHubState();
  }

  // keep legacy global hooks if any inline onclick remains
  window.selectKuberTool = selectKuberTool;
  window.kuberToggleFlag = kuberToggleFlag;
  window.kuberRebuild = kuberRebuild;
  window.kuberCopy = kuberCopy;

  /**
   * OWASP Top 10:2025 grouping for payload library.
   * Technique chips are nested under A01–A10 (+ Other).
   */
  // Technique categories nested under OWASP Top 10:2025 (multi-map OK for cross-cutting topics)
  const PAYLOAD_OWASP_GROUPS = [
    {
      id: 'A01',
      cats: [
        '403 Bypass / access control',
        'Insecure Direct Object References',
        'Mass Assignment',
        'OAuth Misconfiguration',
        'SSRF',
        'Path Traversal',
        'Client Side Path Traversal',
        'File Inclusion',
        'Open Redirect',
        'Cross-Site Request Forgery',
        'CORS Misconfiguration',
        'Account Takeover',
      ],
    },
    {
      id: 'A02',
      cats: [
        'CRLF / Headers',
        'Reverse Proxy Misconfigurations',
        'Insecure Management Interface',
        'Virtual Hosts',
        'Backup Files Exposure',
        'Insecure Source Code Management',
        'Hidden Parameters',
        'HTTP Parameter Pollution',
        'Web Cache Deception',
        'Web Cache Poisoning',
        'DNS Rebinding',
        'Subdomain Takeover',
      ],
    },
    {
      id: 'A03',
      cats: [
        'Dependency Confusion',
        'CVE Exploits',
        'Log4Shell',
      ],
    },
    {
      id: 'A04',
      cats: [
        'Insecure Randomness',
        'SAML Injection',
      ],
    },
    {
      id: 'A05',
      cats: [
        'SQL Injection',
        'XSS',
        'NoSQL',
        'Command Injection',
        'SSTI',
        'XXE Injection',
        'LDAP Injection',
        'GraphQL Injection',
        'LaTeX Injection',
        'CSS Injection',
        'CSV Injection',
        'Server Side Include Injection',
        'XPATH Injection',
        'XSLT Injection',
        'Prompt Injection',
        'ORM Leak',
      ],
    },
    {
      id: 'A06',
      cats: [
        'Business Logic Errors',
        'Race Condition',
        'Tabnabbing',
        'Clickjacking',
        'DOM Clobbering',
        'Prototype Pollution',
        'XS-Leaks',
      ],
    },
    {
      id: 'A07',
      cats: [
        'Account Takeover',
        'OAuth Misconfiguration',
        'API Key Leaks',
      ],
    },
    {
      id: 'A08',
      cats: [
        'Insecure Deserialization',
        'Zip Slip',
        'Upload Insecure Files',
        'Prototype Pollution',
        'Request Smuggling',
      ],
    },
    {
      id: 'A09',
      cats: [
        'Headless Browser',
      ],
    },
    {
      id: 'A10',
      cats: [
        'Denial of Service',
        'Regular Expression',
        'Type Juggling',
        'Encoding Transformations',
        'External Variable Modification',
      ],
    },
    {
      id: 'OTHER',
      cats: [
        'Google Web Toolkit',
        'Java RMI',
        'Web Sockets',
      ],
    },
  ];

  function payloadGroupTitles() {
    return {
      A01: I18n.t('payG_A01'),
      A02: I18n.t('payG_A02'),
      A03: I18n.t('payG_A03'),
      A04: I18n.t('payG_A04'),
      A05: I18n.t('payG_A05'),
      A06: I18n.t('payG_A06'),
      A07: I18n.t('payG_A07'),
      A08: I18n.t('payG_A08'),
      A09: I18n.t('payG_A09'),
      A10: I18n.t('payG_A10'),
      OTHER: I18n.t('payG_OTHER'),
    };
  }

  function payloadGroupMeta() {
    const allCats = Object.keys(DATA.PAYLOADS || {});
    const assigned = new Set();
    const titles = payloadGroupTitles();
    const groups = PAYLOAD_OWASP_GROUPS.map(g => {
      const cats = g.cats.filter(c => allCats.includes(c) && (DATA.PAYLOADS[c] || []).length);
      cats.forEach(c => assigned.add(c));
      return {
        id: g.id,
        title: titles[g.id] || g.id,
        short: g.id === 'OTHER' ? titles.OTHER : g.id,
        cats,
        count: cats.reduce((n, c) => n + ((DATA.PAYLOADS[c] || []).length), 0),
      };
    }).filter(g => g.cats.length > 0);

    const rest = allCats.filter(c => !assigned.has(c) && (DATA.PAYLOADS[c] || []).length);
    if (rest.length) {
      let other = groups.find(g => g.id === 'OTHER');
      if (!other) {
        other = { id: 'OTHER', title: titles.OTHER, short: titles.OTHER, cats: [], count: 0 };
        groups.push(other);
      }
      rest.forEach(c => {
        if (!other.cats.includes(c)) other.cats.push(c);
      });
      other.count = other.cats.reduce((n, c) => n + ((DATA.PAYLOADS[c] || []).length), 0);
    }
    return groups;
  }

  function payloadCategoryLabel(category) {
    if (I18n.lang() === 'en') return category;
    return DATA.PAYLOAD_CATEGORIES_RU?.[category] || category;
  }

  function payloadItemTitle(category, item) {
    const title = String(item?.t || '');
    if (I18n.lang() === 'en') return title;
    return DATA.PAYLOAD_TITLES_RU?.[category]?.[title] || title;
  }

  function payloadItemText(item) {
    const text = String(item?.p || '');
    if (I18n.lang() === 'en') return text;
    const lines = DATA.PAYLOAD_LINES_RU || {};
    return text.split('\n').map(line => lines[line] ?? line).join('\n');
  }

  function renderPayloadsInner() {
    const groups = payloadGroupMeta();
    const g0 = groups[0];
    return `
      <div class="card">
        <div class="cb">
          <div class="pay-owasp-row" id="pay-groups" style="margin-top:8px">
            ${groups.map((g, i) => `
              <button type="button" class="pay-group-chip ${i === 0 ? 'active' : ''}"
                data-gid="${esc(g.id)}"
                title="${esc(g.title)}"
                onclick="Tools.showPayGroup(this)">
                <span class="pay-group-id">${esc(g.short)}</span>
                <span class="pay-group-n">${g.cats.length}</span>
              </button>`).join('')}
          </div>
          <div class="pay-tech-label" id="pay-tech-label">${g0 ? esc(g0.title) : ''}</div>
          <div class="row mb12 pay-tech-row" id="pay-cats">
            ${(g0?.cats || []).map((c, i) => `
              <span class="chip ${i === 0 ? 'active' : ''}" data-cat="${esc(c)}" onclick="Tools.showPayCat(this)">${esc(payloadCategoryLabel(c))}</span>
            `).join('')}
          </div>
          <div id="pay-list"></div>
        </div>
      </div>`;
  }

  function renderPayloads() {
    return renderCommandsHub('payloads');
  }

  function showPayGroup(el) {
    const gid = el.dataset.gid;
    _hubState.payGid = gid;
    saveHubState();
    document.querySelectorAll('#pay-groups .pay-group-chip').forEach(c => c.classList.remove('active'));
    el.classList.add('active');
    const groups = payloadGroupMeta();
    const g = groups.find(x => x.id === gid) || groups[0];
    if (!g) return;
    const label = document.getElementById('pay-tech-label');
    if (label) label.textContent = g.title;
    const wrap = document.getElementById('pay-cats');
    if (!wrap) return;
    const preferCat = _hubState.payCat && g.cats.includes(_hubState.payCat) ? _hubState.payCat : g.cats[0];
    wrap.innerHTML = g.cats.map((c) =>
      `<span class="chip ${c === preferCat ? 'active' : ''}" data-cat="${esc(c)}" onclick="Tools.showPayCat(this)">${esc(payloadCategoryLabel(c))}</span>`
    ).join('');
    const chip = Array.from(wrap.querySelectorAll('.chip')).find(c => c.dataset.cat === preferCat)
      || wrap.querySelector('.chip');
    if (chip) showPayCat(chip);
    else {
      const list = document.getElementById('pay-list');
      if (list) list.innerHTML = `<p class="muted">${I18n.t('payloadEmptyGroup')}</p>`;
    }
  }

  function showPayCat(el) {
    document.querySelectorAll('#pay-cats .chip').forEach(c => c.classList.remove('active'));
    el.classList.add('active');
    const cat = el.dataset.cat;
    _hubState.payCat = cat;
    saveHubState();
    const items = DATA.PAYLOADS[cat] || [];
    const list = document.getElementById('pay-list');
    if (!list) return;
    // Never put payload text into HTML attributes / inline onclick (XSS payloads break out).
    if (!items.length) {
      list.innerHTML = `<p class="muted">${I18n.t('payloadEmptyGroup')}</p>`;
      return;
    }
    list.innerHTML = items.map((it) => `
      <div class="payload-item payload-item-block">
        <div style="min-width:120px;color:var(--mut);font-size:11px;margin-bottom:4px">${esc(payloadItemTitle(cat, it))}</div>
        ${cmdBlockHtml(payloadItemText(it))}
      </div>`).join('');
  }

  function mountPayloads() {
    const groups = payloadGroupMeta();
    let groupEl = null;
    if (_hubState.payGid) {
      groupEl = document.querySelector(`#pay-groups .pay-group-chip[data-gid="${_hubState.payGid}"]`);
    }
    if (!groupEl) groupEl = document.querySelector('#pay-groups .pay-group-chip');
    if (groupEl) {
      showPayGroup(groupEl);
      return;
    }
    const first = document.querySelector('#pay-cats .chip');
    if (first) showPayCat(first);
  }

  /**
   * Map a chain to OWASP Top 10:2025 group.
   * Older seed data often tags Injection as A03 (2021); normalize for 2025 UI.
   */
  function chainOwaspGroup(ch) {
    const tags = (ch.tags || []).map(String);
    const has = (re) => tags.some(t => re.test(t));
    const title = String(I18n.pick(ch.title) || ch.id || '');

    // Domain / technique signals (stronger than legacy A0x numbers)
    if (has(/^(Injection|sqli|XSS|xss|ssti|xxe|CMDi|command-injection|nosql|prompt-injection)$/i)
        || has(/Injection/) || /SQLi|XSS|SSTI|XXE|Command Injection|NoSQL|prompt/i.test(title)) {
      // AI supply-chain / MCP keeps A03 when clearly supply-chain
      if (has(/^AI-LLM$/) && has(/supply-chain|tool-poisoning|mcp/i)) return 'A03';
      if (has(/^AI-LLM$/) || has(/prompt-injection/)) return 'A05';
      return 'A05';
    }
    if (has(/^AI-LLM$/)) return 'A03';
    if (has(/^Client-Side$/) || has(/dom-xss|clickjacking|csrf|cors|postmessage|dom-clobbering|mxss/i)) {
      if (has(/csrf|clickjacking|cors/i)) return 'A01'; // often BAC / session impact
      return 'A05';
    }
    if (has(/^Access-Control$|^API$|^File-Upload$|^IDOR$|^BAC$|bola|bfla|idor|mass-assignment/i)
        || has(/^SSRF$/i) || has(/ssrf|imds|metadata/i)) return 'A01';
    if (has(/^Auth$|^OAuth$|account-takeover|password-reset|session-fixation|2fa|otp|mfa/i)) return 'A07';
    if (has(/^Recon$|git-exposure|swagger|js-recon|misconfiguration|staging/i)
        || has(/^Misconfig$/)) return 'A02';
    if (has(/^Modern-Web$|request-smuggling|cache-poisoning|web-cache|prototype-pollution|cspt/i)) return 'A10';
    if (has(/Deser|deserialization|zip-slip|integrity/i)) return 'A08';
    if (has(/^Logging$|logging-gap/i)) return 'A09';
    if (has(/^Components$|Log4Shell|log4j|CVE|dependency/i)) return 'A03';
    if (has(/algorithm-confusion|alg-none|crypt/i) || has(/^Design$/) && has(/OTP|rate/i)) {
      if (has(/^Design$/)) return 'A06';
      return 'A04';
    }
    if (has(/^Design$|business-logic|race-condition/i)) return 'A06';

    // Legacy A0x tag fallback (normalize known 2021→2025 skews lightly)
    const a = tags.find(t => /^A\d+$/i.test(t));
    if (a) {
      const up = a.toUpperCase();
      // 2021 A03 Injection often left as A03; if title looks like injection already handled above
      return up;
    }
    return 'OTHER';
  }

  function chainGroupMeta() {
    const chains = DATA.CHAINS || [];
    const titles = {
      A01: I18n.t('payG_A01'),
      A02: I18n.t('payG_A02'),
      A03: I18n.t('payG_A03'),
      A04: I18n.t('payG_A04'),
      A05: I18n.t('payG_A05'),
      A06: I18n.t('payG_A06'),
      A07: I18n.t('payG_A07'),
      A08: I18n.t('payG_A08'),
      A09: I18n.t('payG_A09'),
      A10: I18n.t('payG_A10'),
      OTHER: I18n.t('payG_OTHER'),
    };
    const order = ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10', 'OTHER'];
    const bucket = {};
    order.forEach(id => { bucket[id] = []; });
    chains.forEach(ch => {
      const g = chainOwaspGroup(ch);
      if (!bucket[g]) bucket[g] = [];
      bucket[g].push(ch);
    });
    return order.filter(id => (bucket[id] || []).length).map(id => ({
      id,
      title: titles[id] || id,
      short: id === 'OTHER' ? titles.OTHER : id,
      chains: bucket[id],
      count: bucket[id].length,
    }));
  }

  const CHAIN_DOMAINS = [
    ['ai', 'AI / LLM', 'AI / LLM', ['ai-llm']],
    ['modern', 'Современный Web', 'Modern Web', ['modern-web']],
    ['oauth', 'OAuth', 'OAuth', ['oauth']],
    ['ssrf', 'SSRF', 'SSRF', ['ssrf']],
    ['upload', 'Файлы и загрузка', 'Files & Upload', ['file-upload', 'lfi', 'rfi', 'zip-slip']],
    ['api', 'API', 'API', ['api', 'graphql']],
    ['client', 'Клиентские атаки', 'Client-side', ['client-side', 'csrf', 'cors', 'clickjacking', 'dom-xss']],
    ['auth', 'Аутентификация', 'Authentication', ['auth', 'jwt', 'password-reset', '2fa', 'otp', 'session-fixation']],
    ['access', 'Контроль доступа', 'Access control', ['access-control', 'idor', 'bac', 'bola', 'bfla']],
    ['injection', 'Инъекции', 'Injection', ['injection', 'sqli', 'xss', 'cmdi', 'command-injection', 'ssti', 'xxe', 'nosql']],
    ['recon', 'Разведка', 'Recon', ['recon']],
    ['supply', 'Компоненты и целостность', 'Components & integrity', ['components', 'deser', 'deserialization', 'integrity']],
    ['logic', 'Бизнес-логика', 'Business logic', ['design', 'business-logic', 'race-condition']],
    ['logging', 'Логирование', 'Logging', ['logging']],
  ];
  const CHAIN_LEVEL_ORDER = { Newbie: 0, Intermediate: 1, Advanced: 2 };

  function chainDomain(ch) {
    const tags = (ch.tags || []).map(tag => String(tag).toLowerCase());
    return CHAIN_DOMAINS.find(([, , , signals]) => signals.some(signal => tags.includes(signal)))?.[0] || 'other';
  }

  function chainDomainLabel(id) {
    if (id === '*') return I18n.lang() === 'en' ? 'All techniques' : 'Все техники';
    const domain = CHAIN_DOMAINS.find(([domainId]) => domainId === id);
    if (!domain) return I18n.lang() === 'en' ? 'Other' : 'Другое';
    return I18n.lang() === 'en' ? domain[2] : domain[1];
  }

  function chainLevelLabel(level) {
    if (I18n.lang() === 'en') return level;
    return { Newbie: 'Начальный', Intermediate: 'Средний', Advanced: 'Продвинутый' }[level] || level;
  }

  function sortChains(chains) {
    return [...chains].sort((a, b) => {
      const levelDiff = (CHAIN_LEVEL_ORDER[a.level] ?? 99) - (CHAIN_LEVEL_ORDER[b.level] ?? 99);
      return levelDiff || String(I18n.pick(a.title)).localeCompare(String(I18n.pick(b.title)), I18n.lang());
    });
  }

  function filterChainRows(chains, filter = _chainFilter) {
    const query = filter.query.trim().toLowerCase();
    return sortChains(chains.filter(ch => {
      if (filter.domain !== '*' && chainDomain(ch) !== filter.domain) return false;
      if (filter.level !== '*' && ch.level !== filter.level) return false;
      if (!query) return true;
      const haystack = `${I18n.pick(ch.title)} ${(ch.tags || []).join(' ')}`.toLowerCase();
      return haystack.includes(query);
    }));
  }

  function renderChainDomains(chains) {
    const counts = chains.reduce((result, ch) => {
      const id = chainDomain(ch);
      result[id] = (result[id] || 0) + 1;
      return result;
    }, {});
    const domains = [['*', chains.length], ...CHAIN_DOMAINS
      .filter(([id]) => counts[id])
      .map(([id]) => [id, counts[id]])];
    if (counts.other) domains.push(['other', counts.other]);
    return domains.map(([id, count]) => `
      <button type="button" class="pay-group-chip chain-domain-chip ${_chainFilter.domain === id ? 'active' : ''}"
        data-domain="${esc(id)}" onclick="Tools.showChainDomain(this)">
        <span>${esc(chainDomainLabel(id))}</span><span class="pay-group-n">${count}</span>
      </button>`).join('');
  }

  function renderChainList(chains, activeId) {
    if (!chains.length) return `<p class="muted chain-empty">${I18n.lang() === 'en' ? 'No matching scenarios.' : 'Подходящих сценариев нет.'}</p>`;
    return chains.map(ch => `
      <button type="button" class="chain-list-item ${ch.id === activeId ? 'active' : ''}" data-chain="${esc(ch.id)}">
        <span class="chain-list-title">${esc(I18n.pick(ch.title))}</span>
        <span class="chain-list-meta">
          <span>${esc(chainLevelLabel(ch.level))}</span>
          <span>${esc(chainDomainLabel(chainDomain(ch)))}</span>
        </span>
      </button>`).join('');
  }

  function renderChains() {
    const groups = chainGroupMeta();
    const g0 = groups[0];
    return `
      <div class="card">
        <div class="ch"><h2>${I18n.t('chainsTitle')}</h2></div>
        <div class="cb">
          <div class="pay-owasp-row" id="chain-groups">
            ${groups.map((g, i) => `
              <button type="button" class="pay-group-chip ${i === 0 ? 'active' : ''}"
                data-gid="${esc(g.id)}"
                title="${esc(g.title)}"
                onclick="Tools.showChainGroup(this)">
                <span class="pay-group-id">${esc(g.short)}</span>
                <span class="pay-group-n">${g.count}</span>
              </button>`).join('')}
          </div>
          <div class="pay-tech-label" id="chain-group-label">${g0 ? esc(g0.title) : ''}</div>
          <div class="pay-owasp-row chain-domain-row" id="chain-domains"></div>
          <div class="chain-filter-row">
            <input id="chain-search" type="search"
              placeholder="${I18n.lang() === 'en' ? 'Search by title or tag…' : 'Поиск по названию или тегу…'}"
              aria-label="${I18n.lang() === 'en' ? 'Search attack scenarios' : 'Поиск сценариев атак'}">
            <select id="chain-level" aria-label="${I18n.lang() === 'en' ? 'Difficulty' : 'Сложность'}">
              <option value="*">${I18n.lang() === 'en' ? 'All levels' : 'Все уровни'}</option>
              <option value="Newbie">${chainLevelLabel('Newbie')}</option>
              <option value="Intermediate">${chainLevelLabel('Intermediate')}</option>
              <option value="Advanced">${chainLevelLabel('Advanced')}</option>
            </select>
          </div>
          <div class="chain-workspace">
            <nav id="chain-tabs" class="chain-list" aria-label="${I18n.lang() === 'en' ? 'Attack scenarios' : 'Сценарии атак'}"></nav>
            <div id="chain-view" class="chain-detail"></div>
          </div>
        </div>
      </div>`;
  }

  function currentChainGroup() {
    const groups = chainGroupMeta();
    return groups.find(group => group.id === _hubState.chainGid) || groups[0];
  }

  function bindChainList() {
    document.querySelectorAll('#chain-tabs .chain-list-item').forEach(button => {
      button.addEventListener('click', () => showChain(button.getAttribute('data-chain')));
    });
  }

  function refreshChainCatalog(group) {
    if (!group) return;
    const domains = document.getElementById('chain-domains');
    if (domains) domains.innerHTML = renderChainDomains(group.chains);
    const rows = filterChainRows(group.chains);
    const selectedId = rows.some(ch => ch.id === _hubState.chainId) ? _hubState.chainId : rows[0]?.id;
    const list = document.getElementById('chain-tabs');
    if (list) list.innerHTML = renderChainList(rows, selectedId);
    bindChainList();
    if (selectedId) showChain(selectedId);
    else {
      const view = document.getElementById('chain-view');
      if (view) view.innerHTML = `<p class="muted chain-empty">${I18n.lang() === 'en' ? 'Change the filters to see scenarios.' : 'Измени фильтры, чтобы увидеть сценарии.'}</p>`;
    }
  }

  function showChainGroup(el) {
    const gid = el.dataset.gid;
    _hubState.chainGid = gid;
    saveHubState();
    document.querySelectorAll('#chain-groups .pay-group-chip').forEach(c => c.classList.remove('active'));
    el.classList.add('active');
    const groups = chainGroupMeta();
    const g = groups.find(x => x.id === gid) || groups[0];
    if (!g) return;
    const label = document.getElementById('chain-group-label');
    if (label) label.textContent = g.title;
    _chainFilter.domain = '*';
    refreshChainCatalog(g);
  }

  function showChainDomain(el) {
    _chainFilter.domain = el?.dataset?.domain || '*';
    refreshChainCatalog(currentChainGroup());
  }

  function filterChains() {
    _chainFilter.query = document.getElementById('chain-search')?.value || '';
    _chainFilter.level = document.getElementById('chain-level')?.value || '*';
    refreshChainCatalog(currentChainGroup());
  }

  function showChain(id) {
    const ch = (DATA.CHAINS || []).find(c => c.id === id);
    const view = document.getElementById('chain-view');
    if (!ch || !view) return;
    _hubState.chainId = id;
    _hubState.chainGid = chainOwaspGroup(ch);
    saveHubState();
    document.querySelectorAll('#chain-tabs .chain-list-item').forEach(b => {
      b.classList.toggle('active', b.getAttribute('data-chain') === id);
    });
    // No level / OWASP service badges (Newbie/Advanced · A01: …) — just steps
    view.innerHTML = ch.steps.map((s, i) => `
        <div class="chain-step">
          <h4>${i + 1}. ${esc(I18n.pick(s.t))}</h4>
          ${cmdBlockHtml(s.c)}
        </div>`).join('');
  }

  function mountChains() {
    let groupEl = null;
    if (_hubState.chainGid) {
      groupEl = document.querySelector(`#chain-groups .pay-group-chip[data-gid="${_hubState.chainGid}"]`);
    }
    // If we have a saved chain, pick its group
    if (!groupEl && _hubState.chainId) {
      const ch = (DATA.CHAINS || []).find(c => c.id === _hubState.chainId);
      if (ch) {
        const gid = chainOwaspGroup(ch);
        groupEl = document.querySelector(`#chain-groups .pay-group-chip[data-gid="${gid}"]`);
      }
    }
    if (!groupEl) groupEl = document.querySelector('#chain-groups .pay-group-chip');
    const search = document.getElementById('chain-search');
    const level = document.getElementById('chain-level');
    if (search) search.addEventListener('input', filterChains);
    if (level) level.addEventListener('change', filterChains);
    if (groupEl) {
      showChainGroup(groupEl);
      return;
    }
  }

  /** From a lab page (A01…A10): open Attack Chains focused on that OWASP group */
  function openChainsForOwasp(code) {
    const gid = String(code || '').toUpperCase().replace(/[^A0-9]/g, '');
    // Accept A01–A10
    const ok = /^A0[1-9]$|^A10$/.test(gid);
    _hubState.chainGid = ok ? gid : null;
    _hubState.chainId = null; // pick first chain in that group
    saveHubState();
    if (typeof UI !== 'undefined' && UI.route) UI.route('commands', 'chains');
  }

  const REPORT_DRAFT_KEY = 'root-report-drafts-v1';

  function loadReportDrafts() {
    try {
      return JSON.parse(localStorage.getItem(REPORT_DRAFT_KEY) || '{}') || {};
    } catch (_) {
      return {};
    }
  }

  function saveReportDraft(key, md) {
    const all = loadReportDrafts();
    all[key] = md;
    localStorage.setItem(REPORT_DRAFT_KEY, JSON.stringify(all));
  }

  function clearReportDraft(key) {
    const all = loadReportDrafts();
    delete all[key];
    localStorage.setItem(REPORT_DRAFT_KEY, JSON.stringify(all));
  }

  function defaultReportMarkdown(key) {
    const t = DATA.REPORT_TEMPLATES[key];
    if (!t) return '';
    const lang = I18n.lang();
    const title = t.title && t.title[lang] ? t.title[lang] : (t.title || '');
    const body = t.body && t.body[lang] ? t.body[lang] : (t.body || '');
    return `# ${title}\n\n**CWE:** ${t.cwe}\n**CVSS:** \`${t.cvss}\`\n\n${body}`.trim() + '\n';
  }

  function renderReports() {
    const keys = Object.keys(DATA.REPORT_TEMPLATES || {});
    return `
      <div class="card">
        <div class="cb">
          <div class="row mb12" id="report-cats" style="flex-wrap:wrap;gap:6px">
            ${keys.map((k, i) =>
              `<button type="button" class="btn report-cat ${i === 0 ? 'btnp' : ''}" data-key="${esc(k)}">${esc(k)}</button>`
            ).join('')}
          </div>
          <div id="report-view"></div>
        </div>
      </div>`;
  }

  function mountReports() {
    const cats = document.querySelectorAll('#report-cats .report-cat');
    cats.forEach(btn => {
      btn.addEventListener('click', () => {
        cats.forEach(b => b.classList.remove('btnp'));
        btn.classList.add('btnp');
        showReport(btn.getAttribute('data-key'));
      });
    });
    const prefer = _hubState.reportKey
      && document.querySelector(`#report-cats .report-cat[data-key="${_hubState.reportKey}"]`);
    const first = prefer || document.querySelector('#report-cats .report-cat');
    if (first) {
      cats.forEach(b => b.classList.remove('btnp'));
      first.classList.add('btnp');
      showReport(first.getAttribute('data-key'));
    }
  }

  function showReport(key) {
    const t = DATA.REPORT_TEMPLATES[key];
    if (!t) return;
    _hubState.reportKey = key;
    saveHubState();
    const drafts = loadReportDrafts();
    const md = (drafts[key] && String(drafts[key]).trim())
      ? String(drafts[key])
      : defaultReportMarkdown(key);
    const view = document.getElementById('report-view');
    if (!view) return;
    view.innerHTML = `
      <div class="row-between mb8" style="flex-wrap:wrap;gap:8px">
        <div>
          <span class="tag tb">${esc(t.cwe)}</span>
          <code class="inline">${esc(t.cvss)}</code>
          ${drafts[key] ? `<span class="tag tm" style="margin-left:6px">${I18n.lang()==='en'?'draft':'черновик'}</span>` : ''}
        </div>
        <div class="row" style="gap:6px;flex-wrap:wrap">
          <button type="button" class="btn report-save">${I18n.t('reportSave')}</button>
          <button type="button" class="btn report-reset">${I18n.t('reportReset')}</button>
          <button type="button" class="btn btnp report-copy">${I18n.t('copyMd')}</button>
        </div>
      </div>
      <div class="field">
        <label>${I18n.t('reportEdit')}</label>
        <textarea id="report-md" class="report-editor" rows="22" spellcheck="false"></textarea>
      </div>`;
    const ta = document.getElementById('report-md');
    if (ta) ta.value = md;
    view.querySelector('.report-copy')?.addEventListener('click', () => {
      copy(document.getElementById('report-md')?.value || '');
    });
    view.querySelector('.report-save')?.addEventListener('click', () => {
      const text = document.getElementById('report-md')?.value || '';
      saveReportDraft(key, text);
      UI.toast(I18n.t('reportSaved'), 'ok');
      showReport(key);
    });
    view.querySelector('.report-reset')?.addEventListener('click', () => {
      clearReportDraft(key);
      showReport(key);
      UI.toast(I18n.t('reportReset'), 'ok');
    });
  }

  function renderProgress() {
    const mods = DATA.MODS;
    const st = Store.stats(mods);
    const allDone = Store.allChallengesDone();
    return `
      <div data-watermark="PROGRESS" class="hero">
        <h1>${I18n.t('progressTitle')}</h1>
        <p>${I18n.t('progressDesc')}</p>
        <div class="stat-grid">
          <div class="stat"><div class="n" style="color:var(--grn)">${st.challenges}/${st.challengesTotal}</div><div class="l">${I18n.t('statFlags')}</div></div>
          <div class="stat"><div class="n" style="color:var(--blu)">${st.done}/${st.total}</div><div class="l">${I18n.t('modDone')}</div></div>
          <div class="stat"><div class="n" style="color:var(--pur)">${st.challengesTotal ? Math.round(st.challenges/st.challengesTotal*100) : 0}%</div><div class="l">${I18n.t('completion')}</div></div>
        </div>
        <div class="row mt12">
          <button class="btn btnp" onclick="UI.route('scoreboard')">${I18n.t('scoreboard')}</button>
        </div>
      </div>
      <div class="card">
        <div class="ch"><h2>${I18n.t('capturedFlags')}</h2></div>
        <div class="cb">
          ${CHALLENGES.list.map(c => {
            const f = Store.get().flags[c.id];
            return `<div class="payload-item">
              <strong style="min-width:52px;color:var(--red)">${c.code}</strong>
              <span style="min-width:140px;font-size:12px">${esc(I18n.pick(c.title))}</span>
              <code style="color:${f ? 'var(--grn)' : 'var(--mut)'}">${f ? esc(f) : I18n.t('notCaptured')}</code>
              ${f ? '' : `<button class="btn btns" onclick="UI.route('lab','${c.code}');setTimeout(()=>Labs.selectChallenge('${c.code}','${c.id}'),50)">${I18n.t('openLab')}</button>`}
            </div>`;
          }).join('')}
        </div>
      </div>
      <div class="card">
        <div class="ch"><h2>${I18n.t('certTitle')}</h2>
          ${allDone ? `<span class="tag tm">${st.challengesTotal}/${st.challengesTotal}</span>` : `<span class="tag th">${st.challenges}/${st.challengesTotal}</span>`}
        </div>
        <div class="cb">
          <p class="muted mb12">${I18n.t('certDesc')}</p>
          <div class="field"><label>${I18n.t('certName')}</label>
            <input id="cert-name" value="${esc(Store.get().certName || 'Security Learner')}" maxlength="60">
          </div>
          <button class="btn ${allDone ? 'btnp' : ''}" ${allDone ? '' : 'disabled'}
            onclick="Tools.downloadCert()">${allDone ? I18n.t('certDownload') : I18n.t('certLocked')}</button>
        </div>
      </div>
      <div class="card">
        <div class="ch"><h2>${I18n.t('data')}</h2></div>
        <div class="cb row">
          <button class="btn" onclick="Tools.exportProgress()">${I18n.t('exportProg')}</button>
          <button class="btn btnd" onclick="if(confirm(I18n.t('resetConfirm'))){Store.reset();UI.route('lab','A01');UI.refreshNav();UI.paintChrome();}">${I18n.t('resetProg')}</button>
        </div>
      </div>`;
  }

  function exportProgress() {
    const blob = new Blob([Store.exportJSON()], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'owasp-emulator-progress.json';
    a.click();
  }

  function downloadCert() {
    const st = Store.stats(DATA.MODS);
    if (!Store.allChallengesDone()) return;
    const name = (document.getElementById('cert-name')?.value || 'Security Learner').trim() || 'Security Learner';
    Store.get().certName = name;
    Store.save();
    const date = new Date().toISOString().slice(0, 10);
    const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="900" height="600" viewBox="0 0 900 600">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#0d1117"/><stop offset="100%" stop-color="#161b22"/>
    </linearGradient>
  </defs>
  <rect width="900" height="600" fill="url(#g)" stroke="#30363d" stroke-width="4" rx="12"/>
  <rect x="24" y="24" width="852" height="552" fill="none" stroke="#ef4444" stroke-width="1" rx="8" opacity="0.5"/>
  <text x="450" y="90" text-anchor="middle" fill="#ef4444" font-family="system-ui,sans-serif" font-size="14" font-weight="700" letter-spacing="4">RØOT · OFFLINE SECURITY RANGE</text>
  <text x="450" y="150" text-anchor="middle" fill="#e8e8e8" font-family="system-ui,sans-serif" font-size="36" font-weight="700">Certificate of Completion</text>
  <text x="450" y="200" text-anchor="middle" fill="#8a8a8a" font-family="system-ui,sans-serif" font-size="16">This certifies that</text>
  <text x="450" y="250" text-anchor="middle" fill="#22c55e" font-family="system-ui,sans-serif" font-size="32" font-weight="700">${name.replace(/[<>&]/g, '')}</text>
  <text x="450" y="300" text-anchor="middle" fill="#8a8a8a" font-family="system-ui,sans-serif" font-size="16">completed all RØOT challenges</text>
  <text x="450" y="340" text-anchor="middle" fill="#22c55e" font-family="ui-monospace,monospace" font-size="18">A01–A10 · ${st.challenges}/${st.challengesTotal} · ${date}</text>
  <text x="450" y="420" text-anchor="middle" fill="#8a8a8a" font-family="system-ui,sans-serif" font-size="13">Broken Access · Crypto · Injection · Design · Misconfig</text>
  <text x="450" y="445" text-anchor="middle" fill="#8a8a8a" font-family="system-ui,sans-serif" font-size="13">Components · Auth · Integrity · Logging · SSRF</text>
  <text x="450" y="520" text-anchor="middle" fill="#6e7681" font-family="system-ui,sans-serif" font-size="11">Educational use only · For authorized security training</text>
  <text x="450" y="545" text-anchor="middle" fill="#6e7681" font-family="ui-monospace,monospace" font-size="10">RØOT · offline-first OWASP + zero-day range</text>
</svg>`;
    const blob = new Blob([svg], { type: 'image/svg+xml' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'root-certificate.svg';
    a.click();
    UI.toast(I18n.t('certReady'), 'ok');
  }

  function resolveCmdToolId() {
    const tools = DATA.CMD_BUILDERS || [];
    const want = _hubState.cmdToolId;
    if (want && tools.some(t => t.id === want)) return want;
    return tools[0]?.id || '';
  }

  function flagChecked(toolId, flagDef) {
    const saved = _hubState.cmdFlags && _hubState.cmdFlags[toolId];
    if (Array.isArray(saved)) return saved.includes(flagDef.flag);
    return !!flagDef.def;
  }

  function renderCmdBuilder() {
    const en = I18n.lang() === 'en';
    const tools = DATA.CMD_BUILDERS || [];
    const activeId = resolveCmdToolId();
    _hubState.cmdToolId = activeId;
    const targetVal = esc(_hubState.cmdTarget || '10.10.10.5');
    return `
      <div class="hero">
        <h1 style="font-size:20px">${en ? 'Command builder' : 'Сборка команд'}</h1>
        <div class="field" style="max-width:420px">
          <label>TARGET / host</label>
          <input id="cmd-target" value="${targetVal}" oninput="Tools.rebuildCmd()">
        </div>
      </div>
      <div class="card mb12">
        <div class="ch"><h2>${en?'Tool':'Инструмент'}</h2></div>
        <div class="cb">
          <div class="row" id="cmd-tool-chips">
            ${tools.map(t => `<button type="button" class="chip ${t.id === activeId ? 'active' : ''}" data-id="${esc(t.id)}"
              onclick="Tools.selectCmdTool(this,'${esc(t.id)}')">${esc(t.name)}</button>`).join('')}
          </div>
        </div>
      </div>
      <div id="cmd-panel">${cmdPanelHtml(activeId, en)}</div>`;
  }

  function cmdPanelHtml(toolId, en) {
    const t = (DATA.CMD_BUILDERS || []).find(x => x.id === toolId);
    if (!t) return '';
    return `
      <div class="card">
        <div class="ch"><h2>${esc(t.name)}</h2><span class="tag tb">builder</span></div>
        <div class="cb">
          <p class="muted mb12">${esc(I18n.pick(t.desc))}</p>
          <div class="cmd-flags" id="cmd-flags">
            ${t.flags.map(f => `
              <label class="check-row">
                <input type="checkbox" data-flag="${esc(f.flag)}" ${flagChecked(toolId, f) ? 'checked' : ''} onchange="Tools.rebuildCmd()">
                <span><code class="inline">${esc(f.flag)}</code> — ${esc(I18n.pick(f.help))}</span>
              </label>`).join('')}
          </div>
          <div class="field mt12"><label>${en?'Assembled command':'Собранная команда'}</label>
            <textarea id="cmd-out" rows="3" readonly></textarea></div>
          <div class="row">
            <button class="btn btnp" onclick="Tools.rebuildCmd()">${en?'Rebuild':'Собрать'}</button>
            <button class="btn" onclick="Tools.copy(document.getElementById('cmd-out').value)">${I18n.t('copy')}</button>
          </div>
          <p class="muted small mt8">${en?'Placeholder TARGET is replaced from the field above.':'Плейсхолдер TARGET подставляется из поля выше.'}</p>
        </div>
      </div>`;
  }

  function selectCmdTool(el, id) {
    document.querySelectorAll('#cmd-tool-chips .chip').forEach(c => c.classList.remove('active'));
    if (el) el.classList.add('active');
    _hubState.cmdToolId = id;
    saveHubState();
    const en = I18n.lang() === 'en';
    const panel = document.getElementById('cmd-panel');
    if (panel) panel.innerHTML = cmdPanelHtml(id, en);
    rebuildCmd();
  }

  function rebuildCmd() {
    const active = document.querySelector('#cmd-tool-chips .chip.active');
    const id = active?.dataset.id || _hubState.cmdToolId;
    const t = (DATA.CMD_BUILDERS || []).find(x => x.id === id);
    const out = document.getElementById('cmd-out');
    if (!t || !out) return;
    if (id) _hubState.cmdToolId = id;
    let target = (document.getElementById('cmd-target')?.value || 'TARGET').trim() || 'TARGET';
    _hubState.cmdTarget = target;
    const parts = [t.base];
    const checks = document.querySelectorAll('#cmd-flags input[type=checkbox]');
    const checkedFlags = [];
    checks.forEach(ch => {
      if (!ch.checked) return;
      const flag = ch.dataset.flag || '';
      checkedFlags.push(flag);
      // value-bearing short flags like -u that need target after
      if (flag === '-u' || flag === '-h' || flag === '--url') {
        parts.push(flag, target.includes('://') || t.id === 'ffuf' ? target : target);
      } else {
        parts.push(flag);
      }
    });
    _hubState.cmdFlags[id] = checkedFlags;
    saveHubState();
    // if no explicit -u/-h, append target at end for nmap-like
    const hasTargetFlag = [...checks].some(c => c.checked && ['-u','-h','--url'].includes(c.dataset.flag));
    let cmd = parts.join(' ').replace(/\s+/g, ' ').trim();
    if (!hasTargetFlag) cmd = (cmd + ' ' + target).trim();
    // ffuf URL default
    if (t.id === 'ffuf' && !cmd.includes('http')) {
      cmd = cmd.replace(/-u\s+\S+/, '-u ' + (target.includes('FUZZ') ? target : `https://${target}/FUZZ`));
    }
    out.value = cmd;
  }

  function mountCmdBuilder() {
    // Ensure chip active matches persisted tool (render already set HTML)
    const id = resolveCmdToolId();
    document.querySelectorAll('#cmd-tool-chips .chip').forEach(c => {
      c.classList.toggle('active', c.getAttribute('data-id') === id);
    });
    rebuildCmd();
  }

  return {
    renderToolsCatalog, showTool, renderToolPage, filterTools, filterTrack, toggleTrackGroup, toggleCat, allSecTools,
    renderPayloads, renderPayloadsInner, mountPayloads, showPayCat, showPayGroup,
    payloadCategoryLabel, payloadItemTitle, payloadItemText,
    renderCommandsHub, mountCommandsHub,
    chainDomain, sortChains, filterChainRows,
    renderChains, showChain, showChainGroup, showChainDomain, filterChains, mountChains, openChainsForOwasp,
    renderReports, showReport, mountReports, renderProgress, exportProgress, downloadCert, copy, copyFromB64, cmdBlockHtml,
    renderCmdBuilder, selectCmdTool, rebuildCmd, mountCmdBuilder,
    renderKuber, mountKuber, selectKuberTool, kuberToggleFlag, kuberRebuild, kuberCopy,
  };
})();
