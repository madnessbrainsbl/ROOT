/* Zero-Day / KEV catalog: source of truth = SQLite table zero_days */
const ZeroDays = (() => {
  const esc = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const L = (ru, en) => (I18n.lang() === 'en' ? en : ru);
  let activeId = null;
  /** Persist category chip across lang switch + page reload. */
  let _zdFilter = (() => {
    try {
      const f = sessionStorage.getItem('zd_filter');
      if (f != null && f !== '') return f;
    } catch (_) {}
    return '*';
  })();

  /** All rows from SQL (fallback: JS seed if DB not ready) */
  function allItems() {
    if (typeof SqlLab !== 'undefined' && SqlLab.ready) {
      const rows = SqlLab.query('SELECT * FROM zero_days ORDER BY n');
      if (rows.length) return rows;
    }
    return (typeof ZERO_DAYS !== 'undefined' && ZERO_DAYS.items) ? ZERO_DAYS.items : [];
  }

  function getItem(id) {
    let it = null;
    if (typeof SqlLab !== 'undefined' && SqlLab.ready) {
      const rows = SqlLab.query('SELECT * FROM zero_days WHERE id = ?', [id]);
      if (rows.length) it = rows[0];
    }
    const js = (typeof ZERO_DAYS !== 'undefined' && ZERO_DAYS.items)
      ? ZERO_DAYS.items.find(x => x.id === id) : null;
    // Prefer long knowledge articles from JS seed if SQL row is stale/short
    if (js && (!it || !it.theory_ru || String(it.theory_ru).length < 400)) {
      return js;
    }
    return it || js || null;
  }

  function showSql() { /* SQL terminal removed */ }

  function bonuses() {
    if (typeof SqlLab !== 'undefined' && SqlLab.ready) {
      const rows = SqlLab.query('SELECT id, title_en, title_ru, when_txt AS "when", note FROM zero_day_bonuses');
      if (rows.length) return rows;
    }
    return (typeof ZERO_DAYS !== 'undefined' && ZERO_DAYS.bonuses) ? ZERO_DAYS.bonuses : [];
  }

  function count() {
    if (typeof SqlLab !== 'undefined' && SqlLab.ready) {
      try { return SqlLab.countTable('zero_days'); } catch (_) {}
    }
    return allItems().length;
  }

  function capture(id) {
    const it = getItem(id);
    if (!it) return;
    if (Store.hasChallenge(id)) {
      showFlag(it.flag, true);
      return;
    }
    Store.setChallengeFlag(id, it.flag);
    UI.toast(I18n.t('flagCaptured') + ': ' + it.flag, 'ok');
    UI.refreshNav();
    showFlag(it.flag, false);
  }

  function showFlag(flag, already) {
    const el = document.getElementById('zd-flag');
    if (!el) return;
    el.innerHTML = `<div class="flag-box"><div class="flabel">${already ? I18n.t('flagGot') : I18n.t('ctfCaptured')}</div>
      <div class="fval">${esc(flag)}</div></div>`;
  }

  function byCategory() {
    const map = {};
    allItems().forEach(it => {
      const cat = it.category || 'other';
      if (!map[cat]) map[cat] = [];
      map[cat].push(it);
    });
    return map;
  }

  function addFormHtml(en) {
    const practices = 'auth_bypass,cmdi,oob_leak,path_trav,deser,ssrf_rce,crlf,dos,ntlm,race,lpe,uaf,rce_browser,rce_client,info_leak,generic,symlink';
    return `
      <div class="card mb12" id="zd-add-card">
        <div class="ch" style="cursor:pointer" onclick="document.getElementById('zd-add-body').classList.toggle('hidden')">
          <h2>${en ? '+ Add vulnerability' : '+ Добавить уязвимость'}</h2>
        </div>
        <div class="cb hidden" id="zd-add-body">
          <p class="muted small mb8">${en
            ? 'Adds an entry to the catalog (saved locally). Existing CVEs are above.'
            : 'Добавляет запись в каталог (локально). Существующие CVE — выше.'}</p>
          <div class="g2">
            <div class="field"><label>CVE</label><input id="zd-add-cve" placeholder="CVE-2026-12345"></div>
            <div class="field"><label>${en?'Product':'Продукт'}</label><input id="zd-add-product" placeholder="FortiOS / Chrome / …"></div>
            <div class="field"><label>CWE / class</label><input id="zd-add-cwe" placeholder="Auth bypass / UAF"></div>
            <div class="field"><label>${en?'Category key':'Категория (key)'}</label>
              <select id="zd-add-cat">
                ${['kernel','windows','apple','android','browser','edge','iot','virt','enterprise','client','hosting'].map(c =>
                  `<option value="${c}">${c}</option>`).join('')}
              </select>
            </div>
            <div class="field"><label>category_en</label><input id="zd-add-cat-en" placeholder="Edge appliances"></div>
            <div class="field"><label>category_ru</label><input id="zd-add-cat-ru" placeholder="Edge / appliance"></div>
            <div class="field"><label>practice</label>
              <select id="zd-add-practice">
                ${practices.split(',').map(p => `<option value="${p}">${p}</option>`).join('')}
              </select>
            </div>
            <div class="field"><label>owasp_note</label><input id="zd-add-owasp" value="—" placeholder="≈A01 or —"></div>
            <div class="field"><label>points</label><input id="zd-add-points" type="number" value="10" min="1" max="100"></div>
            <div class="field"><label>diff (1–3)</label><input id="zd-add-diff" type="number" value="2" min="1" max="3"></div>
          </div>
          <div class="field"><label>summary_en</label><textarea id="zd-add-sum-en" rows="2"></textarea></div>
          <div class="field"><label>summary_ru</label><textarea id="zd-add-sum-ru" rows="2"></textarea></div>
          <div class="field"><label>theory_en (HTML ok)</label><textarea id="zd-add-th-en" rows="3" placeholder="<h3>…</h3><p>…</p>"></textarea></div>
          <div class="field"><label>theory_ru (HTML ok)</label><textarea id="zd-add-th-ru" rows="3"></textarea></div>
          <div class="row">
            <button class="btn btnp" type="button" onclick="ZeroDays.addFromForm()">${en ? 'Add to catalog' : 'Добавить в каталог'}</button>

          </div>
          <div id="zd-add-msg" class="mt8"></div>
        </div>
      </div>`;
  }

  function addFromForm() {
    if (typeof SqlLab === 'undefined' || !SqlLab.ready) {
      UI.toast(L('Каталог ещё не готов', 'Catalog not ready'), 'err');
      return;
    }
    const g = (id) => (document.getElementById(id)?.value || '').trim();
    const cve = g('zd-add-cve');
    const product = g('zd-add-product');
    if (!cve || !product) {
      UI.toast(L('Нужны CVE и Product', 'CVE and Product required'), 'err');
      return;
    }
    try {
      const nextRows = SqlLab.query('SELECT COALESCE(MAX(n),0)+1 AS n FROM zero_days');
      const n = nextRows[0] ? nextRows[0].n : 1;
      const id = 'zd-' + String(n).padStart(2, '0');
      const flagBase = cve.replace(/CVE-/i, '').replace(/[^0-9a-zA-Z]/g, '_');
      const flag = 'FLAG{zd_' + n + '_' + flagBase.slice(0, 12) + '}';
      const points = parseInt(g('zd-add-points'), 10) || 10;
      const diff = Math.min(3, Math.max(1, parseInt(g('zd-add-diff'), 10) || 2));
      const cat = g('zd-add-cat') || 'edge';
      const sumEn = g('zd-add-sum-en') || (cve + ' affects ' + product);
      const sumRu = g('zd-add-sum-ru') || sumEn;
      const thEn = g('zd-add-th-en') || ('<h3>' + esc(cve) + '</h3><p>' + esc(sumEn) + '</p>');
      const thRu = g('zd-add-th-ru') || ('<h3>' + esc(cve) + '</h3><p>' + esc(sumRu) + '</p>');

      SqlLab.run(
        `INSERT INTO zero_days
          (n,id,cve,product,cwe,category,category_en,category_ru,
           summary_en,summary_ru,practice,owasp_note,flag,points,diff,
           theory_en,theory_ru,source)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [
          n, id, cve, product, g('zd-add-cwe') || '—', cat,
          g('zd-add-cat-en') || cat, g('zd-add-cat-ru') || cat,
          sumEn, sumRu, g('zd-add-practice') || 'generic',
          g('zd-add-owasp') || '—', flag, points, diff,
          thEn, thRu, 'user',
        ]
      );
      UI.toast(L('Добавлено в zero_days: ', 'Inserted into zero_days: ') + id + ' / ' + cve, 'ok');
      UI.route('zerodays');
    } catch (e) {
      UI.toast(String(e.message || e), 'err');
      const msg = document.getElementById('zd-add-msg');
      if (msg) msg.innerHTML = `<div class="resp err">${esc(e.message || e)}</div>`;
    }
  }

  function renderHub() {
    const en = I18n.lang() === 'en';
    return `
      <div class="lab-page tools-page">
        <div class="hero tools-hero zd-intro-hero">
          <h1>Zero-Days</h1>
          <p class="tools-hero-desc">${en
            ? 'CVE catalog and actively exploited vulnerabilities from CISA KEV, NVD, and other sources. Use filters to search, then open a record to view the description, references, and recommendations.'
            : 'Каталог CVE и активно эксплуатируемых уязвимостей из CISA KEV, NVD и других источников. Используйте фильтры для поиска, а затем откройте запись, чтобы посмотреть описание, ссылки и рекомендации.'}</p>
        </div>
        <div class="card" id="zd-catalog">
          <div class="ch">
            <h2 style="flex:1">${en ? 'Vulnerability catalog' : 'Каталог уязвимостей'}</h2>
          </div>
          <div class="cb">
            <div id="cve9-section">
              <div class="root-spin-wrap"><div class="root-spinner"></div></div>
            </div>
          </div>
        </div>
      </div>`;
  }

  function filterCat(elOrKey) {
    const key = (typeof elOrKey === 'string')
      ? elOrKey
      : (elOrKey?.getAttribute?.('data-zd-filter') || '*');
    _zdFilter = key || '*';
    try { sessionStorage.setItem('zd_filter', _zdFilter); } catch (_) {}
    document.querySelectorAll('#zd-cat-filters .chip').forEach(c => {
      c.classList.toggle('active', c.getAttribute('data-zd-filter') === _zdFilter);
    });
    document.querySelectorAll('#zd-tbody tr.zd-row').forEach(tr => {
      const cat = tr.getAttribute('data-zd-cat') || '';
      const show = _zdFilter === '*' || cat === _zdFilter;
      tr.style.display = show ? '' : 'none';
    });
  }

  function bindHub() {
    if (typeof CvesCvss9 !== 'undefined') CvesCvss9.initUnified(allItems());
  }

  function open(id) {
    activeId = id;
    UI.route('zeroday', id);
  }

  /** Study links: from item.sources (JSON/array) + always NVD/CVE.org/MITRE/KEV. */
  function parseSources(it) {
    const cve = String(it?.cve || '').trim().toUpperCase();
    const defaults = [];
    if (cve && /^CVE-\d{4}-\d+/i.test(cve)) {
      defaults.push(
        { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${cve}` },
        { name: 'CVE.org', url: `https://www.cve.org/CVERecord?id=${cve}` },
        { name: 'MITRE', url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}` },
        { name: 'CISA KEV', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
      );
    }
    let extra = [];
    let raw = it?.sources;
    if (typeof raw === 'string' && raw.trim()) {
      try { raw = JSON.parse(raw); } catch (_) { raw = null; }
    }
    if (Array.isArray(raw)) {
      extra = raw.filter(s => s && s.url).map(s => ({
        name: s.name || s.url,
        url: s.url,
      }));
    }
    const seen = new Set();
    const out = [];
    [...extra, ...defaults].forEach(s => {
      const u = String(s.url || '').trim();
      if (!u || seen.has(u)) return;
      seen.add(u);
      out.push({ name: s.name || u, url: u });
    });
    return out;
  }

  function renderSourcesBlock(it, en) {
    const links = parseSources(it);
    if (!links.length) return '';
    const feed = it.feed_from ? String(it.feed_from) : '';
    return `
      <div class="meta-block zd-sources">
        <div class="meta-label">${en ? 'Sources / read more' : 'Источники / читать'}</div>
        ${feed ? `<div class="meta-line muted small" style="margin-bottom:6px">${en ? 'Feeds:' : 'Фиды:'} ${esc(feed)}</div>` : ''}
        <ul class="zd-source-list">
          ${links.map(s =>
            `<li><a href="${esc(s.url)}" target="_blank" rel="noopener noreferrer">${esc(s.name)}</a></li>`
          ).join('')}
        </ul>
      </div>`;
  }

  function splitSections(html) {
    const parts = html.split(/(?=<h3>)/);
    return parts.map(p => {
      const m = p.match(/<h3>(.*?)<\/h3>\s*/);
      return m ? { title: m[1], content: p.slice(m[0].length) } : null;
    }).filter(Boolean);
  }

  /** Prefer real RU body (Cyrillic); else EN + notice when only headers were swapped. */
  function pickLocalizedText(enHtml, ruHtml, en) {
    if (en) return { html: enHtml || ruHtml || '', note: null };
    const ru = ruHtml || '';
    const cyr = (ru.match(/[А-Яа-яЁё]/g) || []).length;
    if (cyr >= 120) return { html: ru, note: null };
    // weak / header-only RU: show best available + honest note
    const html = (cyr >= 40 ? ru : (enHtml || ru));
    return {
      html,
      note: 'Часть текста статьи на английском (фид NVD/KEV). Заголовки и мета — RU; первоисточники — в блоке «Источники».',
    };
  }

  function renderItem(id) {
    const it = getItem(id);
    if (!it) return `<div class="card"><div class="cb">Not found in zero_days</div></div>`;
    const en = I18n.lang() === 'en';
    const done = Store.hasChallenge(id);
    const theoryPick = pickLocalizedText(it.theory_en || '', it.theory_ru || '', en);
    const sumPick = pickLocalizedText(it.summary_en || '', it.summary_ru || '', en);
    const body = theoryPick.html;
    const sum = sumPick.html;
    // Single scroll page — no theory/practice tabs (little content to justify them)
    return `
      <div class="lab-page">
        <div class="row mb12">
          <button class="btn" onclick="UI.route('zerodays')">← ${en?'Catalog':'Каталог'}</button>
        </div>
        <div class="card lab-card">
          <div class="ch lab-header">
            <div class="lab-title">
              <span class="lab-code">#${esc(it.n || '')}</span>
              <div>
                <h2>${esc(it.cve)}</h2>
                <div class="lab-sub">${esc(it.product)} · ${esc(it.cwe)} · ${esc(en?(it.category_en||it.category):(it.category_ru||it.category))}${it.source==='user'?' · user':''}</div>
              </div>
            </div>
            <div class="row">
              ${it.owasp_note && it.owasp_note!=='—'?`<span class="tag tb">${esc(it.owasp_note)}</span>`:''}
              ${done?'<span class="tag tm">FLAG ✓</span>':''}
            </div>
          </div>
          <div class="theory-wrap zd-article" style="padding:12px 16px 8px">
            <div class="theory">
              ${theoryPick.note || sumPick.note ? `<div class="ebox warn" style="margin-top:0">${esc(theoryPick.note || sumPick.note)}</div>` : ''}
              <div class="ebox info" style="margin-top:${theoryPick.note || sumPick.note ? '8px' : '0'}">${esc(sum)}</div>
              <div class="zd-theory-body" style="margin-top:12px">${body}</div>
            </div>
            <aside class="theory-meta">
              <div class="meta-block">
                <div class="meta-label">CVE</div>
                <div class="meta-line"><strong>${esc(it.cve)}</strong></div>
              </div>
              <div class="meta-block">
                <div class="meta-label">${en?'Product':'Продукт'}</div>
                <div class="meta-line">${esc(it.product)}</div>
              </div>
              <div class="meta-block">
                <div class="meta-label">CWE / class</div>
                <div class="meta-line">${esc(it.cwe)}</div>
              </div>
              <div class="meta-block">
                <div class="meta-label">${en?'Category':'Категория'}</div>
                <div class="meta-line">${esc(en?(it.category_en||it.category):(it.category_ru||it.category))}</div>
              </div>
              <div class="meta-block">
                <div class="meta-label">OWASP</div>
                <div class="meta-line">${esc(it.owasp_note || '—')}</div>
              </div>
              <div class="meta-block">
                <div class="meta-label">${en?'Practice type':'Тип практики'}</div>
                <div class="meta-line"><code class="inline">${esc(it.practice)}</code></div>
              </div>
              ${renderSourcesBlock(it, en)}
            </aside>
          </div>
          <div class="zd-practice-block" style="padding:8px 16px 16px;border-top:1px solid var(--bdr)">
            <div class="goal">
              <strong>${en?'Practice: recreate the attack path':'Практика: воспроизведи путь атаки'}</strong>
              <div class="flag-hint">${en?'Simulated lab — no real exploits fire. Capture the flag when the chain succeeds.':'Симуляция — реальные эксплойты не запускаются. Флаг при успешной цепочке.'}</div>
            </div>
            ${practiceUI(it)}
            <div id="zd-flag">${done?`<div class="flag-box"><div class="flabel">${I18n.t('yourFlag')}</div><div class="fval">${esc(it.flag)}</div></div>`:''}</div>
          </div>
        </div>
      </div>`;
  }

  function bindTabs() {
    /* tabs removed — single page layout */
  }

  function toggleCat(id) {
    const el = document.getElementById('zd-cat-' + id);
    if (!el) return;
    const body = el.querySelector('.cb, .tools-group-body');
    const icon = el.querySelector('.zd-acc-icon, .tools-chevron');
    if (!body) return;
    const hide = body.classList.toggle('hidden');
    el.classList.toggle('collapsed', hide);
    if (icon) icon.textContent = hide ? '▸' : '▾';
  }

  function toggleSect(el) {
    const item = el.closest('.zd-acc-item');
    if (!item) return;
    const body = item.querySelector('.zd-acc-b');
    const icon = item.querySelector('.zd-acc-icon');
    if (!body) return;
    body.classList.toggle('hidden');
    item.classList.toggle('open');
    if (icon) icon.textContent = body.classList.contains('hidden') ? '▸' : '▾';
  }

  function frame(url, body) {
    return `<div class="lab-frame"><div class="lab-chrome">
      <div class="dots"><span class="dot r"></span><span class="dot y"></span><span class="dot g"></span></div>
      <div class="url">${esc(url)}</div></div>
      <div class="lab-body">${body}</div></div>`;
  }

  function practiceUI(it) {
    const en = I18n.lang() === 'en';
    const p = it.practice;
    const id = it.id;

    if (p === 'auth_bypass') {
      return frame(`https://${esc(it.product.split(' ')[0].toLowerCase())}.local/mgmt`, `
        <h3>${en?'Unauth management API':'Management API без auth'}</h3>
        <p class="muted">${esc(it.cve)} — ${en?'hit a privileged endpoint without credentials':'привилегированный endpoint без credentials'}</p>
        <div class="field"><label>Path</label>
          <select id="zd-path">
            <option value="/">/</option>
            <option value="/api/v1/status">/api/v1/status</option>
            <option value="/api/v1/admin/users">/api/v1/admin/users</option>
            <option value="/saml/login">/saml/login</option>
          </select></div>
        <div class="field"><label>Authorization</label>
          <select id="zd-auth">
            <option value="none">${en?'(none)':'(нет)'}</option>
            <option value="bearer">Bearer user</option>
            <option value="admin">Bearer admin</option>
          </select></div>
        <button class="btn btnp" onclick="ZeroDays.tryAuth('${id}')">GET</button>
        <div id="zd-out"></div>`);
    }
    if (p === 'cmdi') {
      return frame('https://device.local/diag', `
        <h3>${en?'Diagnostic command':'Диагностическая команда'}</h3>
        <p class="muted">${en?'Input concatenated into shell':'Ввод склеивается в shell'}</p>
        <div class="field"><label>host</label><input id="zd-host" value="127.0.0.1"></div>
        <button class="btn btnp" onclick="ZeroDays.tryCmdi('${id}')">ping</button>
        <div id="zd-out"></div>
        <p class="muted small mt8">Hint: <code class="inline">127.0.0.1; id</code></p>`);
    }
    if (p === 'oob_leak') {
      return frame('https://netscaler.local/saml', `
        <h3>${en?'OOB read (CitrixBleed-class)':'OOB read (класс CitrixBleed)'}</h3>
        <p class="muted">${en?'Oversized/malformed param leaks session memory':'Переразмеренный/битый параметр → утечка session memory'}</p>
        <div class="field"><label>SAML parameter length</label>
          <input id="zd-len" type="number" value="64" min="1" max="99999"></div>
        <button class="btn btnp" onclick="ZeroDays.tryOob('${id}')">${en?'Send':'Отправить'}</button>
        <div id="zd-out"></div>`);
    }
    if (p === 'path_trav' || p === 'symlink') {
      return frame('extract://archive', `
        <h3>${p==='symlink'?'Symlink extract':'Path traversal extract'}</h3>
        <div class="field"><label>${en?'Archive entry path':'Путь внутри архива'}</label>
          <input id="zd-path" style="font-family:var(--mono)" placeholder="../..."></div>
        <button class="btn btnp" onclick="ZeroDays.tryPath('${id}','${p}')">${en?'Extract':'Извлечь'}</button>
        <div id="zd-out"></div>
        <p class="muted small mt8">${p==='symlink'
          ? 'Hint: evil → /home/user/.ssh/authorized_keys'
          : 'Hint: ..\\\\..\\\\..\\\\Users\\\\Public\\\\Startup\\\\evil.dll  or  ../../../.config/autostart/'}</p>`);
    }
    if (p === 'deser') {
      return frame('https://app.local/api/import', `
        <h3>${en?'Deserialization endpoint':'Эндпоинт десериализации'}</h3>
        <div class="field"><label>payload (base64 / gadget name)</label>
          <input id="zd-deser" placeholder="ysoserial / Java serialized…"></div>
        <button class="btn btnp" onclick="ZeroDays.tryDeser('${id}')">POST</button>
        <div id="zd-out"></div>
        <p class="muted small mt8">Hint: include <code class="inline">ysoserial</code> or <code class="inline">rO0AB</code> or <code class="inline">ObjectInputStream</code></p>`);
    }
    if (p === 'ssrf_rce') {
      return frame('https://ebs.local/OA_HTML', `
        <h3>SSRF → internal RCE (${esc(it.cve)})</h3>
        <div class="field"><label>callback URL</label>
          <input id="zd-url" value="http://example.com"></div>
        <div class="row">
          <button class="btn" onclick="document.getElementById('zd-url').value='http://127.0.0.1:7201/OA_HTML/internal'">internal</button>
          <button class="btn btnp" onclick="ZeroDays.trySsrf('${id}')">Fetch</button>
        </div>
        <div id="zd-out"></div>`);
    }
    if (p === 'crlf') {
      return frame('https://cpanel.local:2083', `
        <h3>CRLF → session file (${esc(it.cve)})</h3>
        <div class="field"><label>Cookie / session inject</label>
          <input id="zd-crlf" style="font-family:var(--mono)" placeholder="session=..."></div>
        <button class="btn btnp" onclick="ZeroDays.tryCrlf('${id}')">Send</button>
        <div id="zd-out"></div>
        <p class="muted small mt8">Hint: inject <code class="inline">\\r\\n</code> or <code class="inline">%0d%0a</code> with root=1</p>`);
    }
    if (p === 'dos') {
      return frame('https://edge.local/', `
        <h3>${en?'Resource exhaustion / DoS':'Исчерпание ресурсов / DoS'}</h3>
        <div class="field"><label>${en?'Parallel streams / packets':'Параллельные потоки / пакеты'}</label>
          <input id="zd-n" type="number" value="10" min="1" max="100000"></div>
        <button class="btn btnp" onclick="ZeroDays.tryDos('${id}')">${en?'Flood':'Флуд'}</button>
        <div id="zd-out"></div>
        <p class="muted small mt8">${en?'Need enough volume to trip fail-open / maintenance mode.':'Нужен объём, чтобы сработал fail-open / maintenance mode.'}</p>`);
    }
    if (p === 'ntlm') {
      return frame('file://UNC', `
        <h3>NTLM hash leak (UNC)</h3>
        <div class="field"><label>.lnk / document target</label>
          <input id="zd-unc" style="font-family:var(--mono)" placeholder="\\\\attacker\\share"></div>
        <button class="btn btnp" onclick="ZeroDays.tryNtlm('${id}')">${en?'Open':'Открыть'}</button>
        <div id="zd-out"></div>`);
    }
    if (p === 'race' || p === 'lpe' || p === 'uaf' || p === 'rce_browser' || p === 'rce_client' || p === 'info_leak') {
      return frame(`lab://${esc(it.practice)}`, `
        <h3>${en?'Ordered kill-chain':'Упорядоченная kill-chain'}</h3>
        <p class="muted">${esc(it.cve)} — ${en?'select steps in correct order':'выбери шаги в правильном порядке'}</p>
        <div id="zd-steps" class="zd-steps">
          ${chainOptions(it).map((s,i) => `
            <label class="zd-step"><input type="checkbox" data-i="${i}" data-ok="${s.ok?1:0}"> ${esc(en?s.en:s.ru)}</label>`).join('')}
        </div>
        <button class="btn btnp mt12" onclick="ZeroDays.tryChain('${id}')">${en?'Run chain':'Запустить цепочку'}</button>
        <div id="zd-out"></div>`);
    }
    return frame('lab://generic', `
      <h3>${esc(it.cve)}</h3>
      <p>${en?it.summary_en:it.summary_ru}</p>
      <button class="btn btnp" onclick="ZeroDays.tryGeneric('${id}')">${en?'Mark exploited':'Отметить эксплуатацию'}</button>
      <div id="zd-out"></div>`);
  }

  function chainOptions(it) {
    const p = it.practice;
    if (p === 'race') return [
      {ok:true, en:'1. Open shared epoll fd from unprivileged context', ru:'1. Открыть shared epoll fd из unprivileged контекста'},
      {ok:true, en:'2. Race concurrent ep_remove / wait', ru:'2. Гонка concurrent ep_remove / wait'},
      {ok:true, en:'3. Win UAF → escalate privileges', ru:'3. Выиграть UAF → escalation'},
      {ok:false, en:'Patch kernel before racing', ru:'Патчить kernel перед гонкой'},
      {ok:false, en:'Send SQL injection to epoll', ru:'Отправить SQL injection в epoll'},
    ];
    if (p === 'lpe') return [
      {ok:true, en:'1. Obtain local code execution / open device node', ru:'1. Локальное исполнение / open device node'},
      {ok:true, en:'2. Trigger kernel bug (overflow / logic)', ru:'2. Триггер kernel bug (overflow / logic)'},
      {ok:true, en:'3. Overwrite creds / escape namespace', ru:'3. Перезапись creds / escape namespace'},
      {ok:false, en:'Use default web password admin/admin only', ru:'Только пароль admin/admin в вебе'},
    ];
    if (p === 'uaf' || p === 'rce_browser') return [
      {ok:true, en:'1. Craft HTML/JS triggering engine bug', ru:'1. HTML/JS, триггерящий баг движка'},
      {ok:true, en:'2. Achieve RCE inside renderer/sandbox', ru:'2. RCE внутри renderer/sandbox'},
      {ok:true, en:'3. Optional: chain sandbox escape', ru:'3. Опционально: sandbox escape'},
      {ok:false, en:'Disable JS and reload', ru:'Отключить JS и перезагрузить'},
    ];
    if (p === 'rce_client') return [
      {ok:true, en:'1. Deliver weaponized file (RTF/LNK/doc)', ru:'1. Доставить weaponized файл (RTF/LNK/doc)'},
      {ok:true, en:'2. User or preview opens file', ru:'2. Пользователь/preview открывает файл'},
      {ok:true, en:'3. Payload runs with user privileges', ru:'3. Payload с правами пользователя'},
      {ok:false, en:'Exploit requires SQLmap only', ru:'Нужен только sqlmap'},
    ];
    if (p === 'info_leak') return [
      {ok:true, en:'1. Access config/export without need-to-know', ru:'1. Доступ к config/export без need-to-know'},
      {ok:true, en:'2. Read recoverable secrets', ru:'2. Прочитать recoverable secrets'},
      {ok:false, en:'Encrypt secrets with rot13', ru:'Зашифровать secrets rot13'},
    ];
    return [
      {ok:true, en:'1. Recon surface', ru:'1. Разведка поверхности'},
      {ok:true, en:'2. Trigger vulnerability', ru:'2. Триггер уязвимости'},
      {ok:true, en:'3. Achieve impact', ru:'3. Достичь impact'},
      {ok:false, en:'Ignore vendor advisory', ru:'Игнорировать vendor advisory'},
    ];
  }

  function out(msg, ok) {
    const el = document.getElementById('zd-out');
    if (el) el.innerHTML = `<div class="resp ${ok?'ok':'err'}">${msg}</div>`;
  }

  function tryAuth(id) {
    const path = document.getElementById('zd-path').value;
    const auth = document.getElementById('zd-auth').value;
    if (auth === 'none' && /admin|users|api\/v1\/admin/i.test(path)) {
      out('200 OK — privileged data without auth (auth bypass)', true);
      capture(id);
    } else if (auth !== 'none') {
      out('200 with token — try WITHOUT credentials on admin path', false);
    } else {
      out('200 public — pick a privileged path', false);
    }
  }
  function tryCmdi(id) {
    const h = document.getElementById('zd-host').value;
    if (/[;|&`$]|\$\(/.test(h)) {
      out(`$ ping ${esc(h)}\nuid=0(root) ... command injection RCE`, true);
      capture(id);
    } else out(`PING ${esc(h)} — no injection`, false);
  }
  function tryOob(id) {
    const n = +document.getElementById('zd-len').value;
    if (n >= 2048) {
      out('HTTP 200\n...SESSION_TOKEN=a3f9...\nTLS_KEY_FRAGMENT=...\n(out-of-bounds read)', true);
      capture(id);
    } else out(`Response normal (len=${n}). Increase length to force OOB.`, false);
  }
  function tryPath(id, p) {
    const path = document.getElementById('zd-path').value;
    const ok = p === 'symlink'
      ? /symlink|authorized_keys|\//i.test(path)
      : /\.\.|%2e%2e|startup|autostart|ads|:/i.test(path);
    if (ok) {
      out(`Extracted to unexpected location:\n${esc(path)}\npersistence achieved`, true);
      capture(id);
    } else out('Extracted safely inside archive root', false);
  }
  function tryDeser(id) {
    const v = document.getElementById('zd-deser').value;
    if (/ysoserial|rO0AB|ObjectInputStream|gadget|pickle|Serial/i.test(v)) {
      out('Deserialization gadget executed → RCE (simulated)', true);
      capture(id);
    } else out('Invalid or non-gadget payload', false);
  }
  function trySsrf(id) {
    const u = document.getElementById('zd-url').value;
    if (/127\.0\.0\.1|localhost|internal|169\.254/i.test(u)) {
      out(`SSRF hit ${esc(u)}\n→ internal RCE gadget / data exfil (Clop-class)`, true);
      capture(id);
    } else out('Fetched external page only', false);
  }
  function tryCrlf(id) {
    const v = document.getElementById('zd-crlf').value;
    if (/%0d%0a|\\r\\n|\r\n|root=1/i.test(v)) {
      out('Session file poisoned via CRLF → root shell (simulated)', true);
      capture(id);
    } else out('Session looks normal', false);
  }
  function tryDos(id) {
    const n = +document.getElementById('zd-n').value;
    if (n >= 1000) {
      out(`Flood n=${n} → service maintenance mode / DoS`, true);
      capture(id);
    } else out(`n=${n} absorbed. Try >= 1000`, false);
  }
  function tryNtlm(id) {
    const u = document.getElementById('zd-unc').value;
    if (/\\\\|smb:|attacker/i.test(u)) {
      out(`Authentication to ${esc(u)}\nNTLMv2: user::domain:challenge:response...`, true);
      capture(id);
    } else out('No outbound auth', false);
  }
  function tryChain(id) {
    const boxes = [...document.querySelectorAll('#zd-steps input[type=checkbox]')];
    const selected = boxes.filter(b => b.checked);
    if (!selected.length) { out(L('Выбери шаги','Select steps'), false); return; }
    const allOk = selected.every(b => b.dataset.ok === '1');
    const need = boxes.filter(b => b.dataset.ok === '1').length;
    const got = selected.filter(b => b.dataset.ok === '1').length;
    if (allOk && got >= need) {
      out('Kill-chain complete — impact achieved', true);
      capture(id);
    } else out('Wrong or incomplete chain (do not include defensive-only steps)', false);
  }
  function tryGeneric(id) {
    out('Simulated exploitation complete', true);
    capture(id);
  }

  /** Ensure catalog seeded once (no wipe of user rows) */
  function seedSql() {
    if (typeof SqlLab === 'undefined' || !SqlLab.ready) return;
    try {
      SqlLab.seedZeroDaysCatalog();
      SqlLab.persist();
    } catch (e) {
      console.warn('zero_days seed', e);
    }
  }

  return {
    renderHub, renderItem, open, bindTabs, bindHub, toggleCat, toggleSect, filterCat, seedSql, count, addFromForm, parseSources,
    allItems, getItem, showSql,
    tryAuth, tryCmdi, tryOob, tryPath, tryDeser, trySsrf, tryCrlf, tryDos, tryNtlm, tryChain, tryGeneric,
  };
})();
