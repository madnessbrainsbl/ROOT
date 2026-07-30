/* CvesCvss9 — unified catalog backed by the bundled public CVE seed. */
const CvesCvss9 = (() => {
  let _perPage   = 50;
  let _ctf       = [];
  let _page      = 0;
  let _q         = '';
  let _sev       = '*';
  let _dbReady   = false;
  let _tableCache = null;
  let _chipsCache = null;

  const SS_TABLE = 'root-cve-table-v2';
  const SS_CHIPS = 'root-cve-chips-v2';
  function _ssGet(k)    { try { return sessionStorage.getItem(k); } catch { return null; } }
  function _ssSet(k, v) { try { sessionStorage.setItem(k, v); } catch {} }

  const esc     = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const isEn    = () => I18n.lang() === 'en';
  const safeUrl = u => { try { const p = new URL(u); return (p.protocol==='https:'||p.protocol==='http:') ? esc(u) : '#'; } catch { return '#'; } };

  const SEV_STYLE = {
    CTF:      'background:rgba(99,102,241,.2);color:#818cf8;border:1px solid rgba(99,102,241,.35)',
    CRITICAL: 'background:#dc2626;color:#fff',
    HIGH:     'background:#ea580c;color:#fff',
    MEDIUM:   'background:#d97706;color:#fff',
    LOW:      'background:#16a34a;color:#fff',
    NONE:     'background:var(--bg2);color:var(--mut);border:1px solid var(--bdr)',
  };

  function sevBadge(sev) {
    const s = String(sev||'NONE').toUpperCase();
    return `<span class="tag" style="${SEV_STYLE[s]||SEV_STYLE.NONE}">${esc(s)}</span>`;
  }

  function _normSev(x) {
    const s = String(x.severity||'').toUpperCase();
    if (s && s !== 'NONE') return s;
    const sc = Number(x.cvss_score);
    return sc>=9?'CRITICAL':sc>=7?'HIGH':sc>=4?'MEDIUM':sc>0?'LOW':'NONE';
  }

  function _normCtf() {
    const en = isEn();
    return _ctf.map(it => ({
      _type: 'ctf',
      _id:   String(it.id||''),
      cveId: String(it.cve||it.id||''),
      title: en ? (it.summary_en||'') : (it.summary_ru||it.summary_en||''),
      sev:   'CTF',
      vp:    String(it.product||''),
      pub:   '',
      done:  Store.hasChallenge(it.id),
    }));
  }

  function _normCveRow(x) {
    return {
      _type: 'cve',
      _id:   String(x.cve_id||''),
      cveId: String(x.cve_id||''),
      title: String(x.title||'').slice(0,200),
      sev:   _normSev(x),
      vp:    (x.affected_vendor||'')+(x.affected_product?' / '+x.affected_product:''),
      pub:   (x.published_at||'').slice(0,10).split('-').reverse().join('.'),
      done:  false,
    };
  }

  /* ── Progress overlay ────────────────────────────────── */
  function _showProgress(done, total) {
    const pct = total > 0 ? Math.round(done / total * 100) : 0;
    const bar   = document.getElementById('cve9-imp-bar');
    const pctEl = document.getElementById('cve9-imp-pct');
    if (bar)   bar.style.width   = pct + '%';
    if (pctEl) pctEl.textContent = pct + '%';
    _updateBgIndicator(done, total);
  }

  function _updateBgIndicator(done, total) {
    let el = document.getElementById('cve9-bg-indicator');
    if (done >= total) { if (el) el.remove(); return; }
    if (!_dbReady) return; // overlay still visible — don't duplicate
    const pct = Math.round(done / total * 100);
    if (!el) {
      const section = document.getElementById('cve9-section');
      if (!section) return;
      el = document.createElement('div');
      el.id = 'cve9-bg-indicator';
      el.style.cssText = 'margin-bottom:10px';
      el.innerHTML = `
        <div style="font-family:var(--mono);font-size:11px;color:#fff;font-weight:700;text-align:right;margin-bottom:4px">
          <span id="cve9-bg-pct">${pct}%</span>
        </div>
        <div style="border:1px solid #fff;padding:2px;background:#000">
          <div id="cve9-bg-fill" style="height:6px;width:${pct}%;background:#fff;transition:width .4s linear"></div>
        </div>`;
      section.insertBefore(el, section.firstChild);
    } else {
      const fill = el.querySelector('#cve9-bg-fill');
      const cnt  = el.querySelector('#cve9-bg-cnt');
      const pctEl = el.querySelector('#cve9-bg-pct');
      if (fill)  fill.style.width    = pct + '%';
      if (cnt)   cnt.textContent     = '';
      if (pctEl) pctEl.textContent   = pct + '%';
    }
  }

  function _importOverlayHtml() {
    return `
      <div id="cve9-import-overlay" style="padding:32px 0 24px">
        <div style="font-family:var(--mono);font-size:28px;font-weight:700;color:#fff;text-align:center;margin-bottom:14px;letter-spacing:.06em">
          <span id="cve9-imp-pct" style="animation:cve-blink .9s step-end infinite">0%</span>
        </div>
        <div style="border:2px solid #fff;padding:4px;background:#000">
          <div id="cve9-imp-bar" style="height:28px;width:0%;background:#fff;transition:width .4s linear"></div>
        </div>
      </div>`;
  }

  /* ── DB init ─────────────────────────────────────────── */
  async function _initDb() {
    try {
      // The server swaps the complete SQLite database atomically when ready.
      const allDone = CveDb.init((done, total) => _showProgress(done, total));
      await CveDb.whenReady();
      _dbReady = true;
      await _renderChips();
      await _renderTable();
      const progress = CveDb.progress();
      if (progress.imported < progress.total) _showProgress(progress.imported, progress.total);
      await allDone;        // wait for background import to finish
      await _renderChips(); // refresh counts with full dataset
    } catch(e) {
      console.error('CveDb init failed', e);
      const el = document.getElementById('cve9-import-overlay');
      if (el) el.innerHTML = `<div style="color:var(--red);padding:32px">⚠ ${isEn()?'DB load failed':'Ошибка загрузки'}: ${esc(String(e.message||e))}</div>`;
    }
  }

  /* ── Chips ───────────────────────────────────────────── */
  async function _renderChips() {
    const el = document.getElementById('cve9-chips');
    if (!el) return;
    const en = isEn();
    const ctfCount = _normCtf().length;

    let counts = {}, dbTotal = 0;
    if (_dbReady) {
      const res = await CveDb.countsBySev(_q);
      counts   = res.counts;
      dbTotal  = res.total;
    }

    const allTotal = dbTotal;
    const sevOrder = ['CRITICAL','HIGH','MEDIUM','LOW'];

    el.innerHTML = [
      `<button class="chip${_sev==='*'?' active':''}" onclick="CvesCvss9.filterSev('*')">${en?'All':'Все'} · ${allTotal}</button>`,
      ctfCount ? `<button class="chip${_sev==='CTF'?' active':''}" onclick="CvesCvss9.filterSev('CTF')">${sevBadge('CTF')} ${ctfCount}</button>` : '',
      ...sevOrder.filter(s => counts[s]).map(s =>
        `<button class="chip${_sev===s?' active':''}" onclick="CvesCvss9.filterSev('${s}')">${sevBadge(s)} ${counts[s]}</button>`
      ),
    ].join('');
    _chipsCache = el.innerHTML;
    _ssSet(SS_CHIPS, _chipsCache);
  }

  /* ── Table ───────────────────────────────────────────── */
  async function _renderTable() {
    const el = document.getElementById('cve9-table');
    if (!el) return;
    const en = isEn();

    let rows = [], total = 0;

    if (_sev === 'CTF') {
      // CTF-only mode: filter locally
      const ctf = _normCtf();
      const lq  = _q.toLowerCase();
      const filtered = lq
        ? ctf.filter(r => r.cveId.toLowerCase().includes(lq) || r.title.toLowerCase().includes(lq) || r.vp.toLowerCase().includes(lq))
        : ctf;
      total = filtered.length;
      rows  = filtered.slice(_page * _perPage, _page * _perPage + _perPage);
    } else if (_dbReady) {
      // DB mode (All or severity filter)
      const sev = _sev !== '*' ? _sev : null;
      const res = await CveDb.query({ severity: sev, q: _q, page: _page, perPage: _perPage });
      total = res.total;
      rows = res.rows.map(_normCveRow);
    } else {
      rows = [];
    }

    const totalPages = Math.max(1, Math.ceil(total / _perPage));
    const safePage   = Math.min(_page, totalPages - 1);
    if (safePage !== _page) { _page = safePage; return _renderTable(); }

    const from = _page * _perPage;

    const trs = rows.map(x => {
      const cve      = esc(x.cveId);
      const title    = esc(x.title.slice(0,120)) + (x.title.length > 120 ? '…' : '');
      const doneMark = x.done ? ' <span class="tag tm" style="font-size:10px">✓</span>' : '';
      return `<tr class="cve9-row" data-type="${x._type}" data-id="${esc(x._id)}" role="button" tabindex="0">
        <td class="zd-td-cve" style="white-space:nowrap;color:var(--red);font-weight:600">${cve}${doneMark}</td>
        <td style="max-width:400px">${title}</td>
        <td style="white-space:nowrap">${sevBadge(x.sev)}</td>
        <td class="muted small">${esc(x.vp)}</td>
        <td class="muted small" style="white-space:nowrap">${esc(x.pub)}</td>
      </tr>`;
    }).join('');

    const noRes = `<tr><td colspan="5" class="muted" style="padding:24px;text-align:center">${en?'No results':'Нет результатов'}</td></tr>`;

    el.innerHTML = `
      <div class="rwrap zd-table-wrap">
        <table class="rtab zd-table">
          <thead><tr>
            <th>CVE ID</th>
            <th>${en?'Title':'Заголовок'}</th>
            <th>Severity</th>
            <th>${en?'Vendor / Product':'Вендор / Продукт'}</th>
            <th>${en?'Published':'Дата'}</th>
          </tr></thead>
          <tbody id="cve9-tbody">${trs || noRes}</tbody>
        </table>
      </div>
      ${_paginationHtml(safePage, totalPages, total, from, en)}`;

    _bindTableClicks();

    // Save to in-memory + sessionStorage cache
    const tableEl = document.getElementById('cve9-table');
    if (tableEl) {
      _tableCache = tableEl.innerHTML;
      _ssSet(SS_TABLE, _tableCache);
    }
  }

  function _bindTableClicks() {
    const tbody = document.getElementById('cve9-tbody');
    const openRow = tr => _rowOpen(tr.dataset.type, tr.dataset.id);
    tbody?.addEventListener('click', e => {
      const tr = e.target.closest('tr.cve9-row');
      if (tr) openRow(tr);
    });
    tbody?.addEventListener('keydown', e => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const tr = e.target.closest('tr.cve9-row');
      if (!tr) return;
      e.preventDefault();
      openRow(tr);
    });
  }

  /* ── Pagination ──────────────────────────────────────── */
  function _paginationHtml(p, totalPages, total, from, en) {
    if (total === 0) return '';
    const to  = Math.min(from + _perPage, total);
    const sel = [10,25,50,100].map(n =>
      `<option value="${n}"${n===_perPage?' selected':''}>${n}</option>`).join('');

    let lo = Math.max(0, Math.min(p - 2, totalPages - 5));
    let hi = Math.min(totalPages - 1, lo + 4);
    lo = Math.max(0, hi - 4);
    const nums = [];
    for (let i = lo; i <= hi; i++) {
      const a = i === p;
      nums.push(`<button class="btn"${a?' style="background:var(--red);color:#fff;border-color:var(--red)"':''} onclick="CvesCvss9.goPage(${i})"${a?' disabled':''}>${i+1}</button>`);
    }

    return `
      <div class="row mt8" style="justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;padding:0 2px">
        <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
          <span class="muted small">${en?'Showing':'Показано'} <strong>${from+1}</strong> ${en?'to':'по'} <strong>${to}</strong> ${en?'of':'из'} <strong>${total}</strong> ${en?'results':'результатов'}</span>
          <label style="display:flex;align-items:center;gap:6px" class="muted small">
            ${en?'Results per page:':'Строк на странице:'}
            <select style="background:var(--bg2);color:var(--fg);border:1px solid var(--bdr);border-radius:6px;padding:3px 6px;font-size:13px;cursor:pointer"
                    onchange="CvesCvss9.setPerPage(+this.value)">${sel}</select>
          </label>
        </div>
        <div style="display:flex;gap:4px;flex-wrap:wrap">
          <button class="btn" onclick="CvesCvss9.goPage(0)"${p===0?' disabled':''}>First</button>
          <button class="btn" onclick="CvesCvss9.goPage(${p-1})"${p===0?' disabled':''}>Previous</button>
          ${nums.join('')}
          <button class="btn" onclick="CvesCvss9.goPage(${p+1})"${p>=totalPages-1?' disabled':''}>Next</button>
          <button class="btn" onclick="CvesCvss9.goPage(${totalPages-1})"${p>=totalPages-1?' disabled':''}>Last</button>
        </div>
      </div>`;
  }

  /* ── Initial render — always sets up 3 zones ────────────── */
  function _render() {
    const el = document.getElementById('cve9-section');
    if (!el) return;
    const en = isEn();
    el.innerHTML = `
      <div class="row mb8" style="gap:8px;align-items:center;flex-wrap:wrap">
        <input class="tools-search" type="search" id="cve9-q"
               placeholder="${en?'Filter: CVE / vendor / product…':'Фильтр: CVE / вендор / продукт…'}"
               style="flex:1;min-width:180px;max-width:340px"
               oninput="CvesCvss9.search(this.value)" autocomplete="off">
      </div>
      <div class="row mb8" style="flex-wrap:wrap;gap:6px" id="cve9-chips"></div>
      <div id="cve9-table">${(_dbReady || CveDb.isReadySync()) ? (_tableCache||'') : _importOverlayHtml()}</div>`;

    // Restore from sessionStorage (survives reload) or in-memory cache
    const ssChips = _chipsCache || _ssGet(SS_CHIPS);
    const ssTable = _tableCache || _ssGet(SS_TABLE);

    const chipsEl = document.getElementById('cve9-chips');
    const tableEl = document.getElementById('cve9-table');

    if (ssChips && chipsEl) chipsEl.innerHTML = ssChips;
    else _renderChipsSync();

    if (ssTable && tableEl && (_dbReady || CveDb.isReadySync())) {
      tableEl.innerHTML = ssTable;
      _bindTableClicks();
    }

    // Refresh from IDB in background (silent update)
    if (_dbReady) {
      _renderChips();
      _renderTable();
    }
  }

  // Fast sync chip render with only CTF count — no IDB wait
  function _renderChipsSync() {
    const el = document.getElementById('cve9-chips');
    if (!el) return;
    const en = isEn();
    const ctfCount = _normCtf().length;
    el.innerHTML = [
      `<button class="chip${_sev==='*'?' active':''}" onclick="CvesCvss9.filterSev('*')">${en?'All':'Все'} · ${ctfCount}</button>`,
      ctfCount ? `<button class="chip${_sev==='CTF'?' active':''}" onclick="CvesCvss9.filterSev('CTF')">${sevBadge('CTF')} ${ctfCount}</button>` : '',
    ].join('');
  }

  function _rowOpen(type, id) {
    if (type === 'ctf') ZeroDays.open(id);
    else UI.route('cve9', id);
  }

  function initUnified(ctfItems) {
    _ctf = ctfItems || [];
    _render();          // always sets up DOM zones; skips overlay if _dbReady
    if (!_dbReady) _initDb();
  }

  function open(cveId) { UI.route('cve9', cveId); }

  async function getItem(cveId) {
    if (_dbReady) return CveDb.get(cveId);
    return null;
  }

  async function renderItem(cveId) {
    const en = isEn();
    const x  = await getItem(cveId);
    if (!x) return `<div class="lab-page"><div class="card"><div class="cb"><p class="muted">CVE not found: ${esc(cveId)}</p><button class="btn mt8" onclick="UI.route('zerodays')">← ${en?'Back':'Назад'}</button></div></div></div>`;

    const d     = x.cvss_details || {};
    const score = x.cvss_score != null ? Number(x.cvss_score).toFixed(1) : '—';
    const sev   = _normSev(x);
    const pub   = (x.published_at||'').slice(0,10);
    const upd   = (x.updated_at||'').slice(0,10);
    const refs  = Array.isArray(x.references) ? x.references : [];
    const impactVal = v => ({H:en?'High':'Высокий',L:en?'Low':'Низкий',N:en?'None':'Нет'}[v]||v||'—');

    return `
      <div class="lab-page">
        <div class="row mb12">
          <button class="btn" onclick="UI.route('zerodays')">← ${en?'Back to catalog':'Назад к каталогу'}</button>
        </div>
        <div class="card lab-card cve-detail-card">
          <header class="cve-detail-header">
            <div class="cve-detail-summary">
              <div class="cve-detail-tags">${sevBadge(sev)}<span>${esc(x.cwe_id||'—')}</span></div>
              <h2>${esc(x.cve_id||cveId)}</h2>
              <p>${esc(x.title||x.affected_product||'—')}</p>
            </div>
            <div class="cve-detail-score"><strong>${esc(score)}</strong><span>CVSS</span></div>
          </header>

          <section class="cve-detail-facts">
            <div class="cve-detail-fact"><span>${en?'Published':'Опубликовано'}</span><strong>${esc(pub||'—')}</strong></div>
            <div class="cve-detail-fact"><span>${en?'Updated':'Обновлено'}</span><strong>${esc(upd||'—')}</strong></div>
            <div class="cve-detail-fact cve-detail-vector"><span>${en?'CVSS vector':'Вектор CVSS'}</span><code>${esc(x.cvss_vector||'—')}</code></div>
          </section>

          <div class="theory-wrap zd-article" style="padding:16px">
            <div class="theory">
              <div class="ebox info mb12" style="margin-top:0">
                <strong>${en?'Target Systems':'Целевые системы'}</strong>
                <div class="row mt8" style="gap:24px;flex-wrap:wrap">
                  <div><div class="muted small">${en?'Vendor':'Вендор'}</div><div>${esc(x.affected_vendor||'—')}</div></div>
                  <div><div class="muted small">${en?'Product':'Продукт'}</div><div>${esc(x.affected_product||'—')}</div></div>
                </div>
                ${x.affected_versions?`<div class="mt8"><div class="muted small">${en?'Affected Versions':'Версии'}</div><div class="muted small" style="font-family:var(--mono);font-size:11px;word-break:break-all">${esc(x.affected_versions)}</div></div>`:''}
              </div>

              ${d.C||d.I||d.A?`<div class="ebox mb12" style="margin-top:0;background:rgba(239,68,68,.06);border-color:rgba(239,68,68,.2)">
                <strong>${en?'Impact Assessment':'Оценка воздействия'}</strong>
                <div class="row mt8" style="gap:16px">
                  <div style="text-align:center"><div class="muted small">${en?'Confidentiality':'Конфид.'}</div><div style="font-weight:600">${esc(impactVal(d.C))}</div></div>
                  <div style="text-align:center"><div class="muted small">${en?'Integrity':'Целост.'}</div><div style="font-weight:600">${esc(impactVal(d.I))}</div></div>
                  <div style="text-align:center"><div class="muted small">${en?'Availability':'Доступн.'}</div><div style="font-weight:600">${esc(impactVal(d.A))}</div></div>
                </div>
              </div>`:''}

              <div class="mb16">
                <h3 style="margin:0 0 8px">${en?'Technical Description':'Техническое описание'}</h3>
                <div style="white-space:pre-wrap;line-height:1.6">${esc(x.description||'—')}</div>
              </div>

              ${refs.length?`<div class="mb16">
                <h3 style="margin:0 0 8px">${en?'Intelligence Sources':'Источники'}</h3>
                <ul style="margin:0;padding-left:18px;line-height:1.8">
                  ${refs.map(u=>`<li><a href="${safeUrl(u)}" target="_blank" rel="noopener noreferrer" class="zd-ext" style="font-size:13px">${esc(u)}</a></li>`).join('')}
                </ul>
              </div>`:''}

              <div>
                <h3 style="margin:0 0 8px">${en?'Recommended Actions':'Рекомендуемые действия'}</h3>
                <ol style="margin:0;padding-left:18px;line-height:1.8">
                  <li>${en?`Inventory affected systems${x.affected_versions?' running '+esc(x.affected_versions.slice(0,80)):''}`:
                           `Инвентаризуй затронутые системы${x.affected_versions?' с версией '+esc(x.affected_versions.slice(0,80)):''}`}</li>
                  <li>${en?`Review patch availability from ${esc(x.affected_vendor||'the vendor')}`:
                           `Проверь наличие патчей от ${esc(x.affected_vendor||'вендора')}`}</li>
                  <li>${en?'Implement temporary mitigations if patches unavailable':'Примени временные меры, если патчи недоступны'}</li>
                  <li>${en?'Update incident response procedures':'Обнови процедуры реагирования на инциденты'}</li>
                </ol>
              </div>
            </div>

            <aside class="theory-meta">
              <div class="meta-block"><div class="meta-label">CVE ID</div><div class="meta-line"><strong>${esc(x.cve_id||cveId)}</strong></div></div>
              <div class="meta-block"><div class="meta-label">Severity</div><div class="meta-line">${sevBadge(sev)}</div></div>
              <div class="meta-block"><div class="meta-label">CVSS</div><div class="meta-line"><strong style="font-size:18px">${esc(score)}</strong></div></div>
              ${x.epss_score!=null?`<div class="meta-block"><div class="meta-label">EPSS</div><div class="meta-line">${esc((Number(x.epss_score)*100).toFixed(2))}%</div></div>`:''}
              <div class="meta-block"><div class="meta-label">CWE</div><div class="meta-line">${esc(x.cwe_id||'—')}</div></div>
              <div class="meta-block"><div class="meta-label">${en?'Exploitation':'Эксплойт'}</div><div class="meta-line">${esc(x.enrichment_exploitation||'—')}</div></div>
              ${x.is_kev?`<div class="meta-block"><div class="meta-line"><span class="tag tm">CISA KEV</span></div></div>`:''}
              <div class="meta-block"><div class="meta-label">NVD</div><div class="meta-line"><a href="https://nvd.nist.gov/vuln/detail/${esc(encodeURIComponent(x.cve_id||''))}" target="_blank" rel="noopener noreferrer" class="zd-ext">nvd.nist.gov ↗</a></div></div>
            </aside>
          </div>
        </div>
      </div>`;
  }

  function goPage(p)     { _page = p; _renderTable(); }
  function filterSev(s)  { _sev = s; _page = 0; _renderChips(); _renderTable(); }
  function search(q)     { _q = q; _page = 0; _renderChips(); _renderTable(); }
  function setPerPage(n) { _perPage = n; _page = 0; _renderTable(); }
  return { initUnified, open, _rowOpen, getItem, renderItem, goPage, search, filterSev, setPerPage };
})();
