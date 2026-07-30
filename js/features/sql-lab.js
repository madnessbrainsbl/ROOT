/* RØOT SQLite (sql.js): knowledge DB is the source of truth for vulns.
 *
 * zero_days      — growing catalog (Zero-Day / KEV). INSERT new rows here.
 * vuln_registry  — free-form findings.
 * modules / challenges / cves — OWASP lab corpus.
 * Persist: main DB saved to localStorage after mutations (survives F5).
 * Attack DB — separate SQLi playground only (not persisted).
 */
const SqlLab = (() => {
  let db, dbA, SQL;
  let activeDB = 'main'; // main = RØOT knowledge base, attack = SQLi playground
  let hist = [];
  let histIdx = -1;
  let ready = false;
  const LS_KEY = 'vulnlab_sql_main_v1';

  function u8ToB64(u8) {
    let s = '';
    const chunk = 0x8000;
    for (let i = 0; i < u8.length; i += chunk) {
      s += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
    }
    return btoa(s);
  }
  function b64ToU8(b64) {
    const s = atob(b64);
    const u8 = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
    return u8;
  }

  /** Persist main knowledge DB so INSERT survives refresh */
  function persist() {
    if (!db || !ready) return false;
    try {
      const data = db.export();
      localStorage.setItem(LS_KEY, u8ToB64(data));
      return true;
    } catch (e) {
      console.warn('SqlLab.persist', e);
      return false;
    }
  }

  function clearPersisted() {
    try { localStorage.removeItem(LS_KEY); } catch (_) {}
  }

  function EQ() {
    const L = I18n.lang() === 'en';
    return [
      [L ? 'All security tools' : 'Все security tools',
        'SELECT id, name, track, category, mitre, code FROM sec_tools ORDER BY track, name;'],
      [L ? 'Tools by track' : 'Tools по track',
        'SELECT track, COUNT(*) AS n FROM sec_tools GROUP BY track ORDER BY n DESC;'],
      [L ? 'All zero-days (catalog)' : 'Все zero-day (каталог)',
        'SELECT n, id, cve, product, category, practice, points, source FROM zero_days ORDER BY n;'],
      [L ? 'Zero-days by category' : 'Zero-day по категориям',
        'SELECT category, COUNT(*) AS cnt FROM zero_days GROUP BY category ORDER BY cnt DESC;'],
      [L ? 'User-added vulns only' : 'Только добавленные вручную',
        "SELECT n, id, cve, product, created_at FROM zero_days WHERE source='user' ORDER BY n DESC;"],
      [L ? 'All modules (OWASP)' : 'Все модули (OWASP)',
        "SELECT code, name_en, name_ru, risk, owasp_2021, owasp_2025 FROM modules ORDER BY code;"],
      [L ? 'All challenges' : 'Все челленджи',
        "SELECT id, module, difficulty, points, title_en, flag FROM challenges ORDER BY module, difficulty;"],
      [L ? 'Top CVEs by CVSS' : 'Топ CVE по CVSS',
        "SELECT id, product, vendor, cvss, severity, owasp FROM cves ORDER BY cvss DESC LIMIT 15;"],
      [L ? 'vuln_registry (custom)' : 'vuln_registry (свои)',
        'SELECT id, slug, module, title_en, severity, created_at FROM vuln_registry ORDER BY id DESC;'],
      [L ? 'Join: module → challenges' : 'Join: модуль → челленджи',
        "SELECT m.code, m.name_en, c.id AS challenge, c.difficulty, c.points, c.title_en FROM modules m JOIN challenges c ON c.module=m.code ORDER BY m.code, c.difficulty;"],
    ];
  }

  function seedMain() {
    db.run(`
      CREATE TABLE modules (
        code TEXT PRIMARY KEY,
        name_en TEXT NOT NULL,
        name_ru TEXT NOT NULL,
        risk TEXT,
        owasp_2021 TEXT,
        owasp_2025 TEXT,
        blurb_en TEXT,
        blurb_ru TEXT,
        cwe TEXT,
        flag_primary TEXT
      );
      CREATE TABLE challenges (
        id TEXT PRIMARY KEY,
        module TEXT NOT NULL,
        difficulty INT NOT NULL,
        points INT NOT NULL,
        flag TEXT NOT NULL,
        title_en TEXT,
        title_ru TEXT,
        goal_en TEXT,
        goal_ru TEXT,
        hint1_en TEXT, hint1_ru TEXT,
        hint2_en TEXT, hint2_ru TEXT,
        hint3_en TEXT, hint3_ru TEXT,
        FOREIGN KEY (module) REFERENCES modules(code)
      );
      CREATE TABLE cves (
        id TEXT PRIMARY KEY,
        year INT,
        description TEXT,
        cvss REAL,
        severity TEXT,
        cwe TEXT,
        owasp TEXT,
        vendor TEXT,
        product TEXT
      );
      CREATE TABLE tools (
        id TEXT PRIMARY KEY,
        name TEXT,
        description TEXT,
        category TEXT,
        install_method TEXT
      );
      CREATE TABLE sec_tools (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        url TEXT,
        track TEXT,
        category TEXT,
        mitre TEXT,
        code TEXT,
        desc_en TEXT,
        desc_ru TEXT,
        usage_en TEXT,
        usage_ru TEXT,
        example TEXT,
        install_method TEXT,
        tags TEXT,
        source TEXT DEFAULT 'seed',
        catalog_version INT DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT
      );
      CREATE TABLE payloads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT,
        title TEXT,
        payload TEXT
      );
      CREATE TABLE vuln_registry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT UNIQUE,
        module TEXT,
        title_en TEXT,
        title_ru TEXT,
        cwe TEXT,
        severity TEXT,
        description_en TEXT,
        description_ru TEXT,
        how_to_test_en TEXT,
        how_to_test_ru TEXT,
        remediation_en TEXT,
        remediation_ru TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        notes TEXT
      );
      CREATE TABLE zero_days (
        n INTEGER PRIMARY KEY,
        id TEXT UNIQUE NOT NULL,
        cve TEXT,
        product TEXT,
        cwe TEXT,
        category TEXT,
        category_en TEXT,
        category_ru TEXT,
        summary_en TEXT,
        summary_ru TEXT,
        practice TEXT DEFAULT 'generic',
        owasp_note TEXT DEFAULT '—',
        flag TEXT,
        points INTEGER DEFAULT 10,
        diff INTEGER DEFAULT 2,
        theory_en TEXT,
        theory_ru TEXT,
        source TEXT DEFAULT 'seed',
        sources TEXT DEFAULT '[]',
        feed_from TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE zero_day_bonuses (
        id TEXT PRIMARY KEY,
        title_en TEXT,
        title_ru TEXT,
        when_txt TEXT,
        note TEXT
      );
    `);

    // modules from DATA.MODS
    const insM = db.prepare(
      'INSERT INTO modules VALUES (?,?,?,?,?,?,?,?,?,?)'
    );
    DATA.MODS.forEach(m => {
      const blurbEn = (m.blurb && m.blurb.en) || m.blurb || '';
      const blurbRu = (m.blurb && m.blurb.ru) || m.blurb || '';
      insM.run([
        m.code, m.name, m.nameRu, m.risk,
        m.owasp2021, m.owasp2025,
        typeof blurbEn === 'string' ? blurbEn : '',
        typeof blurbRu === 'string' ? blurbRu : '',
        (m.cwe || []).join(','),
        m.flag || '',
      ]);
    });
    insM.free();

    // challenges from CHALLENGES.list
    if (typeof CHALLENGES !== 'undefined') {
      const insC = db.prepare(
        'INSERT INTO challenges VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
      );
      CHALLENGES.list.forEach(c => {
        const h = c.hints || [];
        const pick = (obj, lang) => (obj && (obj[lang] || obj.en || obj.ru)) || '';
        insC.run([
          c.id, c.code, c.diff, c.points, c.flag,
          pick(c.title, 'en'), pick(c.title, 'ru'),
          pick(c.goal, 'en'), pick(c.goal, 'ru'),
          pick(h[0], 'en'), pick(h[0], 'ru'),
          pick(h[1], 'en'), pick(h[1], 'ru'),
          pick(h[2], 'en'), pick(h[2], 'ru'),
        ]);
      });
      insC.free();
    }

    // CVEs
    const insV = db.prepare('INSERT INTO cves VALUES (?,?,?,?,?,?,?,?,?)');
    DATA.CVES.forEach(c => insV.run([c.id, c.y, c.d, c.v, c.s, c.c, c.o, c.ve, c.p]));
    insV.free();

    // tools (legacy compact table)
    const insT = db.prepare('INSERT INTO tools VALUES (?,?,?,?,?)');
    DATA.TOOLS.forEach(t => insT.run([t.id, t.n, t.d, t.c, t.m]));
    insT.free();

    seedSecToolsCatalog();

    // payloads
    if (DATA.PAYLOADS) {
      const insP = db.prepare('INSERT INTO payloads (category, title, payload) VALUES (?,?,?)');
      Object.keys(DATA.PAYLOADS).forEach(cat => {
        DATA.PAYLOADS[cat].forEach(p => insP.run([cat, p.t, p.p]));
      });
      insP.free();
    }

    // seed example custom vulns in registry (template for future inserts)
    db.run(`INSERT INTO vuln_registry (slug, module, title_en, title_ru, cwe, severity, description_en, description_ru, how_to_test_en, how_to_test_ru, remediation_en, remediation_ru, notes)
      VALUES
      ('example-idor-invoice', 'A01', 'Invoice IDOR', 'IDOR счетов', 'CWE-639', 'HIGH',
       'Invoice API returns any invoice by sequential id without ownership check.',
       'API счетов отдаёт любой счёт по sequential id без проверки владельца.',
       'Two accounts; change /api/invoices/{id}.',
       'Два аккаунта; смена /api/invoices/{id}.',
       'Enforce owner_id == session.user_id server-side.',
       'Проверка owner_id == session.user_id на сервере.',
       'Example row — replace with real findings. Use INSERT to add more.');`);

    seedZeroDaysCatalog();
  }

  /** Ensure zero_days schema exists (for older saved DBs) */
  function ensureZeroDaysSchema() {
    db.run(`
      CREATE TABLE IF NOT EXISTS zero_days (
        n INTEGER PRIMARY KEY,
        id TEXT UNIQUE NOT NULL,
        cve TEXT,
        product TEXT,
        cwe TEXT,
        category TEXT,
        category_en TEXT,
        category_ru TEXT,
        summary_en TEXT,
        summary_ru TEXT,
        practice TEXT DEFAULT 'generic',
        owasp_note TEXT DEFAULT '—',
        flag TEXT,
        points INTEGER DEFAULT 10,
        diff INTEGER DEFAULT 2,
        theory_en TEXT,
        theory_ru TEXT,
        source TEXT DEFAULT 'seed',
        sources TEXT DEFAULT '[]',
        feed_from TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS zero_day_bonuses (
        id TEXT PRIMARY KEY,
        title_en TEXT,
        title_ru TEXT,
        when_txt TEXT,
        note TEXT
      );
      CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT
      );
    `);
    // migrate older DBs
    try { db.run("ALTER TABLE zero_days ADD COLUMN sources TEXT DEFAULT '[]'"); } catch (_) {}
    try { db.run("ALTER TABLE zero_days ADD COLUMN feed_from TEXT DEFAULT ''"); } catch (_) {}
    db.run(`
      CREATE TABLE IF NOT EXISTS vuln_registry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT UNIQUE,
        module TEXT,
        title_en TEXT,
        title_ru TEXT,
        cwe TEXT,
        severity TEXT,
        description_en TEXT,
        description_ru TEXT,
        how_to_test_en TEXT,
        how_to_test_ru TEXT,
        remediation_en TEXT,
        remediation_ru TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        notes TEXT
      );
    `);
  }

  function ensureSecToolsSchema() {
    db.run(`
      CREATE TABLE IF NOT EXISTS sec_tools (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        url TEXT,
        track TEXT,
        category TEXT,
        mitre TEXT,
        code TEXT,
        desc_en TEXT,
        desc_ru TEXT,
        usage_en TEXT,
        usage_ru TEXT,
        example TEXT,
        install_method TEXT,
        tags TEXT,
        source TEXT DEFAULT 'seed',
        catalog_version INT DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT
      );
    `);
    // migrate older sec_tools missing columns
    const cols = new Set();
    try {
      db.exec('PRAGMA table_info(sec_tools)')[0].values.forEach(r => cols.add(r[1]));
    } catch (_) {}
    ['usage_en','usage_ru','example','catalog_version'].forEach(c => {
      if (!cols.has(c)) {
        try {
          const typ = c === 'catalog_version' ? 'INT DEFAULT 1' : 'TEXT';
          db.run(`ALTER TABLE sec_tools ADD COLUMN ${c} ${typ}`);
        } catch (_) {}
      }
    });
  }

  /**
   * Seed / refresh sec_tools from TOOLS_CATALOG.
   * Replaces source='seed' rows when catalog version changes; keeps source='user'.
   */
  function seedSecToolsCatalog() {
    if (typeof TOOLS_CATALOG === 'undefined' || !TOOLS_CATALOG.items) return;
    ensureSecToolsSchema();
    const wantVer = String(TOOLS_CATALOG.version || 1);
    let haveVer = '0';
    try {
      const r = db.exec("SELECT value FROM meta WHERE key='sec_tools_version'");
      if (r.length && r[0].values.length) haveVer = String(r[0].values[0][0]);
    } catch (_) {}
    let cnt = 0;
    try { cnt = db.exec('SELECT COUNT(*) FROM sec_tools')[0].values[0][0]; } catch (_) { cnt = 0; }

    if (cnt > 0 && haveVer === wantVer) return; // up to date

    // refresh seed rows only
    try { db.run("DELETE FROM sec_tools WHERE source='seed' OR source IS NULL"); } catch (_) {
      try { db.run('DELETE FROM sec_tools'); } catch (__) {}
    }

    const ins = db.prepare(
      `INSERT OR REPLACE INTO sec_tools
        (id,name,url,track,category,mitre,code,desc_en,desc_ru,usage_en,usage_ru,example,install_method,tags,source,catalog_version)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    );
    TOOLS_CATALOG.items.forEach(t => {
      ins.run([
        t.id, t.name, t.url || '', t.track || '', t.category || '',
        t.mitre || null, t.code || null,
        t.desc_en || '', t.desc_ru || '',
        t.usage_en || '', t.usage_ru || '',
        t.example || '',
        t.install || '', t.tags || '', 'seed', Number(wantVer) || 1,
      ]);
    });
    ins.free();
    db.run("INSERT OR REPLACE INTO meta(key,value) VALUES ('sec_tools_version', ?)", [wantVer]);
  }

  /**
   * Fill zero_days from ZERO_DAYS JS seed ONLY if table is empty.
   * Never DELETE user rows — catalog grows via INSERT.
   */
  /**
   * Seed / refresh zero_days knowledge articles.
   * Versioned: when catalog version bumps, re-seed source='seed' rows (keeps user inserts).
   */
  function seedZeroDaysCatalog() {
    if (typeof ZERO_DAYS === 'undefined' || !ZERO_DAYS.items) return;
    ensureZeroDaysSchema();
    const wantVer = String(ZERO_DAYS.version || 2);
    let haveVer = '0';
    try {
      const r = db.exec("SELECT value FROM meta WHERE key='zero_days_version'");
      if (r.length && r[0].values.length) haveVer = String(r[0].values[0][0]);
    } catch (_) {}
    let cnt = 0;
    try { cnt = db.exec('SELECT COUNT(*) FROM zero_days')[0].values[0][0]; } catch (_) { cnt = 0; }
    if (cnt > 0 && haveVer === wantVer) return;

    try { db.run("DELETE FROM zero_days WHERE source='seed' OR source IS NULL"); } catch (_) {
      try { db.run('DELETE FROM zero_days'); } catch (__) {}
    }

    const ins = db.prepare(
      `INSERT OR REPLACE INTO zero_days
        (n,id,cve,product,cwe,category,category_en,category_ru,
         summary_en,summary_ru,practice,owasp_note,flag,points,diff,
         theory_en,theory_ru,source,sources,feed_from)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    );
    ZERO_DAYS.items.forEach(it => {
      const sourcesJson = typeof it.sources === 'string'
        ? it.sources
        : JSON.stringify(it.sources || []);
      ins.run([
        it.n, it.id, it.cve, it.product, it.cwe, it.category,
        it.category_en || it.category, it.category_ru || it.category,
        it.summary_en || '', it.summary_ru || '',
        it.practice || 'generic', it.owasp_note || '—',
        it.flag, it.points || 10, it.diff || 2,
        it.theory_en || '', it.theory_ru || '', 'seed',
        sourcesJson, it.feed_from || '',
      ]);
    });
    ins.free();

    if (ZERO_DAYS.bonuses && ZERO_DAYS.bonuses.length) {
      db.run('DELETE FROM zero_day_bonuses');
      const insB = db.prepare(
        'INSERT OR REPLACE INTO zero_day_bonuses VALUES (?,?,?,?,?)'
      );
      ZERO_DAYS.bonuses.forEach(b => {
        insB.run([b.id, b.title_en, b.title_ru, b.when || '', b.note || '']);
      });
      insB.free();
    }
    try {
      db.run("INSERT OR REPLACE INTO meta(key,value) VALUES ('zero_days_version', ?)", [wantVer]);
    } catch (_) {
      ensureSecToolsSchema();
      db.run("INSERT OR REPLACE INTO meta(key,value) VALUES ('zero_days_version', ?)", [wantVer]);
    }
  }

  function seedAttack() {
    dbA.run(`
      CREATE TABLE users(id INT PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT, email TEXT, api_key TEXT);
      CREATE TABLE products(id INT PRIMARY KEY, name TEXT, price REAL, category TEXT, internal_note TEXT, discontinued INT);
      CREATE TABLE orders(id INT PRIMARY KEY, user_id INT, product TEXT, total REAL, status TEXT, admin_only INT);
      CREATE TABLE secrets(id INT PRIMARY KEY, key_name TEXT, secret_value TEXT, clearance TEXT);
      INSERT INTO users VALUES
        (1,'admin','$2b$12$hash_admin','admin','admin@corp.local','sk-prod-9f2k1p8mN3xQ'),
        (2,'alice','$2b$12$hash_alice','user','alice@corp.local','sk-user-2a4b6c8d'),
        (3,'bob','$2b$12$hash_bob','user','bob@corp.local','sk-user-8d2e9f1a'),
        (4,'svc_deploy','$2b$12$hash_svc','service','deploy@corp.local','sk-svc-1a2b3c4d5e6f');
      INSERT INTO products VALUES
        (1,'Public Widget',9.99,'public',NULL,0),
        (2,'Premium Module',299.0,'premium','Margin: 85%',0),
        (3,'INTERNAL TOOL',0.0,'internal','Contains PII — DO NOT EXPOSE',1),
        (4,'Legacy DB Access',999.0,'enterprise','connects to PROD mainframe',0);
      INSERT INTO orders VALUES
        (1,1,'Premium Module',299.0,'completed',1),
        (2,2,'Public Widget',9.99,'completed',0),
        (3,1,'Legacy DB Access',999.0,'pending',1),
        (4,3,'Premium Module',299.0,'completed',0);
      INSERT INTO secrets VALUES
        (1,'AWS_ACCESS_KEY','AKIAIOSFODNN7EXAMPLE','CONFIDENTIAL'),
        (2,'AWS_SECRET_KEY','wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY','CONFIDENTIAL'),
        (3,'DB_PROD_PASSWORD','Pr0d_DB_P@ssw0rd!2024#','RESTRICTED'),
        (4,'JWT_SECRET','HS256_prod_key_never_expose_must_be_32bytes','RESTRICTED'),
        (5,'CTF_FLAG','FLAG{sql_master_dumped_the_vault}','RESTRICTED');
    `);
  }

  async function init() {
    if (ready) return;
    SQL = await initSqlJs({ locateFile: f => 'js/vendor/' + f });

    // Prefer saved main DB (user INSERTs survive F5)
    let loaded = false;
    try {
      const saved = localStorage.getItem(LS_KEY);
      if (saved) {
        db = new SQL.Database(b64ToU8(saved));
        ensureZeroDaysSchema();
        ensureSecToolsSchema();
        seedZeroDaysCatalog(); // only if empty
        seedSecToolsCatalog(); // only if empty
        loaded = true;
      }
    } catch (e) {
      console.warn('SqlLab load saved DB failed, reseeding', e);
      db = null;
    }
    if (!loaded) {
      db = new SQL.Database();
      seedMain();
      persist();
    }

    dbA = new SQL.Database();
    seedAttack();
    ready = true;
    activeDB = Store.get().activeDB || 'main';
    if (activeDB !== 'main' && activeDB !== 'attack') activeDB = 'main';
    buildSchema();
    updateTabs();
  }

  /** SELECT → array of row objects. Optional params for prepared statements. */
  function query(sql, params) {
    if (!ready || !db) return [];
    try {
      if (params && params.length) {
        const stmt = db.prepare(sql);
        stmt.bind(params);
        const rows = [];
        while (stmt.step()) rows.push(stmt.getAsObject());
        stmt.free();
        return rows;
      }
      const res = db.exec(sql);
      if (!res.length) return [];
      return res[0].values.map(row => {
        const o = {};
        res[0].columns.forEach((c, i) => { o[c] = row[i]; });
        return o;
      });
    } catch (e) {
      console.warn('SqlLab.query', e);
      return [];
    }
  }

  function run(sql, params) {
    if (!ready || !db) throw new Error('DB not ready');
    if (params && params.length) db.run(sql, params);
    else db.run(sql);
    persist();
  }

  function countTable(name) {
    try {
      const r = db.exec(`SELECT COUNT(*) FROM ${name}`);
      return r[0].values[0][0];
    } catch (_) { return 0; }
  }

  /** Factory reset: wipe localStorage and reseed from code */
  function resetMainDb() {
    clearPersisted();
    db = new SQL.Database();
    seedMain();
    persist();
    buildSchema();
    updateTabs();
  }

  function getDB() { return activeDB === 'attack' ? dbA : db; }

  function updateTabs() {
    const tabMain = document.getElementById('tab-main');
    const tabAtk = document.getElementById('tab-atk');
    if (tabMain) {
      tabMain.className = 'ttab' + (activeDB === 'main' ? ' active' : '');
      tabMain.textContent = I18n.lang() === 'en' ? '📚 RØOT DB' : '📚 RØOT БД';
    }
    if (tabAtk) {
      tabAtk.className = 'ttab' + (activeDB === 'attack' ? ' active' : '');
      tabAtk.textContent = I18n.lang() === 'en' ? '🔴 Attack DB' : '🔴 Attack DB';
    }
    const lbl = document.getElementById('tmlbl');
    if (lbl) {
      lbl.textContent = activeDB === 'main'
        ? (I18n.lang() === 'en'
          ? '📚 RØOT knowledge DB — modules, challenges, CVEs, sec_tools, zero_days'
          : '📚 RØOT база знаний — modules, challenges, CVEs, sec_tools, zero_days')
        : (I18n.lang() === 'en'
          ? '🔴 Attack DB — SQLi playground only'
          : '🔴 Attack DB — только SQLi-площадка');
    }
  }

  function switchDB(which) {
    activeDB = which === 'attack' ? 'attack' : 'main';
    Store.get().activeDB = activeDB;
    Store.save();
    updateTabs();
    buildSchema();
    const tout = document.getElementById('tout');
    if (tout) {
      tout.innerHTML = `<span style="color:var(--mut)">// ${activeDB === 'attack' ? 'Attack DB' : 'RØOT knowledge DB'}</span>`;
    }
  }

  function buildSchema() {
    if (!ready) return;
    const sl = document.getElementById('slist');
    if (!sl) return;
    const r = getDB().exec("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'");
    sl.innerHTML = '';
    if (!r.length) return;
    r[0].values.forEach(row => {
      const tname = row[0];
      const ci = getDB().exec('PRAGMA table_info(' + tname + ')');
      let h = `<div class="stname" data-t="${tname}">▸ ${tname}</div>`;
      if (ci.length) ci[0].values.forEach(col => {
        h += `<div class="scol"><span>${col[1]}</span><span class="sct">${col[2] || 'TEXT'}</span></div>`;
      });
      sl.innerHTML += h;
    });
    sl.querySelectorAll('.stname').forEach(el => {
      el.addEventListener('click', () => {
        document.getElementById('tsql').value = 'SELECT * FROM ' + el.dataset.t + ' LIMIT 20;';
      });
    });
  }

  function runQ(sql) {
    if (!ready) return;
    const ta = document.getElementById('tsql');
    const q = (sql || (ta && ta.value) || '').trim();
    if (!q) return;
    if (!hist.length || hist[0] !== q) { hist.unshift(q); if (hist.length > 60) hist.pop(); }
    histIdx = -1;
    const out = document.getElementById('tout');
    try {
      const t0 = performance.now();
      const res = getDB().exec(q);
      const ms = (performance.now() - t0).toFixed(1);
      // after mutating knowledge DB, persist + refresh schema
      if (/^\s*(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)/i.test(q) && activeDB === 'main') {
        persist();
        buildSchema();
      }
      if (!res.length) {
        out.innerHTML = `<span style="color:var(--grn)">✓ OK (${ms}ms) — 0 rows / statement done</span>`;
        return res;
      }
      let html = '';
      res.forEach(r => {
        html += '<div class="rwrap"><table class="rtab"><thead><tr>' +
          r.columns.map(c => '<th>' + c + '</th>').join('') + '</tr></thead><tbody>';
        r.values.forEach(row => {
          html += '<tr>' + row.map(v => {
            const s = v === null ? 'NULL' : String(v);
            const disp = v === null ? '<span style="color:var(--mut)">NULL</span>' : (s.length > 80 ? s.slice(0, 80) + '…' : s);
            return `<td title="${String(v ?? '').replace(/"/g, '&quot;')}">${disp}</td>`;
          }).join('') + '</tr>';
        });
        html += `</tbody></table></div><div class="rmeta">${r.values.length} rows · ${ms}ms</div>`;
      });
      out.innerHTML = html;
      return res;
    } catch (e) {
      out.innerHTML = `<div class="resp err">✗ ${e.message}</div>`;
      return null;
    }
  }

  function histNav(d) {
    histIdx = Math.max(-1, Math.min(hist.length - 1, histIdx + d));
    document.getElementById('tsql').value = histIdx >= 0 ? hist[histIdx] : '';
  }

  function clearOut() {
    document.getElementById('tout').innerHTML =
      `<span style="color:var(--mut)">${I18n.t('queryResults')}</span>`;
  }

  function setQuery(sql, dbname) {
    document.getElementById('tsql').value = sql;
    if (dbname && activeDB !== dbname) switchDB(dbname);
    UI.openTerm(true);
    updateTabs();
    runQ(sql);
  }

  function runPreset(i) {
    const eq = EQ();
    if (eq[i]) setQuery(eq[i][1], 'main');
  }

  /** Template INSERT for adding a new zero-day into the catalog */
  function insertTemplate() {
    const nextN = (() => {
      try {
        const r = db.exec('SELECT COALESCE(MAX(n),0)+1 FROM zero_days');
        return r[0].values[0][0];
      } catch (_) { return 1; }
    })();
    const sql = `-- Add a NEW vulnerability into zero_days (source of truth catalog)
-- n must be unique; id must be unique (e.g. zd-51, zd-custom-1)
INSERT INTO zero_days (
  n, id, cve, product, cwe, category, category_en, category_ru,
  summary_en, summary_ru, practice, owasp_note, flag, points, diff,
  theory_en, theory_ru, source
) VALUES (
  ${nextN},
  'zd-${String(nextN).padStart(2, '0')}',
  'CVE-YYYY-NNNNN',
  'Product name',
  'CWE-xxx / class',
  'edge',                         -- kernel|windows|apple|android|browser|edge|iot|virt|enterprise|client|hosting
  'Edge appliances',
  'Edge / appliance',
  'Short summary (EN)',
  'Краткое описание (RU)',
  'auth_bypass',                  -- practice: auth_bypass|cmdi|oob_leak|path_trav|deser|ssrf_rce|crlf|dos|ntlm|race|lpe|uaf|rce_browser|rce_client|info_leak|generic
  '≈A01',                         -- or —
  'FLAG{zd_${nextN}_custom}',
  10,
  2,
  '<h3>Theory EN</h3><p>What broke and why.</p>',
  '<h3>Теория RU</h3><p>Что сломалось и почему.</p>',
  'user'
);

-- Verify:
SELECT n, id, cve, product, source, created_at FROM zero_days ORDER BY n DESC LIMIT 10;`;
    setQuery(sql, 'main');
  }

  function renderExplorer() {
    const en = I18n.lang() === 'en';
    const eq = EQ();
    const counts = {
      zero_days: ready ? countTable('zero_days') : 0,
      modules: ready ? countTable('modules') : 0,
      challenges: ready ? countTable('challenges') : 0,
      cves: ready ? countTable('cves') : 0,
      registry: ready ? countTable('vuln_registry') : 0,
    };
    let userAdded = 0;
    try {
      userAdded = db.exec("SELECT COUNT(*) FROM zero_days WHERE source='user'")[0].values[0][0];
    } catch (_) {}
    return `
      <div data-watermark="SQL" class="hero">
        <h1>${en ? 'Vulnerability database (SQLite)' : 'База уязвимостей (SQLite)'}</h1>
        <p>${en
          ? 'SQLite is the source of truth. Table <code>zero_days</code> holds the Zero-Day/KEV catalog — add rows with an INSERT in the terminal below. Changes are saved to localStorage (survive F5).'
          : 'SQLite — источник правды. Таблица <code>zero_days</code> — каталог Zero-Day/KEV: добавляй строки через INSERT в терминале ниже. Изменения пишутся в localStorage (переживают F5).'}</p>
        <div class="stat-grid">
          <div class="stat"><div class="n" style="color:var(--red)">${counts.zero_days}</div><div class="l">zero_days</div></div>
          <div class="stat"><div class="n" style="color:var(--grn)">${userAdded}</div><div class="l">${en?'user-added':'добавлено'}</div></div>
          <div class="stat"><div class="n" style="color:var(--yel)">${counts.challenges}</div><div class="l">challenges</div></div>
          <div class="stat"><div class="n" style="color:var(--blu)">${counts.cves}</div><div class="l">cves</div></div>
        </div>
        <div class="row mt12">
          <button class="btn btnp" onclick="SqlLab.switchDB('main');UI.openTerm(true)">${en ? 'Open SQL terminal' : 'Открыть SQL-терминал'}</button>
          <button class="btn" onclick="SqlLab.insertTemplate()">${en ? '+ INSERT into zero_days' : '+ INSERT в zero_days'}</button>
          <button class="btn" onclick="UI.route('zerodays')">${en ? '← Zero-Days' : '← Zero-Days'}</button>
          <button class="btn" onclick="if(confirm(I18n.lang()==='en'?'Reset DB to factory seed? User inserts will be lost.':'Сбросить БД к seed? Свои INSERT пропадут.')){SqlLab.resetMainDb();UI.route('zerodays');UI.toast(I18n.lang()==='en'?'DB reset':'БД сброшена','ok');}">${en ? 'Reset DB' : 'Сброс БД'}</button>
        </div>
      </div>

      <div class="card">
        <div class="ch"><h2>${en ? 'Schema (RØOT DB)' : 'Схема (RØOT БД)'}</h2></div>
        <div class="cb theory">
          <div class="ebox info">zero_days      — ★ main catalog (Zero-Day / KEV). INSERT new vulns here
zero_day_bonuses — supply-chain worms (bonus)
vuln_registry  — free-form findings (optional)
modules        — OWASP A01–A10
challenges     — 30 CTF labs
cves           — research CVE corpus
tools / payloads</div>
          <p class="mt12">${en
            ? 'SQL terminal opens from <strong>lab practice</strong> (SQLi tasks), not from the header. Tab <strong>RØOT DB</strong> = knowledge base. <strong>Attack DB</strong> = SQLi playground only.'
            : 'SQL-терминал открывается из <strong>практики лабы</strong> (SQLi), не из шапки. <strong>RØOT БД</strong> — база знаний. <strong>Attack DB</strong> — только SQLi.'}</p>
        </div>
      </div>

      <div class="card">
        <div class="ch"><h2>${en ? 'Quick queries' : 'Быстрые запросы'}</h2></div>
        <div class="cb">
          <div class="bgrid">
            ${eq.map((q, i) => `<button class="btn" style="text-align:left;justify-content:flex-start"
              onclick="SqlLab.runPreset(${i})">${q[0]}</button>`).join('')}
          </div>
        </div>
      </div>

      <div class="card">
        <div class="ch"><h2>${en ? 'Attack DB (SQLi playground)' : 'Attack DB (площадка SQLi)'}</h2></div>
        <div class="cb theory">
          <p>${en ? 'Separate schema for injection practice — not the knowledge base.' : 'Отдельная схема для практики инъекций — не база знаний.'}</p>
          <div class="ebox">users · products · orders · secrets</div>
          <div class="row mt12">
            <button class="btn" onclick="SqlLab.setQuery('SELECT * FROM users;','attack')">users</button>
            <button class="btn" onclick="SqlLab.setQuery('SELECT * FROM secrets;','attack')">secrets</button>
            <button class="btn" onclick="SqlLab.setQuery('SELECT * FROM products WHERE discontinued=1;','attack')">internal products</button>
            <button class="btn" onclick="SqlLab.setQuery('SELECT * FROM orders WHERE admin_only=1;','attack')">admin orders</button>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="ch"><h2>${en ? 'How to add a vulnerability' : 'Как добавить уязвимость'}</h2></div>
        <div class="cb theory">
          <ol>
            <li>${en ? 'Form on Zero-Days page → “Add vulnerability” (easiest).' : 'Форма на странице Zero-Days → «Добавить уязвимость» (проще всего).'}</li>
            <li>${en ? 'Or SQL: INSERT INTO zero_days (…) VALUES (…); then Ctrl+Enter.' : 'Или SQL: INSERT INTO zero_days (…) VALUES (…); затем Ctrl+Enter.'}</li>
            <li>${en ? 'Verify: SELECT * FROM zero_days ORDER BY n DESC LIMIT 5;' : 'Проверка: SELECT * FROM zero_days ORDER BY n DESC LIMIT 5;'}</li>
          </ol>
          <p class="muted small mt8">${en
            ? 'Main DB is persisted in localStorage after every INSERT/UPDATE/DELETE.'
            : 'Основная БД сохраняется в localStorage после каждого INSERT/UPDATE/DELETE.'}</p>
        </div>
      </div>`;
  }

  // SQL research tasks (optional track in labs) — still work
  const TASKS = {
    A01: {
      db: 'main',
      desc: 'Найди челленджи модуля A01.',
      descEn: 'List challenges for module A01.',
      hint: "SELECT id, difficulty, points, title_en, flag FROM challenges WHERE module='A01';",
      chk: r => r && r.length >= 2,
    },
    A02: {
      db: 'main',
      desc: 'CVE категории A02.',
      descEn: 'CVEs for owasp=A02.',
      hint: "SELECT id, product, cvss, year FROM cves WHERE owasp='A02' ORDER BY year;",
      chk: r => r && r.length > 0,
    },
    A03: {
      db: 'attack',
      desc: 'Attack DB: все secrets.',
      descEn: 'Attack DB: all secrets.',
      hint: 'SELECT * FROM secrets;',
      chk: r => r && r.length >= 4,
    },
    A06: {
      db: 'main',
      desc: 'CVE с CVSS = 10.0.',
      descEn: 'CVEs with CVSS = 10.0.',
      hint: 'SELECT id, product, vendor, year, owasp FROM cves WHERE cvss = 10.0 ORDER BY year DESC;',
      chk: r => r && r.length > 0,
    },
    A07: {
      db: 'attack',
      desc: 'Attack DB: role=admin.',
      descEn: 'Attack DB: role=admin.',
      hint: "SELECT * FROM users WHERE role='admin';",
      chk: r => r && r.some(x => x.role === 'admin'),
    },
    A10: {
      db: 'main',
      desc: 'CVE owasp=A10.',
      descEn: 'CVEs owasp=A10.',
      hint: "SELECT id, product, vendor, cvss FROM cves WHERE owasp='A10';",
      chk: r => r && r.length > 0,
    },
  };

  function checkTask(code) {
    const t = TASKS[code];
    if (!t || !ready) return { ok: false, msg: I18n.t('noSqlTask') };
    const sql = document.getElementById('tsql').value.trim();
    if (!sql) return { ok: false, msg: I18n.t('sqlEmpty') };
    try {
      if (t.db !== activeDB) switchDB(t.db);
      const res = getDB().exec(sql);
      const rows = [];
      if (res.length) {
        res[0].values.forEach(row => {
          const obj = {};
          res[0].columns.forEach((col, i) => { obj[col] = row[i]; });
          rows.push(obj);
        });
      }
      runQ(sql);
      if (t.chk(rows)) {
        const st = Store.get();
        st.sqlDone[code] = true;
        Store.save();
        UI.refreshNav();
        return { ok: true, msg: I18n.t('sqlOk') };
      }
      return { ok: false, msg: I18n.t('sqlNo') };
    } catch (e) {
      return { ok: false, msg: e.message };
    }
  }

  return {
    init, switchDB, runQ, histNav, clearOut, setQuery, buildSchema, updateTabs,
    renderExplorer, checkTask, runPreset, insertTemplate, TASKS, EQ,
    query, run, persist, resetMainDb, countTable, seedZeroDaysCatalog, seedSecToolsCatalog,
    get ready() { return ready; },
    get mainDb() { return db; },
  };
})();
