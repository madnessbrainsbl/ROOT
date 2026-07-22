const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const context = {
  console,
  location: { hash: '', pathname: '/app/', search: '' },
  history: { pushState() {}, replaceState() {} },
  document: {
    addEventListener() {},
    getElementById() { return null; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    documentElement: {},
    body: { classList: { add() {}, remove() {}, toggle() { return false; } } },
  },
  sessionStorage: { getItem() { return null; }, setItem() {} },
  requestAnimationFrame(callback) { callback(); },
  setTimeout,
  clearTimeout,
};
context.window = { addEventListener() {} };
vm.createContext(context);
vm.runInContext(
  `${fs.readFileSync('js/app.js', 'utf8')}\nglobalThis.TestUI = UI;`,
  context,
  { filename: 'js/app.js' },
);

assert.deepEqual(
  JSON.parse(JSON.stringify(context.TestUI.parseHash('#/lab/A03'))),
  ['lab', 'A03'],
);
assert.deepEqual(
  JSON.parse(JSON.stringify(context.TestUI.parseHash('#/api/API1'))),
  ['api10', 'API1'],
);
assert.deepEqual(
  JSON.parse(JSON.stringify(context.TestUI.parseHash('#/commands/chains'))),
  ['commands', 'chains'],
);
assert.equal(context.TestUI.parseHash('#/%E0%A4%A'), null);
assert.equal(context.TestUI.routeHash('cve9', 'CVE-2026-0001'), '#/cve/CVE-2026-0001');
