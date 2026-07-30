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
  `${fs.readFileSync('js/core/app.js', 'utf8')}\nglobalThis.TestUI = UI;`,
  context,
  { filename: 'js/core/app.js' },
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
assert.deepEqual(
  JSON.parse(JSON.stringify(context.TestUI.parseHash('#/owasp'))),
  ['owasp', null],
);
assert.deepEqual(
  JSON.parse(JSON.stringify(context.TestUI.parseHash('#/asvs'))),
  ['asvs', null],
);
assert.deepEqual(
  JSON.parse(JSON.stringify(context.TestUI.parseHash('#/frameworks'))),
  ['frameworks', null],
);
assert.deepEqual(
  JSON.parse(JSON.stringify(context.TestUI.parseHash('#/frameworks/stride'))),
  ['framework', 'stride'],
);
assert.deepEqual(
  JSON.parse(JSON.stringify(context.TestUI.parseHash('#/frameworks/wstg'))),
  ['framework', 'wstg'],
);
assert.equal(context.TestUI.parseHash('#/checklists'), null);
assert.equal(context.TestUI.parseHash('#/%E0%A4%A'), null);
assert.equal(context.TestUI.routeHash('cve9', 'CVE-2026-0001'), '#/cve/CVE-2026-0001');
assert.equal(context.TestUI.routeHash('asvs'), '#/asvs');
assert.equal(context.TestUI.routeHash('framework', 'slsa'), '#/frameworks/slsa');

const savedState = new Map([
  ['owasp-emulator-v4', JSON.stringify({ lang: 'ru', checklists: { 'A01:0': true } })],
]);
const stateContext = {
  console,
  localStorage: {
    getItem(key) { return savedState.get(key) || null; },
    setItem(key, value) { savedState.set(key, value); },
  },
};
vm.createContext(stateContext);
vm.runInContext(
  `${fs.readFileSync('js/core/state.js', 'utf8')}\nglobalThis.TestStore = Store;`,
  stateContext,
  { filename: 'js/core/state.js' },
);
assert.equal('checklists' in stateContext.TestStore.get(), false);
assert.equal('checklists' in JSON.parse(savedState.get('owasp-emulator-v4')), false);
