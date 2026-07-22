const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const chains = [
  { id: 'advanced-ai', title: { ru: 'AI атака', en: 'AI attack' }, level: 'Advanced', tags: ['A03', 'AI-LLM', 'prompt-injection'] },
  { id: 'newbie-api', title: { ru: 'API доступ', en: 'API access' }, level: 'Newbie', tags: ['A01', 'API', 'access-control'] },
  { id: 'intermediate-ssrf', title: { ru: 'SSRF облако', en: 'SSRF cloud' }, level: 'Intermediate', tags: ['A01', 'SSRF', 'Cloud'] },
];

const source = fs.readFileSync('js/tools.js', 'utf8');
const context = {
  DATA: { CHAINS: chains },
  I18n: {
    lang: () => 'ru',
    pick: value => value?.ru || value || '',
    t: key => key,
  },
  sessionStorage: { getItem: () => null, setItem: () => {} },
};
context.window = context;
vm.createContext(context);
vm.runInContext(`${source}\nglobalThis.Tools = Tools;`, context, { filename: 'js/tools.js' });

assert.equal(context.Tools.chainDomain(chains[0]), 'ai');
assert.equal(context.Tools.chainDomain(chains[1]), 'api');
assert.equal(context.Tools.chainDomain(chains[2]), 'ssrf');
assert.deepEqual(
  JSON.parse(JSON.stringify(context.Tools.sortChains(chains))).map(chain => chain.id),
  ['newbie-api', 'intermediate-ssrf', 'advanced-ai'],
);

assert.deepEqual(
  JSON.parse(JSON.stringify(context.Tools.filterChainRows(chains, {
    domain: 'api', level: 'Newbie', query: 'доступ',
  }))).map(chain => chain.id),
  ['newbie-api'],
);

const html = context.Tools.renderChains();
assert.match(html, /id="chain-domains"/);
assert.match(html, /id="chain-search"/);
assert.match(html, /id="chain-level"/);
assert.match(html, /class="chain-workspace"/);
