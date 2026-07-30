const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const chains = [
  { id: 'advanced-ai', title: { ru: 'AI атака', en: 'AI attack' }, level: 'Advanced', tags: ['A03', 'AI-LLM', 'prompt-injection'] },
  { id: 'newbie-api', title: { ru: 'API доступ', en: 'API access' }, level: 'Newbie', tags: ['A01', 'API', 'access-control'] },
  { id: 'intermediate-ssrf', title: { ru: 'SSRF облако', en: 'SSRF cloud' }, level: 'Intermediate', tags: ['A01', 'SSRF', 'Cloud'] },
];

const source = fs.readFileSync('js/tools/ui.js', 'utf8');
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
vm.runInContext(`${source}\nglobalThis.Tools = Tools;`, context, { filename: 'js/tools/ui.js' });

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

const chainContext = { DATA: {} };
vm.createContext(chainContext);
vm.runInContext(
  `${fs.readFileSync('js/data/chains.js', 'utf8')}\nglobalThis.catalogChains = DATA.CHAINS;`,
  chainContext,
  { filename: 'js/data/chains.js' },
);

const internalNetworkIds = [
  'internal-network-discovery-service-map',
  'smb-ntlm-exposure-credential-validation',
  'active-directory-path-analysis',
  'kerberos-service-account-review',
  'windows-admin-path-segmentation-validation',
  'linux-ssh-privilege-boundary-review',
];
const internalNetworkChains = chainContext.catalogChains.filter(chain => internalNetworkIds.includes(chain.id));
assert.equal(internalNetworkChains.length, internalNetworkIds.length, 'all internal-network learning chains should exist');
assert.deepEqual(
  Array.from(internalNetworkChains, chain => chain.id),
  internalNetworkIds,
  'internal-network chains should keep the agreed learning order',
);
for (const chain of internalNetworkChains) {
  assert.ok(chain.tags.includes('authorized-lab'), `${chain.id} must be limited to authorized labs`);
  assert.ok(chain.title.ru && chain.title.en, `${chain.id} must be bilingual`);
  assert.equal(chain.steps.length, 5, `${chain.id} should remain a concise five-step workflow`);
  for (const step of chain.steps) {
    assert.ok(step.t.ru && step.t.en && step.c, `${chain.id} steps must be bilingual and actionable`);
  }
  const renderedText = JSON.stringify(chain);
  assert.doesNotMatch(renderedText, /\b(?:exfiltrat|persistence|credential dump|password guess)\b/i,
    `${chain.id} must not teach destructive or credential-theft steps`);
  assert.doesNotMatch(renderedText, /\b(?:10|127|172|192)\.\d{1,3}\.\d{1,3}/,
    `${chain.id} must not contain a real-looking target address`);
}
