const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const vm = require('node:vm');

const SOURCES = [
  'js/tools/security_tools_catalog_en_v2_2026-07-30.md',
  'js/tools/security_tools_catalog_ru_v2_2026-07-30.md',
];
if (SOURCES.every(file => fs.existsSync(file))) {
  execFileSync('python3', ['scripts/build_tools_catalog.py', '--check'], { stdio: 'inherit' });
}

const source = fs.readFileSync('js/tools/catalog.js', 'utf8');
const context = {};
vm.createContext(context);
vm.runInContext(`${source}\nglobalThis.catalog = TOOLS_CATALOG;`, context, {
  filename: 'js/tools/catalog.js',
});

const { version, items } = context.catalog;

assert.ok(Number.isInteger(version) && version > 0, 'version must be a positive integer');
assert.ok(Array.isArray(items) && items.length > 0, 'items must be a non-empty array');
assert.equal(items.length, 420, 'tools catalog should contain 420 curated tools');

function duplicates(values) {
  const seen = new Map();
  values.forEach(value => seen.set(value, (seen.get(value) || 0) + 1));
  return [...seen].filter(([, count]) => count > 1).map(([value]) => value);
}

assert.deepEqual(duplicates(items.map(t => t.id)), [], 'duplicate tool ids');

const codes = items.map(t => t.code).filter(code => code !== null && code !== undefined && code !== '');
assert.deepEqual(duplicates(codes), [], 'duplicate tool codes');

// Normalise cosmetic differences so duplicate commands cannot evade the invariant.
const examples = items
  .map(t => t.example && t.example.trim().replace(/\s+/g, ' ').toLowerCase())
  .filter(Boolean);
assert.deepEqual(duplicates(examples), [], 'tools sharing an example command');

const REQUIRED = ['id', 'name', 'url', 'track', 'category', 'desc_en', 'desc_ru', 'tags'];
const missing = [];
items.forEach(tool => {
  REQUIRED.forEach(field => {
    if (!tool[field]) missing.push(`${tool.id || '<no id>'}.${field}`);
  });
});
assert.deepEqual(missing, [], 'tools with missing required fields');

const CYRILLIC = /[а-яА-ЯёЁ]/;
const localeLeaks = [];
items.forEach(tool => {
  Object.entries(tool).forEach(([field, value]) => {
    if (field.endsWith('_en') && typeof value === 'string' && CYRILLIC.test(value)) {
      localeLeaks.push(`${tool.id}.${field}`);
    }
  });
});
assert.deepEqual(localeLeaks, [], 'Russian text leaked into English-only fields');

// install renders identically in both locales, so it must stay language-neutral
const localisedInstall = [...items].filter(tool => tool.install && CYRILLIC.test(tool.install)).map(tool => tool.id);
assert.deepEqual(localisedInstall, [], 'install must be a language-neutral command, not localised prose');

const usageEchoesInstall = [...items]
  .filter(tool => /(?:^|[\s.!?])(Install|Установка)\s*:/i.test(`${tool.usage_en} ${tool.usage_ru}`))
  .map(tool => tool.id);
assert.deepEqual(usageEchoesInstall, [], 'usage_* must describe usage, not carry an appended install blurb');

const KNOWN_TRACKS = new Set(['mobile', 'offensive', 'appsec', 'devsecops']);
const unknownTracks = [...new Set(items.map(t => t.track))].filter(track => !KNOWN_TRACKS.has(track));
assert.deepEqual(unknownTracks, [], 'tools on a track the catalog UI does not order');

const trackByCategory = {};
items.forEach(t => {
  (trackByCategory[t.category] = trackByCategory[t.category] || new Set()).add(t.track);
});
const straddling = Object.entries(trackByCategory)
  .filter(([, tracks]) => tracks.has('appsec') && tracks.has('devsecops'))
  .map(([category]) => category);
assert.deepEqual(
  straddling.filter(category => category !== 'supply-chain'),
  [],
  'categories split across appsec and devsecops'
);

const categories = new Set(items.map(t => t.category));
for (const [a, b] of [['k8s', 'kubernetes'], ['secrets', 'secrets-mgmt']]) {
  assert.ok(
    !(categories.has(a) && categories.has(b)),
    `"${a}" and "${b}" are the same concept under two slugs — pick one`
  );
}

const devsecops = items.filter(tool => tool.track === 'devsecops');
assert.equal(devsecops.length, 79, 'DevSecOps catalog should contain 79 curated tools');

for (const [id, category] of [
  ['github-code-review', 'code-review'],
  ['gitlab-code-review', 'code-review'],
  ['coderabbit', 'ai-code'],
  ['qwiet-ai', 'ai-code'],
  ['crowdstrike-falcon-edr', 'edr-xdr'],
  ['microsoft-defender-endpoint', 'edr-xdr'],
  ['sentinelone-singularity', 'edr-xdr'],
  ['wazuh', 'edr-xdr'],
]) {
  const tool = items.find(item => item.id === id);
  assert.ok(tool, `${id} should be present in the tools catalog`);
  assert.equal(tool.category, category, `${id} should use the ${category} category`);
}

for (const [id, category] of [
  ['gitguardian-ggshield', 'secret-scanning'],
  ['github-secret-scanning', 'secret-scanning'],
  ['nosey-parker', 'secret-scanning'],
  ['renovate', 'dependency-management'],
  ['snyk', 'appsec-platform'],
  ['socket', 'sca'],
]) {
  const tool = items.find(item => item.id === id);
  assert.ok(tool, `${id} should be present in the tools catalog`);
  assert.equal(tool.category, category, `${id} should use the ${category} category`);
}

for (const [id, category] of [
  ['burpsuite', 'dast'],
  ['owasp-zap', 'dast'],
  ['stackhawk', 'dast'],
  ['arachni', 'dast'],
  ['nikto', 'dast'],
  ['nuclei', 'dast'],
  ['w3af', 'dast'],
  ['caido', 'proxy'],
]) {
  const tool = items.find(item => item.id === id);
  assert.ok(tool, `${id} should be present in the tools catalog`);
  assert.equal(tool.category, category, `${id} should use the ${category} category`);
}

assert.match(items.find(item => item.id === 'nuclei').tags, /template-scan/, 'Nuclei should retain its template-scanner tag');
assert.match(items.find(item => item.id === 'arachni').tags, /legacy/, 'Arachni should retain its legacy tag');

for (const [id, track, category] of [
  ['amazon-guardduty', 'appsec', 'cloud'],
  ['f5-distributed-cloud', 'appsec', 'waf'],
  ['in-toto', 'appsec', 'supply-chain'],
  ['nessus', 'appsec', 'vuln-scan'],
  ['rekor', 'appsec', 'supply-chain'],
  ['signal-sciences-fastly', 'appsec', 'waf'],
  ['slsa', 'appsec', 'supply-chain'],
  ['chain-bench', 'devsecops', 'supply-chain'],
  ['kubeconform', 'devsecops', 'kubernetes'],
  ['attacksurfacemapper', 'offensive', 'attack-surface'],
  ['autorecon', 'offensive', 'network-discovery'],
  ['dnsdumpster', 'offensive', 'passive-osint'],
  ['nmapautomator', 'offensive', 'network-discovery'],
  ['rustscan', 'offensive', 'network-discovery'],
  ['projectdiscovery-suite', 'offensive', 'attack-surface'],
  ['cobalt-strike', 'offensive', 'post-exploitation'],
  ['certipy', 'offensive', 'internal-recon'],
  ['crackmapexec-netexec', 'offensive', 'post-exploitation'],
  ['psudohash', 'offensive', 'post-exploitation'],
  ['roadtools', 'offensive', 'cloud-identity-recon'],
  ['rubeus', 'offensive', 'post-exploitation'],
  ['sharphound', 'offensive', 'internal-recon'],
  ['checksec', 'offensive', 'vulnerability-discovery'],
  ['mobsf', 'mobile', 'mobile'],
  ['nowsecure', 'mobile', 'mobile'],
  ['ostorlab', 'mobile', 'mobile'],
  ['magisk', 'mobile', 'runtime'],
  ['firebasescanner', 'mobile', 'mobile'],
]) {
  const tool = items.find(item => item.id === id);
  assert.ok(tool, `${id} should be present in the tools catalog`);
  assert.equal(tool.track, track, `${id} should use the ${track} track`);
  assert.equal(tool.category, category, `${id} should use the ${category} category`);
}

const offensive = items.filter(tool => tool.track === 'offensive');
assert.equal(offensive.length, 163, 'Offensive Security should include the merged tracks and four Passive OSINT sources');
assert.equal(items.some(tool => tool.track === 'bugbounty' || tool.track === 'redteam'), false, 'legacy offensive tracks should be merged');
const passiveOsint = items.filter(tool => tool.track === 'offensive' && tool.category === 'passive-osint').map(tool => tool.id);
for (const id of ['shodan', 'censys', 'gau', 'waybackurls', 'githound', 'dnsdumpster', 'theharvester', 'securitytrails', 'crt-sh', 'github-code-search']) {
  assert.ok(passiveOsint.includes(id), `${id} should be in Passive OSINT`);
}

for (const [id, category] of [
  ['kustomize', 'kubernetes'],
  ['helmfile', 'cicd'],
  ['cert-manager', 'network'],
  ['node-problem-detector', 'observability'],
  ['stern', 'observability'],
  ['kubectx-kubens', 'kubernetes'],
  ['jaeger', 'observability'],
]) {
  const tool = devsecops.find(item => item.id === id);
  assert.ok(tool, `${id} should be present in the DevSecOps catalog`);
  assert.equal(tool.category, category, `${id} should use the ${category} category`);
  assert.match(tool.url, /^https:\/\//, `${id} should link to its official HTTPS documentation`);
}

for (const query of ['RBAC', 'Velero', 'NetworkPolicy', 'cert-manager', 'Stern', 'Jaeger']) {
  const needle = query.toLowerCase();
  const matches = items.filter(tool =>
    [tool.name, tool.id, tool.category, tool.mitre, tool.tags, tool.desc_en, tool.desc_ru, tool.code]
      .join(' ').toLowerCase().includes(needle)
  );
  assert.ok(matches.length > 0, `tool search should find "${query}"`);
}

const kubeconform = devsecops.find(tool => tool.id === 'kubeconform');
assert.equal(kubeconform.name, 'Kubeconform', 'Kubeconform should not promote a legacy tool in its title');
assert.doesNotMatch(kubeconform.tags, /kubeval/i, 'Kubeconform tags should describe the maintained tool');

const publicKubernetesContent = [
  'js/features/frameworks.js',
  'js/tools/catalog.js',
  'js/data/workflows.js',
  'js/data/labs.js',
].map(file => fs.readFileSync(file, 'utf8')).join('\n');
assert.doesNotMatch(
  publicKubernetesContent,
  /PodSecurityPolicy|Kubernetes Dashboard|kube-ops-view|MicroScanner|Anchore Engine|K8Guard|Copper|kubeval|ksonnet|Tiller|Flux v1|Helm 2/i,
  'public Kubernetes content must not promote obsolete tools or mechanisms'
);

assert.equal(
  fs.existsSync('k8s-devsecops-справочник.md'),
  false,
  'book-derived local notes must not be published'
);
