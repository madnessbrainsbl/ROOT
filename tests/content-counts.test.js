const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const ctx = { DATA: {}, console, I18n: { lang: () => 'en' } };
ctx.window = ctx;
vm.createContext(ctx);
vm.runInContext(
  ['js/data/core.js', 'js/data/labs.js', 'js/data/payloads.js', 'js/data/chains.js',
    'js/data/workflows.js', 'js/data/challenges.js', 'js/tools/catalog.js', 'js/features/frameworks.js']
    .map(f => fs.readFileSync(f, 'utf8')).join('\n')
  + '\nglobalThis.D = DATA; globalThis.CH = CHALLENGES;'
  + ' globalThis.TC = TOOLS_CATALOG; globalThis.FW = SecurityFrameworks;',
  ctx, { filename: 'bundle.js' }
);

const challenges = Array.isArray(ctx.CH) ? ctx.CH : Object.values(ctx.CH).find(Array.isArray);
const payloadGroups = Object.keys(ctx.D.PAYLOADS);
const payloads = Object.values(ctx.D.PAYLOADS).filter(Array.isArray).flat();

const actual = {
  challenges: challenges.length,
  quiz: ctx.D.MODS.reduce((n, m) => n + (m.quiz || []).length, 0),
  tools: ctx.TC.items.length,
  payloadGroups: payloadGroups.length,
  payloads: payloads.length,
  chains: ctx.D.CHAINS.length,
  builders: ctx.D.CMD_BUILDERS.length,
  frameworks: ctx.FW.ITEMS.length,
  kev: JSON.parse(fs.readFileSync('data/cves_public.json', 'utf8')).length,
};

const readme = fs.readFileSync('README.md', 'utf8');
const landing = fs.readFileSync('index.html', 'utf8');

const row = (text, label) => {
  const m = text.match(new RegExp(`\\|\\s*${label}[^|]*\\|\\s*([\\d,]+)\\s*\\|`));
  assert.ok(m, `README row not found: ${label}`);
  return Number(m[1].replace(/,/g, ''));
};
const counter = (text, label) => {
  const m = text.match(new RegExp(`<strong>([\\d,]+)</strong><span>${label}`));
  assert.ok(m, `landing counter not found: ${label}`);
  return Number(m[1].replace(/,/g, ''));
};

assert.equal(row(readme, 'Web CTF challenges'), actual.challenges, 'README: CTF challenges');
assert.equal(row(readme, 'Bilingual quiz questions'), actual.quiz, 'README: quiz questions');
assert.equal(row(readme, 'Public CISA KEV'), actual.kev, 'README: KEV records');
assert.equal(row(readme, 'Security tool references'), actual.tools, 'README: tool references');
assert.equal(row(readme, 'Payload examples'), actual.payloads, 'README: payload examples');
assert.equal(row(readme, 'Attack-chain scenarios'), actual.chains, 'README: attack chains');
assert.equal(row(readme, 'Command builders'), actual.builders, 'README: command builders');
assert.equal(row(readme, 'Security standards and methods'), actual.frameworks, 'README: frameworks');

assert.equal(counter(landing, 'Web CTF challenges'), actual.challenges, 'landing: challenges');
assert.equal(counter(landing, 'bilingual questions'), actual.quiz, 'landing: questions');
assert.equal(counter(landing, 'standards'), actual.frameworks, 'landing: frameworks');
assert.equal(counter(landing, 'public KEV records'), actual.kev, 'landing: KEV');

assert.ok(
  readme.includes(`Payload examples in ${actual.payloadGroups} categories`),
  `README should say "Payload examples in ${actual.payloadGroups} categories"`
);

const groups = ctx.FW.GROUPS.length;
for (const [name, html] of [['index.html', landing]]) {
  const cards = (html.match(/class="map-card/g) || []).length;
  assert.equal(cards, groups, `${name}: map cards should match framework groups`);
}

assert.equal(actual.frameworks, 50, 'framework catalog should contain 50 methods');
assert.equal(groups, 11, 'framework map should contain 11 practical domains');
const frameworkIds = ctx.FW.ITEMS.map(item => item.id);
assert.equal(new Set(frameworkIds).size, frameworkIds.length, 'framework ids must be unique');
assert.equal(new Set(ctx.FW.ITEMS.map(item => item.summary_en)).size, actual.frameworks, 'English framework descriptions must be unique');
assert.equal(new Set(ctx.FW.ITEMS.map(item => item.summary_ru)).size, actual.frameworks, 'Russian framework descriptions must be unique');
const textLength = html => html
  .replace(/<[^>]+>/g, ' ')
  .replace(/&[^;]+;/g, ' ')
  .replace(/\s+/g, ' ')
  .trim()
  .length;
for (const framework of ctx.FW.ITEMS) {
  const english = framework.sections.reduce((total, section) => total + textLength(section.body_en), 0);
  const russian = framework.sections.reduce((total, section) => total + textLength(section.body_ru), 0);
  assert.ok(english >= 900, `${framework.id} should contain practical English guidance`);
  assert.ok(russian >= 900, `${framework.id} should contain practical Russian guidance`);
}
const untranslatedRussianSummaryWords = /\b(?:assessment|behavior|behaviors|capability|delivery|deployment|detection|evidence|governance|identity|impact|lifecycle|model|policy|prevention|remediation|response|risk|runtime|scope|telemetry|workflow|workloads?)\b/i;
for (const framework of ctx.FW.ITEMS) {
  assert.doesNotMatch(
    framework.summary_ru,
    untranslatedRussianSummaryWords,
    `${framework.id}.summary_ru should not mix ordinary English prose into Russian`,
  );
}
for (const id of [
  'k8s-access-control',
  'k8s-hardening',
  'k8s-network-security',
  'k8s-security-assurance',
  'appsec-testing',
  'vulnerability-lifecycle',
  'identity-api-security',
  'detection-engineering',
  'incident-response',
  'ai-agentic-security',
  'governance-compliance',
  'product-security-operating-model',
]) {
  const framework = ctx.FW.ITEMS.find(item => item.id === id);
  assert.ok(framework, `${id} should be present`);
  for (const field of ['title_en', 'title_ru', 'summary_en', 'summary_ru']) {
    assert.ok(framework[field], `${id}.${field} should be present`);
  }
  assert.ok(framework.sections.length >= 3, `${id} should provide detailed guidance`);
  framework.sections.forEach((section, index) => {
    assert.ok(section.title_en && section.title_ru, `${id}.sections[${index}] should be bilingual`);
    assert.ok(section.body_en && section.body_ru, `${id}.sections[${index}] should be bilingual`);
  });
}

const groupedFrameworkIds = ctx.FW.GROUPS.flatMap(group => group.items);
assert.equal(new Set(groupedFrameworkIds).size, groupedFrameworkIds.length, 'framework groups must not duplicate cards');

ctx.I18n.lang = () => 'ru';
const russianFramework = ctx.FW.renderItem('product-security-operating-model');
assert.match(russianFramework, /Операционная модель AppSec и безопасности продукта/, 'framework page should use its Russian title');
assert.doesNotMatch(russianFramework, /AppSec and Product Security Operating Model/, 'Russian framework page should not use its English title');
assert.match(russianFramework, /framework-lede/, 'framework header should include its description');
assert.doesNotMatch(russianFramework, />Описание</, 'framework page should not duplicate the description in a separate card');

const russianNistCsf = ctx.FW.renderItem('nist-csf');
assert.match(russianNistCsf, /Управление \(Govern\)/, 'NIST CSF functions should be explained in Russian');
assert.match(russianNistCsf, /NIST CSF 2\.0 связывает AppSec/, 'NIST CSF should include its own description');
assert.match(ctx.FW.renderHub(), /Управление и соответствие требованиям/, 'framework groups should use Russian titles');
assert.match(ctx.FW.renderHub(), /Находить пути злоупотребления/, 'framework hub should translate abuse paths');
assert.doesNotMatch(ctx.FW.renderHub(), /abuse paths|Test with authorization/, 'framework hub should not expose English flow labels in Russian');

const russianGovernance = ctx.FW.renderItem('governance-compliance');
assert.match(russianGovernance, /Работающие меры вместо формальных чек-листов/, 'GRC guidance should use natural Russian wording');
assert.doesNotMatch(russianGovernance, /театр чек-листов|Цепочка прослеживаемости/, 'GRC guidance should not contain literal translation calques');

assert.equal(
  frameworkIds.filter(id => !groupedFrameworkIds.includes(id)).sort().join(','),
  'llmsvs,masvs-mastg,samm,wstg',
  'only OWASP navigation cards should live outside the framework map'
);

const offensiveIds = ['ptes', 'nist-security-testing', 'attack-lifecycle-models', 'adversary-emulation'];
const offensiveGroup = ctx.FW.GROUPS.find(group => group.id === 'offensive-assessment');
assert.ok(offensiveGroup, 'Offensive Assessment group should be present');
assert.deepEqual(
  Array.from(offensiveGroup.items),
  offensiveIds,
  'Offensive Assessment group should keep the agreed learning order'
);
for (const id of offensiveIds) {
  const framework = ctx.FW.ITEMS.find(item => item.id === id);
  assert.ok(framework, `${id} should be present`);
  assert.ok(framework.title_en && framework.title_ru, `${id} should have a title in both locales`);
  assert.ok(framework.sections.length >= 5 && framework.sections.length <= 7, `${id} should have 5-7 sections`);
  for (const field of ['summary_en', 'summary_ru']) {
    assert.ok(framework[field], `${id}.${field} should be present`);
  }
  framework.sections.forEach((section, index) => {
    assert.ok(section.title_en && section.title_ru, `${id}.sections[${index}] should be bilingual`);
    assert.ok(section.body_en && section.body_ru, `${id}.sections[${index}] should be bilingual`);
  });
  assert.ok(framework.links.length >= 2, `${id} should cite primary sources`);
  framework.links.forEach(([label, url]) => {
    assert.ok(label, `${id} source label should be present`);
    assert.match(url, /^https:\/\//, `${id} source should use HTTPS`);
  });
}
assert.ok(!frameworkIds.includes('osstmm'), 'OSSTMM should remain a comparison, not a card');
assert.ok(!frameworkIds.includes('dread'), 'DREAD should not be a standalone card');

const detectionEngineering = ctx.FW.ITEMS.find(item => item.id === 'detection-engineering');
assert.ok(detectionEngineering.title_en && detectionEngineering.title_ru, 'Detection Engineering should have a title in both locales');
assert.equal(detectionEngineering.title_ru, 'Разработка детектов', 'Detection Engineering should use the established Russian term');
assert.ok(
  detectionEngineering.sections.length >= 5 && detectionEngineering.sections.length <= 7,
  'Detection Engineering should have 5-7 substantial sections'
);
assert.ok(detectionEngineering.links.length >= 4, 'Detection Engineering should cite primary sources');
assert.ok(
  ctx.FW.GROUPS.find(group => group.id === 'detection-resilience').items.includes('detection-engineering'),
  'Detection Engineering should belong to Detection, Response and Resilience'
);
const detectionEnglish = detectionEngineering.sections.map(section => section.body_en).join('');
const detectionRussian = detectionEngineering.sections.map(section => section.body_ru).join('');
for (const term of ['hypothesis', 'telemetry contract', 'Sigma', 'false positives', 'retirement']) {
  assert.match(detectionEnglish, new RegExp(term, 'i'), `Detection Engineering should cover ${term}`);
}
assert.match(detectionRussian, /требования к телеметрии/i, 'Detection Engineering RU should cover telemetry requirements');
assert.doesNotMatch(detectionRussian, /Инженерия обнаружения/i, 'Detection Engineering RU should not use a literal calque');
assert.equal(
  ctx.FW.ITEMS.find(item => item.id === 'chaos-engineering').title_ru,
  'Хаос-инжиниринг',
  'Chaos Engineering should use the established Russian term'
);
assert.equal(
  ctx.FW.ITEMS.find(item => item.id === 'k8s-access-control').title_ru,
  'Управление доступом в Kubernetes',
  'Kubernetes access control should use the established Russian term'
);
assert.match(detectionEnglish, /#\/frameworks\/observability/, 'Detection Engineering should link to observability');
assert.match(detectionEnglish, /#\/frameworks\/incident-response/, 'Detection Engineering should link to incident response');
assert.match(detectionEnglish, /#\/frameworks\/adversary-emulation/, 'Detection Engineering should link to adversary emulation');
assert.match(detectionEnglish, /#\/tool\/wazuh/, 'Detection Engineering should link to an existing detection tool');
for (const [label, url] of detectionEngineering.links) {
  assert.ok(label, 'Detection Engineering source label should be present');
  assert.match(url, /^https:\/\//, 'Detection Engineering source should use HTTPS');
}

const ptes = ctx.FW.ITEMS.find(item => item.id === 'ptes');
assert.equal(ptes.sections.length, 7, 'PTES should provide seven substantial sections');
assert.equal(
  (ptes.sections[1].body_en.match(/<div><strong>\d\./g) || []).length,
  7,
  'PTES should describe all seven phases'
);
assert.match(ptes.sections[0].body_en, /Rules of Engagement[\s\S]*stop conditions/, 'PTES should cover RoE safety');
assert.match(ptes.sections[2].body_en, /evidence/i, 'PTES should cover evidence');
assert.match(ptes.sections[2].body_en, /cleanup/i, 'PTES should cover cleanup');
assert.match(ptes.sections[4].body_en, /#\/frameworks\/wstg/, 'PTES should link to WSTG');
assert.match(ptes.sections[4].body_en, /#\/commands\/chains/, 'PTES should link to attack chains');
assert.match(ptes.sections[4].body_en, /#\/reports/, 'PTES should link to report templates');
assert.match(ptes.sections[0].body_en, /vulnerability and configuration assessment/i, 'PTES should guide assessment selection');
assert.match(ptes.sections[0].body_en, /Black-box[\s\S]*grey-box[\s\S]*white-box/i, 'PTES should distinguish knowledge models');
const internalNetworkPlaybook = ptes.sections.find(section => section.title_en === 'Internal Network Assessment Playbook');
assert.ok(internalNetworkPlaybook, 'PTES should provide the internal network assessment playbook');
assert.match(internalNetworkPlaybook.body_en, /authorized-lab workflow/i, 'PTES network playbook should require authorization');
assert.match(internalNetworkPlaybook.body_en, /#\/commands\/builder/, 'PTES network playbook should link to command builders');
assert.match(internalNetworkPlaybook.body_en, /#\/commands\/chains/, 'PTES network playbook should link to attack chains');
assert.match(internalNetworkPlaybook.body_en, /#\/tools/, 'PTES network playbook should link to tools');
assert.match(internalNetworkPlaybook.body_en, /#\/reports/, 'PTES network playbook should link to reports');

const nistTesting = ctx.FW.ITEMS.find(item => item.id === 'nist-security-testing');
assert.match(nistTesting.summary_en, /repeatable procedures/, 'NIST testing should emphasize repeatability');
assert.match(nistTesting.sections.map(section => section.body_en).join(''), /guidance issued in 2008/, 'NIST testing should state its age');
assert.match(nistTesting.sections.map(section => section.body_en).join(''), /OSSTMM 3/, 'OSSTMM should appear as a comparison');

const lifecycleModels = ctx.FW.ITEMS.find(item => item.id === 'attack-lifecycle-models');
assert.match(lifecycleModels.sections[0].body_en, /Cyber Kill Chain[\s\S]*Unified Kill Chain[\s\S]*MITRE ATT&CK/, 'lifecycle models should compare all three models');
assert.match(lifecycleModels.sections[2].body_en, /eighteen phases/, 'Unified Kill Chain should describe 18 phases');

const adversaryEmulation = ctx.FW.ITEMS.find(item => item.id === 'adversary-emulation');
assert.match(adversaryEmulation.sections.map(section => section.body_en).join(''), /CALDERA[\s\S]*Atomic Red Team/, 'emulation should position both execution tools');
assert.match(adversaryEmulation.sections.map(section => section.body_en).join(''), /MITRE Engage[\s\S]*TIBER-EU[\s\S]*CBEST/, 'emulation should distinguish planning and sector schemes');

const pasta = ctx.FW.ITEMS.find(item => item.id === 'pasta');
assert.equal(pasta.sections.length, 5, 'PASTA should include process, roles, example, comparison and outputs');
assert.equal(
  (pasta.sections[0].body_en.match(/<div><strong>\d\./g) || []).length,
  7,
  'PASTA should describe all seven stages'
);
for (const stage of [
  'Definition of Objectives',
  'Definition of Technical Scope',
  'Application Decomposition',
  'Threat Analysis',
  'Vulnerability Analysis',
  'Attack Modeling',
  'Risk and Impact Analysis',
]) {
  assert.match(pasta.sections[0].body_en, new RegExp(stage), `PASTA should include ${stage}`);
  assert.match(pasta.sections[0].body_ru, new RegExp(stage), `PASTA RU should include ${stage}`);
}
assert.match(pasta.sections[0].body_en, /<b>Input:<\/b>[\s\S]*<b>Output:<\/b>/, 'PASTA stages need inputs and outputs');
assert.match(pasta.sections[1].body_en, /Business \/ product owner[\s\S]*DevSecOps \/ platform/, 'PASTA should name participants');
assert.match(pasta.sections[2].body_en, /Attack path:[\s\S]*Risk treatment:/, 'PASTA should include a worked attack path');
assert.match(pasta.sections[3].body_en, /STRIDE[\s\S]*complementary/, 'PASTA should explain how STRIDE fits');
assert.match(pasta.sections[4].body_en, /risk register[\s\S]*more time/, 'PASTA should state deliverables and limits');
