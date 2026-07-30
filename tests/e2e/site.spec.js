const { test, expect } = require('@playwright/test');

test.beforeEach(async ({ page }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => {
    if (message.type() === 'error') errors.push(message.text());
  });
  page.rootErrors = errors;
});

test.afterEach(async ({ page }) => {
  expect(page.rootErrors).toEqual([]);
});

test('landing presents the product and opens the app', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle(/Offline AppSec Training Range/);
  await expect(page.locator('meta[property="og:image"]')).toHaveAttribute('content', /cover\.jpg$/);
  await expect(page.getByRole('link', { name: 'Open the app' })).toHaveAttribute('href', 'app/#/lab/A01');
  await expect(page.getByText('250', { exact: true })).toBeVisible();
  await expect(page.locator('.standard-links a')).toHaveCount(5);
  await expect(page.locator('.map-card')).toHaveCount(11);
  await expect(page.getByRole('link', { name: /Threat Modeling/ })).toHaveAttribute('href', 'app/#/frameworks/threat-modeling');
  await expect(page.getByRole('link', { name: /AI & Agentic Security/ })).toHaveAttribute('href', 'app/#/frameworks/ai-agentic-security');
});

test('shareable lab route uses the available width', async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.goto('/app/#/lab/A03');
  await expect(page.locator('.lab-card')).toBeVisible();
  await expect(page).toHaveURL(/#\/lab\/A03$/);
  const main = await page.locator('#main').boundingBox();
  const card = await page.locator('.lab-card').boundingBox();
  expect(card.width).toBeGreaterThan(main.width - 80);
});

test('application opens in English and keeps an explicit language choice', async ({ page }) => {
  await page.goto('/app/#/lab/A01');
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.locator('#lang-en')).toHaveClass(/active/);
  await expect(page.getByText('Broken Access Control', { exact: true }).first()).toBeVisible();

  await page.locator('#lang-ru').click();
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('lang', 'ru');
  await expect(page.locator('#lang-ru')).toHaveClass(/active/);
  await expect(page.locator('#nav-owasp [data-nav="owasp-home"] .nn')).toHaveText('Overview');
  await expect(page.locator('#nav-owasp > [data-nav="owasp"] .icon, #nav-frameworks > [data-nav="frameworks"] .icon')).toHaveCount(0);
  await expect(page.locator('[data-nav="checklists"]')).toHaveCount(0);
  await expect(page.locator('[data-i18n="toolkit"]')).toHaveText('Resources');
  await expect(page.locator('[data-i18n="toolsNav"]')).toHaveText('Tools');
  await expect(page.locator('[data-i18n="cmdsNav"]')).toHaveText('Commands');
  await expect(page.locator('[data-i18n="reports"]')).toHaveText('Bug report templates');
  const sidebarOrder = await page.locator('#sidebar [data-nav="tools"], #sidebar [data-nav="commands"], #sidebar [data-nav="reports"], #sidebar [data-nav="zerodays"]')
    .evaluateAll(items => items.map(item => item.dataset.nav));
  expect(sidebarOrder).toEqual(['tools', 'commands', 'reports', 'zerodays']);
  await page.locator('[data-nav="tools"]').click();
  await expect(page.locator('#crumbs')).toHaveText('Resources/Tools');
  await expect(page.locator('[data-nav="tools"].active .nd')).toHaveCount(1);
  await expect(page.locator('[data-nav="tools"].active .icon')).toHaveCount(0);
  await expect(page.locator('#nav-owasp .nav-children')).toBeVisible();
  await page.reload();
  await expect(page.locator('#nav-owasp .nav-children')).toBeVisible();
  await expect(page.locator('#nav-frameworks .nav-children')).toBeHidden();
  await page.locator('#nav-frameworks [data-nav-toggle="frameworks"]').click();
  await expect(page.locator('#nav-frameworks .nav-children')).toBeVisible();
  await page.reload();
  await expect(page.locator('#nav-owasp .nav-children')).toBeVisible();
  await expect(page.locator('#nav-frameworks .nav-children')).toBeVisible();
  await page.evaluate(() => sessionStorage.removeItem('root_nav_groups'));
  await page.reload();
  await expect(page.locator('#nav-owasp .nav-children')).toBeHidden();
  await expect(page.locator('#nav-frameworks .nav-children')).toBeHidden();
  await page.goto('/app/#/frameworks/wstg');
  await expect(page.locator('#nav-owasp .nav-children')).toBeVisible();
  await expect(page.locator('#nav-frameworks .nav-children')).toBeHidden();
  await page.reload();
  await expect(page.locator('#nav-owasp .nav-children')).toBeVisible();
});

test('payload catalog localizes labels without changing payload commands', async ({ page }) => {
  await page.goto('/app/#/commands/payloads');
  await expect(page.getByRole('button', { name: 'Payloads', exact: true })).toBeVisible();
  await page.locator('#pay-groups [data-gid="A05"]').click();
  await page.locator('#pay-cats [data-cat="SQL Injection"]').click();
  await expect(page.locator('#pay-cats [data-cat="SQL Injection"]')).toHaveText('SQL Injection');
  await expect(page.locator('#pay-list .payload-item').first()).toContainText('Auth bypass comment');
  const englishPayload = await page.locator('#pay-list .cmd').first().textContent();

  await page.locator('#lang-ru').click();
  await expect(page.getByRole('button', { name: 'Пейлоады', exact: true })).toBeVisible();
  await expect(page.locator('#pay-cats [data-cat="SQL Injection"]')).toHaveText('SQL-инъекции');
  await expect(page.locator('#pay-list .payload-item').first()).toContainText(
    'Обход аутентификации через комментарий',
  );
  await expect(page.locator('#pay-list .cmd').first()).toHaveText(englishPayload);

  await page.locator('#lang-en').click();
  await expect(page.locator('#pay-list .payload-item').first()).toContainText('Auth bypass comment');
  await expect(page.locator('#pay-list .cmd').first()).toHaveText(englishPayload);
});

test('LLM application areas use an exclusive accordion', async ({ page }) => {
  await page.goto('/app/#/llm');
  const areas = page.locator('.llm-area');
  await expect(areas).toHaveCount(10);
  await expect(areas.first()).not.toHaveAttribute('open', '');

  await areas.nth(0).locator('summary').click();
  await expect(areas.nth(0)).toHaveAttribute('open', '');
  await expect(page.getByRole('button', { name: 'Open page' })).toHaveCount(0);

  await areas.nth(1).locator('summary').click();
  await expect(areas.nth(1)).toHaveAttribute('open', '');
  await expect(areas.nth(0)).not.toHaveAttribute('open', '');
});

test('CVE rows open without a redundant View button', async ({ page }) => {
  await page.goto('/app/#/cves');
  const row = page.locator('#cve9-tbody .cve9-row').first();
  await expect(row).toBeVisible({ timeout: 15_000 });
  await expect(page.getByRole('button', { name: 'View', exact: true })).toHaveCount(0);
  await row.click();
  await expect(page).toHaveURL(/#\/cve\/CVE-/);
});

test('unified OWASP navigation opens the ASVS overview', async ({ page }) => {
  await page.goto('/app/#/owasp');
  await expect(page.getByRole('heading', { name: 'OWASP workspace' })).toBeVisible();
  await expect(page.locator('.owasp-project-open')).toHaveCount(0);
  await expect(page.getByText('Open', { exact: true })).toHaveCount(0);
  await expect(page.locator('#nav-owasp [data-nav="framework-wstg"]')).toBeVisible();
  await expect(page.locator('#nav-owasp [data-nav="framework-llmsvs"]')).toBeVisible();
  await page.locator('#nav-owasp [data-nav="framework-wstg"]').click();
  await expect(page).toHaveURL(/#\/frameworks\/wstg$/);
  await expect(page.getByRole('heading', { name: 'OWASP Web Security Testing Guide' })).toBeVisible();
  await expect(page.locator('#nav-frameworks [data-nav="framework-wstg"]')).toHaveCount(0);
  await expect(page.locator('.owasp-tab', { hasText: 'WSTG 4.2' })).toHaveClass(/active/);
  await page.goto('/app/#/owasp');
  await page.locator('.owasp-tab', { hasText: 'ASVS 5.0' }).click();
  await expect(page).toHaveURL(/#\/asvs$/);
  await expect(page.locator('.asvs-chapter')).toHaveCount(17);
  await expect(page.getByText('345 cumulative requirements')).toBeVisible();
});

test('Web Top 10 cards open labs without redundant buttons', async ({ page }) => {
  await page.goto('/app/#/web');
  const cards = page.locator('.top10-card');
  await expect(cards).toHaveCount(10);
  await expect(page.getByText('All 10 categories', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Open', exact: true })).toHaveCount(0);
  await expect(page.locator('.webtop10-page .theory')).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'OWASP Top 10', exact: true })).toBeVisible();
  await expect(page.locator('#nav-owasp [data-nav="webtop10"] .nn')).toHaveText('Web Top 10');
  await expect(page.locator('#crumbs')).toHaveText('OWASP/Web Top 10');
  await expect(page.getByRole('link', { name: 'Official OWASP Top 10:2025', exact: true }))
    .toHaveAttribute('href', 'https://owasp.org/Top10/2025/');
  await expect(page.locator('.owasp-sources').getByRole('heading', { name: 'Sources', exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Official OWASP Top 10:2025', exact: true })).toHaveClass(/btn/);
  await expect(cards.first()).toHaveAttribute('href', '#/lab/A01');
  await expect(cards.nth(1).getByRole('heading')).toHaveText('Security Misconfiguration');
  await cards.nth(1).click();
  await expect(page).toHaveURL(/#\/lab\/A02$/);
  await expect(page.getByRole('heading', { name: 'Security Misconfiguration', exact: true })).toBeVisible();
  await expect(page.getByText('2017: A06', { exact: true })).toBeVisible();
  await expect(page.getByText('2021: A05', { exact: true })).toBeVisible();
  await expect(page.getByText('2025: A02', { exact: true })).toBeVisible();
  await page.goto('/app/#/lab/A01');
  await page.getByRole('tab', { name: 'Practice', exact: true }).click();
  await expect(page.locator('#chal-strip .chal-chip')).toHaveCount(5);
  await page.goto('/app/#/lab/A10');
  await page.getByRole('tab', { name: 'Practice', exact: true }).click();
  await expect(page.locator('#chal-strip .chal-chip')).toHaveCount(1);
  await page.goto('/app/#/web');
  await page.locator('#lang-ru').click();
  await expect(page.getByText('Подстановка учётных данных, слабые сессии', { exact: false })).toBeVisible();
  await expect(page.locator('.owasp-sources').getByRole('heading', { name: 'Источники', exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Официальный сайт OWASP Top 10:2025', exact: true })).toBeVisible();
  await page.locator('#lang-en').click();
  await cards.first().click();
  await expect(page).toHaveURL(/#\/lab\/A01$/);
  await expect(page.getByRole('heading', { name: 'Broken Access Control', exact: true })).toBeVisible();
  await expect(page.locator('.lab-card')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Official OWASP Top 10:2025', exact: true }))
    .toHaveAttribute('href', 'https://owasp.org/Top10/2025/');
});

test('API Security Top 10 links to the official OWASP source', async ({ page }) => {
  await page.goto('/app/#/api');
  await expect(page.getByRole('link', { name: 'Official OWASP API Security Top 10', exact: true }))
    .toHaveAttribute('href', 'https://owasp.org/API-Security/');
  await expect(page.getByRole('link', { name: 'Official OWASP API Security Top 10', exact: true })).toHaveClass(/btn/);
  await page.locator('#lang-ru').click();
  await expect(page.getByText('описывает десять распространённых и опасных классов рисков API', { exact: false })).toBeVisible();
  await expect(page.getByText('Грубый маппинг', { exact: false })).toHaveCount(0);
  await expect(page.getByText('текущая редакция', { exact: true })).toBeVisible();
  await page.locator('.mod-card').first().click();
  await expect(page).toHaveURL(/#\/api\/API1$/);
  await expect(page.getByRole('link', { name: 'Официальный сайт OWASP API Security Top 10', exact: true }))
    .toHaveAttribute('href', 'https://owasp.org/API-Security/');
  await expect(page.locator('.owasp-sources').getByRole('heading', { name: 'Источники', exact: true })).toBeVisible();
});

test('security frameworks map opens the decoded STRIDE taxonomy', async ({ page }) => {
  await page.goto('/app/#/cves');
  const group = page.locator('#nav-frameworks');
  const parent = group.locator('[data-nav-toggle="frameworks"]');
  await expect(group.locator('.nav-children')).toBeHidden();
  await parent.click();
  await expect(group.locator('.nav-children')).toBeVisible();
  const owaspGroup = page.locator('#nav-owasp');
  const owaspParent = owaspGroup.locator('[data-nav-toggle="owasp"]');
  await expect(owaspGroup.locator('.nav-children')).toBeHidden();
  await owaspParent.click();
  await expect(owaspGroup.locator('.nav-children')).toBeVisible();
  await owaspParent.click();
  await expect(owaspGroup.locator('.nav-children')).toBeHidden();
  await expect(group.locator('.nav-children .nc')).toHaveCount(0);
  await expect(group.locator('.nav-subgroup')).toHaveCount(11);
  await group.locator('.nav-subgroup').first().locator('summary').click();
  const offsets = sel => group.locator(sel).evaluateAll(els =>
    els.map(el => Math.round(el.getBoundingClientRect().left))
  );
  const topLevel = await offsets(':scope > .nav-children > .ni-child .nn');
  const nested = await offsets('.nav-subgroup > div > .ni-child .nn:visible');
  expect(topLevel.length).toBeGreaterThan(0);
  expect(nested.length).toBeGreaterThan(0);
  expect(Math.max(...topLevel) - Math.min(...topLevel)).toBeLessThanOrEqual(1);
  expect(Math.max(...nested) - Math.min(...nested)).toBeLessThanOrEqual(1);
  expect(Math.min(...nested)).toBeGreaterThan(Math.max(...topLevel));
  await group.locator('[data-nav="frameworks-home"]').click();
  await expect(page).toHaveURL(/#\/frameworks$/);
  await expect(page.getByRole('heading', { name: 'Security frameworks across the lifecycle' })).toBeVisible();
  await expect(page.locator('.framework-group')).toHaveCount(11);
  await expect(page.locator('.framework-card-grid .owasp-project-open')).toHaveCount(0);
  for (const id of ['attack-d3fend', 'cvss-epss', 'attack-trees', 'pasta', 'linddun', 'nist-csf',
    'ptes', 'nist-security-testing', 'attack-lifecycle-models', 'adversary-emulation',
    'k8s-access-control', 'k8s-hardening', 'k8s-network-security', 'k8s-security-assurance',
    'secrets-lifecycle', 'observability', 'chaos-engineering', 'appsec-testing',
    'vulnerability-lifecycle', 'identity-api-security', 'incident-response',
    'ai-agentic-security', 'governance-compliance']) {
    await expect(page.locator(`.framework-card-grid [data-arg="${id}"]`)).toHaveCount(1);
  }
  for (const id of ['samm', 'wstg', 'masvs-mastg', 'llmsvs']) {
    await expect(page.locator(`.framework-card-grid [data-arg="${id}"]`)).toHaveCount(0);
  }
  await page.locator('.framework-card-grid [data-arg="stride"]').dispatchEvent('click');
  await expect(page).toHaveURL(/#\/frameworks\/stride$/);
  await expect(page.locator('.stride-grid > div')).toHaveCount(6);
  await expect(page.getByText('Elevation of Privilege', { exact: true })).toBeVisible();

  await page.goto('/app/#/frameworks/pasta');
  await expect(page.getByRole('heading', { name: 'PASTA', exact: true })).toBeVisible();
  await expect(page.locator('.pasta-stages > div')).toHaveCount(7);
  await expect(page.getByText('1. Definition of Objectives', { exact: true })).toBeVisible();
  await expect(page.getByText('Worked example: cross-tenant report access', { exact: true })).toBeVisible();
  await expect(page.getByText('PASTA versus STRIDE', { exact: true })).toBeVisible();
  await expect(page.getByText('Final artifacts and limits', { exact: true })).toBeVisible();

  for (const [id, heading] of [
    ['wstg', 'OWASP Web Security Testing Guide'],
    ['samm', 'OWASP SAMM'],
    ['masvs-mastg', 'OWASP MASVS and MASTG'],
    ['llmsvs', 'OWASP LLM Security Verification Standard'],
    ['attack-trees', 'Attack Trees'],
    ['abuse-cases', 'Abuse and Misuse Cases'],
    ['linddun', 'LINDDUN'],
    ['attack-d3fend', 'MITRE ATT&CK and D3FEND'],
  ]) {
    await page.goto(`/app/#/frameworks/${id}`);
    await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
    await expect(page.locator('.framework-section')).toHaveCount(3);
    await expect(page.getByRole('heading', { name: 'Practical workflow', exact: true })).toBeVisible();
  }

  await page.goto('/app/#/frameworks/k8s-hardening');
  await expect(page.getByRole('heading', { name: 'Kubernetes Workload Hardening' })).toBeVisible();
  await expect(page.getByText('Resources, health and placement', { exact: true })).toBeVisible();
  await expect(page.getByText('Admission enforcement', { exact: true })).toBeVisible();
  const accessControlLink = page.getByRole('link', { name: 'access control', exact: true });
  await expect(accessControlLink).toHaveAttribute('href', '#/frameworks/k8s-access-control');
  await accessControlLink.click();
  await expect(page).toHaveURL(/#\/frameworks\/k8s-access-control$/);

  for (const [id, heading, text] of [
    ['k8s-access-control', 'Kubernetes Access Control', 'kubectl auth can-i'],
    ['k8s-network-security', 'Kubernetes Network & Service Security', 'default-deny'],
    ['k8s-security-assurance', 'Kubernetes Security Assurance', 'node-problem-detector'],
    ['appsec-testing', 'Application Security Testing', 'Operate for signal, not finding volume'],
    ['vulnerability-lifecycle', 'Vulnerability Management Lifecycle', 'Severity is not priority'],
    ['identity-api-security', 'Identity and API Security', 'Authorization is a server-side decision'],
    ['incident-response', 'Detection and Incident Response', 'Response lifecycle'],
    ['ai-agentic-security', 'AI and Agentic Security', 'Constrain agent actions'],
    ['governance-compliance', 'Governance, Controls and Evidence', 'Control system, not checklist theater'],
  ]) {
    await page.goto(`/app/#/frameworks/${id}`);
    await expect(page.getByRole('heading', { name: heading })).toBeVisible();
    await expect(page.getByText(text, { exact: false }).first()).toBeVisible();
  }

  await page.goto('/app/#/frameworks/k8s-security-assurance');
  await page.locator('#lang-ru').click();
  await expect(page.getByRole('heading', { name: 'Проверка безопасности Kubernetes' })).toBeVisible();
  await expect(page.getByText('Проверки до развёртывания', { exact: true })).toBeVisible();
  await expect(page.locator('#nav-frameworks [data-nav="frameworks-home"] .nn')).toHaveText('Карта жизненного цикла');
  await expect(page.locator('#nav-frameworks .nav-subgroup[open] > summary')).toHaveText('Безопасность облака и Kubernetes');
  await expect(page.locator('#nav-frameworks [data-nav="framework-k8s-security-assurance"] .nn')).toHaveText('Проверка безопасности Kubernetes');
  await page.goto('/app/#/frameworks/governance-compliance');
  await expect(page.getByRole('heading', { name: 'Работающие меры вместо формальных чек-листов', exact: true })).toBeVisible();
  await page.goto('/app/#/frameworks');
  await expect(page.getByRole('heading', { name: 'Практики безопасности на всём жизненном цикле', exact: true })).toBeVisible();
});

test('Offensive Assessment methods are detailed, bilingual and cross-linked', async ({ page }) => {
  await page.goto('/app/#/frameworks/ptes');
  await expect(page.getByRole('heading', { name: 'Penetration Testing Execution Standard', exact: true })).toBeVisible();
  expect(await page.locator('.framework-section').count()).toBeGreaterThanOrEqual(6);
  await expect(page.locator('.framework-stage-list').first().locator(':scope > div')).toHaveCount(7);
  await expect(page.getByText('PTES and WSTG serve different scopes', { exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: 'WSTG method', exact: true })).toHaveAttribute('href', '#/frameworks/wstg');
  await expect(page.getByRole('link', { name: 'attack chains', exact: true }).first()).toHaveAttribute('href', '#/commands/chains');
  await page.getByRole('link', { name: 'WSTG method', exact: true }).click();
  await expect(page).toHaveURL(/#\/frameworks\/wstg$/);
  await expect(page.getByRole('heading', { name: 'OWASP Web Security Testing Guide', exact: true })).toBeVisible();

  for (const [id, heading, evidence] of [
    ['nist-security-testing', 'NIST Technical Guide to Information Security Testing', 'guidance issued in 2008'],
    ['attack-lifecycle-models', 'Attack Lifecycle Models', 'Three models, three jobs'],
    ['adversary-emulation', 'Adversary Emulation and Purple Teaming', 'Purple teaming, Engage and sector schemes'],
  ]) {
    await page.goto(`/app/#/frameworks/${id}`);
    await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
    expect(await page.locator('.framework-section').count()).toBeGreaterThanOrEqual(6);
    await expect(page.getByText(evidence, { exact: false }).first()).toBeVisible();
  }

  await page.locator('#lang-ru').click();
  await expect(page.getByRole('heading', { name: 'Эмуляция противника и совместная работа команд', exact: true })).toBeVisible();
  await expect(page.getByText('Назначение и авторизация', { exact: true })).toBeVisible();
  await expect(page.locator('#nav-frameworks .nav-subgroup[open] > summary')).toHaveText('Наступательная оценка безопасности');

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/app/#/frameworks/ptes');
  await expect(page.getByRole('heading', { name: 'Penetration Testing Execution Standard', exact: true })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});

test('PTES internal-network guidance, report template and safe chains are reachable', async ({ page }) => {
  await page.goto('/app/#/frameworks/ptes');
  await expect(page.getByRole('heading', { name: 'Penetration Testing Execution Standard', exact: true })).toBeVisible();
  await expect(page.getByText('Internal Network Assessment Playbook', { exact: true })).toBeVisible();
  await expect(page.getByText('Choose the assessment first', { exact: true })).toBeVisible();

  await page.goto('/app/#/reports');
  await page.locator('#report-cats .report-cat[data-key="Pentest"]').click();
  await expect(page.locator('#report-md')).toHaveValue(/Executive Summary/);

  await page.goto('/app/#/commands/chains');
  await page.locator('#chain-groups [data-gid="A02"]').click();
  await page.locator('#chain-search').fill('Internal network');
  await page.getByText('Internal network: service map', { exact: true }).click();
  await expect(page.getByRole('heading', { name: /Confirm the authorized-lab scope and rules/ })).toBeVisible();
});

test('DevSecOps tools expose Kubernetes security additions through search and categories', async ({ page }) => {
  await page.goto('/app/#/tools');
  await expect(page.locator('#tools-track-chips [data-track="devsecops"]')).toContainText('(79)');
  const tracks = (await page.locator('#tools-track-chips [data-track]:not([data-track="*"])').allTextContents())
    .map(text => text.replace(/ \(\d+\)$/, ''));
  expect(tracks).toEqual([...tracks].sort((a, b) => a.localeCompare(b, 'en', { sensitivity: 'base' })));
  await page.locator('#tools-track-chips [data-track="devsecops"]').click();
  await expect(page.locator('#tools-track-chips [data-track="devsecops"]')).toHaveClass(/active/);
  await expect(page.locator('.tools-group[data-track="devsecops"] .tools-group-head')).toHaveCount(0);
  await expect(page.locator('.tools-group[data-track="devsecops"] .tools-cat-results')).toHaveCount(0);
  await page.reload();
  await expect(page.locator('#tools-track-chips [data-track="devsecops"].active')).toHaveCount(1);
  for (const category of ['kubernetes', 'network', 'observability']) {
    await expect(page.locator(`.tools-group[data-track="devsecops"] .tools-cat[data-cat="${category}"]`)).toHaveCount(1);
  }
  const categories = await page.locator('.tools-group[data-track="devsecops"] .tools-cat-title').allTextContents();
  expect(categories).toEqual([...categories].sort((a, b) => a.localeCompare(b, 'en', { sensitivity: 'base' })));
  await page.locator('.tools-group[data-track="devsecops"] .tools-cat[data-cat="cicd"] .tools-cat-head').click();
  const cicdNames = await page.locator('.tools-group[data-track="devsecops"] .tools-cat[data-cat="cicd"] .tool-name').allTextContents();
  expect(cicdNames).toEqual([...cicdNames].sort((a, b) => a.localeCompare(b, 'en', { sensitivity: 'base' })));

  for (const query of ['RBAC', 'Velero', 'NetworkPolicy', 'cert-manager', 'Stern', 'Jaeger']) {
    await page.locator('#tools-q').fill(query);
    await expect(page.locator('.tool-card').first()).toBeVisible();
  }

  await page.goto('/app/#/tool/attacksurfacemapper');
  await expect(page.locator('.tool-detail-section')).toHaveCount(4);
  await page.reload();
  await expect(page.locator('.tool-detail-section')).toHaveCount(4);
  await page.locator('#lang-ru').click();
  await expect(page.getByText('Он экономит время, но наследует ошибки', { exact: false })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await page.setViewportSize({ width: 390, height: 844 });
  const mobileOverflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  expect(mobileOverflow).toBeLessThanOrEqual(1);
});

test('AppSec DAST groups scanners without proxy-only tools', async ({ page }) => {
  await page.goto('/app/#/tools');
  await page.locator('#tools-track-chips [data-track="appsec"]').click();
  const dast = page.locator('.tools-group[data-track="appsec"] .tools-cat[data-cat="dast"]');
  await dast.locator('.tools-cat-head').click();
  const apiHeight = await page.locator('.tools-group[data-track="appsec"] .tools-cat[data-cat="api"]').evaluate(el => el.getBoundingClientRect().height);
  expect(apiHeight).toBeLessThan(100);
  const results = page.locator('.tools-group[data-track="appsec"] .tools-cat-results');
  for (const name of ['Burp Suite', 'OWASP ZAP', 'Nuclei']) {
    await expect(results.getByText(name, { exact: true })).toBeVisible();
  }
  await expect(results.getByText('Caido', { exact: true })).toHaveCount(0);
});

test('Offensive Security groups research and adversary tools by workflow phase', async ({ page }) => {
  await page.goto('/app/#/tools');
  await expect(page.locator('#tools-track-chips [data-track="bugbounty"], #tools-track-chips [data-track="redteam"]')).toHaveCount(0);
  await expect(page.locator('#tools-track-chips [data-track="offensive"]')).toContainText('(163)');
  await page.locator('#tools-track-chips [data-track="offensive"]').click();
  const phases = await page.locator('.tools-group[data-track="offensive"] .tools-cat').evaluateAll(items => items.map(item => item.dataset.cat));
  expect(phases).toEqual([
    'passive-osint', 'domain-discovery', 'cloud-identity-recon', 'network-discovery', 'fingerprinting', 'internal-recon', 'traffic-analysis', 'credential-utilities',
    'http-probing', 'screenshots', 'web-crawling', 'url-collection', 'content-discovery', 'parameter-discovery', 'api-discovery', 'attack-surface',
    'vulnerability-discovery', 'exploitation-validation', 'post-exploitation',
  ]);
  for (const category of ['passive-osint', 'domain-discovery', 'network-discovery', 'http-probing', 'api-discovery', 'vulnerability-discovery', 'post-exploitation']) {
    await expect(page.locator(`.tools-group[data-track="offensive"] .tools-cat[data-cat="${category}"]`)).toHaveCount(1);
  }
  await page.locator('.tools-group[data-track="offensive"] .tools-cat[data-cat="domain-discovery"] .tools-cat-head').click();
  await expect(page.locator('.tools-group[data-track="offensive"] .tools-cat-results').getByText('Amass', { exact: true })).toBeVisible();
  await page.locator('.tools-group[data-track="offensive"] .tools-cat[data-cat="passive-osint"] .tools-cat-head').click();
  const passiveResults = page.locator('.tools-group[data-track="offensive"] .tools-cat-results');
  await expect(passiveResults.getByText('Shodan', { exact: true })).toBeVisible();
  await expect(passiveResults.getByText('gau (GetAllURLs)', { exact: true })).toBeVisible();
});

test('mobile navigation fits the viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/app/#/lab/A01');
  await expect(page.locator('.lab-card')).toBeVisible();
  await page.locator('#menu-toggle').click();
  await expect(page.locator('#sidebar')).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});
