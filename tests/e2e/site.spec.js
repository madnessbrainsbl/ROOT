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
});

test('CVE rows open without a redundant View button', async ({ page }) => {
  await page.goto('/app/#/cves');
  const row = page.locator('#cve9-tbody .cve9-row').first();
  await expect(row).toBeVisible();
  await expect(page.getByRole('button', { name: 'View' })).toHaveCount(0);
  await row.click();
  await expect(page).toHaveURL(/#\/cve\/CVE-/);
});

test('mobile navigation fits the viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/app/#/lab/A01');
  await page.locator('#menu-toggle').click();
  await expect(page.locator('#sidebar')).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});
