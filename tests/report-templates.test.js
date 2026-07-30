const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('js/data/workflows.js', 'utf8');
const context = { DATA: {} };
vm.createContext(context);
vm.runInContext(source, context, { filename: 'js/data/workflows.js' });

const templates = context.DATA.REPORT_TEMPLATES;
const report = templates.Pentest;

assert.ok(report, 'generic penetration-test report template must exist');
assert.equal(Object.keys(templates).filter(key => /^A\d\d$/.test(key)).length, 10, 'A01-A10 templates must remain');
assert.equal(report.title.en, 'Penetration Test Report');
assert.equal(report.title.ru, 'Отчёт по тестированию на проникновение');

for (const [locale, headings] of Object.entries({
  en: ['Executive Summary', 'Objectives, Scope, and Exclusions', 'Rules of Engagement', 'Methodology, Coverage, and Limitations', 'Attack Narrative / Validation Scenario', 'Technical Findings', 'Cleanup and Retest', 'Appendices'],
  ru: ['Исполнительное резюме', 'Цели, область и исключения', 'Правила взаимодействия', 'Методология, покрытие и ограничения', 'Ход атаки / проверочный сценарий', 'Технические находки', 'Очистка и повторная проверка', 'Приложения'],
})) {
  const body = report.body[locale];
  headings.forEach(heading => assert.match(body, new RegExp(heading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), `${locale} report must cover ${heading}`));
  assert.match(body, /without exploitation|без эксплуатации/, `${locale} report must retain serious unexploited findings`);
}
