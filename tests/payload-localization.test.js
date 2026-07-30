const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

let language = 'en';
const storage = {
  getItem: () => null,
  setItem: () => {},
};
const context = {
  console,
  sessionStorage: storage,
  localStorage: storage,
  I18n: {
    lang: () => language,
    t: key => key,
    pick: value => typeof value === 'string' ? value : value?.[language] || value?.en || value?.ru || '',
  },
};
context.globalThis = context;
context.window = context;
vm.createContext(context);
vm.runInContext('const DATA = {}; this.DATA = DATA;', context);
vm.runInContext(fs.readFileSync('js/data/payloads.js', 'utf8'), context);
const localizationConflicts = [];
for (const file of [
  'js/data/payload-i18n-ru-core.js',
  'js/data/payload-i18n-ru-mid.js',
  'js/data/payload-i18n-ru-tail.js',
]) {
  const linesBefore = { ...context.DATA.PAYLOAD_LINES_RU };
  const titlesBefore = Object.fromEntries(
    Object.entries(context.DATA.PAYLOAD_TITLES_RU).map(([category, titles]) => [
      category,
      { ...titles },
    ]),
  );
  vm.runInContext(fs.readFileSync(file, 'utf8'), context);
  for (const [source, translation] of Object.entries(context.DATA.PAYLOAD_LINES_RU)) {
    if (linesBefore[source] !== undefined && linesBefore[source] !== translation) {
      localizationConflicts.push(`${file}: line "${source}"`);
    }
  }
  for (const [category, titles] of Object.entries(context.DATA.PAYLOAD_TITLES_RU)) {
    for (const [source, translation] of Object.entries(titles)) {
      const previous = titlesBefore[category]?.[source];
      if (previous !== undefined && previous !== translation) {
        localizationConflicts.push(`${file}: title "${category}/${source}"`);
      }
    }
  }
}
vm.runInContext(`${fs.readFileSync('js/tools/ui.js', 'utf8')}; this.ToolsApi = Tools;`, context);

const categories = Object.keys(context.DATA.PAYLOADS);

test('localization shards do not override each other with conflicting translations', () => {
  assert.deepEqual(localizationConflicts, []);
});

test('Russian payload localization covers all categories and block titles', () => {
  assert.deepEqual(
    Object.keys(context.DATA.PAYLOAD_CATEGORIES_RU).sort(),
    [...categories].sort(),
  );

  for (const category of categories) {
    const translated = context.DATA.PAYLOAD_TITLES_RU[category];
    assert.ok(translated, `${category}: missing Russian title map`);
    assert.deepEqual(
      [...Object.keys(translated)].sort(),
      [...new Set(Array.from(context.DATA.PAYLOADS[category], item => item.t))].sort(),
      `${category}: Russian title coverage must match payload blocks`,
    );
  }
});

test('localization changes only mapped human lines and preserves executable payload text', () => {
  for (const category of categories) {
    for (const item of context.DATA.PAYLOADS[category]) {
      const original = item.p;

      language = 'en';
      assert.equal(context.ToolsApi.payloadItemTitle(category, item), item.t);
      assert.equal(context.ToolsApi.payloadItemText(item), original);

      language = 'ru';
      assert.equal(
        context.ToolsApi.payloadItemTitle(category, item),
        context.DATA.PAYLOAD_TITLES_RU[category][item.t],
      );
      const localized = context.ToolsApi.payloadItemText(item);
      const sourceLines = original.split('\n');
      const localizedLines = localized.split('\n');
      assert.equal(localizedLines.length, sourceLines.length, `${category}/${item.t}: line count changed`);
      sourceLines.forEach((line, index) => {
        assert.equal(
          localizedLines[index],
          context.DATA.PAYLOAD_LINES_RU[line] ?? line,
          `${category}/${item.t}: unmapped command or payload line changed`,
        );
      });
      assert.equal(item.p, original, `${category}/${item.t}: canonical payload was mutated`);
    }
  }
});

test('every Russian line translation is used by the payload catalog', () => {
  const sourceLines = new Set(
    categories.flatMap(category =>
      context.DATA.PAYLOADS[category].flatMap(item => item.p.split('\n'))
    ),
  );
  for (const line of Object.keys(context.DATA.PAYLOAD_LINES_RU)) {
    assert.ok(sourceLines.has(line), `unused Russian line translation: ${line}`);
  }
});
