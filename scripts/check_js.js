const { readdirSync } = require('node:fs');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');

for (const name of readdirSync('js').filter(name => name.endsWith('.js'))) {
  const result = spawnSync(process.execPath, ['--check', join('js', name)], {
    stdio: 'inherit',
  });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
