import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const reporter = new URL('../scripts/adapter-test-reporter.js', import.meta.url).href;

test('adapter compatibility reporter rejects missing, empty, skipped, TODO, cancelled and failed files beside a real pass', () => {
  const directory = mkdtempSync(join(tmpdir(), 'adapter-reporter-'));
  const valid = join(directory, 'valid.mjs'); writeFileSync(valid, "import test from 'node:test'; test('real',()=>{});\n");
  const run = files => execFileSync(process.execPath, ['--test', '--test-reporter', reporter, '--', ...files], { env: {}, encoding: 'utf8', timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    assert.match(run([valid]), /# pass 1/);
    for (const code of ['', "import {describe} from 'node:test';describe('empty',()=>{});", "import test from 'node:test';test.skip('skip',()=>{});", "import test from 'node:test';test.todo('todo');", "import test from 'node:test';test('cancel',()=>new Promise(()=>{}));", "import test from 'node:test';test('fail',()=>{throw Error('fixture');});", 'process.exit(2);']) {
      const invalid = join(directory, 'invalid.mjs'); writeFileSync(invalid, code);
      assert.throws(() => run([valid, invalid]), error => error.status !== 0);
    }
    assert.throws(() => run([valid, join(directory, 'missing.mjs')]), error => error.status !== 0);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
