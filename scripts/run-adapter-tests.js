import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);
const files = readdirSync(new URL('../test/', import.meta.url)).filter(file => /^(?:intake-(?:site-)?adapter.*|canary-promotion-guard)\.test\.js$/.test(file)).sort().map(file => fileURLToPath(new URL(`../test/${file}`, import.meta.url)));
if (!files.length) throw Error('No adapter tests discovered');
const env = {};
for (const key of ['PATH', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL']) if (process.env[key]) env[key] = process.env[key];
const result = spawnSync(process.execPath, ['--test', '--test-reporter', new URL('./adapter-test-reporter.js', import.meta.url).href, '--', ...files], { cwd: root, env, timeout: 120000, stdio: 'inherit' });
process.exitCode = result.status === 0 ? 0 : 1;
