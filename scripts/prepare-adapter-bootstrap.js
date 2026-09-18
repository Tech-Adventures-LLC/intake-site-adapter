import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { deepStrictEqual } from 'node:assert/strict';
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { auditPublicBytes } from './prepare-adapter-package.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const NAME = '@tech-adventures-llc/intake-site-adapter';
const VERSION = '0.0.0-bootstrap.0';
const TARBALL = 'tech-adventures-llc-intake-site-adapter-0.0.0-bootstrap.0.tgz';
const EXPIRY = '2026-09-25T23:59:59Z';
const FILES = Object.freeze(['LICENSE', 'README.md', 'package.json']);
const METADATA = Object.freeze({
  name: NAME,
  version: VERSION,
  description: 'Unusable registry setup prerelease; no adapter API',
  license: 'Apache-2.0',
  type: 'module',
  exports: {},
  files: ['README.md', 'LICENSE'],
  publishConfig: { access: 'public', registry: 'https://registry.npmjs.org', tag: 'bootstrap' },
});

function requireCondition(ok, category) { if (!ok) throw Error(category); }
function digest(bytes, algorithm = 'sha256', encoding = 'hex') { return createHash(algorithm).update(bytes).digest(encoding); }
function command(executable, args, cwd, env, category) {
  try { return execFileSync(executable, args, { cwd, env, encoding: 'utf8', timeout: 60000, maxBuffer: 4 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }); }
  catch { throw Error(category); }
}
function npmPath() {
  const path = resolve(dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js');
  requireCondition(existsSync(path), 'npm_cli_missing');
  return path;
}
function isolatedEnvironment(temporary) {
  const home = join(temporary, 'home'), cache = join(temporary, 'cache');
  mkdirSync(home); mkdirSync(cache);
  const user = join(home, 'user.npmrc'), global = join(home, 'global.npmrc');
  writeFileSync(user, ''); writeFileSync(global, '');
  return {
    PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, HOME: home, TMPDIR: tmpdir(),
    NPM_CONFIG_USERCONFIG: user, NPM_CONFIG_GLOBALCONFIG: global, NPM_CONFIG_CACHE: cache,
    NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org', NPM_CONFIG_UPDATE_NOTIFIER: 'false',
    NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_FUND: 'false', NPM_CONFIG_IGNORE_SCRIPTS: 'true',
  };
}
function regular(path, category) {
  const stat = lstatSync(path);
  requireCondition(stat.isFile() && !stat.isSymbolicLink(), category);
}
function outputDirectory(path) {
  if (existsSync(path)) {
    const stat = lstatSync(path);
    requireCondition(stat.isDirectory() && !stat.isSymbolicLink(), 'output_must_be_directory');
    requireCondition(readdirSync(path).length === 0, 'output_directory_must_be_empty');
  } else mkdirSync(path, { recursive: true });
}

export function prepareAdapterBootstrap({ root = ROOT, output, now = () => new Date() } = {}) {
  root = resolve(root);
  output = output ? resolve(output) : mkdtempSync(join(tmpdir(), 'intake-bootstrap-proof-'));
  outputDirectory(output);
  const current = now();
  requireCondition(current instanceof Date && Number.isFinite(current.getTime()), 'clock_invalid');
  requireCondition(current.getTime() < Date.parse(EXPIRY), 'bootstrap_exception_expired');
  const source = join(root, 'release/bootstrap');
  requireCondition(lstatSync(source).isDirectory() && !lstatSync(source).isSymbolicLink(), 'bootstrap_source_invalid');
  requireCondition(JSON.stringify(readdirSync(source).sort()) === JSON.stringify(FILES), 'bootstrap_source_allowlist_invalid');
  const manifest = FILES.map(path => {
    const absolute = join(source, path);
    regular(absolute, 'bootstrap_source_not_regular');
    const bytes = readFileSync(absolute);
    requireCondition(auditPublicBytes(bytes).length === 0, 'bootstrap_source_content_invalid');
    return { path, bytes: bytes.length, sha256: digest(bytes) };
  });
  try { deepStrictEqual(JSON.parse(readFileSync(join(source, 'package.json'), 'utf8')), METADATA); }
  catch { throw Error('bootstrap_metadata_drift'); }
  const temporary = mkdtempSync(join(tmpdir(), 'intake-bootstrap-build-'));
  try {
    const env = isolatedEnvironment(temporary);
    const staged = join(temporary, 'source'); mkdirSync(staged);
    for (const path of FILES) copyFileSync(join(source, path), join(staged, path));
    const npm = (args, cwd, category) => command(process.execPath, [npmPath(), ...args], cwd, env, category);
    const packed = [];
    for (const name of ['first', 'second']) {
      const destination = join(temporary, name); mkdirSync(destination);
      const result = JSON.parse(npm(['pack', '--ignore-scripts', '--offline', '--json', '--pack-destination', destination], staged, 'bootstrap_pack_failed'));
      requireCondition(result.length === 1 && result[0].filename === TARBALL && result[0].name === NAME && result[0].version === VERSION, 'bootstrap_pack_result_invalid');
      const tarball = join(destination, result[0].filename);
      regular(tarball, 'bootstrap_tarball_invalid');
      packed.push({ bytes: readFileSync(tarball), path: tarball, metadata: result[0] });
    }
    requireCondition(packed[0].bytes.equals(packed[1].bytes), 'bootstrap_pack_not_reproducible');
    const expectedPaths = FILES.map(path => `package/${path}`);
    const actualPaths = command('/usr/bin/tar', ['-tzf', packed[0].path], temporary, env, 'bootstrap_tar_list_failed').trim().split('\n').sort();
    requireCondition(JSON.stringify(actualPaths) === JSON.stringify(expectedPaths), 'bootstrap_tar_allowlist_invalid');
    requireCondition(JSON.stringify(packed[0].metadata.files.map(file => file.path).sort()) === JSON.stringify(FILES), 'bootstrap_pack_allowlist_invalid');
    const extracted = join(temporary, 'extracted'); mkdirSync(extracted);
    command('/usr/bin/tar', ['-xzf', packed[0].path, '-C', extracted], temporary, env, 'bootstrap_tar_extract_failed');
    for (const { path } of manifest) {
      const unpacked = join(extracted, 'package', path);
      regular(unpacked, 'bootstrap_packed_file_not_regular');
      requireCondition(readFileSync(unpacked).equals(readFileSync(join(source, path))), 'bootstrap_packed_source_mismatch');
    }
    const consumer = join(temporary, 'consumer'); mkdirSync(consumer);
    copyFileSync(packed[0].path, join(consumer, 'bootstrap.tgz'));
    writeFileSync(join(consumer, 'package.json'), `${JSON.stringify({ private: true, type: 'module', dependencies: { [NAME]: 'file:./bootstrap.tgz' } })}\n`);
    npm(['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund'], consumer, 'bootstrap_offline_install_failed');
    command(process.execPath, ['--input-type=module', '-e', `try { await import('${NAME}'); process.exitCode = 1; } catch (error) { if (error.code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED') process.exitCode = 1; }`], consumer, env, 'bootstrap_module_entry_present');
    const bytes = packed[0].bytes;
    const report = {
      status: 'local-preparation-only', package: NAME, version: VERSION, intended_dist_tag: 'bootstrap',
      exception_expires_at: EXPIRY, tarball: packed[0].metadata.filename, bytes: bytes.length,
      sha256: digest(bytes), integrity: `sha512-${digest(bytes, 'sha512', 'base64')}`,
      files: manifest, reproducible_pack: true, every_packed_byte_matches_source: true,
      offline_install_and_unusable_module_verified: true, publication_ready: false,
    };
    copyFileSync(packed[0].path, join(output, report.tarball));
    writeFileSync(join(output, 'preparation.json'), `${JSON.stringify(report, null, 2)}\n`);
    return { output, ...report };
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    requireCondition(args.length === 0 || (args.length === 2 && args[0] === '--output'), 'invalid_arguments');
    console.log(JSON.stringify(prepareAdapterBootstrap({ output: args[1] })));
  } catch (error) {
    console.error(JSON.stringify({ ok: false, error: /^[a-z_]+$/.test(error.message) ? error.message : 'bootstrap_preparation_failed' }));
    process.exitCode = 1;
  }
}
