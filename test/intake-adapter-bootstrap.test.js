import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { prepareAdapterBootstrap } from '../scripts/prepare-adapter-bootstrap.js';

const BEFORE_EXPIRY = () => new Date('2026-09-18T12:00:00Z');
function fixture(run) {
  const root = mkdtempSync(join(tmpdir(), 'bootstrap-fixture-'));
  cpSync(new URL('../release/bootstrap/', import.meta.url), join(root, 'release/bootstrap'), { recursive: true });
  try { return run(root); } finally { rmSync(root, { recursive: true, force: true }); }
}

test('real bootstrap packs reproducibly with exactly three audited source files and no usable module entry', () => fixture(root => {
  const first = prepareAdapterBootstrap({ root, output: join(root, 'first'), now: BEFORE_EXPIRY });
  const second = prepareAdapterBootstrap({ root, output: join(root, 'second'), now: BEFORE_EXPIRY });
  assert.equal(first.sha256, second.sha256);
  assert.equal(first.integrity, second.integrity);
  assert.equal(first.publication_ready, false);
  assert.equal(first.offline_install_and_unusable_module_verified, true);
  assert.equal(first.intended_dist_tag, 'bootstrap');
  assert.deepEqual(first.files.map(file => file.path), ['LICENSE', 'README.md', 'package.json']);
  const packedMetadata = JSON.parse(execFileSync('/usr/bin/tar', ['-xOzf', join(first.output, first.tarball), 'package/package.json'], { encoding: 'utf8' }));
  assert.equal(packedMetadata.publishConfig.tag, 'bootstrap');
  const expectedReport = { ...first }; delete expectedReport.output;
  assert.deepEqual(JSON.parse(readFileSync(join(first.output, 'preparation.json'))), expectedReport);
  const tarPaths = execFileSync('/usr/bin/tar', ['-tzf', join(first.output, first.tarball)], { encoding: 'utf8' }).trim().split('\n').sort();
  assert.deepEqual(tarPaths, ['package/LICENSE', 'package/README.md', 'package/package.json']);
}));

test('bootstrap preparation rejects metadata drift, extra files, symlinks and secret contamination', () => fixture(root => {
  const source = join(root, 'release/bootstrap');
  const metadata = join(source, 'package.json');
  const original = readFileSync(metadata);
  const changed = JSON.parse(original); changed.version = '0.0.0-bootstrap.1';
  writeFileSync(metadata, JSON.stringify(changed));
  assert.throws(() => prepareAdapterBootstrap({ root, output: join(root, 'drift'), now: BEFORE_EXPIRY }), /bootstrap_metadata_drift/);
  changed.version = '0.0.0-bootstrap.0'; changed.scripts = { prepack: 'node hidden.js' };
  writeFileSync(metadata, JSON.stringify(changed));
  assert.throws(() => prepareAdapterBootstrap({ root, output: join(root, 'script'), now: BEFORE_EXPIRY }), /bootstrap_metadata_drift/);
  delete changed.scripts; changed.exports = { '.': './index.js' };
  writeFileSync(metadata, JSON.stringify(changed));
  assert.throws(() => prepareAdapterBootstrap({ root, output: join(root, 'module'), now: BEFORE_EXPIRY }), /bootstrap_metadata_drift/);
  changed.exports = {}; changed.publishConfig.tag = 'latest';
  writeFileSync(metadata, JSON.stringify(changed));
  assert.throws(() => prepareAdapterBootstrap({ root, output: join(root, 'tag'), now: BEFORE_EXPIRY }), /bootstrap_metadata_drift/);
  delete changed.publishConfig.tag;
  writeFileSync(metadata, JSON.stringify(changed));
  assert.throws(() => prepareAdapterBootstrap({ root, output: join(root, 'missing-tag'), now: BEFORE_EXPIRY }), /bootstrap_metadata_drift/);
  writeFileSync(metadata, original);
  writeFileSync(join(source, 'extra.txt'), 'extra');
  assert.throws(() => prepareAdapterBootstrap({ root, output: join(root, 'extra'), now: BEFORE_EXPIRY }), /bootstrap_source_allowlist_invalid/);
  rmSync(join(source, 'extra.txt'));
  rmSync(join(source, 'LICENSE'));
  symlinkSync(join(source, 'README.md'), join(source, 'LICENSE'));
  assert.throws(() => prepareAdapterBootstrap({ root, output: join(root, 'link'), now: BEFORE_EXPIRY }), /bootstrap_source_not_regular/);
  rmSync(join(source, 'LICENSE'));
  cpSync(new URL('../release/bootstrap/LICENSE', import.meta.url), join(source, 'LICENSE'));
  writeFileSync(join(source, 'README.md'), `ghp_${'a'.repeat(36)}`);
  assert.throws(() => prepareAdapterBootstrap({ root, output: join(root, 'secret'), now: BEFORE_EXPIRY }), /bootstrap_source_content_invalid/);
}));

test('bootstrap expiry and output immutability fail closed', () => fixture(root => {
  assert.throws(() => prepareAdapterBootstrap({ root, output: join(root, 'expired'), now: () => new Date('2026-09-25T23:59:59Z') }), /bootstrap_exception_expired/);
  assert.throws(() => prepareAdapterBootstrap({ root, output: join(root, 'invalid-clock'), now: () => new Date('invalid') }), /clock_invalid/);
  const output = join(root, 'occupied');
  writeFileSync(output, 'existing');
  assert.throws(() => prepareAdapterBootstrap({ root, output, now: BEFORE_EXPIRY }), /output_must_be_directory/);
  const directory = join(root, 'occupied-directory');
  cpSync(new URL('../release/bootstrap/', import.meta.url), directory, { recursive: true });
  assert.throws(() => prepareAdapterBootstrap({ root, output: directory, now: BEFORE_EXPIRY }), /output_directory_must_be_empty/);
}));
