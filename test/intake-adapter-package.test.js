import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { auditPublicBytes, prepareAdapterPackage } from '../scripts/prepare-adapter-package.js';
import { assertProtectedEnvironment, assertReviewedArtifact, checkReleasePreparation } from '../scripts/check-adapter-release.js';

test('real package is reproducible, byte-audited, integrity-installed and consumed through runtime, CLI and declarations', () => {
  const root = mkdtempSync(join(tmpdir(), 'adapter-artifact-test-'));
  try {
    const result = prepareAdapterPackage({ output: join(root, 'output') });
    assert.equal(result.reproducible_pack, true); assert.equal(result.runtime_cli_types, true); assert.equal(result.packed_files, 12); assert.equal(result.publication_ready, false);
    const manifest = JSON.parse(readFileSync(join(result.output, 'packed-files.json')));
    assert.equal(manifest.length, 12); assert.ok(manifest.every(file => /^[a-f0-9]{64}$/.test(file.sha256)));
    const sbom = JSON.parse(readFileSync(join(result.output, 'sbom.cdx.json'))); assert.equal(sbom.bomFormat, 'CycloneDX'); assert.equal(sbom.metadata.component.version, '1.1.0');
    assert.ok(result.source_export.files > result.packed_files);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('packed byte scanner detects credential, internal-origin, local-path and binary contamination', () => {
  const samples = ['-----BEGIN ' + 'PRIVATE KEY-----', 'npm_' + 'a'.repeat(40), 'https://' + '127.0.0.1/internal', '/' + 'Users/synthetic/private/', 'abc\0def'];
  for (const sample of samples) assert.ok(auditPublicBytes(Buffer.from(sample)).length > 0);
  assert.deepEqual(auditPublicBytes(Buffer.from('https://intake.fltechadventures.com')), []);
});

test('publication preparation rejects artifact drift and absent real protection; local flags cannot authorize npm publication', async () => {
  const bytes = Buffer.from('synthetic'), expectedDigest = createHash('sha256').update(bytes).digest('hex'), sourceSha = 'a'.repeat(40);
  assert.throws(() => assertReviewedArtifact({ bytes, expectedDigest, sourceSha, reviewedSourceSha: 'b'.repeat(40) }), /release_source_mismatch/);
  assert.throws(() => assertReviewedArtifact({ bytes, expectedDigest: 'b'.repeat(64), sourceSha, reviewedSourceSha: sourceSha }), /release_artifact_mismatch/);
  for (const environment of [{}, { protection_rules: [] }, { protection_rules: [{ type: 'required_reviewers', prevent_self_review: true, reviewers: [] }] }]) assert.throws(() => assertProtectedEnvironment(environment), /release_environment_unprotected/);
  const base = { bytes, expectedDigest, sourceSha, reviewedSourceSha: sourceSha, metadata: {}, authority: {}, fetchImpl: async () => assert.fail('must fail before any network') };
  await assert.rejects(() => checkReleasePreparation(base), /public_source_identity_missing/);
  const protectedEnvironment = { name: 'npm-release', protection_rules: [{ type: 'required_reviewers', prevent_self_review: true, reviewers: [{ type: 'User', reviewer: { id: 1 } }] }], deployment_branch_policy: { protected_branches: true, custom_branch_policies: false } };
  const configured = { ...base, repository: 'synthetic/adapter', githubToken: 'synthetic', metadata: { repository: { url: 'git+https://github.com/synthetic/adapter.git' } }, authority: { setupStatus: 'owner-reviewed', publicRepository: 'synthetic/adapter', environment: 'npm-release' } };
  await assert.rejects(() => checkReleasePreparation({ ...configured, fetchImpl: async url => Response.json(url.endsWith('npm-release') ? {} : { private: false, full_name: 'synthetic/adapter' }) }), /release_environment_unprotected/);
  await assert.rejects(() => checkReleasePreparation({ ...configured, fetchImpl: async url => Response.json(url.endsWith('npm-release') ? protectedEnvironment : { private: false, full_name: 'synthetic/adapter' }) }), /npm_owner_setup_verification_required/);
});


test('actual preparation rejects contaminated source bytes and expanded file allowlists', () => {
  const directory = mkdtempSync(join(tmpdir(), 'adapter-poisoned-pack-'));
  try {
    const packageRoot = join(directory, 'packages/intake-site-adapter'); mkdirSync(join(directory, 'packages'), { recursive: true });
    cpSync(new URL('../packages/intake-site-adapter/', import.meta.url), packageRoot, { recursive: true });
    const readme = join(packageRoot, 'README.md'); const original = readFileSync(readme);
    writeFileSync(readme, Buffer.concat([original, Buffer.from('npm_' + 'a'.repeat(40))]));
    assert.throws(() => prepareAdapterPackage({ root: directory, output: join(directory, 'poison'), exportPublicSource: false }), /package_content_audit_failed/);
    writeFileSync(readme, original);
    const metadataPath = join(packageRoot, 'package.json'), metadata = JSON.parse(readFileSync(metadataPath)); metadata.files.push('unexpected.txt'); writeFileSync(metadataPath, JSON.stringify(metadata));
    assert.throws(() => prepareAdapterPackage({ root: directory, output: join(directory, 'expanded'), exportPublicSource: false }), /package_allowlist_invalid/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
