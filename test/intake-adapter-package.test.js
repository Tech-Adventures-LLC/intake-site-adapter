import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditPublicBytes, prepareAdapterPackage } from '../scripts/prepare-adapter-package.js';
import { assertProtectedEnvironment, assertReviewedArtifact, checkReleasePreparation } from '../scripts/check-adapter-release.js';

function copyPreparationSource(destination) {
  for (const path of ['packages', 'test', 'qa', 'contracts', 'scripts', 'release', 'package-lock.json']) {
    cpSync(new URL(`../${path}`, import.meta.url), join(destination, path), { recursive: true });
  }
  symlinkSync(new URL('../node_modules/', import.meta.url), join(destination, 'node_modules'), 'dir');
}

function copyPackageOnlySource(destination) {
  mkdirSync(join(destination, 'packages'), { recursive: true });
  cpSync(new URL('../packages/intake-site-adapter/', import.meta.url), join(destination, 'packages/intake-site-adapter'), { recursive: true });
  symlinkSync(new URL('../node_modules/', import.meta.url), join(destination, 'node_modules'), 'dir');
}

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

test('generated public export records a matching configured source identity without treating it as live ownership proof', () => {
  const root = mkdtempSync(join(tmpdir(), 'adapter-configured-export-'));
  try {
    copyPreparationSource(root);
    const result = prepareAdapterPackage({ root, output: join(root, 'output') });
    const readme = readFileSync(join(result.output, 'public-source', 'README.md'), 'utf8');
    const report = JSON.parse(readFileSync(join(result.output, 'preparation.json')));
    assert.match(readme, /Configured public source identity: Tech-Adventures-LLC\/intake-site-adapter\./);
    assert.match(readme, /configuration only; live repository ownership is not verified/i);
    assert.deepEqual(report.source_identity, { status: 'configured-not-live-verified', repository: 'Tech-Adventures-LLC/intake-site-adapter' });
    assert.ok(!report.publication_blockers.includes('approved_public_source_identity_missing'));
    assert.ok(report.publication_blockers.includes('public_source_ownership_not_live_verified'));
    assert.equal(report.publication_ready, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('generated public export retains the missing identity blocker for unconfigured or mismatched metadata', () => {
  for (const mutate of [
    metadata => { delete metadata.repository; },
    metadata => { metadata.repository.url = 'git+https://github.com/synthetic/adapter.git'; },
  ]) {
    const root = mkdtempSync(join(tmpdir(), 'adapter-missing-export-'));
    try {
      copyPreparationSource(root);
      const metadataPath = join(root, 'packages/intake-site-adapter/package.json');
      const metadata = JSON.parse(readFileSync(metadataPath)); mutate(metadata); writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));
      const result = prepareAdapterPackage({ root, output: join(root, 'output') });
      const readme = readFileSync(join(result.output, 'public-source', 'README.md'), 'utf8');
      const report = JSON.parse(readFileSync(join(result.output, 'preparation.json')));
      assert.match(readme, /Public source identity is missing or mismatched\./);
      assert.equal(report.source_identity.status, 'missing-or-mismatched');
      assert.ok(report.publication_blockers.includes('approved_public_source_identity_missing'));
      assert.equal(report.publication_ready, false);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test('package-only root without release authority prepares with public export disabled and retains the missing identity blocker', () => {
  const root = mkdtempSync(join(tmpdir(), 'adapter-package-only-root-'));
  try {
    copyPackageOnlySource(root);
    const result = prepareAdapterPackage({ root, output: join(root, 'output'), exportPublicSource: false });
    const report = JSON.parse(readFileSync(join(result.output, 'preparation.json')));
    assert.equal(result.source_export, null);
    assert.equal(report.source_identity.status, 'missing-or-mismatched');
    assert.ok(report.publication_blockers.includes('approved_public_source_identity_missing'));
    assert.equal(report.publication_ready, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('package-only root rejects malformed present release authority even when public export is disabled', () => {
  const root = mkdtempSync(join(tmpdir(), 'adapter-malformed-authority-'));
  try {
    copyPackageOnlySource(root);
    mkdirSync(join(root, 'release')); writeFileSync(join(root, 'release/adapter-release-authority.json'), '{ malformed');
    assert.throws(() => prepareAdapterPackage({ root, output: join(root, 'output'), exportPublicSource: false }), /release_authority_invalid/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('packed byte scanner detects credential, internal-origin, local-path and binary contamination', () => {
  const samples = ['-----BEGIN ' + 'PRIVATE KEY-----', 'npm_' + 'a'.repeat(40), 'https://' + '127.0.0.1/internal', '/' + 'Users/synthetic/private/', 'abc\0def'];
  for (const sample of samples) assert.ok(auditPublicBytes(Buffer.from(sample)).length > 0);
  assert.deepEqual(auditPublicBytes(Buffer.from('https://intake.fltechadventures.com')), []);
});

const PUBLIC_REPOSITORY = 'Tech-Adventures-LLC/intake-site-adapter';
const OWNER = { type: 'User', reviewer: { id: 142938424, login: 'ii-am-modiify' } };
const SOURCE_SHA = 'a'.repeat(40);
const RELEASE_BYTES = Buffer.from('synthetic release artifact');
const RELEASE_ENVIRONMENT = {
  name: 'npm-release', can_admins_bypass: false,
  protection_rules: [{ type: 'required_reviewers', prevent_self_review: false, reviewers: [OWNER] }],
  deployment_branch_policy: { protected_branches: true, custom_branch_policies: false },
};
const RELEASE_REPOSITORY = { id: 1375264810, private: false, full_name: PUBLIC_REPOSITORY, default_branch: 'main' };
const RELEASE_RUN = {
  id: 12345, repository: { id: 1375264810, full_name: PUBLIC_REPOSITORY }, actor: { id: 142938424, login: 'ii-am-modiify' },
  triggering_actor: { id: 142938424, login: 'ii-am-modiify' },
  event: 'workflow_dispatch', head_branch: 'main', head_sha: SOURCE_SHA,
  path: `${PUBLIC_REPOSITORY}/.github/workflows/release-adapter.yml@main`,
};
const RELEASE_BRANCH = { name: 'main', protected: true, commit: { sha: SOURCE_SHA } };
function releaseInput(changes = {}) {
  return {
    bytes: RELEASE_BYTES, expectedDigest: createHash('sha256').update(RELEASE_BYTES).digest('hex'),
    sourceSha: SOURCE_SHA, reviewedSourceSha: SOURCE_SHA, repository: PUBLIC_REPOSITORY,
    githubToken: 'synthetic-token', ref: 'refs/heads/main', eventName: 'workflow_dispatch',
    actorId: '142938424', triggeringActor: 'ii-am-modiify', runId: '12345',
    metadata: { repository: { type: 'git', url: `git+https://github.com/${PUBLIC_REPOSITORY}.git`, directory: 'packages/intake-site-adapter' } },
    authority: JSON.parse(readFileSync(new URL('../release/adapter-release-authority.json', import.meta.url))),
    ...changes,
  };
}
function releaseFetch(overrides = {}) {
  const fixtures = { '': RELEASE_REPOSITORY, '/actions/runs/12345': RELEASE_RUN, '/branches/main': RELEASE_BRANCH, '/environments/npm-release': RELEASE_ENVIRONMENT, ...overrides };
  const calls = [];
  const fetchImpl = async (url, options) => {
    const path = url.slice(`https://api.github.com/repos/${PUBLIC_REPOSITORY}`.length);
    calls.push({ path, options });
    const item = fixtures[path];
    return item instanceof Response ? item : Response.json(item ?? {}, { status: 200 });
  };
  return { fetchImpl, calls };
}
async function expectReleaseError(input, category) {
  await assert.rejects(() => checkReleasePreparation(input), error => error.message === category);
}

test('release preparation binds reviewed bytes, source and local policy before network', async () => {
  const noNetwork = async () => assert.fail('network must not be reached');
  await expectReleaseError(releaseInput({ sourceSha: 'b'.repeat(40), fetchImpl: noNetwork }), 'release_source_mismatch');
  await expectReleaseError(releaseInput({ expectedDigest: 'b'.repeat(64), fetchImpl: noNetwork }), 'release_artifact_mismatch');
  await expectReleaseError(releaseInput({ repository: 'synthetic/adapter', fetchImpl: noNetwork }), 'public_source_identity_missing');
  await expectReleaseError(releaseInput({ metadata: {}, fetchImpl: noNetwork }), 'public_source_identity_missing');
  for (const edit of [
    authority => { authority.publicRepositoryId = 1; },
    authority => { authority.reviewPolicy.mode = 'multiple-reviewers'; },
    authority => { authority.reviewPolicy.requiredReviewer.id = 1; },
    authority => { authority.reviewPolicy.requiredReviewer.login = 'other'; },
    authority => { delete authority.reviewPolicy; },
  ]) {
    const authority = releaseInput().authority; edit(authority);
    await expectReleaseError(releaseInput({ authority, fetchImpl: noNetwork }), 'release_authority_mismatch');
  }
  for (const edit of [
    { ref: 'refs/heads/feature' }, { eventName: 'push' }, { actorId: '1' },
    { triggeringActor: 'other' }, { runId: '0' }, { runId: '9007199254740992' },
  ]) await expectReleaseError(releaseInput({ ...edit, fetchImpl: noNetwork }), 'release_workflow_context_invalid');
  await expectReleaseError(releaseInput({ githubToken: '', fetchImpl: noNetwork }), 'github_settings_access_missing');
});

test('exact sole-owner environment and protected main reach terminal npm setup gate', async () => {
  const { fetchImpl, calls } = releaseFetch();
  await expectReleaseError(releaseInput({ fetchImpl }), 'npm_owner_setup_verification_required');
  assert.deepEqual(calls.map(call => call.path), ['', '/actions/runs/12345', '/branches/main', '/environments/npm-release']);
  assert.ok(calls.every(call => call.options.redirect === 'error' && call.options.signal instanceof AbortSignal));
  assert.ok(calls.every(call => call.options.headers.authorization === 'Bearer synthetic-token'));
  assert.doesNotThrow(() => assertProtectedEnvironment(RELEASE_ENVIRONMENT));
});

test('environment rejects missing, altered or extra reviewers, bypass and branch-policy drift', async () => {
  const badReviews = [
    {}, { ...RELEASE_ENVIRONMENT, can_admins_bypass: true },
    { ...RELEASE_ENVIRONMENT, can_admins_bypass: undefined },
    { ...RELEASE_ENVIRONMENT, protection_rules: [] },
    { ...RELEASE_ENVIRONMENT, protection_rules: [{ type: 'required_reviewers', prevent_self_review: false, reviewers: [] }] },
    { ...RELEASE_ENVIRONMENT, protection_rules: [{ type: 'required_reviewers', prevent_self_review: true, reviewers: [OWNER] }] },
    { ...RELEASE_ENVIRONMENT, protection_rules: [{ type: 'required_reviewers', prevent_self_review: false, reviewers: [OWNER, OWNER] }] },
    { ...RELEASE_ENVIRONMENT, protection_rules: [{ type: 'required_reviewers', prevent_self_review: false, reviewers: [{ type: 'User', reviewer: { id: 1, login: 'ii-am-modiify' } }] }] },
    { ...RELEASE_ENVIRONMENT, protection_rules: [{ type: 'required_reviewers', prevent_self_review: false, reviewers: [{ type: 'User', reviewer: { id: 142938424, login: 'other' } }] }] },
    { ...RELEASE_ENVIRONMENT, protection_rules: [{ type: 'required_reviewers', prevent_self_review: false, reviewers: [{ type: 'Team', reviewer: { id: 142938424, login: 'ii-am-modiify' } }] }] },
    { ...RELEASE_ENVIRONMENT, protection_rules: [RELEASE_ENVIRONMENT.protection_rules[0], RELEASE_ENVIRONMENT.protection_rules[0]] },
  ];
  for (const environment of badReviews) {
    assert.throws(() => assertProtectedEnvironment(environment), error => error.message === 'release_environment_unprotected');
    await expectReleaseError(releaseInput({ fetchImpl: releaseFetch({ '/environments/npm-release': environment }).fetchImpl }), 'release_environment_unprotected');
  }
  for (const deployment_branch_policy of [{ protected_branches: false, custom_branch_policies: false }, { protected_branches: true, custom_branch_policies: true }, undefined]) {
    const environment = { ...RELEASE_ENVIRONMENT, deployment_branch_policy };
    await expectReleaseError(releaseInput({ fetchImpl: releaseFetch({ '/environments/npm-release': environment }).fetchImpl }), 'release_branch_policy_unverified');
  }
});

test('repository, run and branch settings must match exact reviewed main', async () => {
  for (const repository of [
    { ...RELEASE_REPOSITORY, id: 1 }, { ...RELEASE_REPOSITORY, private: true },
    { ...RELEASE_REPOSITORY, full_name: 'other/adapter' }, { ...RELEASE_REPOSITORY, default_branch: 'other' },
  ]) await expectReleaseError(releaseInput({ fetchImpl: releaseFetch({ '': repository }).fetchImpl }), 'public_source_not_verified');
  for (const run of [
    { ...RELEASE_RUN, id: 12346 },
    { ...RELEASE_RUN, repository: { id: 1375264810, full_name: 'other/adapter' } },
    { ...RELEASE_RUN, actor: { id: 1, login: 'ii-am-modiify' } },
    { ...RELEASE_RUN, triggering_actor: { id: 1, login: 'ii-am-modiify' } },
    { ...RELEASE_RUN, event: 'push' }, { ...RELEASE_RUN, head_branch: 'other' },
    { ...RELEASE_RUN, head_sha: 'b'.repeat(40) },
    { ...RELEASE_RUN, path: '.github/workflows/other.yml@main' },
  ]) await expectReleaseError(releaseInput({ fetchImpl: releaseFetch({ '/actions/runs/12345': run }).fetchImpl }), 'release_workflow_context_invalid');
  for (const branch of [{ ...RELEASE_BRANCH, name: 'other' }, { ...RELEASE_BRANCH, protected: false }, {}])
    await expectReleaseError(releaseInput({ fetchImpl: releaseFetch({ '/branches/main': branch }).fetchImpl }), 'release_main_unprotected');
  await expectReleaseError(releaseInput({ fetchImpl: releaseFetch({ '/branches/main': { ...RELEASE_BRANCH, commit: { sha: 'b'.repeat(40) } } }).fetchImpl }), 'release_branch_source_mismatch');
});

test('GitHub settings transport fails closed on non-200, malformed, oversized and thrown responses', async () => {
  for (const response of [
    new Response('unavailable', { status: 403 }), new Response('not json'),
    new Response('x'.repeat(65537)), new Response('null'),
  ]) await expectReleaseError(releaseInput({ fetchImpl: async () => response }), 'github_settings_unavailable');
  for (const path of ['', '/actions/runs/12345', '/branches/main', '/environments/npm-release'])
    await expectReleaseError(releaseInput({ fetchImpl: releaseFetch({ [path]: new Response('server detail', { status: 502 }) }).fetchImpl }), 'github_settings_unavailable');
  await expectReleaseError(releaseInput({ fetchImpl: async () => { throw Error('secret transport detail'); } }), 'github_settings_unavailable');
  await expectReleaseError(releaseInput({ fetchImpl: async () => { throw Object.assign(Error('secret timeout detail'), { name: 'AbortError' }); } }), 'github_settings_unavailable');
});

test('non-200 settings response aborts request and cancels a stalled body', async () => {
  let signal; let canceled = false;
  const response = new Response(new ReadableStream({
    start() {},
    cancel() { canceled = true; },
  }), { status: 502 });
  await expectReleaseError(releaseInput({ fetchImpl: async (_url, options) => { signal = options.signal; return response; } }), 'github_settings_unavailable');
  assert.equal(signal.aborted, true);
  assert.equal(canceled, true);
});

test('GitHub settings deadline ends a stalled fetch and stalled response body', { timeout: 8000 }, async () => {
  const stalledBody = new Response(new ReadableStream({ start() {} }));
  const started = Date.now();
  await Promise.all([
    expectReleaseError(releaseInput({ fetchImpl: async () => new Promise(() => {}) }), 'github_settings_unavailable'),
    expectReleaseError(releaseInput({ fetchImpl: async () => stalledBody }), 'github_settings_unavailable'),
  ]);
  assert.ok(Date.now() - started >= 4800);
});

test('release CLI reports a fixed category without echoing token or artifact bytes', () => {
  const root = mkdtempSync(join(tmpdir(), 'release-cli-test-'));
  try {
    const artifact = join(root, 'candidate.tgz'); writeFileSync(artifact, 'synthetic artifact body');
    const result = spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/check-adapter-release.js', import.meta.url)), artifact], {
      encoding: 'utf8', env: {
        PATH: process.env.PATH ?? '/usr/bin:/bin', GITHUB_SHA: SOURCE_SHA,
        REVIEWED_SOURCE_SHA: 'b'.repeat(40), REVIEWED_TARBALL_SHA256: 'c'.repeat(64),
        GITHUB_TOKEN: 'synthetic-secret',
      },
    });
    assert.equal(result.status, 1);
    assert.deepEqual(JSON.parse(result.stderr.trim()), { ok: false, error: 'release_source_mismatch' });
    assert.doesNotMatch(result.stderr, /synthetic-secret|synthetic artifact body/);
  } finally { rmSync(root, { recursive: true, force: true }); }
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
