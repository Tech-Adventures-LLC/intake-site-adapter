import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditPublicBytes, prepareAdapterPackage } from '../scripts/prepare-adapter-package.js';
import { prepareAdapterBootstrap } from '../scripts/prepare-adapter-bootstrap.js';
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
const PACKAGE_NAME = '@tech-adventures-llc/intake-site-adapter';
const USABLE_SHA256 = 'c2b2fbe7e182bda697178b817e57ded088e7d046c9de530674670e83fa516d8b';
const BOOTSTRAP_VERSION = '0.0.0-bootstrap.0';
const BOOTSTRAP_SRI = 'sha512-E6/4J6azPc+J6UBs0dv/recGgbW4gUsOzaGSW5g4a7I5OIY687EhNfgjuc1EWJeE/pu7UxlxzYDOWhOHL1L/qw==';
const REGISTRY_METADATA_URL = 'https://registry.npmjs.org/@tech-adventures-llc%2fintake-site-adapter';
const REGISTRY_TAGS_URL = 'https://registry.npmjs.org/-/package/@tech-adventures-llc%2fintake-site-adapter/dist-tags';
const BOOTSTRAP_URL = 'https://registry.npmjs.org/@tech-adventures-llc/intake-site-adapter/-/intake-site-adapter-0.0.0-bootstrap.0.tgz';
const REGISTRY_TAGS = { bootstrap: BOOTSTRAP_VERSION, latest: BOOTSTRAP_VERSION };
const REGISTRY_METADATA = {
  name: PACKAGE_NAME, 'dist-tags': REGISTRY_TAGS,
  versions: { [BOOTSTRAP_VERSION]: { name: PACKAGE_NAME, version: BOOTSTRAP_VERSION, dist: { integrity: BOOTSTRAP_SRI, tarball: BOOTSTRAP_URL } } },
};
let approvedArtifacts;
function releaseArtifacts() {
  if (approvedArtifacts) return approvedArtifacts;
  const root = mkdtempSync(join(tmpdir(), 'release-approved-bytes-'));
  try {
    const usable = prepareAdapterPackage({ output: join(root, 'usable') });
    const bootstrap = prepareAdapterBootstrap({ output: join(root, 'bootstrap'), now: () => new Date('2026-09-19T00:00:00Z') });
    assert.equal(usable.sha256, USABLE_SHA256);
    assert.equal(bootstrap.sha256, '386d45bc298d57fc18b24e04ebb01194eb5f98f4ebf101d2572efe48070fbdf6');
    approvedArtifacts = { usable: readFileSync(join(usable.output, usable.tarball)), bootstrap: readFileSync(join(bootstrap.output, bootstrap.tarball)) };
    return approvedArtifacts;
  } finally { rmSync(root, { recursive: true, force: true }); }
}
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
    bytes: releaseArtifacts().usable, expectedDigest: USABLE_SHA256, now: () => new Date('2026-09-19T00:00:00Z'),
    sourceSha: SOURCE_SHA, reviewedSourceSha: SOURCE_SHA, repository: PUBLIC_REPOSITORY,
    githubToken: 'synthetic-token', ref: 'refs/heads/main', eventName: 'workflow_dispatch',
    actorId: '142938424', triggeringActor: 'ii-am-modiify', runId: '12345',
    metadata: { name: PACKAGE_NAME, version: '1.1.0', repository: { type: 'git', url: `git+https://github.com/${PUBLIC_REPOSITORY}.git`, directory: 'packages/intake-site-adapter' } },
    authority: JSON.parse(readFileSync(new URL('../release/adapter-release-authority.json', import.meta.url))),
    ...changes,
  };
}
function releaseFetch(overrides = {}) {
  const fixtures = { '': RELEASE_REPOSITORY, '/actions/runs/12345': RELEASE_RUN, '/branches/main': RELEASE_BRANCH, '/environments/npm-release': RELEASE_ENVIRONMENT, [REGISTRY_METADATA_URL]: REGISTRY_METADATA, [REGISTRY_TAGS_URL]: REGISTRY_TAGS, [BOOTSTRAP_URL]: releaseArtifacts().bootstrap, ...overrides };
  const calls = [];
  const fetchImpl = async (url, options) => {
    const path = url.startsWith('https://api.github.com/') ? url.slice(`https://api.github.com/repos/${PUBLIC_REPOSITORY}`.length) : url;
    calls.push({ path, options });
    const item = fixtures[path];
    if (typeof item === 'function') return item(url, options);
    return item instanceof Response ? item : Buffer.isBuffer(item) ? new Response(item) : Response.json(item === undefined ? {} : item, { status: 200 });
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

test('exact reviewed artifacts, protected GitHub settings and anonymous registry satisfy only prerequisites', async () => {
  const { fetchImpl, calls } = releaseFetch();
  assert.deepEqual(await checkReleasePreparation(releaseInput({ fetchImpl })), {
    ok: true, status: 'release_prerequisites_verified', npm_live_trust_verified: false,
    publication_verified: false, provenance_verified: false, owner_approval_verified: false,
  });
  assert.deepEqual(calls.map(call => call.path), ['', '/actions/runs/12345', '/branches/main', '/environments/npm-release', REGISTRY_METADATA_URL, REGISTRY_TAGS_URL, BOOTSTRAP_URL]);
  assert.ok(calls.every(call => call.options.redirect === 'error' && call.options.signal.aborted));
  assert.ok(calls.slice(0, 4).every(call => call.options.headers.authorization === 'Bearer synthetic-token'));
  assert.ok(calls.slice(4).every(call => !new Headers(call.options.headers).has('authorization') && call.options.credentials === 'omit'));
  assert.doesNotThrow(() => assertProtectedEnvironment(RELEASE_ENVIRONMENT));
});

test('package identity and immutable approved digest cannot be replaced by owner input or authority edits', async () => {
  const noNetwork = async () => assert.fail('network must not be reached');
  for (const edit of [{ name: 'other' }, { version: BOOTSTRAP_VERSION }, { version: undefined }]) {
    await expectReleaseError(releaseInput({ metadata: { ...releaseInput().metadata, ...edit }, fetchImpl: noNetwork }), 'release_package_mismatch');
  }
  const bytes = Buffer.from('arbitrary owner-approved bytes');
  await expectReleaseError(releaseInput({ bytes, expectedDigest: createHash('sha256').update(bytes).digest('hex'), fetchImpl: noNetwork }), 'release_artifact_mismatch');
  for (const edit of [
    authority => { authority.reviewedArtifact.sha256 = 'b'.repeat(64); },
    authority => { authority.reviewedArtifact.integrity = 'sha512-other'; },
    authority => { authority.bootstrap.sha256 = 'b'.repeat(64); },
    authority => { authority.bootstrap.integrity = 'sha512-other'; },
    authority => { authority.bootstrap.bytes = 4536; },
    authority => { authority.bootstrap.version = 'other'; },
    authority => { authority.tagExceptionExpiresAt = '2099-01-01T00:00:00Z'; },
  ]) {
    const authority = releaseInput().authority; edit(authority);
    await expectReleaseError(releaseInput({ authority, fetchImpl: noNetwork }), 'release_authority_mismatch');
  }
});

test('tag exception expires at its exact boundary and rejects an invalid clock before requests', async () => {
  const noNetwork = async () => assert.fail('network must not be reached');
  for (const instant of ['2026-09-25T23:59:59Z', '2026-09-26T00:00:00Z'])
    await expectReleaseError(releaseInput({ now: () => new Date(instant), fetchImpl: noNetwork }), 'npm_tag_exception_expired');
  for (const value of [new Date('invalid'), '2026-09-19', null])
    await expectReleaseError(releaseInput({ now: () => value, fetchImpl: noNetwork }), 'clock_invalid');
  const result = await checkReleasePreparation(releaseInput({ now: () => new Date('2026-09-25T23:59:58.999Z'), fetchImpl: releaseFetch().fetchImpl }));
  assert.equal(result.ok, true);
});

test('registry package and bootstrap identity, only-version state and immutable SRI fail closed', async () => {
  const cases = [
    [metadata => { metadata.name = 'other'; }, 'npm_registry_identity_mismatch'],
    [metadata => { delete metadata.versions; }, 'npm_registry_version_mismatch'],
    [metadata => { metadata.versions = []; }, 'npm_registry_version_mismatch'],
    [metadata => { metadata.versions = {}; }, 'npm_registry_version_mismatch'],
    [metadata => { metadata.versions['1.1.0'] = {}; }, 'npm_registry_version_mismatch'],
    [metadata => { metadata.versions['2.0.0'] = {}; }, 'npm_registry_version_mismatch'],
    [metadata => { metadata.versions[BOOTSTRAP_VERSION].name = 'other'; }, 'npm_registry_identity_mismatch'],
    [metadata => { metadata.versions[BOOTSTRAP_VERSION].version = 'other'; }, 'npm_registry_identity_mismatch'],
    [metadata => { metadata.versions[BOOTSTRAP_VERSION] = null; }, 'npm_registry_identity_mismatch'],
    [metadata => { delete metadata.versions[BOOTSTRAP_VERSION].dist; }, 'npm_bootstrap_integrity_mismatch'],
    [metadata => { metadata.versions[BOOTSTRAP_VERSION].dist.integrity = 'sha512-other'; }, 'npm_bootstrap_integrity_mismatch'],
  ];
  for (const [mutate, category] of cases) {
    const metadata = structuredClone(REGISTRY_METADATA); mutate(metadata);
    const { fetchImpl, calls } = releaseFetch({ [REGISTRY_METADATA_URL]: metadata });
    await expectReleaseError(releaseInput({ fetchImpl }), category);
    assert.equal(calls.length, 5);
  }
});

test('both independent tag views must match exactly with no added, missing or changed tag', async () => {
  for (const tags of [{}, { bootstrap: BOOTSTRAP_VERSION }, { ...REGISTRY_TAGS, next: '1.1.0' }, { ...REGISTRY_TAGS, latest: '1.1.0' }, [], null]) {
    for (const endpoint of [REGISTRY_METADATA_URL, REGISTRY_TAGS_URL]) {
      const value = endpoint === REGISTRY_METADATA_URL ? { ...REGISTRY_METADATA, 'dist-tags': tags } : tags;
      const { fetchImpl } = releaseFetch({ [endpoint]: value });
      await expectReleaseError(releaseInput({ fetchImpl }), endpoint === REGISTRY_TAGS_URL && (tags === null || Array.isArray(tags)) ? 'npm_registry_tags_unavailable' : 'npm_registry_tags_mismatch');
    }
  }
});

test('bootstrap bytes must match exact length and both hashes; metadata cannot choose a request URL', async () => {
  for (const bytes of [Buffer.from('short'), Buffer.concat([releaseArtifacts().bootstrap, Buffer.from('x')]), Buffer.from(releaseArtifacts().bootstrap).fill(0, 100, 101)]) {
    const { fetchImpl, calls } = releaseFetch({ [BOOTSTRAP_URL]: bytes });
    await expectReleaseError(releaseInput({ fetchImpl }), 'npm_bootstrap_artifact_mismatch');
    assert.equal(calls.length, 7);
  }
  const metadata = structuredClone(REGISTRY_METADATA);
  metadata.versions[BOOTSTRAP_VERSION].dist.tarball = 'https://attacker.invalid/steal';
  const { fetchImpl, calls } = releaseFetch({ [REGISTRY_METADATA_URL]: metadata });
  assert.equal((await checkReleasePreparation(releaseInput({ fetchImpl }))).ok, true);
  assert.equal(calls.at(-1).path, BOOTSTRAP_URL);
});

const REGISTRY_REQUESTS = [
  [REGISTRY_METADATA_URL, 1048576, 'npm_registry_metadata_unavailable'],
  [REGISTRY_TAGS_URL, 65536, 'npm_registry_tags_unavailable'],
  [BOOTSTRAP_URL, 8192, 'npm_bootstrap_tarball_unavailable'],
];
test('registry transport rejects non-200, malformed shapes, oversize, redirects and thrown failures without retries', async () => {
  for (const [endpoint, limit, category] of REGISTRY_REQUESTS) {
    const failures = [
      () => new Response('private response detail', { status: 404 }),
      () => new Response('private response detail', { status: 302, headers: { location: 'https://attacker.invalid/' } }),
      () => new Response(Buffer.alloc(limit + 1)),
      () => { throw Error('private transport detail'); },
      () => { const response = new Response('private response detail'); Object.defineProperty(response, 'redirected', { value: true }); return response; },
      () => new Response(null),
    ];
    if (endpoint !== BOOTSTRAP_URL) failures.push(() => new Response('malformed'), () => new Response('null'), () => new Response('[]'));
    for (const failure of failures) {
      const { fetchImpl, calls } = releaseFetch({ [endpoint]: failure });
      await expectReleaseError(releaseInput({ fetchImpl }), category);
      assert.equal(calls.filter(call => call.path === endpoint).length, 1);
      assert.ok(calls.every(call => call.options.signal.aborted));
    }
  }
});

test('registry cancels and aborts stalled error bodies and oversized bodies at every endpoint', async () => {
  for (const [endpoint, limit, category] of REGISTRY_REQUESTS) {
    for (const status of [502, 200]) {
      let canceled = false;
      const response = new Response(new ReadableStream({ start(controller) { if (status === 200) controller.enqueue(new Uint8Array(limit + 1)); }, cancel() { canceled = true; } }), { status });
      const { fetchImpl, calls } = releaseFetch({ [endpoint]: response });
      await expectReleaseError(releaseInput({ fetchImpl }), category);
      assert.equal(canceled, true);
      assert.equal(calls.at(-1).options.signal.aborted, true);
    }
  }
});

test('registry five-second deadline covers fetch and body at every endpoint with cancellation and no retry', { timeout: 8000 }, async () => {
  await Promise.all(REGISTRY_REQUESTS.flatMap(([endpoint, _limit, category]) => [false, true].map(async body => {
    let canceled = false;
    const response = new Response(new ReadableStream({ start() {}, cancel() { canceled = true; } }));
    const { fetchImpl, calls } = releaseFetch({ [endpoint]: body ? response : () => new Promise(() => {}) });
    const started = Date.now();
    await expectReleaseError(releaseInput({ fetchImpl }), category);
    assert.ok(Date.now() - started >= 4800);
    assert.equal(calls.filter(call => call.path === endpoint).length, 1);
    assert.ok(calls.at(-1).options.signal.aborted);
    if (body) assert.equal(canceled, true);
  })));
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

test('release CLI emits only a category for source, owner-digest substitution and registry failures', () => {
  const root = mkdtempSync(join(tmpdir(), 'release-cli-test-'));
  try {
    const artifact = join(root, 'candidate.tgz');
    const shim = join(root, 'fetch-fixture.mjs');
    const fixture = {
      [`https://api.github.com/repos/${PUBLIC_REPOSITORY}`]: RELEASE_REPOSITORY,
      [`https://api.github.com/repos/${PUBLIC_REPOSITORY}/actions/runs/12345`]: RELEASE_RUN,
      [`https://api.github.com/repos/${PUBLIC_REPOSITORY}/branches/main`]: RELEASE_BRANCH,
      [`https://api.github.com/repos/${PUBLIC_REPOSITORY}/environments/npm-release`]: RELEASE_ENVIRONMENT,
    };
    // Effects are replaced only in the isolated child; no real registry request
    // or dependency on the wall date occurs during this CLI failure fixture.
    writeFileSync(shim, `
      const WallDate = Date;
      globalThis.Date = class extends WallDate { constructor(...args) { super(...(args.length ? args : ['2026-09-19T00:00:00Z'])); } };
      const fixture = ${JSON.stringify(fixture)};
      globalThis.fetch = async (url, options) => {
        if (Object.hasOwn(fixture, url)) return Response.json(fixture[url]);
        if (url === ${JSON.stringify(REGISTRY_METADATA_URL)} && !new Headers(options.headers).has('authorization')) return new Response('synthetic-secret response detail', {status: 503});
        throw Error('synthetic-secret unexpected request');
      };
    `);
    const arbitrary = Buffer.from('synthetic artifact body');
    for (const [bytes, reviewedSha, category] of [
      [arbitrary, 'b'.repeat(40), 'release_source_mismatch'],
      [arbitrary, SOURCE_SHA, 'release_artifact_mismatch'],
      [releaseArtifacts().usable, SOURCE_SHA, 'npm_registry_metadata_unavailable'],
    ]) {
      writeFileSync(artifact, bytes);
      const result = spawnSync(process.execPath, ['--import', shim, fileURLToPath(new URL('../scripts/check-adapter-release.js', import.meta.url)), artifact], {
        encoding: 'utf8', timeout: 10000, env: {
          PATH: process.env.PATH ?? '/usr/bin:/bin', GITHUB_SHA: SOURCE_SHA,
          REVIEWED_SOURCE_SHA: reviewedSha, REVIEWED_TARBALL_SHA256: createHash('sha256').update(bytes).digest('hex'),
          GITHUB_TOKEN: 'synthetic-secret', GITHUB_REPOSITORY: PUBLIC_REPOSITORY,
          GITHUB_REF: 'refs/heads/main', GITHUB_EVENT_NAME: 'workflow_dispatch',
          GITHUB_ACTOR_ID: '142938424', GITHUB_TRIGGERING_ACTOR: 'ii-am-modiify', GITHUB_RUN_ID: '12345',
        },
      });
      assert.equal(result.status, 1);
      assert.equal(result.stdout, '');
      assert.deepEqual(JSON.parse(result.stderr.trim()), { ok: false, error: category });
      assert.doesNotMatch(result.stderr, /synthetic-secret|synthetic artifact body|response detail/);
    }
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
