import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { prepareAdapterPackage } from '../scripts/prepare-adapter-package.js';
import { prepareAdapterBootstrap } from '../scripts/prepare-adapter-bootstrap.js';
import { publishAdapter } from '../scripts/publish-adapter.js';

const repository = 'Tech-Adventures-LLC/intake-site-adapter';
const source = 'a'.repeat(40);
const sha256 = 'c2b2fbe7e182bda697178b817e57ded088e7d046c9de530674670e83fa516d8b';
const root = mkdtempSync(join(tmpdir(), 'adapter-publication-test-'));
let artifactPath, usableBytes, bootstrapBytes, preparation;
const now = () => new Date('2026-09-19T00:00:00Z');
before(() => {
  preparation = prepareAdapterPackage({ output: join(root, 'usable') });
  artifactPath = join(preparation.output, preparation.tarball);
  usableBytes = readFileSync(artifactPath);
  const bootstrap = prepareAdapterBootstrap({ output: join(root, 'bootstrap'), now });
  bootstrapBytes = readFileSync(join(bootstrap.output, bootstrap.tarball));
  assert.equal(preparation.sha256, sha256);
});
after(() => rmSync(root, { recursive: true, force: true }));
function environment(changes = {}) {
  return {
    GITHUB_ACTIONS: 'true', CI: 'true', GITHUB_SERVER_URL: 'https://github.com',
    GITHUB_REPOSITORY: repository, GITHUB_REPOSITORY_ID: '1375264810', GITHUB_REPOSITORY_OWNER_ID: '276808671',
    GITHUB_REF: 'refs/heads/main', GITHUB_SHA: source, GITHUB_EVENT_NAME: 'workflow_dispatch',
    GITHUB_WORKFLOW_REF: `${repository}/.github/workflows/release-adapter.yml@refs/heads/main`,
    GITHUB_WORKFLOW_SHA: source, GITHUB_RUN_ID: '12345', GITHUB_RUN_ATTEMPT: '1', RUNNER_ENVIRONMENT: 'github-hosted',
    GITHUB_ACTOR_ID: '142938424', GITHUB_TRIGGERING_ACTOR: 'ii-am-modiify',
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://example.actions.githubusercontent.com/oidc?api-version=2.0',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'synthetic-oidc-secret', GITHUB_TOKEN: 'synthetic-github-secret',
    REVIEWED_SOURCE_SHA: source, REVIEWED_TARBALL_SHA256: sha256,
    NODE_AUTH_TOKEN: 'synthetic-npm-secret', NPM_TOKEN: 'synthetic-npm-secret', NODE_OPTIONS: '--synthetic-danger',
    npm_config_registry: 'https://invalid.example', NPM_CONFIG_USERCONFIG: '/synthetic/auth',
    DATABASE_URL: 'synthetic-database-secret', RESEND_API_KEY: 'synthetic-provider-secret', HOME: '/synthetic/auth-home',
    ...changes,
  };
}
function fakeFetch(overrides = {}) {
  const tags = { bootstrap: '0.0.0-bootstrap.0', latest: '0.0.0-bootstrap.0' };
  const fixtures = {
    '': { id: 1375264810, private: false, full_name: repository, default_branch: 'main' },
    '/actions/runs/12345': { id: 12345, repository: { id: 1375264810, full_name: repository }, actor: { id: 142938424, login: 'ii-am-modiify' }, triggering_actor: { id: 142938424, login: 'ii-am-modiify' }, event: 'workflow_dispatch', head_branch: 'main', head_sha: source, path: '.github/workflows/release-adapter.yml' },
    '/branches/main': { name: 'main', protected: true, commit: { sha: source } },
    '/environments/npm-release': { name: 'npm-release', can_admins_bypass: false, protection_rules: [{ type: 'required_reviewers', prevent_self_review: false, reviewers: [{ type: 'User', reviewer: { id: 142938424, login: 'ii-am-modiify' } }] }], deployment_branch_policy: { protected_branches: true, custom_branch_policies: false } },
    'https://registry.npmjs.org/@tech-adventures-llc%2fintake-site-adapter': { name: '@tech-adventures-llc/intake-site-adapter', 'dist-tags': tags, versions: { '0.0.0-bootstrap.0': { name: '@tech-adventures-llc/intake-site-adapter', version: '0.0.0-bootstrap.0', dist: { integrity: 'sha512-E6/4J6azPc+J6UBs0dv/recGgbW4gUsOzaGSW5g4a7I5OIY687EhNfgjuc1EWJeE/pu7UxlxzYDOWhOHL1L/qw==' } } } },
    'https://registry.npmjs.org/-/package/@tech-adventures-llc%2fintake-site-adapter/dist-tags': tags,
    'https://registry.npmjs.org/@tech-adventures-llc/intake-site-adapter/-/intake-site-adapter-0.0.0-bootstrap.0.tgz': bootstrapBytes,
    ...overrides,
  };
  return async url => {
    const item = fixtures[url.replace(`https://api.github.com/repos/${repository}`, '')];
    assert.notEqual(item, undefined, 'unexpected network target');
    return Buffer.isBuffer(item) ? new Response(item) : Response.json(item);
  };
}
function input(changes = {}) {
  return { artifactPath, env: environment(), now, fetchImpl: fakeFetch(), runtime: { nodeVersion: '22.23.2', platform: 'linux', execPath: process.execPath, npmVersion: '11.15.0' }, ...changes };
}

test('publication uses immutable reviewed bytes once with isolated config, strict context and explicit flags', async () => {
  let calls = 0, temporary;
  const result = await publishAdapter(input({ runNpm: (executable, args, options) => {
    calls++; temporary = options.cwd;
    assert.equal(executable, process.execPath);
    assert.match(args[0], /\/lib\/node_modules\/npm\/bin\/npm-cli\.js$/);
    assert.equal(args[1], 'publish');
    assert.deepEqual(args.slice(3), ['--registry=https://registry.npmjs.org', '--access', 'public', '--provenance', '--tag', 'latest', '--ignore-scripts']);
    assert.equal(dirname(args[2]), options.cwd);
    assert.notEqual(args[2], artifactPath);
    assert.deepEqual(JSON.parse(readFileSync(join(options.cwd, 'package.json'))), { private: true });
    assert.deepEqual(readFileSync(args[2]), usableBytes);
    assert.equal(readFileSync(options.env.NPM_CONFIG_USERCONFIG, 'utf8'), '');
    assert.equal(readFileSync(options.env.NPM_CONFIG_GLOBALCONFIG, 'utf8'), '');
    assert.ok(options.env.HOME.startsWith(temporary));
    assert.ok(options.env.NPM_CONFIG_CACHE.startsWith(temporary));
    for (const key of ['GITHUB_TOKEN', 'NODE_AUTH_TOKEN', 'NPM_TOKEN', 'NODE_OPTIONS', 'npm_config_registry', 'DATABASE_URL', 'RESEND_API_KEY', 'GITHUB_ACTOR_ID']) assert.equal(options.env[key], undefined, key);
    for (const key of ['GITHUB_ACTIONS', 'CI', 'GITHUB_SERVER_URL', 'GITHUB_REPOSITORY', 'GITHUB_REPOSITORY_ID', 'GITHUB_REPOSITORY_OWNER_ID', 'GITHUB_REF', 'GITHUB_SHA', 'GITHUB_EVENT_NAME', 'GITHUB_WORKFLOW_REF', 'GITHUB_WORKFLOW_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'RUNNER_ENVIRONMENT', 'ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN']) assert.equal(options.env[key], environment()[key]);
    assert.equal(options.env.NPM_CONFIG_FETCH_RETRIES, '0');
    assert.equal(options.env.NPM_CONFIG_IGNORE_SCRIPTS, 'true');
    assert.equal(options.env.NPM_CONFIG_LOGS_MAX, '0');
    assert.equal(options.env.NPM_CONFIG_LOGLEVEL, 'silent');
    assert.equal(options.timeout, 120000); assert.equal(options.maxBuffer, 65536);
    assert.deepEqual(options.stdio, ['ignore', 'pipe', 'pipe']);
    return { status: 0, stdout: 'synthetic-provider-secret', stderr: 'synthetic-oidc-secret' };
  } }));
  assert.equal(calls, 1); assert.equal(existsSync(temporary), false);
  assert.deepEqual(result, { ok: true, status: 'publication_command_succeeded', package: '@tech-adventures-llc/intake-site-adapter', version: '1.1.0', sha256, source_sha: source, publication_verified: false, provenance_verified: false });
});

test('rejected real preflight and changed exact artifact prevent any npm call', async () => {
  let calls = 0;
  for (const changes of [
    { fetchImpl: fakeFetch({ '/branches/main': { name: 'main', protected: false, commit: { sha: source } } }) },
    { env: environment({ REVIEWED_TARBALL_SHA256: 'b'.repeat(64) }) },
    { now: () => new Date('2026-09-26') },
  ]) await assert.rejects(publishAdapter(input({ ...changes, runNpm: () => { calls++; } })), /release_preparation_blocked/);
  assert.equal(calls, 0);
});

test('invalid OIDC, hosted identity or provenance context prevents publication', async () => {
  let calls = 0;
  for (const changes of [
    { ACTIONS_ID_TOKEN_REQUEST_TOKEN: '' }, { ACTIONS_ID_TOKEN_REQUEST_URL: 'http://example.actions.githubusercontent.com/oidc' },
    { ACTIONS_ID_TOKEN_REQUEST_URL: 'https://evil.example/oidc' }, { GITHUB_ACTIONS: 'false' }, { CI: 'false' },
    { RUNNER_ENVIRONMENT: 'self-hosted' }, { GITHUB_SERVER_URL: 'https://enterprise.example' },
    { GITHUB_REPOSITORY: 'synthetic/other' }, { GITHUB_REPOSITORY_ID: '1' }, { GITHUB_REPOSITORY_OWNER_ID: '1' },
    { GITHUB_REF: 'refs/heads/feature' }, { GITHUB_SHA: 'b'.repeat(40) }, { GITHUB_EVENT_NAME: 'push' },
    { GITHUB_WORKFLOW_REF: `${repository}/.github/workflows/other.yml@refs/heads/main` },
    { GITHUB_WORKFLOW_SHA: 'b'.repeat(40) }, { GITHUB_RUN_ID: '0' }, { GITHUB_RUN_ATTEMPT: '0' }, { GITHUB_RUN_ATTEMPT: '9007199254740992' },
  ]) await assert.rejects(publishAdapter(input({ env: environment(changes), runNpm: () => { calls++; } })), /publication_context_invalid/);
  assert.equal(calls, 0);
});

test('publication toolchain rejects unsupported Node, platform and nonexact npm before child execution', async () => {
  let calls = 0;
  for (const changes of [{ nodeVersion: '20.20.2' }, { nodeVersion: '22.13.1' }, { nodeVersion: 'invalid' }, { npmVersion: '11.14.0' }, { npmVersion: '11.16.0' }, { platform: 'darwin' }]) {
    const options = input(); Object.assign(options.runtime, changes);
    await assert.rejects(publishAdapter({ ...options, runNpm: () => { calls++; } }), /publication_toolchain_invalid/);
  }
  assert.equal(calls, 0);
});

test('failed, timed out, signalled or throwing npm is ambiguous with one attempt and owned cleanup', async () => {
  for (const outcome of [{ status: 1, stderr: 'synthetic-secret' }, { status: null, error: Error('synthetic-secret') }, { status: 0, signal: 'SIGTERM' }, 'throw']) {
    let calls = 0, temporary;
    await assert.rejects(publishAdapter(input({ runNpm: (_executable, _args, options) => {
      calls++; temporary = options.cwd;
      if (outcome === 'throw') throw Error('synthetic-secret');
      return outcome;
    } })), error => error.message === 'publication_failed_or_ambiguous');
    assert.equal(calls, 1); assert.equal(existsSync(temporary), false);
    assert.deepEqual(readFileSync(artifactPath), usableBytes);
  }
});

test('local preparation exports the runner and reports remaining gates without claiming setup is missing', () => {
  assert.ok(existsSync(join(preparation.output, 'public-source/scripts/publish-adapter.js')));
  assert.equal(preparation.publication_ready, false);
  assert.ok(preparation.publication_blockers.includes('protected_workflow_activation_and_exact_artifact_owner_approval_required'));
  assert.ok(preparation.publication_blockers.includes('registry_publication_and_provenance_unverified'));
  assert.ok(!preparation.publication_blockers.includes('protected_environment_and_npm_owner_setup_unverified'));
  assert.ok(!preparation.publication_blockers.includes('first_package_bootstrap_unresolved'));
});

test('native CLI refuses a local credential-bearing context without exposing errors or starting npm', () => {
  const sentinel = join(root, 'untouched-session'); writeFileSync(sentinel, 'synthetic-retained-auth');
  const result = spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/publish-adapter.js', import.meta.url)), artifactPath], {
    env: { PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, HOME: root, NPM_CONFIG_USERCONFIG: sentinel, NODE_AUTH_TOKEN: 'synthetic-secret' },
    encoding: 'utf8', timeout: 10000,
  });
  assert.equal(result.status, 1); assert.equal(result.stdout, '');
  assert.deepEqual(JSON.parse(result.stderr), { ok: false, error: 'publication_context_invalid' });
  assert.equal(readFileSync(sentinel, 'utf8'), 'synthetic-retained-auth');
});
