import { spawnSync } from 'node:child_process';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { assertReviewedArtifact, checkReleasePreparation } from './check-adapter-release.js';

const REPOSITORY = 'Tech-Adventures-LLC/intake-site-adapter';
const CONTEXT_FIELDS = Object.freeze([
  'GITHUB_ACTIONS', 'GITHUB_SERVER_URL', 'GITHUB_REPOSITORY', 'GITHUB_REPOSITORY_ID',
  'GITHUB_REPOSITORY_OWNER_ID', 'GITHUB_REF', 'GITHUB_SHA', 'GITHUB_EVENT_NAME',
  'GITHUB_WORKFLOW_REF', 'GITHUB_WORKFLOW_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT',
  'RUNNER_ENVIRONMENT', 'CI', 'ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
]);
class PublicationError extends Error {}
function requireCondition(ok, category) { if (!ok) throw new PublicationError(category); }
function positiveInteger(value) { return typeof value === 'string' && /^[1-9][0-9]*$/.test(value) && Number.isSafeInteger(Number(value)); }
function assertContext(env) {
  let oidc;
  try { oidc = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL); } catch { /* Rejected below. */ }
  requireCondition(env.GITHUB_ACTIONS === 'true' && env.CI === 'true' && env.RUNNER_ENVIRONMENT === 'github-hosted'
    && env.GITHUB_SERVER_URL === 'https://github.com' && env.GITHUB_REPOSITORY === REPOSITORY
    && env.GITHUB_REPOSITORY_ID === '1375264810' && env.GITHUB_REPOSITORY_OWNER_ID === '276808671'
    && env.GITHUB_REF === 'refs/heads/main' && env.GITHUB_EVENT_NAME === 'workflow_dispatch'
    && /^[a-f0-9]{40}$/.test(env.REVIEWED_SOURCE_SHA ?? '') && env.GITHUB_SHA === env.REVIEWED_SOURCE_SHA
    && env.GITHUB_WORKFLOW_SHA === env.REVIEWED_SOURCE_SHA
    && env.GITHUB_WORKFLOW_REF === `${REPOSITORY}/.github/workflows/release-adapter.yml@refs/heads/main`
    && positiveInteger(env.GITHUB_RUN_ID) && positiveInteger(env.GITHUB_RUN_ATTEMPT)
    && oidc?.protocol === 'https:' && oidc.hostname.endsWith('.actions.githubusercontent.com')
    && !oidc.username && !oidc.password && !oidc.port && !oidc.hash
    && typeof env.ACTIONS_ID_TOKEN_REQUEST_TOKEN === 'string' && env.ACTIONS_ID_TOKEN_REQUEST_TOKEN.length > 0,
  'publication_context_invalid');
}
function toolchain(runtime) {
  const execPath = runtime.execPath;
  const npmRoot = resolve(dirname(execPath), '../lib/node_modules/npm');
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(runtime.nodeVersion);
  let npmVersion = runtime.npmVersion;
  if (npmVersion === undefined) {
    try { npmVersion = JSON.parse(readFileSync(join(npmRoot, 'package.json'), 'utf8')).version; }
    catch { throw new PublicationError('publication_toolchain_invalid'); }
  }
  requireCondition(runtime.platform === 'linux' && match && (Number(match[1]) > 22 || (Number(match[1]) === 22 && Number(match[2]) >= 14))
    && npmVersion === '11.15.0', 'publication_toolchain_invalid');
  return join(npmRoot, 'bin/npm-cli.js');
}
function isolatedEnvironment(temporary, env, execPath) {
  const home = join(temporary, 'home'), cache = join(temporary, 'cache'), temp = join(temporary, 'tmp');
  for (const directory of [home, cache, temp]) mkdirSync(directory, { mode: 0o700 });
  const user = join(home, 'user.npmrc'), global = join(home, 'global.npmrc');
  for (const path of [user, global]) writeFileSync(path, '', { mode: 0o600, flag: 'wx' });
  const child = {
    PATH: `${dirname(execPath)}:/usr/bin:/bin`, HOME: home, TMPDIR: temp, LANG: 'C.UTF-8',
    NPM_CONFIG_USERCONFIG: user, NPM_CONFIG_GLOBALCONFIG: global, NPM_CONFIG_CACHE: cache,
    NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org', NPM_CONFIG_IGNORE_SCRIPTS: 'true',
    NPM_CONFIG_FETCH_RETRIES: '0', NPM_CONFIG_FETCH_TIMEOUT: '30000',
    NPM_CONFIG_PROGRESS: 'false', NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_FUND: 'false',
    NPM_CONFIG_UPDATE_NOTIFIER: 'false', NPM_CONFIG_LOGLEVEL: 'silent', NPM_CONFIG_LOGS_MAX: '0',
  };
  for (const key of CONTEXT_FIELDS) child[key] = env[key];
  return child;
}

// Only external boundaries (transport, time, runtime metadata and child execution)
// are injected. There is no successful-preflight override or alternate publish path.
export async function publishAdapter({ artifactPath, env = process.env, fetchImpl = fetch, now = () => new Date(),
  runtime = { execPath: process.execPath, nodeVersion: process.versions.node, platform: process.platform }, runNpm = spawnSync } = {}) {
  assertContext(env);
  const npmCli = toolchain(runtime);
  let metadata, authority, bytes;
  try {
    const stat = lstatSync(artifactPath);
    requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 1048576, 'publication_artifact_invalid');
    bytes = readFileSync(artifactPath);
    metadata = JSON.parse(readFileSync(new URL('../packages/intake-site-adapter/package.json', import.meta.url), 'utf8'));
    authority = JSON.parse(readFileSync(new URL('../release/adapter-release-authority.json', import.meta.url), 'utf8'));
  } catch { throw new PublicationError('publication_artifact_invalid'); }
  const reviewed = { bytes, expectedDigest: env.REVIEWED_TARBALL_SHA256, sourceSha: env.GITHUB_SHA, reviewedSourceSha: env.REVIEWED_SOURCE_SHA };
  try {
    await checkReleasePreparation({ ...reviewed, metadata, authority, fetchImpl, now,
      repository: env.GITHUB_REPOSITORY, githubToken: env.GITHUB_TOKEN, ref: env.GITHUB_REF,
      eventName: env.GITHUB_EVENT_NAME, actorId: env.GITHUB_ACTOR_ID, triggeringActor: env.GITHUB_TRIGGERING_ACTOR, runId: env.GITHUB_RUN_ID });
  } catch { throw new PublicationError('release_preparation_blocked'); }
  let temporary;
  try {
    temporary = mkdtempSync(join(tmpdir(), 'intake-reviewed-publication-'));
    chmodSync(temporary, 0o700);
    const artifact = join(temporary, 'tech-adventures-llc-intake-site-adapter-1.1.0.tgz');
    writeFileSync(artifact, bytes, { mode: 0o400, flag: 'wx' });
    // Stop npm's project-root search here; no ancestor project npmrc is read.
    writeFileSync(join(temporary, 'package.json'), JSON.stringify({ private: true }), { mode: 0o400, flag: 'wx' });
    const childEnv = isolatedEnvironment(temporary, env, runtime.execPath);
    // Re-read the immutable owned copy immediately before the sole publish call.
    assertReviewedArtifact({ ...reviewed, bytes: readFileSync(artifact) });
    const result = runNpm(runtime.execPath, [npmCli, 'publish', artifact,
      '--registry=https://registry.npmjs.org', '--access', 'public', '--provenance', '--tag', 'latest', '--ignore-scripts'], {
      cwd: temporary, env: childEnv, timeout: 120000, killSignal: 'SIGKILL', maxBuffer: 65536,
      stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8',
    });
    requireCondition(result?.status === 0 && !result.error && !result.signal, 'publication_failed_or_ambiguous');
    return { ok: true, status: 'publication_command_succeeded', package: metadata.name, version: metadata.version,
      sha256: reviewed.expectedDigest, source_sha: reviewed.sourceSha, publication_verified: false, provenance_verified: false };
  } catch { throw new PublicationError('publication_failed_or_ambiguous'); }
  finally { if (temporary) rmSync(temporary, { recursive: true, force: true }); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    requireCondition(process.argv.length === 3, 'artifact_path_required');
    console.log(JSON.stringify(await publishAdapter({ artifactPath: process.argv[2] })));
  } catch (error) {
    console.error(JSON.stringify({ ok: false, error: error instanceof PublicationError ? error.message : 'publication_failed_or_ambiguous' }));
    process.exitCode = 1;
  }
}
