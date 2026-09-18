import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const PUBLIC_REPOSITORY = 'Tech-Adventures-LLC/intake-site-adapter';
const PUBLIC_REPOSITORY_ID = 1375264810;
const OWNER_ID = 142938424;
const OWNER_LOGIN = 'ii-am-modiify';
const SETTINGS_TIMEOUT_MS = 5000;
const SETTINGS_MAX_BYTES = 65536;
function requireCondition(condition, category) { if (!condition) throw Error(category); }

export function assertProtectedEnvironment(environment) {
  const rules = environment?.protection_rules;
  const reviews = Array.isArray(rules) ? rules.filter(rule => rule?.type === 'required_reviewers') : [];
  requireCondition(environment?.name === 'npm-release' && environment.can_admins_bypass === false && reviews.length === 1, 'release_environment_unprotected');
  const review = reviews[0];
  requireCondition(review.prevent_self_review === false && Array.isArray(review.reviewers) && review.reviewers.length === 1, 'release_environment_unprotected');
  const reviewer = review.reviewers[0];
  requireCondition(reviewer?.type === 'User' && reviewer.reviewer?.id === OWNER_ID && reviewer.reviewer?.login === OWNER_LOGIN, 'release_environment_unprotected');
  requireCondition(environment.deployment_branch_policy?.protected_branches === true && environment.deployment_branch_policy.custom_branch_policies === false, 'release_branch_policy_unverified');
}

export function assertReviewedArtifact({ bytes, expectedDigest, sourceSha, reviewedSourceSha }) {
  requireCondition(/^[a-f0-9]{40}$/.test(sourceSha ?? '') && sourceSha === reviewedSourceSha, 'release_source_mismatch');
  requireCondition(/^[a-f0-9]{64}$/.test(expectedDigest ?? '') && createHash('sha256').update(bytes).digest('hex') === expectedDigest, 'release_artifact_mismatch');
}

function assertAuthority(authority) {
  const reviewer = authority?.reviewPolicy?.requiredReviewer;
  requireCondition(authority?.publicRepository === PUBLIC_REPOSITORY && authority.publicRepositoryId === PUBLIC_REPOSITORY_ID
    && authority.environment === 'npm-release' && authority.workflowFilename === 'release-adapter.yml'
    && authority.npmPackage === '@tech-adventures-llc/intake-site-adapter' && authority.version === '1.1.0'
    && authority.intendedPublisherAction === 'publish' && authority.reviewPolicy?.mode === 'sole-owner'
    && reviewer?.type === 'User' && reviewer.id === OWNER_ID && reviewer.login === OWNER_LOGIN,
  'release_authority_mismatch');
}

async function readGitHubSettings(fetchImpl, repository, path, githubToken) {
  const controller = new AbortController();
  let timeout; let activeReader;
  try {
    return await Promise.race([
      (async () => {
        const response = await fetchImpl(`https://api.github.com/repos/${repository}${path}`, {
          redirect: 'error', signal: controller.signal,
          headers: { authorization: `Bearer ${githubToken}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' },
        });
        requireCondition(response?.status === 200 && response.body?.getReader, 'github_settings_unavailable');
        const reader = response.body.getReader();
        activeReader = reader;
        const chunks = []; let size = 0;
        try {
          while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            size += value.byteLength;
            requireCondition(size <= SETTINGS_MAX_BYTES, 'github_settings_unavailable');
            chunks.push(Buffer.from(value));
          }
        } finally { activeReader = undefined; reader.cancel().catch(() => {}); }
        const result = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        requireCondition(result !== null && typeof result === 'object' && !Array.isArray(result), 'github_settings_unavailable');
        return result;
      })(),
      new Promise((_, reject) => { timeout = setTimeout(() => { controller.abort(); activeReader?.cancel().catch(() => {}); reject(Error('github_settings_unavailable')); }, SETTINGS_TIMEOUT_MS); }),
    ]);
  } catch { throw Error('github_settings_unavailable'); }
  finally { clearTimeout(timeout); }
}

export async function checkReleasePreparation({ metadata, authority, bytes, expectedDigest, sourceSha, reviewedSourceSha, repository, fetchImpl = fetch, githubToken, ref, eventName, actorId, triggeringActor, runId }) {
  assertReviewedArtifact({ bytes, expectedDigest, sourceSha, reviewedSourceSha });
  requireCondition(repository === PUBLIC_REPOSITORY && metadata?.repository?.type === 'git'
    && metadata.repository.url === `git+https://github.com/${PUBLIC_REPOSITORY}.git`
    && metadata.repository.directory === 'packages/intake-site-adapter', 'public_source_identity_missing');
  assertAuthority(authority);
  requireCondition(ref === 'refs/heads/main' && eventName === 'workflow_dispatch'
    && actorId === String(OWNER_ID) && triggeringActor === OWNER_LOGIN
    && typeof runId === 'string' && /^[1-9][0-9]*$/.test(runId)
    && Number.isSafeInteger(Number(runId)), 'release_workflow_context_invalid');
  requireCondition(typeof githubToken === 'string' && githubToken.length > 0, 'github_settings_access_missing');
  const repo = await readGitHubSettings(fetchImpl, repository, '', githubToken);
  requireCondition(repo.id === PUBLIC_REPOSITORY_ID && repo.private === false && repo.full_name === PUBLIC_REPOSITORY && repo.default_branch === 'main', 'public_source_not_verified');
  const run = await readGitHubSettings(fetchImpl, repository, `/actions/runs/${runId}`, githubToken);
  requireCondition(run.id === Number(runId) && run.repository?.id === PUBLIC_REPOSITORY_ID
    && run.repository?.full_name === PUBLIC_REPOSITORY && run.actor?.id === OWNER_ID && run.actor?.login === OWNER_LOGIN
    && run.triggering_actor?.id === OWNER_ID && run.triggering_actor?.login === OWNER_LOGIN
    && run.event === 'workflow_dispatch' && run.head_branch === 'main' && run.head_sha === sourceSha
    && ['.github/workflows/release-adapter.yml', '.github/workflows/release-adapter.yml@main',
      `${PUBLIC_REPOSITORY}/.github/workflows/release-adapter.yml@main`,
      `${PUBLIC_REPOSITORY}/.github/workflows/release-adapter.yml@refs/heads/main`].includes(run.path),
  'release_workflow_context_invalid');
  const branch = await readGitHubSettings(fetchImpl, repository, '/branches/main', githubToken);
  requireCondition(branch.name === 'main' && branch.protected === true, 'release_main_unprotected');
  requireCondition(branch.commit?.sha === sourceSha, 'release_branch_source_mismatch');
  const environment = await readGitHubSettings(fetchImpl, repository, '/environments/npm-release', githubToken);
  assertProtectedEnvironment(environment);
  // Repository protection and local policy do not prove npm package existence,
  // account 2FA, trust or the permitted publisher action.
  throw Error('npm_owner_setup_verification_required');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const artifact = process.argv[2]; requireCondition(Boolean(artifact), 'artifact_path_required');
    await checkReleasePreparation({ metadata: JSON.parse(readFileSync(new URL('../packages/intake-site-adapter/package.json', import.meta.url))), authority: JSON.parse(readFileSync(new URL('../release/adapter-release-authority.json', import.meta.url))), bytes: readFileSync(artifact), expectedDigest: process.env.REVIEWED_TARBALL_SHA256, sourceSha: process.env.GITHUB_SHA, reviewedSourceSha: process.env.REVIEWED_SOURCE_SHA, repository: process.env.GITHUB_REPOSITORY, githubToken: process.env.GITHUB_TOKEN, ref: process.env.GITHUB_REF, eventName: process.env.GITHUB_EVENT_NAME, actorId: process.env.GITHUB_ACTOR_ID, triggeringActor: process.env.GITHUB_TRIGGERING_ACTOR, runId: process.env.GITHUB_RUN_ID });
  } catch (error) { console.error(JSON.stringify({ ok: false, error: /^[a-z_]+$/.test(error.message) ? error.message : 'release_preparation_blocked' })); process.exitCode = 1; }
}
