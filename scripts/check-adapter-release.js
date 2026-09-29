import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const PUBLIC_REPOSITORY = 'Tech-Adventures-LLC/intake-site-adapter';
const PUBLIC_REPOSITORY_ID = 1375264810;
const OWNER_ID = 142938424;
const OWNER_LOGIN = 'ii-am-modiify';
const REQUEST_TIMEOUT_MS = 5000;
const PACKAGE_NAME = '@tech-adventures-llc/intake-site-adapter';
const USABLE_VERSION = '2.0.0';
const USABLE_BYTES = 19629;
const USABLE_SHA256 = '79bde19a1146871f2b87ae237bc469d31c42cc28ecd7cfd51772d9691f499676';
const USABLE_SRI = 'sha512-esndSi0gwacIvxMbiKFkXQOYaEyGg/SuSvgCNV+kf1LHchhqZB0fm7R5TCnVfMOsFUNhdq9r2i8iOGnpMG9cng==';
const PREVIOUS_VERSION = '1.1.0';
const PREVIOUS_BYTES = 19323;
const PREVIOUS_SHA256 = 'c2b2fbe7e182bda697178b817e57ded088e7d046c9de530674670e83fa516d8b';
const PREVIOUS_SRI = 'sha512-B6zv2z66z7TKrp7GVtF3fI3ZtAQLEG7DUwVCT6iMoRO1SXZsxIMYLS+BHedQw4Km9c/4WQfnoG0cTorgIHLfOA==';
const BOOTSTRAP_VERSION = '0.0.0-bootstrap.0';
const BOOTSTRAP_BYTES = 4535;
const BOOTSTRAP_SHA256 = '386d45bc298d57fc18b24e04ebb01194eb5f98f4ebf101d2572efe48070fbdf6';
const BOOTSTRAP_SRI = 'sha512-E6/4J6azPc+J6UBs0dv/recGgbW4gUsOzaGSW5g4a7I5OIY687EhNfgjuc1EWJeE/pu7UxlxzYDOWhOHL1L/qw==';
const REGISTRY_METADATA_URL = 'https://registry.npmjs.org/@tech-adventures-llc%2fintake-site-adapter';
const REGISTRY_TAGS_URL = 'https://registry.npmjs.org/-/package/@tech-adventures-llc%2fintake-site-adapter/dist-tags';
const PREVIOUS_URL = 'https://registry.npmjs.org/@tech-adventures-llc/intake-site-adapter/-/intake-site-adapter-1.1.0.tgz';
const BOOTSTRAP_URL = 'https://registry.npmjs.org/@tech-adventures-llc/intake-site-adapter/-/intake-site-adapter-0.0.0-bootstrap.0.tgz';
const digest = (bytes, algorithm = 'sha256', encoding = 'hex') => createHash(algorithm).update(bytes).digest(encoding);
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
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
    && authority.npmPackage === '@tech-adventures-llc/intake-site-adapter' && authority.version === USABLE_VERSION
    && authority.intendedPublisherAction === 'publish' && authority.intendedDistTag === 'latest' && authority.reviewPolicy?.mode === 'sole-owner'
    && reviewer?.type === 'User' && reviewer.id === OWNER_ID && reviewer.login === OWNER_LOGIN,
  'release_authority_mismatch');
  requireCondition(authority.reviewedArtifact?.bytes === USABLE_BYTES && authority.reviewedArtifact?.sha256 === USABLE_SHA256 && authority.reviewedArtifact?.integrity === USABLE_SRI
    && authority.bootstrap?.version === BOOTSTRAP_VERSION && authority.bootstrap?.bytes === BOOTSTRAP_BYTES
    && authority.bootstrap?.sha256 === BOOTSTRAP_SHA256 && authority.bootstrap?.integrity === BOOTSTRAP_SRI
    && authority.previousRelease?.version === PREVIOUS_VERSION && authority.previousRelease?.bytes === PREVIOUS_BYTES
    && authority.previousRelease?.sha256 === PREVIOUS_SHA256 && authority.previousRelease?.integrity === PREVIOUS_SRI
    && Array.isArray(authority.registryBaseline?.versions) && authority.registryBaseline.versions.length === 2
    && authority.registryBaseline.versions[0] === BOOTSTRAP_VERSION && authority.registryBaseline.versions[1] === PREVIOUS_VERSION
    && isObject(authority.registryBaseline.distTags) && Object.keys(authority.registryBaseline.distTags).length === 2
    && authority.registryBaseline.distTags.bootstrap === BOOTSTRAP_VERSION && authority.registryBaseline.distTags.latest === PREVIOUS_VERSION
    && !Object.hasOwn(authority, 'tagExceptionExpiresAt'), 'release_authority_mismatch');
}

function assertValidClock(now) {
  const current = now();
  requireCondition(current instanceof Date && Number.isFinite(current.getTime()), 'clock_invalid');
}

async function readBoundedResponse(fetchImpl, url, { headers, credentials, maxBytes, category, json = true }) {
  const controller = new AbortController();
  let timeout; let activeReader;
  try {
    return await Promise.race([
      (async () => {
        const response = await fetchImpl(url, { redirect: 'error', signal: controller.signal, headers, credentials });
        requireCondition(response?.body?.getReader, category);
        const reader = response.body.getReader();
        activeReader = reader;
        const chunks = []; let size = 0;
        try {
          requireCondition(!controller.signal.aborted && response.status === 200 && !response.redirected, category);
          while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            size += value.byteLength;
            requireCondition(size <= maxBytes, category);
            chunks.push(Buffer.from(value));
          }
        } finally { activeReader = undefined; reader.cancel().catch(() => {}); }
        const bytes = Buffer.concat(chunks);
        if (!json) return bytes;
        const result = JSON.parse(bytes.toString('utf8'));
        requireCondition(isObject(result), category);
        return result;
      })(),
      new Promise((_, reject) => { timeout = setTimeout(() => { controller.abort(); activeReader?.cancel().catch(() => {}); reject(Error(category)); }, REQUEST_TIMEOUT_MS); }),
    ]);
  } catch { throw Error(category); }
  finally { clearTimeout(timeout); controller.abort(); activeReader?.cancel().catch(() => {}); }
}

function readGitHubSettings(fetchImpl, repository, path, githubToken) {
  return readBoundedResponse(fetchImpl, `https://api.github.com/repos/${repository}${path}`, {
    headers: { authorization: `Bearer ${githubToken}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' },
    maxBytes: 65536, category: 'github_settings_unavailable',
  });
}

function assertRegistryBaselineTags(tags) {
  requireCondition(isObject(tags) && Object.keys(tags).length === 2
    && tags.bootstrap === BOOTSTRAP_VERSION && tags.latest === PREVIOUS_VERSION, 'npm_registry_tags_mismatch');
}

async function assertRegistryPrerequisites(fetchImpl) {
  // Public registry requests never receive GitHub credentials or local npm auth.
  const anonymous = { credentials: 'omit', headers: { accept: 'application/json' } };
  const metadata = await readBoundedResponse(fetchImpl, REGISTRY_METADATA_URL, {
    ...anonymous, maxBytes: 1048576, category: 'npm_registry_metadata_unavailable',
  });
  requireCondition(metadata.name === PACKAGE_NAME, 'npm_registry_identity_mismatch');
  requireCondition(isObject(metadata.versions) && Object.keys(metadata.versions).length === 2
    && Object.hasOwn(metadata.versions, BOOTSTRAP_VERSION) && Object.hasOwn(metadata.versions, PREVIOUS_VERSION), 'npm_registry_version_mismatch');
  const retained = [
    { version: BOOTSTRAP_VERSION, bytes: BOOTSTRAP_BYTES, sha256: BOOTSTRAP_SHA256, integrity: BOOTSTRAP_SRI,
      url: BOOTSTRAP_URL, maxBytes: 8192, category: 'npm_bootstrap' },
    { version: PREVIOUS_VERSION, bytes: PREVIOUS_BYTES, sha256: PREVIOUS_SHA256, integrity: PREVIOUS_SRI,
      url: PREVIOUS_URL, maxBytes: 32768, category: 'npm_previous' },
  ];
  for (const artifact of retained) {
    const published = metadata.versions[artifact.version];
    requireCondition(published?.name === PACKAGE_NAME && published.version === artifact.version, 'npm_registry_identity_mismatch');
    requireCondition(published.dist?.integrity === artifact.integrity, `${artifact.category}_integrity_mismatch`);
  }
  assertRegistryBaselineTags(metadata['dist-tags']);
  const tags = await readBoundedResponse(fetchImpl, REGISTRY_TAGS_URL, {
    ...anonymous, maxBytes: 65536, category: 'npm_registry_tags_unavailable',
  });
  assertRegistryBaselineTags(tags);
  // Both previously published artifacts remain immutable. Ignore dist.tarball:
  // neither retained version's metadata may choose a network destination.
  for (const artifact of retained) {
    const bytes = await readBoundedResponse(fetchImpl, artifact.url, {
      credentials: 'omit', headers: { accept: 'application/octet-stream' },
      maxBytes: artifact.maxBytes, category: `${artifact.category}_tarball_unavailable`, json: false,
    });
    requireCondition(bytes.length === artifact.bytes && digest(bytes) === artifact.sha256
      && `sha512-${digest(bytes, 'sha512', 'base64')}` === artifact.integrity, `${artifact.category}_artifact_mismatch`);
  }

}

export async function checkReleasePreparation({ metadata, authority, bytes, expectedDigest, sourceSha, reviewedSourceSha, repository, fetchImpl = fetch, githubToken, ref, eventName, actorId, triggeringActor, runId, now = () => new Date() }) {
  assertReviewedArtifact({ bytes, expectedDigest, sourceSha, reviewedSourceSha });
  requireCondition(repository === PUBLIC_REPOSITORY && metadata?.repository?.type === 'git'
    && metadata.repository.url === `git+https://github.com/${PUBLIC_REPOSITORY}.git`
    && metadata.repository.directory === 'packages/intake-site-adapter', 'public_source_identity_missing');
  requireCondition(metadata.name === PACKAGE_NAME && metadata.version === USABLE_VERSION, 'release_package_mismatch');
  requireCondition(bytes.length === USABLE_BYTES && expectedDigest === USABLE_SHA256 && `sha512-${digest(bytes, 'sha512', 'base64')}` === USABLE_SRI, 'release_artifact_mismatch');
  assertAuthority(authority);
  assertValidClock(now);
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
  await assertRegistryPrerequisites(fetchImpl);
  assertValidClock(now);
  // Historical setup evidence is not a runtime trust/2FA check. Current npm trust
  // is enforced only by the separately protected OIDC publication operation.
  return {
    ok: true, status: 'release_prerequisites_verified', npm_live_trust_verified: false,
    publication_verified: false, provenance_verified: false, owner_approval_verified: false,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const artifact = process.argv[2]; requireCondition(Boolean(artifact), 'artifact_path_required');
    const result = await checkReleasePreparation({ metadata: JSON.parse(readFileSync(new URL('../packages/intake-site-adapter/package.json', import.meta.url))), authority: JSON.parse(readFileSync(new URL('../release/adapter-release-authority.json', import.meta.url))), bytes: readFileSync(artifact), expectedDigest: process.env.REVIEWED_TARBALL_SHA256, sourceSha: process.env.GITHUB_SHA, reviewedSourceSha: process.env.REVIEWED_SOURCE_SHA, repository: process.env.GITHUB_REPOSITORY, githubToken: process.env.GITHUB_TOKEN, ref: process.env.GITHUB_REF, eventName: process.env.GITHUB_EVENT_NAME, actorId: process.env.GITHUB_ACTOR_ID, triggeringActor: process.env.GITHUB_TRIGGERING_ACTOR, runId: process.env.GITHUB_RUN_ID });
    console.log(JSON.stringify(result));
  } catch (error) { console.error(JSON.stringify({ ok: false, error: /^[a-z_]+$/.test(error.message) ? error.message : 'release_preparation_blocked' })); process.exitCode = 1; }
}
