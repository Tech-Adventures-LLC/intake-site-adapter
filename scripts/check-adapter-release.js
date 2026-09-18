import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

function requireCondition(condition, category) { if (!condition) throw Error(category); }
export function assertProtectedEnvironment(environment) {
  const review = environment?.protection_rules?.find(rule => rule.type === 'required_reviewers');
  requireCondition(review?.prevent_self_review === true && Array.isArray(review.reviewers) && review.reviewers.length > 0 && review.reviewers.every(item => ['User', 'Team'].includes(item.type) && Number.isInteger(item.reviewer?.id)), 'release_environment_unprotected');
  requireCondition(environment.deployment_branch_policy?.protected_branches === true && environment.deployment_branch_policy.custom_branch_policies === false, 'release_branch_policy_unverified');
}
export function assertReviewedArtifact({ bytes, expectedDigest, sourceSha, reviewedSourceSha }) {
  requireCondition(/^[a-f0-9]{40}$/.test(sourceSha ?? '') && sourceSha === reviewedSourceSha, 'release_source_mismatch');
  requireCondition(/^[a-f0-9]{64}$/.test(expectedDigest ?? '') && createHash('sha256').update(bytes).digest('hex') === expectedDigest, 'release_artifact_mismatch');
}
export async function checkReleasePreparation({ metadata, authority, bytes, expectedDigest, sourceSha, reviewedSourceSha, repository, fetchImpl = fetch, githubToken }) {
  assertReviewedArtifact({ bytes, expectedDigest, sourceSha, reviewedSourceSha });
  requireCondition(typeof repository === 'string' && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository), 'public_source_identity_missing');
  requireCondition(metadata.repository?.url === `git+https://github.com/${repository}.git` && authority.publicRepository === repository, 'public_source_identity_missing');
  requireCondition(authority.setupStatus === 'owner-reviewed' && authority.environment === 'npm-release', 'owner_setup_not_verified');
  requireCondition(typeof githubToken === 'string' && githubToken.length > 0, 'github_settings_access_missing');
  async function get(path) {
    const response = await fetchImpl(`https://api.github.com/repos/${repository}${path}`, { redirect: 'error', signal: AbortSignal.timeout(5000), headers: { authorization: `Bearer ${githubToken}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' } });
    requireCondition(response.ok, 'github_settings_unavailable');
    const reader = response.body.getReader(); const chunks = []; let size = 0;
    try { while (true) { const { value, done } = await reader.read(); if (done) break; size += value.byteLength; requireCondition(size <= 65536, 'github_settings_unavailable'); chunks.push(Buffer.from(value)); } }
    finally { reader.cancel().catch(() => {}); }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  }
  const repo = await get(''); requireCondition(repo.private === false && repo.full_name === repository, 'public_source_not_verified');
  const environment = await get('/environments/npm-release'); requireCondition(environment.name === 'npm-release', 'release_environment_unprotected'); assertProtectedEnvironment(environment);
  // No boolean in a local file substitutes for owner-side npm account/package,
  // 2FA and exact trusted-publisher action verification. First-package bootstrap
  // is unresolved. This preparation guard deliberately has no publish-ready exit.
  throw Error('npm_owner_setup_verification_required');
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const artifact = process.argv[2]; requireCondition(Boolean(artifact), 'artifact_path_required');
    await checkReleasePreparation({ metadata: JSON.parse(readFileSync(new URL('../packages/intake-site-adapter/package.json', import.meta.url))), authority: JSON.parse(readFileSync(new URL('../release/adapter-release-authority.json', import.meta.url))), bytes: readFileSync(artifact), expectedDigest: process.env.REVIEWED_TARBALL_SHA256, sourceSha: process.env.GITHUB_SHA, reviewedSourceSha: process.env.REVIEWED_SOURCE_SHA, repository: process.env.GITHUB_REPOSITORY, githubToken: process.env.GITHUB_TOKEN });
  } catch (error) { console.error(JSON.stringify({ ok: false, error: /^[a-z_]+$/.test(error.message) ? error.message : 'release_preparation_blocked' })); process.exitCode = 1; }
}
