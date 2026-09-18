import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyCanaryRoute } from '../packages/intake-site-adapter/verify-route.js';

const projectRoot = fileURLToPath(new URL('..', import.meta.url));

test('promotion guard proves anonymous 401 and authenticated 200 for Vercel routes', async () => {
  const result = await verifyCanaryRoute({ projectRoot, routePath: 'qa/fixtures/canary-routes/vercel.js', source: 'fixture-site' });
  assert.equal(result.ok, true);
  assert.equal(result.style, 'vercel');
  assert.equal(result.anonymous_status, 401);
  assert.equal(result.authenticated_status, 200);
});

test('promotion guard proves the same contract for Web Request routes', async () => {
  const result = await verifyCanaryRoute({ projectRoot, routePath: 'qa/fixtures/canary-routes/web.js', source: 'fixture-site' });
  assert.equal(result.ok, true);
  assert.equal(result.style, 'web');
});

test('promotion guard blocks missing routes, public routes, and path traversal', async () => {
  await assert.rejects(() => verifyCanaryRoute({ projectRoot, routePath: 'api/missing.js', source: 'fixture-site' }), /route_not_found/);
  await assert.rejects(() => verifyCanaryRoute({ projectRoot, routePath: 'qa/fixtures/canary-routes/public.js', source: 'fixture-site' }), /anonymous_canary_not_protected/);
  await assert.rejects(() => verifyCanaryRoute({ projectRoot, routePath: '../outside.js', source: 'fixture-site' }), /route_path_outside_project/);
});

test('promotion guard rejects a route symlink that escapes the site project', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'intake-route-guard-'));
  const project = join(directory, 'site');
  const outside = join(directory, 'outside.js');
  await mkdir(join(project, 'api'), { recursive: true });
  await writeFile(outside, 'export default () => {};\n');
  await symlink(outside, join(project, 'api', 'intake-canary.js'));
  await assert.rejects(() => verifyCanaryRoute({ projectRoot: project, routePath: 'api/intake-canary.js', source: 'fixture-site' }), /route_path_outside_project/);
  await rm(directory, { recursive: true });
});
