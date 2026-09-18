#!/usr/bin/env node
import { fork } from 'node:child_process';
import { realpath, stat } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { ADAPTER_VERSION, CONTRACT_VERSION } from './index.js';

const failures = new Set(['route_execution_failed', 'route_timeout', 'canary_handler_export_missing', 'anonymous_canary_not_protected', 'wrong_token_canary_not_protected', 'unexpected_canary_transport', 'canary_release_evidence_mismatch', 'authenticated_canary_failed']);
function inside(base, target) { const relative = path.relative(base, target); return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative); }
async function resolveRoute(root, routePath) {
  if (typeof routePath !== 'string' || !/^[A-Za-z0-9_./-]{1,240}\.[cm]?js$/.test(routePath) || path.isAbsolute(routePath)) throw Error('route_path_must_be_relative');
  const resolvedRoot = path.resolve(root), resolvedRoute = path.resolve(resolvedRoot, routePath);
  if (!inside(resolvedRoot, resolvedRoute)) throw Error('route_path_outside_project');
  let realRoot, realRoute;
  try { [realRoot, realRoute] = await Promise.all([realpath(resolvedRoot), realpath(resolvedRoute)]); }
  catch { throw Error('route_not_found'); }
  if (!inside(realRoot, realRoute)) throw Error('route_path_outside_project');
  if (!(await stat(realRoute)).isFile()) throw Error('route_not_found');
  return realRoute;
}

export async function verifyCanaryRoute({ projectRoot = process.cwd(), routePath, source, timeoutMs = 5000 } = {}) {
  if (typeof source !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,79}$/.test(source)) throw Error('invalid_site_source');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000) throw Error('invalid_timeout');
  const route = await resolveRoute(projectRoot, routePath);
  return new Promise((resolve, reject) => {
    const child = fork(new URL('./verify-route-worker.js', import.meta.url), [], {
      execArgv: [], env: { VERCEL: '1', VERCEL_ENV: 'preview', VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40), INTAKE_CANARY_PROBE_TOKEN: `probe_${'p'.repeat(40)}`, INTAKE_CANARY_TOKEN: `canary_${'c'.repeat(40)}` },
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    });
    let result, failure;
    const timer = setTimeout(() => { failure = 'route_timeout'; child.kill('SIGKILL'); }, timeoutMs);
    child.on('error', () => { failure = 'route_execution_failed'; });
    child.on('message', message => {
      if (message?.ok === true && ['web', 'vercel'].includes(message.style)) result = message.style;
      else failure = failures.has(message?.error) ? message.error : 'route_execution_failed';
    });
    child.on('close', code => {
      clearTimeout(timer);
      if (failure || code !== 0 || !result) return reject(Error(failure ?? 'route_execution_failed'));
      resolve({ ok: true, route: routePath, style: result, anonymous_status: 401, wrong_token_status: 401, authenticated_status: 200, source, contract_version: CONTRACT_VERSION, adapter_version: ADAPTER_VERSION, source_sha: 'a'.repeat(40), environment: 'preview' });
    });
    child.send({ route, source });
  });
}
async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== '--route' || args[2] !== '--source') throw Error('invalid_arguments');
  process.stdout.write(`${JSON.stringify(await verifyCanaryRoute({ routePath: args[1], source: args[3] }))}\n`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  main().catch(error => {
    const allowed = new Set([...failures, 'invalid_arguments', 'invalid_site_source', 'invalid_timeout', 'route_not_found', 'route_path_must_be_relative', 'route_path_outside_project']);
    process.stderr.write(`${JSON.stringify({ ok: false, error: allowed.has(error.message) ? error.message : 'route_execution_failed' })}\n`); process.exitCode = 1;
  });
}
