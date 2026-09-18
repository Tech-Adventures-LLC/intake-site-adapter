import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyCanaryRoute } from '../packages/intake-site-adapter/verify-route.js';

const execute = promisify(execFile);
const adapter = new URL('../packages/intake-site-adapter/index.js', import.meta.url).href;
const cli = fileURLToPath(new URL('../packages/intake-site-adapter/verify-route.js', import.meta.url));
async function fixture(code, run) {
  const root = await mkdtemp(join(tmpdir(), 'adapter-verifier-'));
  try { await writeFile(join(root, 'route.mjs'), code); return await run(root); }
  finally { await rm(root, { recursive: true, force: true }); }
}
const validCode = `import { createCanaryHandler } from ${JSON.stringify(adapter)}; export default createCanaryHandler({source:'fixture-site',logger:null});`;
const verify = root => verifyCanaryRoute({ projectRoot: root, routePath: 'route.mjs', source: 'fixture-site' });

test('verifier exceptions expose a fixed category and never exception messages or console output', async () => {
  await fixture("console.log('synthetic-private-output'); throw Error('synthetic-private-exception');", async root => {
    await assert.rejects(() => verify(root), error => error.message === 'route_execution_failed');
    try {
      await execute(process.execPath, [cli, '--route', 'route.mjs', '--source', 'fixture-site'], { cwd: root, env: {}, timeout: 3000, maxBuffer: 4096 }); assert.fail('CLI must fail');
    } catch (error) {
      assert.equal(error.code, 1); assert.equal(error.stdout, '');
      assert.deepEqual(JSON.parse(error.stderr), { ok: false, error: 'route_execution_failed' });
    }
  });
});

test('verifier kills bounded import and handler hangs', async () => {
  for (const code of ["await new Promise(() => {});", "export default async () => new Promise(() => {});"]) {
    await fixture(code, async root => {
      const started = Date.now();
      await assert.rejects(() => verifyCanaryRoute({ projectRoot: root, routePath: 'route.mjs', source: 'fixture-site', timeoutMs: 150 }), /route_timeout/);
      assert.ok(Date.now() - started < 3000);
    });
  }
});

test('verifier isolates all environment and global mutations across concurrent invocations', async () => {
  const beforeFetch = globalThis.fetch;
  const beforeValue = process.env.ADAPTER_VERIFIER_PRIVATE;
  process.env.ADAPTER_VERIFIER_PRIVATE = 'synthetic-private-env';
  try {
    await fixture(`if (process.env.ADAPTER_VERIFIER_PRIVATE || process.env.INTAKE_SITE_TOKEN || process.env.DATABASE_URL || process.env.NODE_OPTIONS || process.env.HOME) throw Error('inherited'); process.env.ADAPTER_VERIFIER_PRIVATE='changed'; ${validCode}`, async root => {
      const results = await Promise.all([verify(root), verify(root)]);
      assert.ok(results.every(result => result.ok)); assert.equal(process.env.ADAPTER_VERIFIER_PRIVATE, 'synthetic-private-env'); assert.equal(globalThis.fetch, beforeFetch);
    });
  } finally { if (beforeValue === undefined) delete process.env.ADAPTER_VERIFIER_PRIVATE; else process.env.ADAPTER_VERIFIER_PRIVATE = beforeValue; }
});

test('verifier disables ordinary direct network and subprocess transports before route import', async () => {
  for (const code of ["import https from 'node:https'; https.get('https://example.invalid');", "import { spawn } from 'node:child_process'; spawn(process.execPath,['-e','process.exit(0)']);"]) {
    await fixture(code, root => assert.rejects(() => verify(root), /route_execution_failed/));
  }
});

test('verifier rejects rewritten acknowledged output even when HTTP status stays successful', async () => {
  await fixture(`import {createCanaryHandler} from ${JSON.stringify(adapter)}; const handler=createCanaryHandler({source:'fixture-site',logger:null}); export default async (req,res)=>handler(req,{...res,status(code){res.status(code);return this;},json(body){return res.json(body.ok?{...body,source_sha:'c'.repeat(40)}:body);}});`, root => assert.rejects(() => verify(root), /canary_release_evidence_mismatch/));
});

test('actual CLI validates arguments and succeeds only for a protected acknowledged route', async () => {
  await fixture(validCode, async root => {
    const { stdout, stderr } = await execute(process.execPath, [cli, '--route', 'route.mjs', '--source', 'fixture-site'], { cwd: root, env: {}, timeout: 3000, maxBuffer: 4096 });
    assert.equal(stderr, ''); const result = JSON.parse(stdout); assert.equal(result.ok, true); assert.equal(result.adapter_version, '1.1.0'); assert.equal(result.wrong_token_status, 401);
    await assert.rejects(() => execute(process.execPath, [cli, '--route', 'route.mjs', '--source', 'fixture-site', '--anything', 'secret'], { cwd: root, env: {}, timeout: 3000, maxBuffer: 4096 }), error => error.code === 1 && JSON.parse(error.stderr).error === 'invalid_arguments');
  });
});
