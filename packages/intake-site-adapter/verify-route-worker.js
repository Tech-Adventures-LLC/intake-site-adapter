// Internal subprocess entrypoint. Checks trusted local code; this is not an OS sandbox.
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { pathToFileURL } from 'node:url';
import { ADAPTER_VERSION, CONTRACT_VERSION } from './index.js';

const blocked = () => { throw Error('network_or_process_disabled'); };
http.request = http.get = https.request = https.get = blocked;
net.connect = net.createConnection = net.Socket.prototype.connect = tls.connect = dgram.createSocket = blocked;
for (const key of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) childProcess[key] = blocked;
syncBuiltinESMExports();
const transmit = process.send?.bind(process);
const exit = process.exit.bind(process);
const requestToken = process.env.INTAKE_CANARY_PROBE_TOKEN;
const canaryToken = process.env.INTAKE_CANARY_TOKEN;
const sourceSha = process.env.VERCEL_GIT_COMMIT_SHA;
const release = 'b'.repeat(40);
const checkedAt = '2026-01-01T00:00:00.000Z';
class VerificationFailure extends Error {}
const fail = category => { throw new VerificationFailure(category); };
function recorder() { return { code: 0, body: null, headers: {}, setHeader(k, v) { this.headers[k.toLowerCase()] = String(v); }, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } }; }
function selectHandler(module) {
  if (typeof module.POST === 'function') return { style: 'web', handler: module.POST };
  for (const name of ['default', 'canary', 'handler']) if (typeof module[name] === 'function') return { style: 'vercel', handler: module[name] };
  fail('canary_handler_export_missing');
}
async function invoke({ style, handler }, authorization) {
  if (style === 'web') {
    const response = await handler(new Request('https://site.invalid/api/intake-canary', { method: 'POST', headers: authorization ? { authorization } : {} }));
    const reader = response.body?.getReader(); let size = 0; const chunks = [];
    try { while (reader) { const { value, done } = await reader.read(); if (done) break; size += value.byteLength; if (size > 8192) fail('canary_release_evidence_mismatch'); chunks.push(Buffer.from(value)); } }
    finally { reader?.cancel().catch(() => {}); }
    return { status: response.status, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) };
  }
  const response = recorder(); await handler({ method: 'POST', headers: authorization ? { authorization } : {} }, response);
  return { status: response.code, body: response.body };
}
async function verify({ route, source }) {
  const command = { source, contract_version: CONTRACT_VERSION, adapter_version: ADAPTER_VERSION, source_sha: sourceSha, environment: 'preview' };
  let calls = 0;
  globalThis.fetch = async (url, options) => {
    calls++;
    if (calls > 1 || String(url) !== 'https://intake.fltechadventures.com/v1/canary' || options?.method !== 'POST' || options.redirect !== 'error') fail('unexpected_canary_transport');
    const headers = new Headers(options.headers);
    if (headers.get('authorization') !== `Bearer ${canaryToken}` || headers.get('x-intake-contract') !== CONTRACT_VERSION || headers.get('content-type') !== 'application/json' || typeof options.body !== 'string' || Buffer.byteLength(options.body) > 1024) fail('unexpected_canary_transport');
    const input = JSON.parse(options.body);
    if (Object.keys(input).length !== Object.keys(command).length || Object.entries(command).some(([key, value]) => input[key] !== value)) fail('canary_release_evidence_mismatch');
    return Response.json({ ok: true, site: source, source, checked_at: checkedAt, release, ...command, result_category: 'observed', duration_ms: null }, { headers: { 'x-intake-contract': CONTRACT_VERSION, 'x-intake-release': release } });
  };
  const selected = selectHandler(await import(pathToFileURL(route).href));
  const anonymous = await invoke(selected);
  if (anonymous.status !== 401 || calls !== 0) fail('anonymous_canary_not_protected');
  const incorrect = await invoke(selected, `Bearer wrong_${'w'.repeat(40)}`);
  if (incorrect.status !== 401 || calls !== 0) fail('wrong_token_canary_not_protected');
  const authenticated = await invoke(selected, `Bearer ${requestToken}`);
  if (authenticated.status !== 200 || calls !== 1) fail('authenticated_canary_failed');
  const expected = { ok: true, site: source, checked_at: checkedAt, release, contract_version: CONTRACT_VERSION, adapter_version: ADAPTER_VERSION, source_sha: sourceSha, environment: 'preview' };
  if (!authenticated.body || Object.keys(authenticated.body).length !== Object.keys(expected).length || Object.entries(expected).some(([key, value]) => authenticated.body[key] !== value)) fail('canary_release_evidence_mismatch');
  return { ok: true, style: selected.style };
}
process.on('message', input => {
  verify(input).then(result => transmit(result, () => exit(0)), error => transmit({ ok: false, error: error instanceof VerificationFailure ? error.message : 'route_execution_failed' }, () => exit(1)));
});
