import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { createIntakeHandler, createCanaryHandler, createWebHandler, ADAPTER_VERSION, CONTRACT_VERSION } from '../packages/intake-site-adapter/index.js';

const uuid = '123e4567-e89b-42d3-a456-426614174000';
const sha = 'a'.repeat(40), release = 'b'.repeat(40);
const now = Date.parse('2026-09-17T12:00:00Z');
const config = { formMap: { contact: { name: 'name', email: 'email', phone: 'phone' } }, turnstile: { action: 'contact', allowedHostnames: ['example.com'] }, clock: () => now, logger: null };
const body = { name: 'Synthetic Visitor', email: 'visitor@example.com', turnstile_token: 'synthetic-challenge' };
const headers = { 'content-type': 'application/json', 'idempotency-key': uuid, 'x-vercel-forwarded-for': '192.0.2.1' };
const recorder = () => ({ code: 0, body: null, headers: {}, setHeader(k, v) { this.headers[k.toLowerCase()] = v; }, status(v) { this.code = v; return this; }, json(v) { this.body = v; return this; } });
const protocol = { 'x-intake-contract': CONTRACT_VERSION, 'x-intake-release': release };
const lead = (data = {}, status = 202, extra = {}) => Response.json({ ok: true, lead_id: uuid, status: 'received', duplicate: false, ...data }, { status, headers: { ...protocol, ...extra } });
const challenge = (data = {}) => Response.json({ success: true, action: 'contact', hostname: 'example.com', challenge_ts: new Date(now).toISOString(), ...data });
const canary = (data = {}, extra = {}) => Response.json({ ok: true, site: 'fixture-site', source: 'fixture-site', checked_at: new Date(now).toISOString(), release, contract_version: CONTRACT_VERSION, adapter_version: ADAPTER_VERSION, source_sha: sha, environment: 'preview', result_category: 'observed', duration_ms: null, ...data }, { headers: { ...protocol, ...extra } });
async function environment(fn, overrides = {}) {
  const values = { VERCEL: '1', TURNSTILE_SECRET_KEY: 'synthetic-challenge-secret-xxxxxxxx', INTAKE_SITE_TOKEN: 'synthetic-lead-token-xxxxxxxxxxxxxxxxxxxx', INTAKE_CANARY_TOKEN: 'synthetic-canary-token-xxxxxxxxxxxxxxxxxx', INTAKE_CANARY_PROBE_TOKEN: 'synthetic-probe-token-xxxxxxxxxxxxxxxxxxx', VERCEL_ENV: 'preview', VERCEL_GIT_COMMIT_SHA: sha, SOURCE_SHA: '', ...overrides };
  const old = Object.fromEntries(Object.keys(values).map(k => [k, process.env[k]]));
  Object.assign(process.env, values);
  try { return await fn(); } finally { for (const [k, v] of Object.entries(old)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
}
let client = 1;
async function invoke(handler, input = body, inputHeaders = headers) { const res = recorder(); await handler({ method: 'POST', headers: inputHeaders === headers ? { ...headers, 'x-vercel-forwarded-for': `198.51.100.${client++}` } : inputHeaders, body: input }, res); return res; }
const ajv = new Ajv({ strict: true }); addFormats(ajv);
const validateCommand = ajv.compile(JSON.parse(readFileSync(new URL('../contracts/intake/v1/lead-command.schema.json', import.meta.url))));

test('all bounded P01 detail and attribution fields map to a valid emitted command', async () => environment(async () => {
  const schema = validateCommand.schema;
  const input = { ...body, phone: '202-555-0101', details: {}, attribution: {}, consent: { phone_contact: true, sms: true, disclosure_version: 'fixture-v1' } };
  const formMap = structuredClone(config.formMap);
  for (const section of ['details', 'attribution', 'consent']) {
    formMap[section] = {};
    for (const [key, definition] of Object.entries(schema.properties[section].properties)) {
      if (section !== 'consent') input[section][key] = 'x'.repeat(definition.maxLength);
      formMap[section][key] = `${section}.${key}`;
    }
  }
  let emitted;
  const handler = createIntakeHandler({ ...config, formMap, fetchImpl: async (url, options) => {
    if (url.includes('turnstile')) return challenge();
    emitted = JSON.parse(options.body); assert.equal(options.headers['x-intake-contract'], CONTRACT_VERSION); return lead();
  } });
  assert.equal((await invoke(handler, input)).code, 202);
  assert.equal(validateCommand(emitted), true, JSON.stringify(validateCommand.errors));
  assert.deepEqual(emitted.details, input.details); assert.deepEqual(emitted.attribution, input.attribution);
}));

test('mapped types, bounds and consent fail before any transport', async () => environment(async () => {
  for (const mutation of [{ name: 3 }, { name: 'x'.repeat(161) }, { email: 'invalid' }, { details: { notes: 'x'.repeat(1201) } }, { details: { notes: false } }, { consent: { sms: true } }, { consent: { phone_contact: true, disclosure_version: 'x' }, phone: '  ' }, { consent: { disclosure_version: 'x' } }]) {
    const handler = createIntakeHandler({ ...config, formMap: { ...config.formMap, details: { notes: 'details.notes' }, consent: { sms: 'consent.sms', phone_contact: 'consent.phone_contact', disclosure_version: 'consent.disclosure_version' } }, fetchImpl: async () => assert.fail('invalid command must not leave site') });
    assert.equal((await invoke(handler, { ...body, ...mutation })).code, 400);
  }
}));

test('mapped consent booleans reject supplied invalid types without dropping empty strings', async () => environment(async () => {
  for (const field of ['contact_request', 'phone_contact', 'sms']) {
    for (const value of ['', null, 'false', 'true', 0, 1]) {
      const handler = createIntakeHandler({ ...config, formMap: { ...config.formMap, consent: { [field]: 'selected' } }, fetchImpl: async () => assert.fail('invalid mapped consent must fail before transport') });
      const result = await invoke(handler, { ...body, selected: value });
      assert.equal(result.code, 400, `${field}:${JSON.stringify(value)}`); assert.equal(result.body.error, 'invalid_request');
    }
    for (const value of [undefined, false, true]) {
      let emitted;
      const consent = value === true && field !== 'contact_request' ? { phone_contact: { literal: true }, disclosure_version: { literal: 'synthetic-v1' } } : {};
      const handler = createIntakeHandler({ ...config, formMap: { ...config.formMap, details: { company: 'company' }, consent: { ...consent, [field]: 'selected' } }, fetchImpl: async (url, options) => {
        if (url.includes('turnstile')) return challenge(); emitted = JSON.parse(options.body); return lead();
      } });
      const result = await invoke(handler, { ...body, phone: '+12025550101', selected: value, company: '' });
      assert.equal(result.code, 202); assert.equal(validateCommand(emitted), true, JSON.stringify(validateCommand.errors));
      assert.equal(emitted.consent?.[field], value); assert.equal(emitted.details?.company, undefined);
    }
  }
  const literal = createIntakeHandler({ ...config, formMap: { ...config.formMap, consent: { contact_request: { literal: '' } } }, fetchImpl: async () => assert.fail('invalid literal consent must fail before transport') });
  assert.equal((await invoke(literal)).code, 400);
  assert.throws(() => createIntakeHandler({ ...config, formMap: { ...config.formMap, metadata: { test: 'selected' } } }), /unsupported formMap section/);
}));

test('lead acknowledgement requires status and duplicate to agree before browser success', async () => environment(async () => {
  for (const [status, duplicate, expected] of [[200, false, 503], [202, true, 503], [200, true, 200], [202, false, 202]]) {
    const keys = [], logs = [];
    const handler = createIntakeHandler({ ...config, logger: { info: entry => logs.push(entry) }, sleep: async () => assert.fail('a malformed success must not be retried'), fetchImpl: async (url, options) => {
      if (url.includes('turnstile')) return challenge(); keys.push(options.headers['idempotency-key']); return lead({ duplicate, private_extra: 'private-upstream-marker' }, status);
    } });
    const result = await invoke(handler); assert.equal(result.code, expected); assert.deepEqual(keys, [uuid]);
    if (expected === 503) { assert.equal(result.body.ok, false); assert.equal(result.body.error, 'temporarily_unavailable'); assert.match(result.body.request_id, /^[0-9a-f-]{36}$/); }
    else assert.deepEqual(result.body, { ok: true, lead_id: uuid, status: 'received', duplicate });
    assert.doesNotMatch(JSON.stringify([result.body, logs]), /private-upstream-marker/);
  }
}));

test('unsafe request identifiers never reach errors or logs; valid UUIDs survive', async () => environment(async () => {
  for (const requestId of ['person@example.com', 'Bearer private-value', 'private\nvalue', ['private'], 'x'.repeat(400), uuid]) {
    const logs = [];
    const res = await invoke(createIntakeHandler({ ...config, logger: { info: e => logs.push(e) } }), {}, { ...headers, 'idempotency-key': '', 'x-request-id': requestId });
    assert.match(logs[0].request_id, /^[0-9a-f-]{36}$/);
    assert.equal(res.body.request_id, logs[0].request_id);
    if (requestId === uuid) assert.equal(logs[0].request_id, uuid);
    assert.doesNotMatch(JSON.stringify([res.body, logs]), /private|person@|xxxx/);
  }
}));

test('safe success validates fields and response protocol acknowledgement', async () => environment(async () => {
  const invalid = [() => lead({ lead_id: 'private@example.com' }), () => lead({ status: 'provider-secret' }), () => lead({ duplicate: 'yes' }), () => lead({ ok: false }), () => Response.json({ ok: true }), () => lead({}, 201), () => lead({}, 202, { 'x-intake-contract': 'wrong' }), () => lead({}, 202, { 'x-intake-release': 'untracked' }), () => Response.json({ ok: true, lead_id: uuid, status: 'received', duplicate: false })];
  for (const result of invalid) {
    const res = await invoke(createIntakeHandler({ ...config, fetchImpl: async url => url.includes('turnstile') ? challenge() : result() }));
    assert.equal(res.code, 503); assert.equal(res.body.error, 'temporarily_unavailable'); assert.doesNotMatch(JSON.stringify(res.body), /private|provider-secret/);
  }
  const res = await invoke(createIntakeHandler({ ...config, fetchImpl: async url => url.includes('turnstile') ? challenge() : lead({ secret: 'not-forwarded' }) }));
  assert.deepEqual(res.body, { ok: true, lead_id: uuid, status: 'received', duplicate: false });
}));

test('canary requires acknowledged site, contract, adapter, SHA, environment and immutable API release', async () => environment(async () => {
  for (const field of ['site', 'contract_version', 'adapter_version', 'source_sha', 'environment', 'release', 'checked_at']) {
    for (const value of [undefined, 'wrong']) {
      const handler = createCanaryHandler({ source: 'fixture-site', logger: null, fetchImpl: async (_url, options) => {
        assert.equal(options.headers['x-intake-contract'], CONTRACT_VERSION); return canary({ [field]: value });
      } });
      assert.equal((await invoke(handler, undefined, { authorization: `Bearer ${process.env.INTAKE_CANARY_PROBE_TOKEN}` })).code, 502, field);
    }
  }
  for (const values of [{}, { 'x-intake-contract': 'wrong' }, { 'x-intake-release': 'c'.repeat(40) }]) {
    const handler = createCanaryHandler({ source: 'fixture-site', logger: null, fetchImpl: async () => canary({}, values) });
    assert.equal((await invoke(handler, undefined, { authorization: `Bearer ${process.env.INTAKE_CANARY_PROBE_TOKEN}` })).code, Object.keys(values).length ? 502 : 200);
  }
}));

test('production requires Git authority while controlled preview allows SOURCE_SHA', async () => environment(async () => {
  const handler = createCanaryHandler({ source: 'fixture-site', logger: null, fetchImpl: async () => assert.fail('no Git source') });
  assert.equal((await invoke(handler, undefined, { authorization: `Bearer ${process.env.INTAKE_CANARY_PROBE_TOKEN}` })).code, 503);
}, { VERCEL_ENV: 'production', VERCEL_GIT_COMMIT_SHA: '', SOURCE_SHA: sha }));

test('every canary error exposes a safe request UUID through Node and Web wrappers', async () => environment(async () => {
  const validateError = new Ajv({ strict: true }).compile(JSON.parse(readFileSync(new URL('../contracts/intake/v1/error-response.schema.json', import.meta.url))));
  const handler = createCanaryHandler({ source: 'fixture-site', logger: null, fetchImpl: async () => canary({ site: 'mismatch' }) });
  const authorization = `Bearer ${process.env.INTAKE_CANARY_PROBE_TOKEN}`;
  for (const [method, authorized, configured, expectedStatus] of [['GET', true, true, 405], ['POST', false, true, 401], ['POST', true, false, 503], ['POST', true, true, 502]]) {
    for (const requestId of [uuid, 'person@example.com', ['private'], 'Bearer private', 'x'.repeat(200)]) {
      process.env.VERCEL_GIT_COMMIT_SHA = configured ? sha : '';
      const result = recorder();
      await handler({ method, headers: { ...(authorized ? { authorization } : {}), 'x-request-id': requestId } }, result);
      assert.equal(result.code, expectedStatus); assert.equal(validateError(result.body), true);
      assert.match(result.body.request_id, /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
      if (requestId === uuid) assert.equal(result.body.request_id, uuid);
      assert.doesNotMatch(JSON.stringify(result.body), /private|person@|xxxx/);
    }
  }
  const response = await createWebHandler(handler)(new Request('https://example.com/api/canary', { method: 'POST', headers: { 'x-request-id': uuid } }));
  assert.equal(response.status, 401); const output = await response.json(); assert.equal(validateError(output), true); assert.equal(output.request_id, uuid);
}));

test('Web requests enforce a streamed byte cap and do not read unauthorized canary input', async () => environment(async () => {
  let pulls = 0, cancelled = false;
  const stream = new ReadableStream({ pull(controller) { pulls++; if (pulls > 7) controller.close(); else controller.enqueue(new Uint8Array(8192)); }, cancel() { cancelled = true; } }, { highWaterMark: 0 });
  const POST = createWebHandler(createIntakeHandler({ ...config, fetchImpl: async () => assert.fail('oversized input') }));
  const response = await POST(new Request('https://example.com/api/intake', { method: 'POST', headers, body: stream, duplex: 'half' }));
  assert.equal(response.status, 413); assert.ok(pulls <= 5); assert.equal(cancelled, true);
  let read = false;
  const input = new ReadableStream({ pull() { read = true; throw Error('must not read'); } }, { highWaterMark: 0 });
  const canaryPost = createWebHandler(createCanaryHandler({ source: 'fixture-site', logger: null, fetchImpl: async () => assert.fail('unauthorized') }));
  assert.equal((await canaryPost(new Request('https://example.com/api/canary', { method: 'POST', body: input, duplex: 'half' }))).status, 401);
  assert.equal(read, false);
}));

test('upstream streamed bodies are bounded and cancelled', async () => environment(async () => {
  let cancelled = false, pulls = 0;
  const handler = createIntakeHandler({ ...config, fetchImpl: async url => url.includes('turnstile') ? challenge() : new Response(new ReadableStream({ pull(c) { pulls++; if (pulls > 7) c.close(); else c.enqueue(new Uint8Array(4096)); }, cancel() { cancelled = true; } }, { highWaterMark: 0 }), { status: 202, headers: protocol }) });
  const res = await invoke(handler); assert.equal(res.code, 503); assert.equal(cancelled, true); assert.ok(pulls <= 9);
}));

test('hosting boundary fails closed for absent, spoofed and malformed client identity; rate limit is shared by handler instances', async () => environment(async () => {
  const fetchImpl = async () => assert.fail('must not fetch');
  for (const value of [undefined, ['192.0.2.1'], '192.0.2.1, 192.0.2.2', 'private@example.com', 'fe80::1%en0']) {
    const res = await invoke(createIntakeHandler({ ...config, fetchImpl }), body, { ...headers, 'x-vercel-forwarded-for': value, 'x-forwarded-for': '192.0.2.2' });
    assert.equal(res.code, 503);
  }
  process.env.VERCEL = '';
  assert.equal((await invoke(createIntakeHandler({ ...config, fetchImpl }))).code, 503);
  process.env.VERCEL = '1';
  for (let count = 0; count < 11; count++) {
    const handler = createIntakeHandler({ ...config, fetchImpl: async url => url.includes('turnstile') ? challenge() : lead() });
    const res = await invoke(handler, body, { ...headers, 'x-vercel-forwarded-for': '192.0.2.200' });
    assert.equal(res.code, count < 10 ? 202 : 429);
  }
}));

test('all contract retry and permanent categories have bounded stable-key behavior', async () => environment(async () => {
  for (const status of [400, 413, 415, 422, 401, 403, 409, 429, 500, 502, 503, 504]) {
    let calls = 0; const keys = [], delays = [];
    const handler = createIntakeHandler({ ...config, sleep: async ms => { delays.push(ms); }, fetchImpl: async (url, options) => {
      if (url.includes('turnstile')) return challenge(); calls++; keys.push(options.headers['idempotency-key']); return Response.json({ ok: false, error: 'private' }, { status, headers: { ...protocol, 'retry-after': '600' } });
    } });
    const res = await invoke(handler, body, { ...headers, 'x-vercel-forwarded-for': `192.0.2.${status % 200 + 10}` });
    const retry = [429, 500, 502, 503, 504].includes(status);
    assert.equal(calls, retry ? 3 : 1, String(status)); assert.ok(keys.every(k => k === uuid)); assert.equal(delays.length, retry ? 2 : 0); assert.ok(delays.every(ms => ms > 0 && ms <= 2000)); assert.equal(res.body.ok, false);
  }
}));

test('lead success rejects a non-string UUID instead of coercing it into a public response', async () => environment(async () => {
  for (const lead_id of [[uuid], { toString: () => uuid }]) {
    const res = await invoke(createIntakeHandler({ ...config, fetchImpl: async url => url.includes('turnstile') ? challenge() : lead({ lead_id }) }));
    assert.equal(res.code, 503);
  }
}));

test('Turnstile missing tokens, provider failures and freshness boundaries never forward rejected contacts', async () => environment(async () => {
  for (const token of [undefined, '', 5, 'x'.repeat(2049)]) {
    const res = await invoke(createIntakeHandler({ ...config, fetchImpl: async () => assert.fail('invalid token') }), { ...body, turnstile_token: token });
    assert.equal(res.code, 403);
  }
  for (const fixture of [() => challenge({ success: false }), () => challenge({ challenge_ts: new Date(now + 1).toISOString() }), () => challenge({ challenge_ts: new Date(now - 300001).toISOString() }), () => Response.json(null), () => new Response('not-json'), () => new Response('x'.repeat(8193)), () => { throw Error('private-provider-body'); }]) {
    let upstream = 0;
    const res = await invoke(createIntakeHandler({ ...config, fetchImpl: async url => { if (url.includes('turnstile')) return fixture(); upstream++; return lead(); } }));
    assert.ok([403, 503].includes(res.code)); assert.equal(upstream, 0); assert.doesNotMatch(JSON.stringify(res.body), /private-provider/);
  }
  const res = await invoke(createIntakeHandler({ ...config, fetchImpl: async url => url.includes('turnstile') ? challenge({ challenge_ts: new Date(now - 300000).toISOString() }) : lead() }));
  assert.equal(res.code, 202);
}));

test('default canary retries actually wait and preserve exact command', async () => environment(async () => {
  const calls = []; const started = Date.now();
  const handler = createCanaryHandler({ source: 'fixture-site', logger: null, fetchImpl: async (_url, options) => {
    calls.push(options.body); return calls.length === 1 ? new Response('', { status: 503 }) : canary();
  } });
  const res = await invoke(handler, undefined, { authorization: `Bearer ${process.env.INTAKE_CANARY_PROBE_TOKEN}` });
  assert.equal(res.code, 200); assert.equal(calls.length, 2); assert.equal(calls[0], calls[1]); assert.ok(Date.now() - started >= 90);
}));

test('transport deadlines abort a hung Turnstile operation and all bounded Intake attempts', async t => environment(async () => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const flush = () => new Promise(resolve => setImmediate(resolve));
  let signal;
  const challengeHandler = createIntakeHandler({ ...config, fetchImpl: (_url, options) => { signal = options.signal; return new Promise(() => {}); } });
  const challenged = invoke(challengeHandler); await flush(); t.mock.timers.tick(5000); await flush();
  assert.equal((await challenged).code, 503); assert.equal(signal.aborted, true);
  const signals = [], keys = [];
  const handler = createIntakeHandler({ ...config, fetchImpl: async (url, options) => {
    if (url.includes('turnstile')) return challenge(); signals.push(options.signal); keys.push(options.headers['idempotency-key']); return new Promise(() => {});
  } });
  const pending = invoke(handler); await flush();
  for (const delay of [100, 200, 0]) { t.mock.timers.tick(8000); await flush(); if (delay) { t.mock.timers.tick(delay); await flush(); } }
  assert.equal((await pending).code, 503); assert.equal(signals.length, 3); assert.ok(signals.every(item => item.aborted)); assert.deepEqual(keys, [uuid, uuid, uuid]);
}));

test('actual Web lead wrapper maps JSON, honors protocol and emits schema-safe errors', async () => environment(async () => {
  const handler = createWebHandler(createIntakeHandler({ ...config, fetchImpl: async url => url.includes('turnstile') ? challenge() : lead() }));
  const valid = await handler(new Request('https://example.com/api/intake', { method: 'POST', headers: { ...headers, 'x-vercel-forwarded-for': '192.0.2.240' }, body: JSON.stringify(body) }));
  assert.equal(valid.status, 202); assert.equal((await valid.json()).lead_id, uuid);
  const invalid = await handler(new Request('https://example.com/api/intake', { method: 'POST', headers: { ...headers, 'x-vercel-forwarded-for': '192.0.2.241' }, body: '{' }));
  const validateError = ajv.compile(JSON.parse(readFileSync(new URL('../contracts/intake/v1/error-response.schema.json', import.meta.url))));
  assert.equal(invalid.status, 400); assert.equal(validateError(await invalid.json()), true);
}));

test('configuration rejects values that only become valid through string coercion', () => {
  assert.throws(() => createCanaryHandler({ source: ['fixture-site'] }), /source/);
  assert.throws(() => createIntakeHandler({ ...config, honeypotField: ['website'] }), /honeypot/);
  assert.throws(() => createIntakeHandler({ ...config, turnstile: { ...config.turnstile, action: ['contact'] } }), /Turnstile/);
});

test('stalled Web body reads time out and release their reader before any transport', async t => environment(async () => {
  t.mock.timers.enable({ apis: ['setTimeout'] }); let cancelled = false;
  const input = new ReadableStream({ pull() {}, cancel() { cancelled = true; } }, { highWaterMark: 0 });
  const handler = createWebHandler(createIntakeHandler({ ...config, fetchImpl: async () => assert.fail('stalled input') }));
  const result = handler(new Request('https://example.com/api/intake', { method: 'POST', headers: { ...headers, 'x-vercel-forwarded-for': '192.0.2.242' }, body: input, duplex: 'half' }));
  await new Promise(resolve => setImmediate(resolve)); t.mock.timers.tick(5000);
  assert.equal((await result).status, 400); assert.equal(cancelled, true);
}));
