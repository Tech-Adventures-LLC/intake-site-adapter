import test, { beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  ADAPTER_VERSION,
  CONTRACT_VERSION,
  SiteAdapterConfigurationError,
  createCanaryHandler,
  createIntakeHandler,
  createWebHandler,
  verifyCanaryHandler,
} from '../packages/intake-site-adapter/index.js';

const submissionId = '123e4567-e89b-42d3-a456-426614174000';
const sourceSha = 'a'.repeat(40);
let ip = 1;
let oldHost;
beforeEach(() => { oldHost = process.env.VERCEL; process.env.VERCEL = '1'; });
afterEach(() => { if (oldHost === undefined) delete process.env.VERCEL; else process.env.VERCEL = oldHost; });
const protocol = { 'x-intake-contract': CONTRACT_VERSION, 'x-intake-release': 'b'.repeat(40) };
function canaryResponse(site, environment = process.env.VERCEL_ENV) { return Response.json({ ok: true, site, checked_at: '2026-09-17T12:00:00Z', release: 'b'.repeat(40), contract_version: CONTRACT_VERSION, adapter_version: ADAPTER_VERSION, source_sha: sourceSha, environment }, { headers: protocol }); }

function responseRecorder() {
  return { code: 0, body: null, headers: {}, setHeader(name, value) { this.headers[name] = value; }, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
}

function request(body = {}, headers = {}) {
  return { method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': submissionId, 'x-vercel-forwarded-for': `203.0.113.${ip++}`, ...headers }, body };
}

function env(values, fn) {
  const previous = Object.fromEntries(Object.keys(values).map((key) => [key, process.env[key]]));
  Object.assign(process.env, values);
  return Promise.resolve().then(fn).finally(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  });
}

const config = {
  formMap: {
    contact: { name: 'person.name', email: 'person.email', phone: 'person.phone' },
    details: { message: 'message' },
    consent: { contact_request: { literal: true } },
  },
  turnstile: { action: 'contact_submit', allowedHostnames: ['example.com'] },
};

function turnstileResponse(overrides = {}) {
  return Response.json({ success: true, action: 'contact_submit', hostname: 'example.com', challenge_ts: '2026-09-14T15:00:00.000Z', ...overrides });
}

function intakeResponse(overrides = {}, status = 202) {
  return Response.json({ ok: true, lead_id: submissionId, status: 'received', duplicate: false, ...overrides }, { status, headers: protocol });
}

test('configuration cannot select trust boundaries or arbitrary fields', () => {
  assert.throws(() => createIntakeHandler({ ...config, intake: { url: 'https://evil.example' } }), SiteAdapterConfigurationError);
  assert.throws(() => createIntakeHandler({ ...config, formMap: { tenant_id: { value: 'tenant' } } }), /unsupported formMap section/);
  assert.throws(() => createIntakeHandler({ ...config, formMap: { contact: { recipient: 'email' } } }), /unsupported formMap field/);
  assert.throws(() => createIntakeHandler({ ...config, formMap: { contact: { email: () => 'x@example.com' } } }), /invalid formMap selector/);
  assert.throws(() => createIntakeHandler({ ...config, formMap: { details: { message: 'turnstile_token' } } }), /invalid formMap selector/);
  assert.throws(() => createIntakeHandler({ ...config, formMap: { details: { message: '__proto__.secret' } } }), /invalid formMap selector/);
});

test('lead handler fails closed for method, content type, missing stable UUID, and oversized bodies', async () => {
  const handler = createIntakeHandler({ ...config, fetchImpl: async () => assert.fail('must not fetch'), logger: null });
  for (const [input, expected] of [
    [{ method: 'GET', headers: {} }, 405],
    [{ method: 'POST', headers: { 'content-type': 'text/plain', 'idempotency-key': submissionId }, body: {} }, 415],
    [{ method: 'POST', headers: { 'content-type': 'application/json' }, body: {} }, 400],
    [request({ message: 'x'.repeat(33 * 1024) }), 413],
  ]) {
    const response = responseRecorder();
    await handler(input, response);
    assert.equal(response.code, expected);
  }
});

test('honeypot rejects safely without sending contact data upstream', async () => {
  const handler = createIntakeHandler({ ...config, fetchImpl: async () => assert.fail('must not fetch'), logger: null });
  const response = responseRecorder();
  await handler(request({ website: 'spam', person: { name: 'Bot', email: 'bot@example.com' } }), response);
  assert.equal(response.code, 400);
  assert.equal(response.body.error, 'invalid_request');
});

test('Turnstile requires exact action, exact hostname, and fresh challenge', async () => {
  await env({ TURNSTILE_SECRET_KEY: 'secret-value-that-is-long-enough', INTAKE_SITE_TOKEN: 'site-token-that-is-at-least-thirty-two-characters' }, async () => {
    for (const turnstile of [
      turnstileResponse({ action: 'other' }),
      turnstileResponse({ hostname: 'preview.example.com' }),
      turnstileResponse({ challenge_ts: '2026-09-14T14:54:59.000Z' }),
    ]) {
      const handler = createIntakeHandler({ ...config, clock: () => Date.parse('2026-09-14T15:00:00.000Z'), fetchImpl: async () => turnstile, logger: null });
      const response = responseRecorder();
      await handler(request({ turnstile_token: 'token', person: { name: 'Jane', email: 'jane@example.com' } }), response);
      assert.equal(response.code, 403);
      assert.equal(response.body.error, 'turnstile_failed');
    }
  });
});

test('valid lead maps only allowlisted fields and forwards one stable idempotency key', async () => {
  await env({ TURNSTILE_SECRET_KEY: 'secret-value-that-is-long-enough', INTAKE_SITE_TOKEN: 'site-token-that-is-at-least-thirty-two-characters' }, async () => {
    const calls = [];
    const handler = createIntakeHandler({
      ...config,
      clock: () => Date.parse('2026-09-14T15:00:00.000Z'),
      fetchImpl: async (url, options) => {
        calls.push({ url, options });
        return calls.length === 1 ? turnstileResponse() : intakeResponse();
      },
      logger: null,
    });
    const response = responseRecorder();
    await handler(request({ turnstile_token: 'token', person: { name: 'Jane', email: 'jane@example.com', phone: '555-0100' }, message: 'Help', recipient: 'attacker@example.com', tenant_id: 'other' }), response);
    assert.equal(response.code, 202);
    assert.equal(calls[1].url, 'https://intake.fltechadventures.com/v1/intake');
    assert.equal(calls[1].options.headers['idempotency-key'], submissionId);
    assert.deepEqual(JSON.parse(calls[1].options.body), {
      type: 'project_inquiry',
      contact: { name: 'Jane', email: 'jane@example.com', phone: '555-0100' },
      details: { message: 'Help' },
      consent: { contact_request: true },
      metadata: { turnstile_verified: true },
    });
  });
});

test('bounded retry reuses the same key and duplicate response is returned as success', async () => {
  await env({ TURNSTILE_SECRET_KEY: 'secret-value-that-is-long-enough', INTAKE_SITE_TOKEN: 'site-token-that-is-at-least-thirty-two-characters' }, async () => {
    const intakeCalls = [];
    const sleeps = [];
    let call = 0;
    const handler = createIntakeHandler({
      ...config,
      clock: () => Date.parse('2026-09-14T15:00:00.000Z'),
      sleep: async (ms) => sleeps.push(ms),
      fetchImpl: async (url, options) => {
        if (url.includes('turnstile')) return turnstileResponse();
        intakeCalls.push(options);
        call += 1;
        if (call === 1) return { ok: false, status: 503, headers: new Headers(), json: async () => ({ ok: false, error: 'temporarily_unavailable' }) };
        return intakeResponse({ duplicate: true }, 200);
      },
      logger: null,
    });
    const response = responseRecorder();
    await handler(request({ turnstile_token: 'token', person: { name: 'Jane', email: 'jane@example.com' } }), response);
    assert.equal(response.code, 200);
    assert.equal(response.body.duplicate, true);
    assert.equal(intakeCalls.length, 2);
    assert.deepEqual(intakeCalls.map((options) => options.headers['idempotency-key']), [submissionId, submissionId]);
    assert.deepEqual(sleeps, [100]);
  });
});

test('concurrent browser double-clicks retain one site-scoped idempotency identity', async () => {
  await env({ TURNSTILE_SECRET_KEY: 'secret-value-that-is-long-enough', INTAKE_SITE_TOKEN: 'site-token-that-is-at-least-thirty-two-characters' }, async () => {
    const keys = [];
    let intakeCall = 0;
    const handler = createIntakeHandler({
      ...config,
      clock: () => Date.parse('2026-09-14T15:00:00.000Z'),
      fetchImpl: async (url, options) => {
        if (url.includes('turnstile')) return turnstileResponse();
        keys.push(options.headers['idempotency-key']);
        intakeCall += 1;
        return intakeResponse({ duplicate: intakeCall > 1 }, intakeCall > 1 ? 200 : 202);
      },
      logger: null,
    });
    const first = responseRecorder();
    const second = responseRecorder();
    const body = { turnstile_token: 'token', person: { name: 'Jane', email: 'jane@example.com' } };
    await Promise.all([handler(request(body), first), handler(request(body), second)]);
    assert.deepEqual(keys, [submissionId, submissionId]);
    assert.deepEqual([first.body.duplicate, second.body.duplicate].sort(), [false, true]);
  });
});

test('retry is capped and browser responses never expose provider or contact data', async () => {
  await env({ TURNSTILE_SECRET_KEY: 'secret-value-that-is-long-enough', INTAKE_SITE_TOKEN: 'site-token-that-is-at-least-thirty-two-characters' }, async () => {
    let calls = 0;
    const handler = createIntakeHandler({
      ...config,
      clock: () => Date.parse('2026-09-14T15:00:00.000Z'),
      sleep: async () => {},
      fetchImpl: async (url) => {
        if (url.includes('turnstile')) return turnstileResponse();
        calls += 1;
        return { ok: false, status: 429, headers: new Headers({ 'retry-after': '600' }), json: async () => ({ ok: false, error: 'provider_secret', email: 'jane@example.com' }) };
      },
      logger: null,
    });
    const response = responseRecorder();
    await handler(request({ turnstile_token: 'token', person: { name: 'Jane', email: 'jane@example.com' } }), response);
    assert.equal(calls, 3);
    assert.equal(response.code, 503);
    assert.equal(response.body.error, 'temporarily_unavailable');
    assert.match(response.body.request_id, /^[0-9a-f-]{36}$/);
  });
});

test('structured logs contain operational metadata but no body, token, or contact fields', async () => {
  await env({ TURNSTILE_SECRET_KEY: 'secret-value-that-is-long-enough', INTAKE_SITE_TOKEN: 'site-token-that-is-at-least-thirty-two-characters' }, async () => {
    const logs = [];
    const handler = createIntakeHandler({
      ...config,
      clock: () => Date.parse('2026-09-14T15:00:00.000Z'),
      fetchImpl: async (url) => url.includes('turnstile') ? turnstileResponse() : intakeResponse(),
      logger: { info: (entry) => logs.push(entry) },
    });
    await handler(request({ turnstile_token: 'sensitive-token', person: { name: 'Jane Secret', email: 'jane@example.com' } }), responseRecorder());
    const serialized = JSON.stringify(logs);
    assert.match(serialized, /adapter_version/);
    assert.doesNotMatch(serialized, /Jane Secret|jane@example\.com|sensitive-token|site-token/);
  });
});

test('canary is protected and reports immutable contract, adapter, environment, and source SHA', async () => {
  const probeToken = `probe_${'p'.repeat(40)}`;
  await env({ INTAKE_CANARY_PROBE_TOKEN: probeToken, INTAKE_CANARY_TOKEN: 'canary-token-that-is-at-least-thirty-two-characters', VERCEL_GIT_COMMIT_SHA: sourceSha, VERCEL_ENV: 'production' }, async () => {
    let forwarded;
    const handler = createCanaryHandler({
      source: 'example-site',
      logger: null,
      fetchImpl: async (url, options) => {
        forwarded = { url, options };
        return canaryResponse('example-site');
      },
    });
    const result = await verifyCanaryHandler(handler, { probeToken });
    assert.deepEqual(result, { ok: true, unauthorized: 401, authorized: 200 });
    assert.equal(forwarded.url, 'https://intake.fltechadventures.com/v1/canary');
    assert.deepEqual(JSON.parse(forwarded.options.body), { source: 'example-site', contract_version: CONTRACT_VERSION, adapter_version: ADAPTER_VERSION, source_sha: sourceSha, environment: 'production' });
  });
});

test('canary fails closed when immutable release identity is missing or Intake returns wrong site', async () => {
  const probeToken = `probe_${'q'.repeat(40)}`;
  await env({ INTAKE_CANARY_PROBE_TOKEN: probeToken, INTAKE_CANARY_TOKEN: 'canary-token-that-is-at-least-thirty-two-characters', VERCEL_GIT_COMMIT_SHA: '', VERCEL_ENV: 'production' }, async () => {
    const handler = createCanaryHandler({ source: 'example-site', fetchImpl: async () => assert.fail('must not fetch'), logger: null });
    const response = responseRecorder();
    await handler({ method: 'POST', headers: { authorization: `Bearer ${probeToken}` } }, response);
    assert.equal(response.code, 503);
  });
  await env({ INTAKE_CANARY_PROBE_TOKEN: probeToken, INTAKE_CANARY_TOKEN: 'canary-token-that-is-at-least-thirty-two-characters', VERCEL_GIT_COMMIT_SHA: sourceSha, VERCEL_ENV: 'preview' }, async () => {
    const handler = createCanaryHandler({ source: 'example-site', fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ ok: true, site: 'other-site' }) }), logger: null });
    const response = responseRecorder();
    await handler({ method: 'POST', headers: { authorization: `Bearer ${probeToken}` } }, response);
    assert.equal(response.code, 502);
  });
});

test('canary never reuses the lead-ingestion credential', async () => {
  const probeToken = `probe_${'z'.repeat(40)}`;
  await env({
    INTAKE_CANARY_PROBE_TOKEN: probeToken,
    INTAKE_SITE_TOKEN: 'lead-token-that-is-at-least-thirty-two-characters',
    VERCEL_GIT_COMMIT_SHA: sourceSha,
    VERCEL_ENV: 'preview',
  }, async () => {
    const handler = createCanaryHandler({
      source: 'example-site',
      fetchImpl: async () => assert.fail('must not call Intake without a canary credential'),
      logger: null,
    });
    const response = responseRecorder();
    await handler({ method: 'POST', headers: { authorization: `Bearer ${probeToken}` } }, response);
    assert.equal(response.code, 503);
    assert.match(response.body.request_id, /^[0-9a-f-]{36}$/);
    assert.deepEqual(response.body, { ok: false, error: 'canary_not_configured', request_id: response.body.request_id });
  });
});

test('canary uses explicit source SHA when a manual deployment provides an empty Git SHA', async () => {
  const probeToken = `probe_${'m'.repeat(40)}`;
  await env({
    INTAKE_CANARY_PROBE_TOKEN: probeToken,
    INTAKE_CANARY_TOKEN: 'canary-token-that-is-at-least-thirty-two-characters',
    VERCEL_GIT_COMMIT_SHA: '',
    SOURCE_SHA: sourceSha,
    VERCEL_ENV: 'preview',
  }, async () => {
    let forwarded;
    const handler = createCanaryHandler({
      source: 'manual-site',
      logger: null,
      fetchImpl: async (_url, options) => {
        forwarded = JSON.parse(options.body);
        return canaryResponse('manual-site');
      },
    });
    const response = responseRecorder();
    await handler({ method: 'POST', headers: { authorization: `Bearer ${probeToken}` } }, response);
    assert.equal(response.code, 200);
    assert.equal(response.body.source_sha, sourceSha);
    assert.equal(forwarded.source_sha, sourceSha);
  });
});

test('Web Request wrapper preserves protected canary behavior for Next.js-style routes', async () => {
  const probeToken = `probe_${'w'.repeat(40)}`;
  await env({ INTAKE_CANARY_PROBE_TOKEN: probeToken, INTAKE_CANARY_TOKEN: 'canary-token-that-is-at-least-thirty-two-characters', VERCEL_GIT_COMMIT_SHA: sourceSha, VERCEL_ENV: 'preview' }, async () => {
    const POST = createWebHandler(createCanaryHandler({
      source: 'example-site',
      logger: null,
      fetchImpl: async () => canaryResponse('example-site'),
    }));
    const unauthorized = await POST(new Request('https://example.com/api/intake-canary', { method: 'POST' }));
    assert.equal(unauthorized.status, 401);
    const authorized = await POST(new Request('https://example.com/api/intake-canary', { method: 'POST', headers: { authorization: `Bearer ${probeToken}` } }));
    assert.equal(authorized.status, 200);
    assert.equal((await authorized.json()).source_sha, sourceSha);
  });
});
