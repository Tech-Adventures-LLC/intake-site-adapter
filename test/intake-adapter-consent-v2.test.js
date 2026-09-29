import assert from 'node:assert/strict';
import test from 'node:test';
import { ADAPTER_VERSION, CONTRACT_VERSION, createIntakeHandler } from '../packages/intake-site-adapter/index.js';

const id = '123e4567-e89b-42d3-a456-426614174000';
const now = Date.parse('2026-09-24T12:00:00.000Z');
const response = () => ({ code: 0, body: null, setHeader() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } });
async function environment(fn) {
  const values = { VERCEL: '1', INTAKE_SITE_TOKEN: `synthetic_${'l'.repeat(40)}`, TURNSTILE_SECRET_KEY: `synthetic_${'t'.repeat(40)}` };
  const old = Object.fromEntries(Object.keys(values).map(key => [key, process.env[key]]));
  Object.assign(process.env, values);
  try { await fn(); } finally { for (const [key, value] of Object.entries(old)) if (value === undefined) delete process.env[key]; else process.env[key] = value; }
}

test('adapter 2.0 negotiates v2 and never infers phone-call consent from SMS', async () => environment(async () => {
  let visitor = 1;
  for (const choices of [{ phone_contact: false, sms: false }, { phone_contact: true, sms: false }, { phone_contact: false, sms: true }, { phone_contact: true, sms: true }]) {
    const consent = { ...choices, ...(choices.phone_contact || choices.sms ? { disclosure_version: 'synthetic-current' } : {}) };
    const calls = [];
    const handler = createIntakeHandler({
      formMap: { contact: { name: 'name', email: 'email', phone: 'phone' }, consent: { phone_contact: 'consent.phone_contact', sms: 'consent.sms', disclosure_version: 'consent.disclosure_version' } },
      turnstile: { action: 'contact', allowedHostnames: ['example.com'] }, clock: () => now, logger: null,
      fetchImpl: async (url, options) => {
        if (url.includes('turnstile')) return Response.json({ success: true, action: 'contact', hostname: 'example.com', challenge_ts: new Date(now).toISOString() });
        calls.push({ headers: options.headers, command: JSON.parse(options.body) });
        return Response.json({ ok: true, lead_id: id, status: 'received', duplicate: false }, { status: 202, headers: { 'x-intake-contract': CONTRACT_VERSION, 'x-intake-release': 'b'.repeat(40) } });
      },
    });
    const result = response();
    await handler({ method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': id, 'x-vercel-forwarded-for': `192.0.2.${visitor++}` }, body: { name: 'Synthetic Visitor', email: 'visitor@example.com', phone: '+12025550101', turnstile_token: 'synthetic', consent } }, result);
    assert.equal(result.code, 202);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].headers['x-intake-contract'], CONTRACT_VERSION);
    assert.equal(calls[0].headers['idempotency-key'], id);
    assert.deepEqual(calls[0].command.consent, consent);
  }
  assert.equal(ADAPTER_VERSION, '2.0.0');
  assert.equal(CONTRACT_VERSION, 'intake-contract-v2');
}));
