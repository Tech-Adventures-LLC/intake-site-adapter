import { randomUUID, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import { FIELD_LIMITS, validCommand } from './validation.js';

export const ADAPTER_VERSION = '1.1.0';
export const CONTRACT_VERSION = 'intake-contract-v1';

const INTAKE_ORIGIN = 'https://intake.fltechadventures.com';
const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[0-9a-f]{40}$/;
const SLUG = /^[a-z0-9][a-z0-9._-]{0,79}$/;
const ACTION = /^[a-z0-9][a-z0-9_-]{0,79}$/;
const HOSTNAME = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;
const RETRYABLE = new Set([429, 500, 502, 503, 504]);
const MAX_BODY_BYTES = 32 * 1024;
const MAX_RESPONSE_BYTES = 8 * 1024;
const MAX_ATTEMPTS = 3;
const MAX_RETRY_DELAY_MS = 2000;
const sleepDefault = ms => new Promise(resolve => setTimeout(resolve, ms));
// Shared across handler instances in this process, bounded in both time and memory.
const visitorBuckets = new Map();

export class SiteAdapterConfigurationError extends Error {}
class BodyLimitError extends Error {}

function validToken(value) { return typeof value === 'string' && /^[\x21-\x7e]{32,512}$/.test(value); }
function safeEqual(supplied, expected) {
  if (!validToken(supplied) || !validToken(expected)) return false;
  const left = Buffer.from(supplied), right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}
function header(request, name) {
  const value = typeof request?.headers?.get === 'function' ? request.headers.get(name)
    : Object.entries(request?.headers ?? {}).find(([key]) => key.toLowerCase() === name)?.[1];
  return typeof value === 'string' ? value : undefined;
}
function send(response, status, body, headers = {}) {
  response.setHeader?.('cache-control', 'no-store');
  for (const [name, value] of Object.entries(headers)) response.setHeader?.(name, value);
  return response.status(status).json(body);
}
function optionsAllowed(options, allowed) {
  if (!options || typeof options !== 'object' || Array.isArray(options) || Object.keys(options).some(key => !allowed.includes(key))) throw new SiteAdapterConfigurationError('unsupported adapter option');
}
async function deadline(action, milliseconds) {
  const controller = new AbortController();
  let timer;
  const expired = new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error('transport_timeout')); }, milliseconds); });
  try { return await Promise.race([Promise.resolve().then(() => action(controller.signal)), expired]); }
  finally { clearTimeout(timer); controller.abort(); }
}
async function boundedText(stream, limit, signal) {
  if (!stream) return '';
  const reader = stream.getReader();
  let size = 0;
  const chunks = [];
  const cancel = () => { reader.cancel().catch(() => {}); };
  signal?.addEventListener('abort', cancel, { once: true });
  try {
    while (true) {
      signal?.throwIfAborted();
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new BodyLimitError();
      chunks.push(Buffer.from(value));
    }
    signal?.throwIfAborted();
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, size));
  } finally { cancel(); signal?.removeEventListener('abort', cancel); }
}
async function parseBody(request) {
  try {
    let value = request.body;
    if (value?.getReader) value = await deadline(signal => boundedText(value, MAX_BODY_BYTES, signal), 5000);
    else if (value === undefined && request[Symbol.asyncIterator]) {
      // Native IncomingMessage: adapt lazily after method/header/hosting checks.
      value = await deadline(async signal => {
        const chunks = []; let size = 0;
        const abort = () => request.destroy?.(); signal.addEventListener('abort', abort, { once: true });
        try {
          for await (const chunk of request) {
            size += Buffer.byteLength(chunk); if (size > MAX_BODY_BYTES) throw new BodyLimitError(); chunks.push(Buffer.from(chunk));
          }
          return Buffer.concat(chunks).toString('utf8');
        } finally { signal.removeEventListener('abort', abort); }
      }, 5000);
    }
    if (value instanceof Uint8Array) value = Buffer.from(value).toString('utf8');
    const raw = typeof value === 'string' ? value : JSON.stringify(value ?? {});
    if (Buffer.byteLength(raw) > MAX_BODY_BYTES) throw new BodyLimitError();
    const body = JSON.parse(raw);
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw Error();
    return { body };
  } catch (error) { return { error: error instanceof BodyLimitError ? 'request_too_large' : 'invalid_request', status: error instanceof BodyLimitError ? 413 : 400 }; }
}
function validateMap(formMap) {
  if (!formMap || typeof formMap !== 'object' || Array.isArray(formMap)) throw new SiteAdapterConfigurationError('formMap must be an object');
  for (const [section, fields] of Object.entries(formMap)) {
    if (!Object.hasOwn(FIELD_LIMITS, section)) throw new SiteAdapterConfigurationError('unsupported formMap section');
    if (!fields || typeof fields !== 'object' || Array.isArray(fields)) throw new SiteAdapterConfigurationError('formMap fields must be an object');
    for (const [field, selector] of Object.entries(fields)) {
      if (!Object.hasOwn(FIELD_LIMITS[section], field)) throw new SiteAdapterConfigurationError('unsupported formMap field');
      const validPath = typeof selector === 'string' && /^[A-Za-z0-9_.-]{1,160}$/.test(selector);
      const sensitivePath = validPath && selector.split('.').some(part => /^(?:__proto__|prototype|constructor|authorization|cookie|password|secret|token|turnstile_token|recipient|route|tenant_id|site_id)$/i.test(part));
      const validLiteral = selector && typeof selector === 'object' && Object.keys(selector).length === 1 && Object.hasOwn(selector, 'literal') && ['string', 'boolean'].includes(typeof selector.literal);
      if ((!validPath && !validLiteral) || sensitivePath) throw new SiteAdapterConfigurationError('invalid formMap selector');
    }
  }
  return structuredClone(formMap);
}
function readPath(input, path) {
  return path.split('.').reduce((value, key) => value && typeof value === 'object' && Object.hasOwn(value, key) ? value[key] : undefined, input);
}
function mapCommand(body, formMap) {
  const command = { type: 'project_inquiry' };
  for (const [section, fields] of Object.entries(formMap)) {
    const mapped = {};
    for (const [field, selector] of Object.entries(fields)) {
      const value = typeof selector === 'string' ? readPath(body, selector) : selector.literal;
      // Only optional text treats an empty string as absent. Supplied boolean
      // values must survive mapping so the contract type check can reject them.
      if (value !== undefined && (value !== '' || FIELD_LIMITS[section][field] === null)) mapped[field] = value;
    }
    if (Object.keys(mapped).length) command[section] = mapped;
  }
  command.metadata = { turnstile_verified: true };
  return command;
}
function validateTurnstile(turnstile) {
  if (!turnstile || typeof turnstile !== 'object' || Object.keys(turnstile).some(k => !['action', 'allowedHostnames'].includes(k)) || typeof turnstile.action !== 'string' || !ACTION.test(turnstile.action)) throw new SiteAdapterConfigurationError('valid Turnstile action is required');
  if (!Array.isArray(turnstile.allowedHostnames)) throw new SiteAdapterConfigurationError('valid Turnstile hostnames are required');
  const hostnames = [...new Set(turnstile.allowedHostnames)];
  if (!hostnames.length || hostnames.length > 20 || hostnames.some(value => typeof value !== 'string' || !HOSTNAME.test(value))) throw new SiteAdapterConfigurationError('valid Turnstile hostnames are required');
  return { action: turnstile.action, allowedHostnames: hostnames };
}
async function jsonResponse(response, signal) {
  const length = header(response, 'content-length');
  if (length && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE_BYTES)) { response.body?.cancel().catch(() => {}); throw new BodyLimitError(); }
  return JSON.parse(await boundedText(response.body, MAX_RESPONSE_BYTES, signal));
}
async function verifyTurnstile({ token, policy, fetchImpl, now }) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (typeof secret !== 'string' || secret.length < 20 || secret.length > 512) throw new SiteAdapterConfigurationError('Turnstile is not configured');
  if (typeof token !== 'string' || token.length < 1 || token.length > 2048) return false;
  return deadline(async signal => {
    const response = await fetchImpl(TURNSTILE_VERIFY_URL, { method: 'POST', body: new URLSearchParams({ secret, response: token }), signal, redirect: 'error' });
    const result = await jsonResponse(response, signal);
    if (!response.ok || result?.success !== true || result.action !== policy.action || !policy.allowedHostnames.includes(result.hostname)) return false;
    const challengedAt = typeof result.challenge_ts === 'string' ? Date.parse(result.challenge_ts) : NaN;
    return Number.isFinite(challengedAt) && challengedAt <= now() && now() - challengedAt <= 300000;
  }, 5000);
}
function visitorLimit(request, now) {
  if (process.env.VERCEL !== '1') return { status: 503, error: 'configuration_error' };
  const raw = header(request, 'x-vercel-forwarded-for');
  if (!raw || raw.includes('%') || !isIP(raw)) return { status: 503, error: 'configuration_error' };
  const ip = isIP(raw) === 6 ? new URL(`http://[${raw}]/`).hostname : raw;
  for (const [key, bucket] of visitorBuckets) if (now >= bucket.until) visitorBuckets.delete(key);
  let bucket = visitorBuckets.get(ip);
  if (!bucket) {
    if (visitorBuckets.size >= 10000) return { status: 429, error: 'rate_limited' };
    bucket = { count: 0, until: now + 60000 }; visitorBuckets.set(ip, bucket);
  }
  bucket.count++;
  return bucket.count > 10 ? { status: 429, error: 'rate_limited' } : null;
}
function retryDelay(response, attempt) {
  if (response.status !== 429) return Math.min(100 * 2 ** attempt, MAX_RETRY_DELAY_MS);
  const raw = header(response, 'retry-after');
  const milliseconds = raw && /^\d+(?:\.\d+)?$/.test(raw) ? Number(raw) * 1000 : Date.parse(raw ?? '') - Date.now();
  return Math.min(Number.isFinite(milliseconds) && milliseconds > 0 ? milliseconds : 1000, MAX_RETRY_DELAY_MS);
}
async function callIntake({ path, token, body, idempotencyKey, fetchImpl, sleep }) {
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    let result;
    try {
      result = await deadline(async signal => {
        const response = await fetchImpl(`${INTAKE_ORIGIN}${path}`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', 'x-intake-contract': CONTRACT_VERSION, ...(idempotencyKey ? { 'idempotency-key': idempotencyKey } : {}) }, body: JSON.stringify(body), signal, redirect: 'error' });
        if (RETRYABLE.has(response.status)) { response.body?.cancel().catch(() => {}); return { response }; }
        // Permanent failures never echo or buffer upstream error bodies.
        if (!response.ok) { response.body?.cancel().catch(() => {}); return { response }; }
        return { response, payload: await jsonResponse(response, signal) };
      }, 8000);
    } catch {
      if (attempt + 1 === MAX_ATTEMPTS) return { unavailable: true };
      await sleep(Math.min(100 * 2 ** attempt, MAX_RETRY_DELAY_MS)); continue;
    }
    if (!RETRYABLE.has(result.response.status) || attempt + 1 === MAX_ATTEMPTS) return result;
    await sleep(retryDelay(result.response, attempt));
  }
  return { unavailable: true };
}
function protocolValid(response) { return header(response, 'x-intake-contract') === CONTRACT_VERSION && SHA.test(header(response, 'x-intake-release') ?? ''); }
function logEvent(logger, event) {
  try { logger?.info?.({ adapter_version: ADAPTER_VERSION, contract_version: CONTRACT_VERSION, ...event }); } catch { /* Logging must not leak exceptions or alter acceptance. */ }
}
export function createIntakeHandler(options = {}) {
  optionsAllowed(options, ['formMap', 'turnstile', 'honeypotField', 'fetchImpl', 'sleep', 'clock', 'logger']);
  const { formMap, turnstile, honeypotField = 'website', fetchImpl = fetch, sleep = sleepDefault, clock = Date.now, logger = console } = options;
  const mapping = validateMap(formMap), turnstilePolicy = validateTurnstile(turnstile);
  if (typeof honeypotField !== 'string' || !/^[A-Za-z0-9_-]{1,80}$/.test(honeypotField)) throw new SiteAdapterConfigurationError('invalid honeypotField');
  return async function intakeHandler(request, response) {
    const started = clock();
    const rawRequestId = header(request, 'x-request-id');
    const requestId = UUID.test(rawRequestId ?? '') ? rawRequestId : randomUUID();
    const submissionId = header(request, 'idempotency-key') ?? header(request, 'x-intake-submission-id') ?? '';
    const finish = (status, category, body, extraHeaders) => {
      logEvent(logger, { request_id: requestId, submission_id: UUID.test(submissionId) ? submissionId : undefined, operation: 'lead', status_category: category, duration_ms: Math.max(0, clock() - started) });
      return send(response, status, body ?? { ok: false, error: category, request_id: requestId }, extraHeaders);
    };
    if (request.method !== 'POST') return finish(405, 'method_not_allowed', null, { Allow: 'POST' });
    if (!/^application\/json(?:\s*;|$)/i.test(header(request, 'content-type') ?? '')) return finish(415, 'invalid_request');
    if (!UUID.test(submissionId)) return finish(400, 'invalid_request');
    const limited = visitorLimit(request, started);
    if (limited) return finish(limited.status, limited.error, null, limited.status === 429 ? { 'retry-after': '60' } : {});
    const parsed = await parseBody(request);
    if (parsed.error) return finish(parsed.status, parsed.error);
    if (parsed.body[honeypotField]) return finish(400, 'invalid_request');
    const command = mapCommand(parsed.body, mapping);
    if (!validCommand(command)) return finish(400, 'invalid_request');
    const intakeToken = process.env.INTAKE_SITE_TOKEN;
    if (!validToken(intakeToken)) return finish(503, 'configuration_error');
    try {
      if (!await verifyTurnstile({ token: parsed.body.turnstile_token, policy: turnstilePolicy, fetchImpl, now: clock })) return finish(403, 'turnstile_failed');
    } catch (error) { return finish(503, error instanceof SiteAdapterConfigurationError ? 'configuration_error' : 'temporarily_unavailable'); }
    const result = await callIntake({ path: '/v1/intake', token: intakeToken, body: command, idempotencyKey: submissionId, fetchImpl, sleep });
    if (result.unavailable || RETRYABLE.has(result.response?.status)) return finish(503, 'temporarily_unavailable');
    if (!result.response?.ok) {
      if ([401, 403, 409].includes(result.response?.status)) return finish(503, 'configuration_error');
      return finish([400, 413, 415, 422].includes(result.response?.status) ? 400 : 503, [400, 413, 415, 422].includes(result.response?.status) ? 'invalid_request' : 'temporarily_unavailable');
    }
    const payload = result.payload;
    if (!protocolValid(result.response) || ![200, 202].includes(result.response.status) || payload?.ok !== true || typeof payload.lead_id !== 'string' || !UUID.test(payload.lead_id) || !['received', 'held_for_review'].includes(payload.status) || typeof payload.duplicate !== 'boolean' || payload.duplicate !== (result.response.status === 200)) return finish(503, 'temporarily_unavailable');
    return finish(result.response.status, payload.duplicate ? 'duplicate' : 'accepted', { ok: true, lead_id: payload.lead_id, status: payload.status, duplicate: payload.duplicate });
  };
}
export function createCanaryHandler(options = {}) {
  optionsAllowed(options, ['source', 'fetchImpl', 'sleep', 'logger']);
  const { source, fetchImpl = fetch, sleep = sleepDefault, logger = console } = options;
  if (typeof source !== 'string' || !SLUG.test(source)) throw new SiteAdapterConfigurationError('valid canary source is required');
  return async function canaryHandler(request, response) {
    const suppliedRequestId = header(request, 'x-request-id');
    const requestId = UUID.test(suppliedRequestId ?? '') ? suppliedRequestId : randomUUID();
    const failure = (status, error, headers) => send(response, status, { ok: false, error, request_id: requestId }, headers);
    if (request.method !== 'POST') return failure(405, 'method_not_allowed', { Allow: 'POST' });
    const authorization = header(request, 'authorization') ?? '';
    if (!authorization.startsWith('Bearer ') || !safeEqual(authorization.slice(7), process.env.INTAKE_CANARY_PROBE_TOKEN)) return failure(401, 'unauthorized');
    const token = process.env.INTAKE_CANARY_TOKEN;
    const environment = process.env.VERCEL_ENV;
    const sourceSha = process.env.VERCEL_GIT_COMMIT_SHA || (environment === 'preview' ? process.env.SOURCE_SHA : '') || '';
    if (!validToken(token) || !SHA.test(sourceSha) || !['production', 'preview'].includes(environment)) return failure(503, 'canary_not_configured');
    const command = { source, contract_version: CONTRACT_VERSION, adapter_version: ADAPTER_VERSION, source_sha: sourceSha, environment };
    const result = await callIntake({ path: '/v1/canary', token, body: command, fetchImpl, sleep });
    const payload = result.payload;
    const valid = result.response?.status === 200 && protocolValid(result.response) && payload?.ok === true && payload.site === source && ['contract_version', 'adapter_version', 'source_sha', 'environment'].every(key => payload[key] === command[key]) && SHA.test(payload.release ?? '') && payload.release === header(result.response, 'x-intake-release') && typeof payload.checked_at === 'string' && payload.checked_at.length <= 40 && Number.isFinite(Date.parse(payload.checked_at));
    if (!valid) return failure(502, 'intake_canary_failed');
    logEvent(logger, { operation: 'canary', status_category: 'healthy', source_sha: sourceSha, environment });
    return send(response, 200, { ok: true, site: payload.site, checked_at: payload.checked_at, release: payload.release, contract_version: payload.contract_version, adapter_version: payload.adapter_version, source_sha: payload.source_sha, environment: payload.environment });
  };
}
export function createWebHandler(handler) {
  if (typeof handler !== 'function') throw new SiteAdapterConfigurationError('handler must be a function');
  return async function webHandler(request) {
    const output = { code: 200, body: null, headers: {}, setHeader(name, value) { this.headers[name] = String(value); }, status(code) { this.code = code; return this; }, json(value) { this.body = value; return this; } };
    try { await handler({ method: request.method, headers: request.headers, body: request.body }, output); }
    finally { if (request.body && !request.body.locked) request.body.cancel().catch(() => {}); }
    return Response.json(output.body, { status: output.code, headers: output.headers });
  };
}
export async function verifyCanaryHandler(handler, { probeToken = `probe_${'a'.repeat(40)}` } = {}) {
  const recorder = () => ({ code: 0, body: null, headers: {}, setHeader(name, value) { this.headers[name] = value; }, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } });
  const unauthorized = recorder(), authorized = recorder();
  await deadline(() => handler({ method: 'POST', headers: {} }, unauthorized), 5000);
  await deadline(() => handler({ method: 'POST', headers: { authorization: `Bearer ${probeToken}` } }, authorized), 30000);
  return { ok: unauthorized.code === 401 && authorized.code === 200, unauthorized: unauthorized.code, authorized: authorized.code };
}
