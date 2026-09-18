# Intake site adapter

`@tech-adventures-llc/intake-site-adapter` provides server-side lead and canary
handlers for `intake-contract-v1`. Node.js 20 and 22 are supported. It has no
runtime dependencies. Pin the exact approved version and commit the lockfile:

```sh
npm install --save-exact @tech-adventures-llc/intake-site-adapter@1.1.0
```

Use the public registry only after the public release has been independently
verified. A local candidate install does not establish public availability.
Never import this package or server credentials into browser code.

## Lead handler

```js
import { createIntakeHandler, createWebHandler } from '@tech-adventures-llc/intake-site-adapter';

const lead = createIntakeHandler({
  formMap: {
    contact: { name: 'name', email: 'email', phone: 'phone' },
    details: { message: 'message', postal_code: 'postalCode' },
    consent: { contact_request: { literal: true } },
  },
  turnstile: { action: 'contact_submit', allowedHostnames: ['example.com'] },
});

export default lead; // Node/Vercel-style request and response
// In a separate Web Request route module:
export const POST = createWebHandler(lead);
```

The Node response interface supplies `status`, `json`, and optional `setHeader`.
The Web wrapper accepts a standard `Request` and returns a `Response`. Streamed
bodies are read lazily, capped at 32 KiB and timed out after five seconds. If a
framework parses the body first, configure its parser limit to 32 KiB as well;
the adapter cannot undo buffering that occurred before invocation.

The browser sends JSON with a `turnstile_token` and `Idempotency-Key` containing
one UUID created for the submission. Retain that UUID across double-clicks,
network errors and resubmissions until acceptance is confirmed. Generating a
new UUID inside every submit handler defeats duplicate protection. Browser
lifecycle retention must be tested in the consuming site.

Server-only environment variables: `INTAKE_SITE_TOKEN`, `TURNSTILE_SECRET_KEY`,
and Vercel's `VERCEL=1` runtime context. Lead and canary credentials are distinct.
The fixed upstream is the reviewed public API at
`https://intake.fltechadventures.com`; callers cannot choose destinations,
tenants, recipients, provider accounts or retry policy.

The form map has four closed sections: contact, details, attribution and
consent. Selectors read own properties through a dotted path or use a string/
boolean `{ literal: value }`. Sensitive paths and unknown destination fields
are rejected. All current v1 detail fields, first/last-touch attribution and
consent fields retain contract types and limits; invalid mapped values fail
before any transport. Explicit empty strings in boolean consent fields are
invalid; absent fields and valid booleans remain distinct. Empty optional text
keeps its omission behavior. Phone or SMS consent requires a nonblank phone and
disclosure version; SMS also requires phone consent. Disclosure authorization
remains Intake's responsibility. Unmapped browser fields cannot affect routing.

An optional `honeypotField` defaults to `website`. Nonempty honeypots fail with
a safe invalid-request response. The adapter never claims durable acceptance
without a valid Intake acknowledgement.

Turnstile requires success, exact action and hostname, and a challenge no more
than five minutes old and not in the future. Response reads are capped at 8 KiB.
Intake attempts have an eight-second deadline and at most three attempts with
the same UUID. Only transport failures, 429 and 500/502/503/504 retry; delays
start at 100/200 ms or bounded `Retry-After`, capped at two seconds. Permanent
caller errors and authorization/conflict responses do not retry.

Successful responses require v1 and immutable release headers, a UUID lead ID,
`received` or `held_for_review`, and a boolean duplicate flag. Extra upstream
fields are discarded. HTTP 200 must acknowledge `duplicate: true`, and HTTP 202
must acknowledge `duplicate: false`; contradictory pairs fail closed. Errors
contain stable categories and a safe request UUID;
contact data, response bodies and credentials are never logged or forwarded.
Only valid request UUIDs are retained from `X-Request-Id`.

## Hosting and visitor limits

The shared implementation uses one valid `x-vercel-forwarded-for` address only
when running in the approved Vercel runtime. It ignores arbitrary forwarded
headers and rejects missing, multi-value, malformed and scoped IP addresses.
The runtime flag is configuration, not cryptographic proof; setting it on an
untrusted self-hosted endpoint does not create a trusted proxy boundary.

A bounded process-wide bucket allows ten attempts per visitor per minute and
stores at most 10,000 active addresses. IPv6 representations are canonicalized.
This is an instance-level guard, not a distributed quota across serverless
instances. Intake's own authenticated limits and separately verified edge
controls remain necessary. Approved deployment tests must prove header behavior.
External proxies need their own verified hosting setup; none is assumed here.
See [Vercel request headers](https://vercel.com/docs/headers/request-headers) and
[Vercel reverse proxies](https://vercel.com/docs/security/reverse-proxy).

## Canary

```js
import { createCanaryHandler } from '@tech-adventures-llc/intake-site-adapter';
export default createCanaryHandler({ source: 'example-site' });
```

`INTAKE_CANARY_PROBE_TOKEN` protects the website route;
`INTAKE_CANARY_TOKEN` authenticates the Intake canary call. No lead-token
fallback exists. Requests without the correct probe receive 401 without reading
their body or contacting Intake. Configure `VERCEL_ENV=preview|production` and
an immutable lowercase 40-hex `VERCEL_GIT_COMMIT_SHA`. Controlled previews may
use `SOURCE_SHA` only if Git SHA is empty. Production requires Git SHA.

Healthy responses require Intake to acknowledge exact site, contract, adapter,
source SHA and environment, with a valid timestamp and immutable API release
matching its response header. Missing/legacy headers or mismatches fail closed.
Separate credential names do not prove server-side purpose enforcement; that
server integration must be verified before site promotion.

## Route verification

```sh
intake-verify-canary-route --route api/intake-canary.js --source example-site
```

```js
import { verifyCanaryRoute } from '@tech-adventures-llc/intake-site-adapter/verify-route';
await verifyCanaryRoute({ projectRoot: process.cwd(), routePath: 'api/intake-canary.js', source: 'example-site' });
```

The command imports the actual JavaScript route in a fresh subprocess containing
only synthetic environment values. It requires anonymous and wrong-token 401,
one authenticated synthetic Intake request and exact acknowledged output. It
supports Node/Vercel default, `handler` or `canary` exports, and Web `POST`.
It rejects path and symlink escape, hides route output/exception details, and
terminates after five seconds (API configurable from 100 to 10,000 ms).

Run only reviewed local code in a clean disposable checkout. Common network and
subprocess APIs are disabled, but this is not an OS security sandbox: imported
code can access files it is allowed to read. Use OS network isolation for
stronger no-network proof. Synthetic verifier success is not deployment proof.

`fetchImpl`, `sleep`, `clock` and `logger` are server-side dependency-injection
seams for tests; `logger: null` disables logging. A fetch implementation must
return standard `Response` objects and preserve the fixed destination boundary.
Use production defaults for transport, timing and retry policy.

See [security boundaries](SECURITY.md) and [upgrade/rollback policy](CHANGELOG.md).
Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
