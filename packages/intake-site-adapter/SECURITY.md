# Security boundary

This is server-only reusable code. Browser payloads cannot select a tenant,
site, recipient, route, credential, provider or destination. Server secrets
stay in the approved runtime. Public material contains no client configuration.

Use distinct lead-ingestion, Intake-canary and website-probe credentials. The
package separates names and calls; only the API can enforce credential purpose,
expiry, revocation and site scope. Verify those controls in the actual release.

Only the approved Vercel-injected visitor address is used for instance limits.
Do not expose this handler outside that reviewed hosting boundary by setting a
runtime flag. The CLI executes trusted source in a bounded synthetic process;
it is not a sandbox for hostile source or a substitute for deployed canary proof.

Do not log tokens, contact values, request bodies or raw provider responses.
Report suspected vulnerabilities privately through the approved source
repository's security reporting channel once established; do not post secrets
or client data in public issues. No unverified support address is designated.

Release checks audit every allowlisted packed file, dependency inventory and
credential patterns. They are review aids, not proof that all possible secrets
or vulnerabilities are absent. High or critical unresolved findings block release.
Public publication requires approved source identity, immutable artifacts,
trusted publishing, provenance, account 2FA and an actually protected environment.
