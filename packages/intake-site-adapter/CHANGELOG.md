# Upgrade and rollback policy

## 1.1.0 preparation

Adds bounded current v1 mapping/consent validation, safe UUID logging, strict
request/response protocol acknowledgement, streamed input/output limits,
transport deadlines, actual canary retry waits, trusted-host visitor limits,
production Git source authority and isolated route verification. Public runtime,
CLI and declarations share version 1.1.0. Apache-2.0 licensing applies.

Pre-release review corrections preserve invalid mapped boolean values for
validation and require HTTP status to agree with duplicate acknowledgement.
Optional text omission and valid boolean values retain their defined behavior.

The private 1.0.3 release remains immutable transition rollback material. Local
historical source is not claimed byte-identical to that registry artifact.
Before updating a site, record its exact current package lockfile and deployment.
Pin the approved public version exactly, remove package-download credentials,
and prove a clean install, build, contract tests, valid/duplicate/consent handling,
anonymous401 and authenticated200 with exact source/package/API evidence.
Production requires separate approval of that exact preview artifact.

Strict protocol validation and hosting identity checks intentionally fail closed
against legacy API responses or unsupported hosting. Upgrade the reviewed API
protocol dependency before promoting consuming sites. Verify credential-purpose
enforcement separately; package tests do not create that server capability.

If a site fails, restore its recorded previous deployment and exact lockfile
without overwriting any package version. Do not remove the private rollback
until every affected site and the onboarding flow have completed production
proof and the observation period. Do not roll back additive database migrations
as part of an adapter rollback.

Future releases use semantic versioning and a new immutable version. Contract
changes need a versioned contract decision. Every release repeats Node20/22
consumer, tarball-content, dependency/security and provenance checks.
