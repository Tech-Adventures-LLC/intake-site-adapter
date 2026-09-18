# Intake site adapter public source

Source identity is configured for `Tech-Adventures-LLC/intake-site-adapter`.
The reusable package is `@tech-adventures-llc/intake-site-adapter` version
`1.1.0` in `packages/intake-site-adapter`.

This source supports Node.js 20 and newer. Local validation uses Node 20.20.2
and 22.23.2 with the following commands:

```sh
npm ci --ignore-scripts --registry=https://registry.npmjs.org
npm test
npm run adapter:pack -- --output ./intake-adapter-package-output
```

The repository contains reusable adapter code, public contracts, synthetic
fixtures, and package-consumer checks. It does not contain a deployed service,
tenant configuration, or release credentials.

These commands prepare and validate a local candidate only. Repository identity
is configuration, not live ownership verification. npm owner setup, package
bootstrap, trusted publishing, 2FA, protected release settings, provenance, and
publication remain unresolved; the inactive release template and fail-closed
guard cannot publish a package.
