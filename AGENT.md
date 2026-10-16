# AGENT.md - genesis-mesh-sdk (TypeScript)

Guidance for AI coding agents and human contributors working inside the
Genesis Mesh TypeScript SDK.

This SDK is a standalone package. It does **not** import from the Python main
repo. It wraps the NA HTTP API surface documented in:

- `genesismesh/docs/sdk/typescript.md` - public reference
- `genesismesh/docs/api/trust-http.md` - NA HTTP routes
- `genesismesh/api/trust-http.md` - same, canonical Sphinx source

---

## Repo layout and layers

[docs/architecture.md](docs/architecture.md) holds the module map (one line per
`src/` file), the layer table, the request and verification flows, and the
recipes for common changes (which files to touch, which check fails if one is
missed). Keep it current when you add a module or change where code lives.

```text
sdk-typescript/
  src/            # the package: leaf <- protocol <- transport <- orchestration <- index.ts
  tests/          # *.test.ts by area; *-conformance.test.ts run the core's vectors;
                  # e2e*.test.ts run against a disposable local NA (npm run test:e2e)
  tests/fixtures/ # copies of the core's conformance vectors and Python fixtures
  etc/            # the public API report (npm run api:update), reviewed as a diff
  scripts/        # build helpers, the e2e NA harness, changelog.py, vector and API tools
  changelog.d/    # changelog fragments (see changelog.d/README.md)
  dist/           # generated (ESM, CJS, types) - never edit directly
```

`tests/architecture.test.ts` enforces the layer table: no import from a higher
layer beyond its shrinking allowlist, no runtime import cycle, and nothing but
`src/` modules and `node:` built-ins.

**Do not mix layers.** If a sub-client needs to sign something directly, it
belongs in `auth.ts`. If a sub-client is doing HTTP retry logic, it belongs in
`client.ts`.

---

## Architectural principles

### 1. No runtime dependencies

The SDK uses only Node.js built-ins (`node:crypto`, `node:crypto`'s `fetch`
polyfill, `node:fs`). Do not introduce `axios`, `node-fetch`, or any other
HTTP library. Do not introduce utility libraries (`lodash`, `ramda`, etc.).

### 2. Field names follow the wire format exactly

All `types.ts` interfaces use snake_case, matching the NA's JSON API exactly.
This means no camelCase transformation. Callers work with snake_case; so does
TypeScript.

The reason: the same protocol models ship in Python, Go, and C#. A shared
naming convention makes cross-language debugging tractable.

### 3. Security-sensitive code stays boring

`auth.ts` is the most security-critical file. Keep it minimal and explicit:

- Do not add caching or memoization to key operations.
- Do not add fallbacks for unsupported key formats.
- Do not silently swallow signing errors.
- The PKCS8 DER prefix (`302e020100300506032b657004220420`) is a fixed constant -
  never derive it dynamically.

### 4. Errors fail closed

`fromHttpError` must handle the NA's nested error format:
`{ error: { message: "...", code: "..." } }`. If the format changes,
**throw**, do not silently produce a misleading error.

Unknown HTTP status codes fall through to `GenesisMeshError` with the
raw status - never swallow them.

### 5. Admin route invariant

The NA constructs and signs protocol artifacts from declared intent.
The SDK must not pre-build a model client-side and ask the NA to sign it.
Sub-client methods send parameters, not pre-built signed models.

---

## Known constraints (learned from smoke testing)

These are non-obvious and not in the HTTP reference. Tests must cover them.

| Constraint | Detail |
|-----------|--------|
| Evidence verdict | Must be `"allow"` \| `"block"` \| `"escalate"` \| `"warn"`. The value `"trusted"` is invalid. |
| Role prefixes | Roles must start with `role:anchor`, `role:bridge`, `role:client`, `role:operator`, or `role:service:<name>`. Bare names return 422. |
| Agreement accept | Requires the NA to hold an active recognition treaty for the `responder_sovereign_id`. Issue it via `POST /admin/recognition-treaties` first. |
| `DataSourceDescriptor` | `source_type` (`"personal"` \| `"proprietary"` \| `"public"` \| `"synthetic"`) and `owner_sovereign_id` are required. |
| Ed25519 in Node.js ≥ 22 | Raw seed format not supported. Must use PKCS8 DER: prepend `302e020100300506032b657004220420` to the 32-byte seed, then `createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })`. |
| Failover (v0.60) | With `baseUrls`, only idempotent requests are replayed on another instance; a non-idempotent request moves only on a connection failure (`NetworkError.connectFailed`). Never relax this: a delivered evaluate, issue, publish or revoke must not run twice. |
| ESM + Jest on Windows | Use `node --experimental-vm-modules node_modules/jest/bin/jest.js` (not the bash shebang wrapper). Import `jest` from `@jest/globals` in tests. |

---

## Development environment

**This is a Windows project.** Development is on Windows 11 / PowerShell.
CI runs on Linux. Code must work on both.

- Use forward slashes in file paths inside TypeScript source.
- PowerShell: use `;` not `&&` to chain commands in Windows PowerShell 5.1.
- Do not assume `node` is on PATH without being invoked by npm scripts.

---

## Pre-commit equivalent

There is no pre-commit framework in this repo. Run these before every commit
(CI runs the same on Node 22 and 24):

```sh
npm run typecheck
npm run build
npm run test:package   # the ESM and CJS entry points, from the built package
npm run check:types    # arethetypeswrong on the packed tarball
npm run api:check      # the committed API report matches the build (api:update rewrites it)
npm run test:coverage  # the tests, with the coverage floors in jest.config.cjs
```

After adding a sub-client method, add tests in the corresponding
`tests/{domain}.test.ts`.

---

## Testing requirements

Every public method must have:

- A happy-path test with a `mockFetch` that returns the expected shape.
- A test that the method calls the correct URL path.
- A test that admin methods send the four `X-Admin-*` headers.
- A negative test: the method rejects / throws if the NA returns an error.

Use `helpers.ts`:

```typescript
import { jest } from '@jest/globals';
import { generateTestKeyPair, mockFetch, buildTransport } from './helpers.js';
```

`generateTestKeyPair()` returns a `{ seedBase64, pubBase64 }` pair from the
same Ed25519 key. Never generate the seed and pub from separate calls.

---

## Coding standards

- ESM throughout (`"type": "module"` in `package.json`). All imports end in `.js`.
- `strict: true` in TypeScript. No `any` in `src/`. `unknown` + narrowing only.
- No `console.log` in `src/`. Throw or return, never log.
- Do not add comments explaining what the code does. Only add comments for
  non-obvious invariants (e.g. the PKCS8 prefix).

---

## CJS build

`tsconfig.cjs.json` is standalone - it does **not** extend `tsconfig.json`.
This avoids a TypeScript 5 conflict where `declaration: false` cannot coexist
with an inherited `declarationDir`. Do not add `extends` to `tsconfig.cjs.json`.

---

## Release process

The core and all official SDKs share one coordinated version, and the core
leads: CI refuses a version ahead of the core's (`release-train`), and the
publish workflow refuses a tag the core has not tagged first. `VERSION`,
`package.json`, `package-lock.json` and the release tag must match
(`npm run check:version`).

- Pull requests add a fragment in `changelog.d/<version>/`; they never edit
  `CHANGELOG.md` (CI check "Changelog fragments").
- The release pull request (branch `release/<version>`) folds the fragments
  into `CHANGELOG.md` with `python scripts/changelog.py release`, and removes
  any "*Unreleased.*" marker from `README.md` and `docs/`.
- The Maintainer tags `vX.Y.Z` after the core's tag; `publish.yml` builds,
  checks the package, runs the tests, publishes to npm with provenance and
  creates the GitHub release.

See the core's `docs/development/versioning.md`.

---

## Agent behavior rules

When acting as an AI coding agent in this repository:

1. Read this file before making changes.
2. A bug fix comes with the test that fails without it (the "Regression test"
   check enforces it for `fix:` pull requests).
3. Keep changes small. One method → one test. One sub-client → one test file.
4. Preserve layer boundaries. No signing logic in sub-clients. No domain
   knowledge in `client.ts`.
5. Match the NA's wire format exactly - no camelCase, no aliases, no convenience
   transformations.
6. Do not introduce runtime dependencies.
7. Do not add methods that the NA HTTP API does not expose.
8. When a NA constraint is discovered (invalid enum value, missing required
   field, prerequisite call), add it to the "Known constraints" table in this
   file AND cover it with a negative test.
9. Confirm before destructive operations. Approval once does not generalize.
10. Validate TypeScript SDK output with the Python-generated fixtures in
    `tests/fixtures/`, the SDK unit tests and `npm run test:e2e`. Regenerate the
    fixtures with `scripts/generate_vectors.py` using the core Python environment.
    The core conformance runner validates Python suites and does not support a
    `--sdk typescript` option.


## Governed lifecycle additions

- `canonical.ts` derives signed model bodies and digests using `auth.ts`.
- `validation.ts` checks complete signed wire artifacts without coercing them.
- `execution.ts` builds evidence and checks metadata. `verify.ts` verifies
  artifacts and evidence exports offline. Both are pure protocol modules.
- `policy.ts` and `evidence_store.ts` wrap the corresponding NA routes.
- `governance.ts` composes clients and the recorder and compares inventories.
- Metadata preflight checks in sub-clients delegate to `execution.ts`.
- Governed actions require trusted verification keys and expected policies;
  attestation-backed ALLOWs require the expected attestation. Check the request
  context ID and recheck expiry after reading history.
- Recognition policies put allowed roles and accepted statuses inside each
  recognized issuer. Public attestation verification requires an explicit policy
  or an active policy saved on the NA.
- Required policy enforcement still permits an empty matching policy set. Use
  expected bindings to require a particular policy in governed actions.
- Use `parseJson` for artifacts received from Python. Normal JSON cloning can
  lose integral float lexemes and invalidate offline signatures.
- The CommonJS build needs its generated `dist/cjs/package.json` marker. Do not
  edit generated files directly; `scripts/finish_cjs.mjs` creates it.
- Run `npm run typecheck`, `npm run build`, `npm run test:package`, `npm test`
  and `npm run test:e2e` for protocol changes. E2E uses a disposable local NA
  with synthetic callbacks, not external services. See `docs/offline-verification.md`.
  With `GM_E2E_REQUIRED=1` (set in CI) a live test that cannot run, or a core
  feature the NA lacks, fails instead of passing as skipped.
