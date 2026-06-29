# AGENT.md — @genesismeshlabs/sdk (TypeScript)

Guidance for AI coding agents and human contributors working inside the
Genesis Mesh TypeScript SDK.

This SDK is a standalone package. It does **not** import from the Python main
repo. It wraps the NA HTTP API surface documented in:

- `genesismesh/docs/sdk/typescript.md` — public reference
- `genesismesh/docs/api/trust-http.md` — NA HTTP routes
- `genesismesh/api/trust-http.md` — same, canonical Sphinx source

---

## Repo layout

```text
sdk-typescript/
  src/
    auth.ts        # canonicalJson, Ed25519/PKCS8-DER signing, buildAdminHeaders
    client.ts      # HttpTransport — fetch, timeout, typed error mapping
    errors.ts      # GenesisMeshError + typed subclasses, fromHttpError
    types.ts       # Protocol interfaces (snake_case, matching Pydantic models)
    agreement.ts   # AgreementClient
    attestation.ts # AttestationClient
    boundary.ts    # BoundaryClient
    consensus.ts   # ConsensusClient
    data_usage.ts  # DataUsageClient
    disclosure.ts  # DisclosureClient
    evidence.ts    # EvidenceClient
    index.ts       # GenesisMeshClient + all re-exports
  tests/
    helpers.ts     # test utilities: generateTestKeyPair, mockFetch, buildTransport
    auth.test.ts
    client.test.ts
    agreement.test.ts
    boundary.test.ts
    evidence.test.ts
    attestation.test.ts
    disclosure.test.ts
    consensus.test.ts
    data_usage.test.ts
  dist/            # generated (ESM, CJS, types) — never edit directly
  package.json
  tsconfig.json         # ESM output
  tsconfig.cjs.json     # CJS output (standalone, does NOT extend tsconfig.json)
  jest.config.cjs
  README.md
  AGENT.md         # this file
```

---

## Layer rule

Mirror the Python main repo's enforced layer separation:

```
src/auth.ts        = Pure crypto: canonicalJson, signBytes, buildAdminHeaders.
                     No HTTP. No fetch. No domain knowledge.
                     Python equivalent: genesis_mesh/crypto/

src/client.ts      = HTTP transport only: fetch, timeout, header injection,
                     error mapping via fromHttpError.
                     No signing logic. No domain knowledge.
                     Python equivalent: na_service/ (transport layer)

src/errors.ts      = Typed error classes only.
                     No domain logic. No HTTP calls.

src/types.ts       = Protocol interfaces only.
                     No functions. No classes. Pure type declarations.
                     Python equivalent: genesis_mesh/models/

src/{domain}.ts    = Sub-client: thin wrapper over HttpTransport.
                     One file per domain. Methods call adminPost/publicPost/publicGet.
                     No signing logic inline. No URL construction beyond the path.
                     Python equivalent: na_service/routes/
```

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
- The PKCS8 DER prefix (`302e020100300506032b657004220420`) is a fixed constant —
  never derive it dynamically.

### 4. Errors fail closed

`fromHttpError` must handle the NA's nested error format:
`{ error: { message: "...", code: "..." } }`. If the format changes,
**throw**, do not silently produce a misleading error.

Unknown HTTP status codes fall through to `GenesisMeshError` with the
raw status — never swallow them.

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

There is no pre-commit framework in this repo. Run these manually before
every commit:

```sh
npm run build   # must exit 0 — TypeScript compile errors block shipping
npm test        # all tests must pass
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

`tsconfig.cjs.json` is standalone — it does **not** extend `tsconfig.json`.
This avoids a TypeScript 5 conflict where `declaration: false` cannot coexist
with an inherited `declarationDir`. Do not add `extends` to `tsconfig.cjs.json`.

---

## Release process

This SDK follows the same release process as the main Python repo. Every
version shipped must:

1. Pass `npm run build` and `npm test`.
2. Have a CHANGELOG entry in the main repo's `CHANGELOG.md`.
3. Have its plan marked `[x]` in `genesismesh/ops/plan-vX.Y.Z.md`.
4. Be committed, tagged `vX.Y.Z`, pushed, and have a GitHub release created.
5. Have `genesismesh/docs/development/history.md` updated with a narrative entry.

The main repo's `/ship` skill drives this process for Python releases. For SDK
releases, follow the same checklist manually or adapt `/ship` to the SDK context.

See `genesismesh/ops/release-checklist.md` for the manual checklist.

---

## Agent behavior rules

When acting as an AI coding agent in this repository:

1. Read this file before making changes.
2. Identify which release milestone (v0.53 TS, v0.54 Go, v0.55 C#) the change supports.
3. Keep changes small. One method → one test. One sub-client → one test file.
4. Preserve layer boundaries. No signing logic in sub-clients. No domain
   knowledge in `client.ts`.
5. Match the NA's wire format exactly — no camelCase, no aliases, no convenience
   transformations.
6. Do not introduce runtime dependencies.
7. Do not add methods that the NA HTTP API does not expose.
8. When a NA constraint is discovered (invalid enum value, missing required
   field, prerequisite call), add it to the "Known constraints" table in this
   file AND cover it with a negative test.
9. Confirm before destructive operations. Approval once does not generalize.
