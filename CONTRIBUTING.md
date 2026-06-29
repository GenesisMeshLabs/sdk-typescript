# Contributing to @genesismeshlabs/sdk

Thank you for your interest in contributing. This document covers how to set up
the development environment, run tests, and submit changes.

---

## Prerequisites

| Tool | Minimum version |
|------|----------------|
| Node.js | 20 LTS |
| npm | 9 |
| TypeScript | 5.0 (installed via `npm ci`) |

---

## Set up

```sh
git clone https://github.com/GenesisMeshLabs/sdk-typescript.git
cd sdk-typescript
npm ci
```

Verify the build and tests pass before making any changes:

```sh
npm run build
npm test
```

---

## Project structure

Read [AGENT.md](AGENT.md) for the enforced layer rule before adding or changing
source files. The short version:

| File | What goes here |
|------|---------------|
| `src/auth.ts` | Crypto only — canonical JSON, Ed25519 signing, admin headers |
| `src/client.ts` | HTTP transport only — fetch, timeout, error mapping |
| `src/errors.ts` | Typed error classes only |
| `src/types.ts` | Protocol interfaces only — no functions, no classes |
| `src/{domain}.ts` | Sub-client — thin wrapper over HttpTransport |

Do not mix layers. A sub-client file must not contain crypto primitives.
The auth module must not make HTTP calls.

---

## Making changes

### Branching

Branch from `main`. Use the pattern `{type}/{short-description}`:

```
feat/add-consensus-threshold-param
fix/datasource-required-fields
docs/update-raw-admin-examples
```

### Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(attestation): add optional subject_public_key param
fix(errors): handle nested NA error format correctly
docs(readme): correct evidence verdict values
test(consensus): add negative test for threshold below vote count
chore(deps): update ts-jest to 29.4
```

Scope is the primary area: `auth`, `transport`, `types`, `agreement`,
`boundary`, `evidence`, `attestation`, `disclosure`, `consensus`,
`data-usage`, `sdk`, `ci`, `docs`.

### Code style

- `strict: true` TypeScript throughout — no `any` in `src/`
- snake_case field names on all types (matches the NA wire format)
- No comments explaining what the code does — only non-obvious invariants
- No `console.log` in `src/`

### Tests

Every public method needs four tests in `tests/{domain}.test.ts`:

1. Happy-path — mocked response returns the correct shape
2. URL — method calls the correct route path
3. Auth — admin methods send the four `X-Admin-*` headers
4. Error — NA 4xx → typed SDK error with correct `.code`

Use `helpers.ts`:

```typescript
import { jest } from '@jest/globals';
import { generateTestKeyPair, mockFetch, buildTransport } from './helpers.js';
```

Run the full suite:

```sh
npm test
```

---

## NA protocol constraints

Before adding a new sub-client method, check the constraints table in
[AGENT.md](AGENT.md). Common traps:

- Evidence `verdict` must be `"allow" | "block" | "escalate" | "warn"`
- Roles must use a `role:` prefix (`role:client`, `role:anchor`, etc.)
- `DataSourceDescriptor` requires `source_type` and `owner_sovereign_id`
- Agreement `accept` requires the NA to hold a prior recognition treaty

---

## Pull requests

- Keep PRs focused — one feature or fix per PR
- Include a test for every changed behaviour
- Ensure `npm run build` and `npm test` pass locally before opening the PR
- Fill in the PR template — the checklist exists for a reason

If your change adds a new NA constraint discovered during testing, add it to
the **Known constraints** table in `AGENT.md`.

---

## Smoke testing against a live NA

The unit tests mock HTTP. To run against a real Network Authority:

```sh
cd ../sandbox/sdk-smoke
npm install
npm run smoke   # requires NA on http://127.0.0.1:9443
```

See `sandbox/sdk-smoke/smoke.ts` for setup instructions.

---

## Reporting issues

Use the GitHub issue templates:

- **Bug report** — unexpected behaviour, wrong types, broken build
- **Feature request** — new sub-client method, new NA route support

For security vulnerabilities, follow the process in [SECURITY.md](SECURITY.md).
