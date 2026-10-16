# Contributing to genesis-mesh-sdk

Thank you for your interest in contributing. This document covers how to set up
the development environment, run tests, and submit changes.

---

## Prerequisites

| Tool | Minimum version |
|------|----------------|
| Node.js | 22 (`engines`; CI runs 22 and 24) |
| npm | 10 |
| TypeScript | installed via `npm ci` |
| Python | 3.12 with the core installed, for `npm run test:e2e` only |

---

## Set up

```sh
git clone https://github.com/GenesisMeshLabs/sdk-typescript.git
cd sdk-typescript
npm ci
```

Verify the checks pass before making any changes (CI runs the same):

```sh
npm run typecheck
npm run build
npm run test:package   # the ESM and CJS entry points, from the built package
npm run check:types    # arethetypeswrong on the packed tarball
npm test
```

---

## Project structure

Read [AGENT.md](AGENT.md) for the module map and the layer rule before adding
or changing source files. The short version:

| Layer | Files |
|-------|-------|
| Types and errors | `src/types.ts` (interfaces only), `src/errors.ts` |
| Protocol, no HTTP | `src/auth.ts` (signing), `canonical.ts`, `strict*.ts`, `validation.ts`, `execution.ts`, `out-of-band.ts`, `remediation.ts`, `grants.ts`, `key-history.ts`, `anchors.ts`, `verify.ts`, `audit-pack.ts`, `outbox.ts` |
| Transport and sub-clients | `src/client.ts` (HTTP only), one `src/{domain}.ts` per route group; `evidence_store.ts` also flushes the outboxes |
| Orchestration | `src/governance.ts`, `src/grant-holder.ts` |
| Public entry | `src/index.ts` |

`src/canonical-registry.ts` is generated: run `npm run sync:registry` after
copying the core's `field_registry.json` into `tests/fixtures/conformance/`.

Do not mix layers. A sub-client file must not contain crypto primitives.
The protocol modules must not make HTTP calls.

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

A bug fix comes with the test that fails without it: say in the pull request
which test it is and that you saw it fail on the parent commit.

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
- Include a test for every changed behaviour. A `fix:` pull request that
  changes source files must change a test (the "Regression test" check),
  unless the Maintainer labels it `no-test-needed`
- Add a changelog fragment, `changelog.d/<version>/<short-name>.md` (see
  [changelog.d/README.md](changelog.d/README.md)); never edit `CHANGELOG.md`,
  which only a `release/<version>` pull request changes. A breaking change, or
  one callers must act on, gets an `### Upgrading` note
- Run the checks above locally before opening the PR
- Fill in the PR template. Changes to workflows, vectors, signing and
  verification, the public API or `SECURITY.md` need the Maintainer's merge

If your change adds a new NA constraint discovered during testing, add it to
the **Known constraints** table in `AGENT.md`.

---

## Testing against a live NA

The unit tests mock HTTP. `npm run test:e2e` runs the SDK against a disposable
local Network Authority that `scripts/e2e_na.py` starts from the core. It uses
the core checkout next to this one (`../genesismesh/.venv`) or the interpreter
in `GM_E2E_PYTHON`:

```sh
GM_E2E_PYTHON=/path/to/python npm run test:e2e
```

The HA failover test also needs `GM_E2E_HA_DATABASE_URL` (an empty PostgreSQL
database) and nginx; without them it is skipped. CI sets `GM_E2E_REQUIRED=1`,
which makes a live test that cannot run, or a core feature the NA lacks, fail
instead of passing as skipped.

---

## Reporting issues

Use the GitHub issue templates:

- **Bug report** — unexpected behaviour, wrong types, broken build
- **Feature request** — new sub-client method, new NA route support

For security vulnerabilities, follow the process in [SECURITY.md](SECURITY.md).
