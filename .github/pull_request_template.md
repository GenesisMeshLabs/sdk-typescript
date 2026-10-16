## What changed

<!-- What this pull request changes and why, in 2-4 sentences. Link the issue or the core change it follows. -->

## How it was tested

<!-- The commands you ran and what they showed: npm run typecheck, npm run build,
npm run test:package, npm run check:types, npm test, and npm run test:e2e for a
protocol change (GM_E2E_REQUIRED=1 makes a skipped live test fail). -->

Bug fix: the test that fails without this change is ___
<!-- Name the test, and say how you checked that it fails on the parent commit. A fix:
pull request that changes source files must change a test, unless the Maintainer
labels it no-test-needed (the "Regression test" check). -->

## Changelog

- [ ] A fragment in `changelog.d/<version>/<short-name>.md` (see `changelog.d/README.md`), or no user-facing change.
      Only a `release/<version>` pull request edits `CHANGELOG.md`.

## Breaking change

- [ ] No breaking change.
- [ ] Breaking change, or a change callers must act on: the fragment has a `### Upgrading` note saying what to do.

## Flagged paths

These need the Maintainer's merge; tick any this pull request touches:

- [ ] Contract: the public API (`src/index.ts`, `src/types.ts`), routes or error codes the core defines
- [ ] Vectors: `tests/fixtures/`, `src/canonical-registry.ts`, `scripts/generate_vectors.py`, `scripts/sync-canonical-registry.mjs`
- [ ] Migrations or stored formats: the outbox and record outbox files
- [ ] Signing and verification: `src/auth.ts`, `src/canonical*.ts`, `src/strict*.ts`, `src/verify.ts`, `src/audit-pack.ts`, `src/key-history.ts`, `src/grants.ts`
- [ ] Workflows: `.github/`
- [ ] `SECURITY.md`
