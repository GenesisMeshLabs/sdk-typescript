### Added

- **Pre-issued grants.** `gm.grants` wraps the NA's grant routes (beta):
  `issueGrant`, `listGrants`, `getGrant` and `revokeGrant` (admin), and the
  holder's `requestTimeToken` (signed by the bearer key) and
  `submitGrantUse`. The new records are typed and verified:
  `verifyCapabilityGrant`, `verifyTimeToken`, `verifyTimeTokenRequest`,
  `verifyGrantUse` and `verifyGrantRevocation` (an NA-signed record read
  alone is placed at its `issued_at`, a revocation at its `revoked_at`).
  `envelopeParameter`, `envelopeProblem` and `useProblem` apply the NA's
  envelope and use rules, with its number rules: an integral number is an
  integer, integers fit 64 bits, comparisons are exact, booleans are never
  numbers, and set membership is type-strict.
- **`GrantHolder`.** Acts within a grant while the NA cannot be reached: it
  checks the capability, the closed envelope, secret material, the budget,
  the validity, the revocation feed it holds and its time token offline,
  signs each use with the bearer key and keeps it in the record outbox (a
  new kind, `grant_execution`). `sync()` reads the revocation feed, asks for
  a fresh time token and uploads the uses in order. When the grant has
  ended, its budget or time token is spent, or it is revoked, `act` with a
  `fallback` goes through `governedAction` with break-glass naming the
  capability: an NA that answers decides, and one that cannot be reached
  leaves the change to run under break-glass, judged after the fact. A DENY
  is never broken through.
- **Verification.** `verifyEvidenceEvents` verifies `grant`,
  `grant_execution` and `grant_revocation` entries and counts them, with the
  whole-store rules (`grant_missing`, `grant_mismatch`,
  `grant_bearer_mismatch`, `grant_use_chain_break`,
  `duplicate_grant_revocation`; `cited_record_missing` in a pack), then the
  use rules with the NA's admission codes, and the resource positions the NA
  assigns. A judgement may be `governed_by: grant` and a quarantine entry
  may keep a refused grant use. `verifyRevocationFeedSignature` verifies a
  feed listing `revoked_grant_ids`. Audit packs check a grant's policy
  binding and basis attestation, and their report lists grant uses as
  changes and has *Grants* and *Grant revocations* sections when the pack
  holds them.

### Upgrading

- Upgrade every verifier that reads your exports, audit packs and revocation
  feed to 1.6 before the NA turns on `EVIDENCE_GRANTS=on`: 1.5 refuses the
  new entry kinds and the feed's `revoked_grant_ids`.
- A record outbox now also holds grant uses (`kind: "grant_execution"`): an
  SDK before 1.6 cannot read such an outbox file.
