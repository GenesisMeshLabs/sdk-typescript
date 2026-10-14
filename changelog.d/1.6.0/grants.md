### Added

- **Pre-issued grants.** `gm.grants` wraps the NA's grant routes (beta):
  `issueGrant`, `listGrants`, `getGrant` and `revokeGrant` (admin), and the
  holder's `requestTimeToken` (signed by the bearer key) and
  `submitGrantUse`; `listGrantUses` reads a grant's use chain and
  `getGrant` its `chain_length`. `evidenceStore.search` takes `grant_id`,
  `storedResourceHead` names a resource head's `entry_kind` and `record_id`,
  and `isRetryableConflict` covers `grant_issuance_conflict`. The new records are typed and verified:
  `verifyCapabilityGrant`, `verifyTimeToken`, `verifyTimeTokenRequest`,
  `verifyGrantUse` and `verifyGrantRevocation` (an NA-signed record read
  alone is placed at its `issued_at`, a revocation at its `revoked_at`).
  `envelopeParameter`, `envelopeProblem` and `useProblem` apply the NA's
  envelope and use rules, with its number rules: an integral number is an
  integer, integers fit 64 bits, comparisons are exact, booleans are never
  numbers, and set membership is type-strict.
- **`GrantHolder`.** Acts within a grant while the NA cannot be reached: it
  checks secret material, the bearer key's resource prefix, the capability,
  the closed envelope, the budget, the validity, the revocation feed it
  holds and its time token offline, signs each use with the bearer key and
  keeps it in the record outbox (a new kind, `grant_execution`). A use the
  NA quarantines stays in the chain; a chain gap and a use dated ahead of
  the NA's clock are retried. `sync()` reads the revocation feed, asks for
  a fresh time token and uploads the uses in order. When the grant has
  ended, its budget or time token is spent, or it is revoked, `act` with a
  `fallback` goes through `governedAction` with break-glass naming the
  capability: an NA that answers decides, and one that cannot be reached
  leaves the change to run under break-glass, judged after the fact. A DENY
  is never broken through.
- **Verification.** `verifyEvidenceEvents` verifies `grant`,
  `grant_execution` and `grant_revocation` entries and counts them, with the
  whole-store rules (`grant_missing`, `grant_mismatch`,
  `grant_bearer_mismatch`, `grant_use_out_of_scope`, `grant_use_chain_break`
  with a quarantined use as the chain's head, `duplicate_grant_revocation`,
  `duplicate_record` for a use ID shared with execution evidence or a
  break-glass record; `cited_record_missing` in a pack), then the use rules
  with the NA's admission codes, and the resource positions the NA assigns. A judgement may be `governed_by: grant` and a quarantine entry
  may keep a refused grant use. `verifyRevocationFeedSignature` verifies a
  feed listing `revoked_grant_ids`. Audit packs check a grant's policy
  binding and its basis, an attestation or an agreement from
  `trust/agreements.jsonl` (`cited_agreement_missing`,
  `cited_agreement_mismatch`, `agreement_invalid_signature`), and their
  report lists grant uses as changes and has *Grants* and *Grant
  revocations* sections when the pack holds them.

### Upgrading

- Upgrade every verifier that reads your exports, audit packs and revocation
  feed to 1.6 before the NA turns on `EVIDENCE_GRANTS=on`: 1.5 refuses the
  new entry kinds and the feed's `revoked_grant_ids`.
- A record outbox now also holds grant uses (`kind: "grant_execution"`): an
  SDK before 1.6 cannot read such an outbox file.
