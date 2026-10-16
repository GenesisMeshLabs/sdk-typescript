### Changed

- **Every record kind the verifier knows is checked at compile time.**
  `EntryKind` is now derived from `ENTRY_KINDS`, which `npm run
  sync:registry` generates into `src/canonical-registry.ts` from the core's
  field registry, and the verifier's kind tables (payload checks, record-ID
  fields, envelope maps, payload models, signer roles) are typed against
  it, as is the record outbox's `RecordOutboxKind`. A table that misses a
  kind, or a kind the registry adds, now fails to compile instead of
  skipping that kind's envelope or record-ID check. `EntryKind` and
  `RecordOutboxKind` name the same kinds as before; verification results do
  not change.
