### Fixed

- **A grant use behind one that never took its place in the chain is a dead letter.** The record outbox retried a use the NA refused for a chain gap (`grant_use_chain_gap`) forever, even when the gap was left by an earlier use of the grant that the outbox holds as a dead letter and that never took its place: one refused without a quarantine entry, or quarantined as a conflict or a chain mismatch. Every `ignoreBackoff` flush then ended on it. Such a use is now a dead letter too (`evidence_predecessor_dead_lettered`, the code the evidence outbox gives a record behind a refused one), with the earlier use named, and the flush goes on. A gap behind a use the NA kept in the chain, behind another grant's dead letter or a later use's, or one the outbox cannot be read to look behind, is still retried.
- **A grant's uses are sent in their chain's order** by `flushRecords`, whatever order they were kept in, as when two uses were kept at once offline.

### Documentation

- `GrantUseSummary`: once retention has removed a use's store entry, the NA answers `recorded_at` and `outcome` as null; the types keep them as strings until a major release can widen them.
