### Fixed

- **A record the NA cannot read no longer blocks the outboxes.** A value the
  NA's strict JSON reader refuses (a lone surrogate, such as half an emoji cut
  by `slice`, an integer beyond 64 bits, or nesting deeper than 64) was
  signed, then retried forever as `invalid_json` with its whole batch, and
  after a restart the outbox file could not be read, so every governed action
  failed. Now:
  - `ExecutionRecorder.record`, `ObservationRecorder.record` and
    `signBreakGlass` refuse such a record before signing (`StrictJsonError`);
    after an action has run, `governedAction` records the outcome without the
    value and throws `MetadataRefusedError`, as it does for secret material;
  - the NA's `invalid_json` is a permanent refusal for execution, observation
    and break-glass records;
  - a batch of observations the NA refuses as a whole is split until the
    record it refuses is sent alone;
  - a `FileOutbox` or `FileRecordOutbox` file that cannot be read is moved
    aside as `<name>.unreadable`; the first read throws
    `outbox_file_unreadable` naming it, and the outbox works again from the
    next call.
- **Records with integers beyond 2^53 are sent after a restart.** They were
  read back as `bigint`, which the metadata guard's size check could not
  serialise; the error was filed as `network_error` and retried forever. The
  guard now sizes metadata without `JSON.stringify`, and an exception in this
  process before any request is filed as `local_error`.

### Changed

- **A record whose predecessor was refused is now sent.** It was
  dead-lettered unsent (`evidence_predecessor_dead_lettered`), so the NA
  never quarantined it even when it would have refused it for its own reason,
  such as a retired key, and the action it records was missing from the
  store's history. It is now submitted in turn: the NA's own refusal is its
  dead letter's code, and a refusal only for the gap its predecessor left
  (`evidence_chain_gap`, `resource_chain_gap`) dead-letters it as
  `evidence_predecessor_dead_lettered`.
- New codes: `local_error` (a submission that failed in this process,
  retried) and `outbox_file_unreadable`; `invalid_json` joins
  `PERMANENT_REFUSALS` and `RECORD_PERMANENT_REFUSALS`. New export
  `checkSignable`.
