### Added

- **Changes made outside the controlled path** (Genesis Mesh 1.3.0, NA with
  `EVIDENCE_OUT_OF_BAND=on`). See `docs/out-of-band-changes.md`.
  - `ObservationRecorder` signs an `ObservationRecord` with an observer key;
    `observationFromFinding` turns a reconciliation finding into one, known
    within the window between two scans.
  - `governedAction` with `breakGlass: { justification }` runs the action when
    the evaluation fails transiently (network error, timeout, `5xx`, `429`)
    and keeps a signed `BreakGlassRecord`; the result is a `BreakGlassResult`
    (`brokeGlass: true`). Never on a DENY. `ExecutionRecorder.signBreakGlass`
    and `signBreakGlass` sign one directly.
  - A record outbox (`ClientOptions.recordOutbox`, `FileRecordOutbox`, format
    `gm.evidence.record-outbox.v1`) keeps observations and break-glass
    records until the NA admits them: `evidenceStore.enqueueRecord` and
    `flushRecords`, observations up to 100 per request.
  - `evidenceStore.submitObservation`, `submitObservations`,
    `submitBreakGlass`, `judgeObservation`, `judgeBreakGlass`,
    `resourceChanges`, `operatorHolders`, `proposeHolder` and
    `approveHolder`; `registerExecutorKey` takes `role` and
    `resource_prefix`.
  - `verifyEvidenceEvents` verifies the entry kinds `observation`,
    `break_glass`, `judgement`, `quarantine` and `registry`, with the reasons
    `envelope_mismatch`, `observation_chain_break`, `duplicate_judgement`,
    `judgement_subject_mismatch`, `judgement_subject_missing`,
    `match_reused`, `quarantine_digest_mismatch` and
    `evidence_cites_judgement`, and counts them (`observations`,
    `break_glass`, `judgements`, `quarantined`). The conformance suite
    `out_of_band` runs in the tests.
  - `outOfBandCanonical`, `outOfBandDigest` and `verifyOutOfBandRecord` for
    the records' signed forms.

### Changed

- An execution record verifies only under an executor key: a key listed with
  `role: 'observer'` signs observations only (`ExecutorKeyInfo.role`).
- The embedded field registry lists the 1.3.0 records and the envelope fields
  `record_id`, `subject_id`, `matched_evidence_id` and
  `observation_sequence`, left out of the entry digest when absent, and the
  checkpoint's `observation_heads`.
- `MemoryOutbox` is generic (`MemoryOutbox<RecordOutboxEntry>` holds records);
  `EvidenceOutbox` is now `Outbox<OutboxEntry>`. `classifySubmissionError`
  takes the set of permanent refusals.
- The NA refuses execution evidence from a retired key as
  `evidence_executor_key_retired`, and from a key whose role or resource
  prefix does not cover it as `evidence_out_of_scope` (they were
  `evidence_unknown_executor`, which the outbox retried forever, holding
  every later record of the resource behind it). Both are permanent
  refusals, as are `observation_key_retired` and `break_glass_key_retired`.
- `governedAction` breaks the glass only under an attestation-based
  evaluation (an agreement-based one cannot be judged after the fact), and
  never on `429 admin_auth_throttled` or `503 evidence_store_unavailable`.

### Fixed

- **Verifiers refuse a record that leaves out a field the reference always
  writes** (`non_canonical_form`), as the reference does: a decision signed
  without `denial_reason` used to verify here and was refused by the NA.
  `nonCanonicalFields` replaces `nonCanonicalTimestamps` in every verifier.
- `verifyEvidenceEvents` reports a stored record signed over a form the
  reference does not write as `non_canonical_form` (it verified here), for
  every entry kind.
- A record's integral floats (`1000.0`) and a `"__proto__"` key are kept when
  its signed form is built, so the signature is checked over what was
  received; they were lost (an intent re-encoded as `1000` verified).
- `verifyEvidenceEvents` no longer throws on a decision entry whose context
  holds an integer beyond 2^53 or is missing; it reports it.
- Unknown-field paths are sorted by code point, as the other implementations
  sort them.
- The file outboxes run their changes one at a time (an update could rename
  a record back over one just removed, so an admitted record came back as
  pending after a restart), an add no longer scans every entry (it threw
  past about 125,000 entries), and a flush during `enqueue` leaves the record
  being submitted to it.
- Outbox files are read and written keeping a record's float spellings and
  large integers, so a record another SDK wrote (`1.0`) still verifies and
  is submitted as signed.
- A response the NA sent but whose body could not be read or parsed is
  `NetworkError` with code `response_body_unreadable`; it never breaks the
  glass (the NA may have decided, even denied).
- `governedAction` with `breakGlass` checks, before anything runs, that
  `requested_capability` is named, that the context's `request_parameters`
  and `attributes` are objects, and that they leave room for the record;
  an outcome detail longer than the NA admits is cut to 1024 characters, and
  a report the guard still refuses is left out, so a record is always kept
  once the action ran.
- 1.3.0 records verify as the reference reads them: an unsigned extra field
  is `payload_invalid`, a field the reference fills when absent is
  `non_canonical_form`, timestamps must be UTC, an observation names one
  change time or an ordered window, and lengths count characters.
  `verifyOutOfBandRecord` checks the record's form and fields too.
- `flushRecords` sends a batch the NA refuses as too large (`413`) one
  observation at a time.
