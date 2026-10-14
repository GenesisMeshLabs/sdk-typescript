# Changelog

All notable changes to `genesis-mesh-sdk` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions align with the [Genesis Mesh release sequence](https://github.com/GenesisMeshLabs/genesismesh/blob/main/CHANGELOG.md).

---

## [1.7.0] - 2026-10-14

### Fixed

- **A grant holder no longer counts a use the NA quarantined against the
  grant's budget.** The NA's budget counts admitted uses only, but
  `GrantHolder` counted every use it had signed, so a holder with a
  quarantined use fell back with `grant_budget_exhausted` while the grant
  still had uses left. Offline the holder still counts every use it signed,
  since it cannot know which the NA will admit; once the NA has answered a
  use as quarantined after it continued the chain, that use stops counting
  and keeps its place in the chain. A use quarantined as a conflict or a
  chain mismatch (it did not continue the chain) or as
  `grant_budget_exhausted` (the NA counted more admitted uses than the
  holder knew of) still counts.
- **A dead letter names the NA's quarantine entry.** When the NA keeps a
  refused record as a quarantine entry, the outbox entry's
  `last_error.quarantine_id` now holds its ID (the NA's
  `error.details.quarantine_id`).

## [1.6.0] - 2026-10-14

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
  `cited_agreement_mismatch`, `agreement_invalid_signature`; an agreement
  the NA signed for both parties needs the responder's treaty in the pack),
  and their
  report lists grant uses as changes and has *Grants* and *Grant
  revocations* sections when the pack holds them.

### Upgrading

- Upgrade every verifier that reads your exports, audit packs and revocation
  feed to 1.6 before the NA turns on `EVIDENCE_GRANTS=on`: 1.5 refuses the
  new entry kinds and the feed's `revoked_grant_ids`.
- A record outbox now also holds grant uses (`kind: "grant_execution"`): an
  SDK before 1.6 cannot read such an outbox file.

## [1.5.0] - 2026-10-13

### Added

- **The NA's key history.** `verifyKeyHistory` verifies a genesis block and
  its key successions from the root public key you hold, and returns an
  `NAKeyHistory` (`keysAt`, `signingKeyAt`, `allKeys`). A succession carries
  three signatures: the root key's, the new key's (proof of possession) and
  the outgoing key's. The genesis block is refused as `genesis_invalid`,
  `genesis_root_mismatch`, `unknown_field`, `non_canonical_form` or
  `genesis_invalid_signature`; each succession, in this order, as
  `payload_invalid`, `unknown_field` or `invalid_signature`,
  `non_canonical_form`, `succession_sovereign_mismatch`,
  `succession_chain_break`, `succession_key_reused` (also the root key),
  `succession_backdated`, `succession_not_increasing`,
  `succession_after_expiry`, `succession_invalid_root_signature`,
  `succession_invalid_new_key_signature`,
  `succession_invalid_previous_signature`. `gm.na.getKeyHistory()` reads
  `GET /na/key-history`, and `gm.na.verifiedKeyHistory(rootPublicKey)`
  verifies it (`KeyHistoryError`).
- **Signatures at the record's own time.** Every verifier that takes NA keys
  also takes the key history: an export entry at its `recorded_at`, a record
  read alone at its own signed time (`NA_RECORD_TIME_FIELDS`), an agreement
  the NA signed at `agreed_terms.valid_from` while its key is still accepted
  now. A succeeded key is accepted for 300 seconds after the next key takes
  effect. A signature by another key of the history is
  `na_key_not_valid_at_time` (decisions, exports, anchors). A decision valid
  past its key's end, the hand-over and the 300-second lifetime cap is
  `decision_outlives_key`. A list of keys keeps the behaviour before 1.5.0.
  `verifyBoundaryDecision` takes `atRecordTime` to judge an archived decision
  as of its own time.
- **Exports.** `verifyEvidenceEvents` verifies `key_succession` entries
  (signed by the outgoing and the new key; with a history, one of its
  successions, `succession_not_in_history`, signed by the root key and
  recorded at least 60 seconds before it takes effect,
  `succession_backdated`) and `archive` entries, and counts them. Entries
  recorded more than 300 seconds before an earlier one are
  `recorded_at_out_of_order` (carried entries excepted), and an NA key must
  also be valid at the latest earlier time. Executor and observer keys
  placed in the store (`registered_sequence`, `registered_at_time`,
  `retired_sequence`, `retired_at_time`) verify only records between their
  registration and retirement. A cited retention checkpoint supplies the
  heads of the chains it removed. With `prior` (an audit pack's cited
  records) a record the run cites that neither holds is
  `cited_record_missing`.
- **Anchors offline.** `verifyStoreAnchors` and `checkEventsAgainstAnchors`
  port the reference's anchor checks; `evidenceStore.anchors`, `allAnchors`
  and `anchor` wrap the anchor routes.
- **Audit packs.** `evidenceStore.auditPack` asks the NA for a pack (read
  tier), `auditPackFiles` and `readAuditPackDir` give its files, and
  `verifyAuditPack` verifies it offline from the root key and the anchors you
  hold, with the reference's reason codes (`packReasons`): the manifest and
  trust files as received, `manifest_unknown_file`, `manifest_backdated`,
  cited entries against prior packs (`priorEntries`, `packEntryDigests`) and
  held anchors (`cited_entry_mismatch`, warning `cited_entry_unanchored`),
  the report rendered byte for byte (`renderReport`, `report_mismatch`), and
  the period covered (`period`, `pack_period_not_covered`).
  `checkCompleteness` and `parseChanges` (JSON or CSV, strict RFC 3339 times)
  match changes from an outside log against a pack (`change_unmatched`,
  warnings `changes_outside_period` and `change_duplicate`).
- **Archives.** `evidenceStore.archives` and `recordArchive` wrap the archive
  routes; `verifyArchiveRecord` verifies an archive record.
- **Treaties.** `verifyTreatySignature` and `treatyCanonical`.
- **Error codes.** `AuditErrorCode` lists the codes of the 1.5.0 routes.

### Changed

- `evidenceStore.applyRetention(olderThanDays, { throughSequence })`:
  `olderThanDays` may be `null` when `throughSequence` is given.
  `RetentionResult.held_back` names why retention stopped short (1.5.0:
  `not_archived`).
- `EvidenceStoreStatus` lists the fields the NA already returns:
  `latest_anchor`, `unanchored_entries`, `anchoring_blocked`,
  `policy_history_started`, `registry_healthy` and `registry_problems`.
  `Readiness` gains `na_key` (`signing`, `pending` or `stopped`).
- A retention checkpoint in an export with a field outside its signature is
  `payload_invalid`, as the reference reads it.
- The field registry is the 1.5.0 one (`KeySuccessionRecord`,
  `ArchiveRecord`, `AuditPackManifest`, `GenesisBlock` and
  `RecognitionTreaty` are roots; entry kinds `key_succession` and
  `archive`).

### Upgrading

- After an NA key succession, verify with the key history rather than a list
  of keys: a list of only the old key refuses records signed by the new one,
  and a list of both accepts either key at any time.
- An audit pack is not retried: the NA allows a few per hour and answers
  `429` beyond that. Raise `ClientOptions.timeout` for a large range.

## [1.4.0] - 2026-10-12

### Added

- **Remediation records.** `signRemediation` and `ExecutionRecorder.signRemediation`
  build and sign a `RemediationRecord` (entry kind `remediation`) with the
  executor key, refused before signing as the NA would refuse it
  (`remediation_malformed`, `remediation_secret_material`, `StrictJsonError`).
  `evidenceStore.submitRemediation` submits one; the record outbox keeps them
  too (`kind: "remediation"`) and submits them after break-glass records and
  observations. New permanent refusals in `RECORD_PERMANENT_REFUSALS`:
  `invalid_remediation`, `remediation_malformed`,
  `remediation_invalid_signature`, `remediation_key_retired`,
  `remediation_out_of_scope`, `remediation_secret_material`,
  `remediation_subject_mismatch`, `remediation_steps_mismatch`,
  `remediation_rotation_mismatch`, `remediation_rotation_before_change`,
  `remediation_rotation_other_executor`, `remediation_rotation_reused`,
  `remediation_not_due`, `remediation_already_recorded`,
  `remediation_conflict`.
- **The cancel pair.** `cancelByRotatingForward` cancels a denied change to a
  versioned resource as the NA states it: a governed rotation to a new version
  (its evidence names `execution_parameters.version_id`), then a disable of the
  denied version, then the remediation record linking the two. It checks the
  state (`remediation_due` or `overdue`; a pending review does not stop it),
  the plan and the record before the denied version is disabled, and throws
  `RemediationNotRecordedError` (`remediation_not_recorded`) for a failure
  after the rotation. `remediationSubject` names a decision never executed
  (`fallback: not_executed`) as its own change, for the alert that closes it.
- **The due queue, notices and reviews.** `evidenceStore.listRemediations`
  (paged with `after`; `state: "review_pending"` lists every change with a
  pending review), `allRemediations`, `remediation` (its newest 100 reviews
  and records, with `reviews_truncated` and `records_truncated`),
  `markNotified`, `requestReview`, `review` and `decideReview` wrap the NA's
  1.4.0 routes. A judgement, a resource's changes and the store status carry
  the remediation state (`RemediationStatus`), where a pending review is the
  flag `review_pending` beside the state, not a state: it stops no clock.
- **Urgent changes.** `urgentAction` runs an urgent change under the ordinary
  capability, under the emergency capability (with its justification
  parameter) when the ordinary one is denied, or under break-glass naming the
  emergency capability when the NA cannot be reached or answers `5xx` or
  `429`. It is never blocked, and always judged.
- **Offline verification of the new records.** `verifyEvidenceEvents` verifies
  the `remediation` and `review` entry kinds, with the new reasons
  `duplicate_remediation`, `remediation_subject_mismatch`,
  `remediation_subject_missing`, `remediation_rotation_missing`,
  `remediation_rotation_mismatch`, `remediation_rotation_other_executor`,
  `remediation_rotation_before_change`, `remediation_rotation_reused`,
  `review_approval_invalid`,
  `review_approval_key_mismatch`, `review_same_holder`,
  `review_subject_mismatch`, `review_subject_missing` and
  `review_waiver_after_remediation`, and the counts `remediations` and
  `reviews`. The missing-subject and missing-rotation checks apply to a run
  from entry 1 or right after the `checkpoint` passed, and only registry
  records the NA signed bind an operator key. `reviewApprovalProblem` proves
  a review from the operators' signed requests embedded in it, whose
  timestamps and waiver end are strict RFC 3339 (`rfc3339`);
  `verifyRemediationRecord`, `verifyReviewRecord`, `adminApprovalValid`,
  `reviewHolderProblem` and `reviewRequestProblem` check one record each.
- **The NA's rules, as pure functions.** `remediationPlan`,
  `decisionPlan`, `remediationGuidance`, `cancelSteps`, `changeFacts`,
  `remediationDueAt`, `dueAfterDenial`, `dueAfterWaiver`, `stepsProblem`,
  `remediationRecordProblem` (the record's exact form first, then
  `checkRemediation`), `rotationProblem`, `nextState(state, event,
  reviewPending)` (with `TransitionRefusedError` and the NA's codes),
  `emergencyMap` and `policySectionIssues`. All 340 vectors of the shared
  `remediation` conformance suite pass.
- Policy types carry the 1.4.0 sections `remediation`, `review_required` and
  `emergency`.

### Changed

- `policyDigest` and `policyCanonical` leave a policy's `remediation`,
  `review_required` and `emergency` sections out when they are absent or
  `null`, as the reference does, so a policy without them keeps its 1.3
  digest and a decision that binds it still verifies.
- `resourceChanges` takes `limit` and `after_sequence` (the NA pages a
  resource's changes from 1.4.0, 1000 at a time by default), and
  `allResourceChanges` follows the pages.
- The field registry covers `RemediationRecord`, `ReviewRecord`,
  `AdminApproval` and the new policy sections, and knows the `remediation` and
  `review` entry kinds; a quarantine entry may hold a refused remediation
  record (`record_kind: "remediation"`).

### Upgrading

- Upgrade every SDK that reads policies or verifies exports before the NA
  turns on `EVIDENCE_REMEDIATION`: a 1.3 SDK refuses policies with the new
  sections as `unknown_field` and exports with the new entry kinds as
  `unknown_entry_kind`.
- A `FileRecordOutbox` written by 1.4.0 may hold remediation records. A 1.3
  SDK cannot read them and moves their files aside as `<name>.unreadable`:
  flush the record outbox before going back to 1.3.

## [1.3.1] - 2026-10-11

### Changed

- New error code `na_public_key_unavailable` (status of the `/sovereign.json`
  answer) for a failed NA public key lookup; it was `network_error`.
- The default `observation_id` is derived from the source event instead of a
  random UUID. A second record of one source event with other fields (a later
  `observed_at`) is refused as `observation_conflict`, as before; take
  `observed_at` from your first record when you read an event again.
- New exports: `metadataProblem`, `observationId`.
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
- `GenesisMeshError.retryAfterSeconds` holds the response's `Retry-After`
  (seconds; null without one). New export `nextAttemptAt`.
- New export `recordMetadataProblem(kind, record)`: the NA's metadata guard
  over an observation or a break-glass record, as the recorders apply it.
- New reasons from `verifyEvidenceEvents`: `duplicate_record`,
  `judgement_match_missing`, `retention_count_mismatch`.

### Fixed

- **A firewall's `403` or a `404` no longer breaks the glass.** When the NA's
  public key could not be read from `/sovereign.json`, any failure, an HTTP
  answer included, became a `NetworkError`, so `governedAction` with
  `breakGlass` ran the action without ever calling evaluate. Now only a lookup
  that gets no answer is a network error (or a timeout); an answer without the
  key throws `na_public_key_unavailable` with that answer's HTTP status, and
  breaks the glass only when it is a `5xx` or `429`. Another NA instance is
  still tried after a `502`, `503` or `504`.
- **Keys named like built-ins are fields like any other.** Validation of an
  export envelope accepted an unknown field named `constructor` or
  `toString`, and `verifyEvidenceEvents` threw instead of returning a verdict
  for an unsigned field next to a signature whose `key_id` was `constructor`.
  Both now look at own properties only.
- **Observations and break-glass records pass the NA's own metadata guard
  before they are signed.** The SDK sized their metadata as UTF-8, left the
  justification out of the total, skipped `actor`, `source_event_id` and
  `version_id`, and counted the justification in UTF-16 units. A record the NA
  then refused was dead-lettered after its action had run: 3000 `é` in
  metadata, a context near 16 KiB plus a justification, or a justification of
  under 1024 characters ending in emoji (of which no record was kept at all).
  `metadataProblem` is now the reference's `metadata_problem`: escaped JSON,
  the same fields and order, characters counted as the NA counts them, and a
  refused justification named as `justification` rather than
  `outcome_detail`.
- **String times are signed in the form the NA writes.** `changed_at`,
  `changed_not_before`, `changed_not_after`, `observed_at` and `executed_at`
  given as strings were signed exactly as passed, so the documented
  `changed_at: event.time` with `toISOString()` output (`.573Z`), `+00:00` or a
  seven-digit fraction was refused as `observation_malformed`, and the SDK's
  own `verifyOutOfBandRecord` refused it too. Any ISO 8601 time with a UTC
  offset is now converted to UTC microseconds (`...00.573000Z`); a string
  without an offset, or that is not a time, is refused before signing.
- **A repeated reconciliation scan is a duplicate, not a conflict.**
  `observationFromFinding` records got a random `observation_id`, so signing a
  finding again was refused as `observation_conflict` and dead-lettered. The
  recorder now derives the default ID from the source event:
  `observationId(observer, source, source_event_id)`, the SHA-256 in hex of
  the three joined by NUL characters. Give your own IDs the same way.
- `governedAction` with `breakGlass` checks the record as it will be signed
  before evaluating or running anything, with room for the action's report as
  the NA sizes it, so a record can always be kept once the action has run.
- A change window is ordered to the microsecond, as the NA orders it.
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
- **The record outbox drains under the NA's rate limit.** `flushRecords` sent
  observations 100 at a time and retried a `429` unchanged, so with
  `NA_RATE_LIMIT_OBSERVATIONS_PER_MINUTE` below 100 the backlog never drained
  and break-glass records waited behind it. Batches now halve after each
  `429`, nothing is sent until the NA's `Retry-After` has passed (unless
  `ignoreBackoff`), and break-glass records go first.
- **`flushPending` never answers with a partial run.** A call made while a
  governed action was draining the records its own record chains from got
  that drain's result, and every other pending record was left untried; a
  call asking for `ignoreBackoff` during a run that kept backoff got that
  run's result too. A call now joins a run only when it tries everything the
  call asks for, and otherwise starts its own once that one ends. The same
  holds for `flushRecords`.
- A record that failed with a `Retry-After` is retried no earlier than it
  asks (at most 15 minutes), in both outboxes.
- **Reconciliation counts break-glass changes.** `resourceStates` read
  execution records only, so after a break-glass rotation reconciliation
  reported the new version as `drifted`, and the change was recorded and
  judged a second time. Break-glass records now count as the resource's
  changes, in the order the changes were made; `last_break_glass_id` names
  the record when the latest change was one. The chain head
  (`resource_sequence`, `record_digest`) and `last_decision_id` stay the
  newest execution record's, 0 and empty for a resource with only break-glass
  records.
- **Exports verify as the reference verifies them** (the 1.3.1 contract,
  conformance suite `out_of_band`). `verifyEvidenceEvents` now:
  - reports a record copied within a run once per kind as
    `duplicate_record`, and still checks the copy like any record;
  - checks every envelope field the NA derives from a Stage 2 record
    (`envelope_mismatch`, at most once per entry);
  - looks up judgement subjects by kind and ID, so a break-glass record and an
    observation may share an ID;
  - reports a judgement whose matched record a run from entry 1 does not hold
    (`judgement_match_missing`), and a retention checkpoint that removed fewer
    or more entries than positions (`retention_count_mismatch`);
  - takes the first record it holds of each resource as that chain's start
    when a run starts neither at entry 1 nor right after its checkpoint (a
    later export page), instead of reporting `resource_chain_break`;
  - checks the form of a record whose unsigned fields it set aside, and gives a
    record that leaves out a field the reference always writes as null the
    reference's reason (`non_canonical_form` or `invalid_signature`, not
    `payload_invalid`).
- **Numbers are read by the JSON grammar as whole tokens.** `parseJson` backed
  off to the longest valid prefix, so `[-0.]` was refused as `negative_zero`;
  it is `invalid_json`, as in every implementation (`[-01]` stays
  `negative_zero`, `[1e400.]` is `non_finite_number`).
- `parseExportLines` and `verifyEvidenceEvents` refuse `schema_version: 1.0`
  and envelope integers written as floats, as the reference does.
- `verifyAgreement` returns `missing_offerer_signature` for `signatures` that
  is not a list; it threw a `TypeError`. Attestation and revocation feed
  verification read such signatures as none too.
- A JSON fault in a response the SDK read back is no longer a permanent
  refusal: only the NA's own `invalid_json` dead-letters a record, since the NA
  may have admitted it.

## [1.3.0] - 2026-10-10

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

## [1.2.0] - 2026-10-10

Coordinated Genesis Mesh v1.2.0 release, *Nothing Lost, Anchored*: an
evidence outbox for governed actions, verifiers that refuse what they do not
know, strict input and records only in canonical form.

### Changed (breaking)

- **Verifiers refuse signed fields they do not know.** This SDK used to copy
  every received field into the signed form, so a field a newer signer
  covered verified here and could change what a record means. The SDK now
  embeds the field registry of signed records (generated from the Python
  reference, shipped in the shared conformance suite `field_registry`).
  Verifiers check the signature over the record as received first; an
  authentic record with a signed field the registry does not list is then
  refused as `unknown_field`, meaning this SDK must be upgraded:
  `verifyBoundaryDecision` (also for the expected policies and attestation),
  `verifyAgreement`, the signature helpers (which return `false`),
  `verifyDataAccessIntent` (an `intent_exceeds_license` violation naming the
  field) and `verifyEvidenceEvents`. Only the signed projection is checked:
  the signature, and an agreement's unsigned fields, are not. Free-form
  fields (`claims`, `scope`, `execution_parameters`, ...) stay open.
  `BoundaryVerificationReason` and `AgreementVerificationReason` gain
  `unknown_field`.
- `verifyEvidenceEvents` names an entry of an unknown kind
  (`unknown_entry_kind`, previously `payload_invalid`) and keeps it in the
  chain; `parseExportLines` and the export clients accept entries of any
  kind, so one new kind no longer aborts a whole page. A field outside a
  stored record's signature (records stored before 1.1.1) is reported in the
  new `warnings` list as `unsigned_field` and the record is verified without
  it.

- **Records are valid only in their canonical form.** A decision, an
  agreement or a data license policy whose signature verifies over a
  timestamp the reference does not write (`+00:00` rather than `Z`, a
  fraction `.000`) is refused as `non_canonical_form`
  (`verifyDataLicensePolicySignature` returns `false`; an intent check reports
  `Not in canonical form: intent` or `...: policy`). Records the NA signs are
  always canonical; build timestamps with `pythonTimestamp`, not
  `toISOString`. `BoundaryVerificationReason` and
  `AgreementVerificationReason` gain `non_canonical_form`.
- **`parseJson` reads strictly.** JSON every implementation would not read
  alike throws `StrictJsonError` with a `reason` (also its `code`):
  `duplicate_key`, `non_finite_number` (`1e400`), `integer_out_of_range`
  (outside `-2**63 .. 2**64 - 1`), `negative_zero` (the integer `-0`),
  `lone_surrogate`, or `invalid_json` (not JSON, a byte order mark, or arrays
  and objects nested more than 64 deep). `parseExportLines` and the export
  clients throw it. An HTTP response refused for one of the first five
  reasons throws `StrictJsonError`; a response that is not JSON, or not
  UTF-8 (no longer repaired with U+FFFD), throws `NetworkError` as before.
- **A decision without `denial_reason` or `freshness_proof` is no longer
  `payload_invalid`.** It is checked like any other: the NA signs both as
  `null`, so one received without them fails as `invalid_signature`, as in
  every implementation.
- `parseExportLines` strips only JSON whitespace around a line (`trim()`
  also removed a byte order mark and other spaces, which every other
  implementation refuses).

### Added

- `canonicalTimestamp`, `nonCanonicalTimestamps`, `checkStrictJson` and
  `StrictJsonError`; the shared conformance suite `canonical`, whose
  vectors include the check order and records signed before 1.2.0 with
  `null` fields.
- `unknownFields(model, record)` and `isKnownEntryKind(kind)`;
  `npm run sync:registry` regenerates the embedded registry from a new copy
  of the suite.
- **An evidence outbox keeps signed evidence until the NA admits it.** With
  `ClientOptions.outbox`, `governedAction` writes each signed record to the
  outbox before submitting it and removes it once admitted. A failed
  submission then does not throw: the result's `queued` is the outbox entry,
  `pending` after a failure a later attempt can overcome (network, timeout,
  `5xx`, `429`, an executor key not registered yet, a chain gap, a disabled
  store, a proxy's error page) or `dead_letter` with the code after a refusal
  no retry can overcome. Dead letters are kept, never dropped. A resource with
  pending records chains from the newest of them, which the next action on it
  submits first. Without an outbox, `governedAction` behaves as in 1.1.
- `FileOutbox` (one file per record, synced and renamed into place, crash
  leftovers recovered, private permissions on POSIX), `MemoryOutbox` for tests,
  and the `EvidenceOutbox` interface for other storage.
- `evidenceStore.flushPending()`: submits pending records in order, waits
  behind pending predecessors, dead-letters records whose predecessor was
  refused, and backs off from 5 s to 15 minutes. `evidenceStore.enqueue()` and
  `evidenceStore.pendingHead()`.
- With an outbox, a secret-guard refusal of the metadata an action reported
  still records the outcome, with the accepted parameters and a note naming
  the dropped ones, and throws `MetadataRefusedError`
  (`governed_action_metadata_refused`) with the action's `value`, the
  `evidence` and what became of it. `EvidenceNotKeptError`
  (`governed_action_evidence_unkept`): the action ran but its evidence could
  not be signed or kept; carries the `value` and the signed `evidence`.
- `GovernedActionError` carries the signed failure record as `evidence` when
  there is one.

## [1.1.1] - 2026-10-09

Coordinated Genesis Mesh v1.1.1 release: security fixes in the Network
Authority. No API change in this SDK.

### Changed

- A 1.1.1 Network Authority decides under an agreement only if two parties it
  recognises signed it, binds the requester and provider to the agreement's
  parties, needs a privileged key to counter an offer, and admits execution
  evidence only in its exact signed form with UTC timestamps. Requests this
  SDK builds are unchanged; see *Upgrading to 1.1.1* in the core upgrade
  guide.

## [1.1.0] - 2026-10-08

Coordinated Genesis Mesh v1.1.0 release: signed container images and a local
governed Network Authority. No API change in this SDK.

### Fixed

- `ExecutionRecorder` no longer stamps evidence before its decision. Evidence
  recorded in the decision's millisecond, or on a host whose clock is behind
  the Network Authority's, could come out before `decision_made_at`, and the
  NA refused it with `evidence_outside_decision_window`. Without an explicit
  `executed_at`, the recorder now uses the later of the clock and the
  decision time. An explicit `executed_at` is signed unchanged.

### Changed

- The README links *Develop Against a Local Network Authority*: a governed
  Network Authority on a developer's machine, with a privileged setup key and
  a standard controller key (`genesis-mesh` 1.1.0).
- CI pins its actions to commits and runs with a read-only token; the
  security policy follows the core.

## [1.0.2] - 2026-10-05

Coordinated Genesis Mesh v1.0.2 release: fixes from external testing.

### Changed

- **Admin signatures cover the whole request (signature version 2):** the
  client signs the HTTP method, the decoded path, the query parameters and the
  target NA's public key, read once from `/sovereign.json` or given as the new
  `audience` option. Network Authorities from 1.0.2 accept only version 2 by
  default.
- `attestation.list()` signs its request when the client has a signing key:
  Network Authorities from 1.0.2 list attestations to operators and give the
  count to everyone else. `AttestationList.attestations` is optional.
- **Breaking:** `buildAdminHeaders` and
  `buildAdminHeadersWithSigner` take an `AdminRequest`
  (`{method, path, query?, audience, body?}`) instead of a body. New exports:
  `adminSigningPayload`, `ADMIN_SIGNATURE_VERSION`, and the `AdminRequest` and
  `AdminSigningOptions` types. The shared conformance vectors are in
  `tests/fixtures/conformance/admin_auth.json`.

### Fixed

- **Disclosure types match the Network Authority.** `CapabilityCommitment` has
  `issuer_sovereign_id`, `capability_count` and one `signature`; it declared
  `capabilities`, `issued_by` and `signatures`, which the NA never sends (a
  commitment reveals how many capabilities, not which).
  `CapabilityMembershipProof` has `revealed_capability`, `leaf_hash` and
  `merkle_path` steps (the new `MerklePathStep`: `sibling_hash`, `is_left`),
  not `capability` and strings. `CapabilityNullifier` has
  `prover_sovereign_id`, `nonce`, `expires_at` and one `signature`. The names
  the NA never sends are optional and deprecated.
- `TrustSignal` is `{code, severity, detail}`, what the NA reads and signs:
  signals built to the old type (`signal_id`, `signal_type`, `value`) were
  refused with `400 invalid_decision`. `TrustDecision` lists the fields the NA
  signs (`trusted`, `hop_count`, `trust_path`, `requested_roles`,
  `evaluated_at`), and `TrustEvidence` has the six fields it lacked.
- Code that builds these objects itself, such as test fixtures, needs the
  newly required fields.

## [1.0.1] - 2026-10-04

Coordinated Genesis Mesh v1.0.1 release: gateway console fixes. No changes in
this SDK.

## [1.0.0] - 2026-10-04

Coordinated Genesis Mesh v1.0.0 release: the public contract is stable for
the 1.x line and Genesis Mesh is ready for an independently operated pilot.
No functional changes in this SDK; its documented stable surface follows the
1.x compatibility rules.

## [0.65.0] - 2026-10-04

Coordinated Genesis Mesh v0.65.0 release: demo access and a guided tour in the
gateway, and the public reference federated with the live NA. No changes in
this SDK.

## [0.64.1] - 2026-10-03

Coordinated Genesis Mesh v0.64.1 release: the Network Authority republishes an
expiring CRL. No changes in this SDK.

## [0.64.0] - 2026-10-03

Coordinated Genesis Mesh v0.64.0 release: the Rust SDK and the Rust gateway
reach governed-action parity (boundary policies, evidence store, offline
verification). No changes in this SDK.

## [0.63.1] - 2026-10-02

Coordinated Genesis Mesh v0.63.1 release.

### Fixed

- `resourceHead()` (used by `governedAction` before every action) reads the
  chain head from the NA's new `/admin/evidence/resource-heads` lookup instead
  of downloading the resource's whole history. A long-lived resource's
  history grew with every action (22 MB for a few thousand records), and past
  10,000 records the NA cut it to the oldest records, so the computed head was
  stale and every later action was refused as a conflict. Against an NA older
  than 0.63.1 it still reads the history, and now refuses a truncated one.
- `ResourceHistory` and `VendorHistory` carry `truncated`.

## [0.63.0] - 2026-10-02

Coordinated Genesis Mesh v0.63.0 release: pilot readiness. No changes in
this SDK.

## [0.62.0] - 2026-10-02

Coordinated Genesis Mesh v0.62.0 release: the v1 public contract and security
review. No changes in this SDK. On the Network Authority, accepting an
agreement (`/admin/agreements/accept`) and creating a data license policy
(`/admin/data-usage/policy`) now require a privileged operator key; a
standard key gets `403 insufficient_operator_tier`.

## [0.61.1] - 2026-10-02

Coordinated Genesis Mesh v0.61.1 release.

### Fixed

- Consensus types match Python's models: `JustificationProof` is the
  `DecisionJustification` returned by `boundary.evaluate`; `ValidatorVote`
  has `context_digest` and a single `signature`; `ConsensusProof` has
  `reached_at`, `expires_at` and `cascade_assessment_digest` (not
  `assembled_at`, `issued_by`, `signatures`). `ConsensusVerification.reason`
  is typed with the reference reason codes. A compile-time check and a test
  against the `consensus` conformance vectors keep the fields exact.

## [0.61.0] - 2026-10-02

Coordinated Genesis Mesh v0.61.0 release: the cross-language interoperability
proof. The core's interop scenario uses this SDK to sign data access intents,
submit them to the NA, and verify Python records.

### Added

- `verifyAgreement`, `verifyDataLicensePolicySignature` and
  `verifyDataAccessIntent`: offline verification with the reason codes of the
  Python reference.
- `createDataAccessIntent`: build and sign a data access intent as the agent.
- `agreementCanonical`, `dataLicensePolicyCanonical`,
  `dataAccessIntentCanonical`.
- The shared `interop` conformance vectors (25) in
  `tests/fixtures/conformance/interop.json`, all passing.

### Fixed

- `AgreementRecord`, `AgreementTerms`, `CapabilityOffer`, `CapabilityCounter`,
  `DataAccessIntent` and `DataSourceDescriptor` now match the wire format.
- `parseJson` keeps integer literals beyond `Number.MAX_SAFE_INTEGER` exactly
  (as `bigint`), and `canonicalJson` encodes them.

## [0.60.0] - 2026-10-01

Coordinated Genesis Mesh v0.60.0 release: client support for the Network
Authority's optional high availability.

- Add `baseUrls`: several NA instances without a load balancer. Idempotent
  requests fail over on transport errors and 502/503/504. Non-idempotent
  requests move only when the connection was never made, and are never
  replayed after it may have been.
- Add `NetworkError.connectFailed`.
- Add `client.health`: `liveness()`, `readiness()` (typed `/readyz`, not-ready
  returned as `ready: false` with the failing checks), `health()`, and
  `endpoints()` to probe every configured instance.
- Add `isRetryableConflict()` and the `HaConflictCode` type for the 409 codes
  an NA instance returns when it loses a race the database decided.
- Add a live HA test (`tests/e2e-ha.test.ts`): two instances on PostgreSQL
  behind nginx, one killed mid-run. CI runs it against core `main`.

## [0.59.1] - 2026-10-01

Coordinated Genesis Mesh v0.59.1 release: TypeScript support for governed
secret lifecycles (attestation-backed evaluation, policy lifecycle, evidence
store, offline verification).

- Add attestation-backed evaluation, attestation queries, recognition policy reads
  and signed revocation feeds.
- Add boundary-policy management, the execution evidence-store client, signed
  execution recording, governed actions and inventory reconciliation.
- Add Python-compatible canonical JSON, model digests and offline verification
  of signed artifacts and complete evidence exports.
- Require verified decisions and expected bindings before governed callbacks;
  guard evaluation and execution metadata before sending it to the NA.
- Add async signers, signed admin GETs, NDJSON paging, bounded opt-in retries and
  typed errors carrying NA details and request IDs.
- Correct wire types and CommonJS package loading; require Node.js 22 or newer.
- Add Python-vector, negative-path, public-route and live local-NA tests, plus
  typechecking of the test suite and package entry-point smoke checks.

## [0.59.0] - 2026-10-01

Coordinated Genesis Mesh v0.59.0 release. No functional changes; the core adds
the Network Authority evidence store, which this SDK does not wrap yet.

## [0.58.1] - 2026-09-29

Coordinated Genesis Mesh v0.58.1 release. No functional changes; the core adds
attestation-backed boundary evaluation, which this SDK does not wrap yet.

## [0.58.0] - 2026-09-29

Coordinated Genesis Mesh v0.58.0 release. No functional changes; the SDK passes its
compatibility tests against the v0.58.0 Network Authority. Version 0.57 was skipped
across the train (see the core `docs/development/versioning.md`).

### Changed

- CI and publishing now fail if this component's version is ahead of the Genesis Mesh core version.

## [0.56.0] - Unreleased

### Changed

- Joined the coordinated Genesis Mesh v0.56.0 release train.
- Added a shared `VERSION` declaration and publishing guard that rejects tags
  which do not match package metadata.
- Updated the supported security line to `0.56.x`.

---

## [0.53.0] - 2026-06-29

### Added

- `GenesisMeshClient` - unified entry point with 7 domain sub-clients
- `AgreementClient` - capability offer, counter, accept, verify
- `BoundaryClient` - boundary decision and verification
- `EvidenceClient` - trust evidence build and verify
- `AttestationClient` - membership attestation issue, revoke, recognition policy
- `DisclosureClient` - selective Merkle capability disclosure, nullifier
- `ConsensusClient` - validator vote, consensus proof assembly and verify
- `DataUsageClient` - data license policy, access intent, verify
- `src/auth.ts` - `canonicalJson`, `signBytes`, `buildAdminHeaders` (Ed25519 / PKCS8-DER)
- `src/client.ts` - `HttpTransport` with fetch, timeout, and typed error mapping
- `src/errors.ts` - `GenesisMeshError` and typed subclasses for all NA error codes
- `src/types.ts` - 30+ protocol interfaces matching the NA JSON wire format
- ESM and CJS dual build (`dist/esm/`, `dist/cjs/`, `dist/types/`)
- 74 Jest unit tests covering all sub-clients

[0.53.0]: https://github.com/GenesisMeshLabs/sdk-typescript/releases/tag/v0.53.0
