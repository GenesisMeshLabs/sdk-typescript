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
