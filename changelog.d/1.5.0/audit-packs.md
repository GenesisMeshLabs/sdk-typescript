### Added

- **The NA's key history.** `verifyKeyHistory` verifies a genesis block and
  its key successions from the root public key you hold, and returns an
  `NAKeyHistory` (`keysAt`, `signingKeyAt`, `allKeys`). Each succession is
  refused by name, in the contract's order: `payload_invalid`,
  `invalid_signature`, `unknown_field`, `non_canonical_form`,
  `succession_sovereign_mismatch`, `succession_chain_break`,
  `succession_key_reused`, `succession_not_increasing`,
  `succession_after_expiry`, `succession_invalid_root_signature`,
  `succession_invalid_previous_signature`; the genesis block as
  `genesis_invalid`, `genesis_root_mismatch` or `genesis_invalid_signature`.
  `gm.na.getKeyHistory()` reads `GET /na/key-history`, and
  `gm.na.verifiedKeyHistory(rootPublicKey)` verifies it (`KeyHistoryError`).
- **Signatures at the record's own time.** Every verifier that takes NA keys
  also takes the key history: decisions (`decision_made_at`), export entries
  (`recorded_at`), anchors (`anchored_at`), checkpoints (`created_at`),
  policies, attestations and treaties (`issued_at`), agreements
  (`established_at`) and archive records (`archived_at`). A succeeded key is
  accepted for 300 seconds after the next key takes effect. A signature by
  another key of the history is `na_key_not_valid_at_time` (decisions,
  exports, anchors). A list of keys keeps the behaviour before 1.5.0.
  `verifyBoundaryDecision` takes `atRecordTime` to judge an archived decision
  as of its own time.
- **New entry kinds.** `verifyEvidenceEvents` verifies `key_succession`
  entries (signed by the outgoing key; with a history, one of its successions,
  `succession_not_in_history`, signed by the root key) and `archive` entries
  (NA-signed), and counts them (`key_successions`, `archives`). With `prior`
  (an audit pack's cited records) a record the run cites that neither holds
  is `cited_record_missing`.
- **Anchors offline.** `verifyStoreAnchors` and `checkEventsAgainstAnchors`
  port the reference's anchor checks; `evidenceStore.anchors`, `allAnchors`
  and `anchor` wrap the anchor routes.
- **Audit packs.** `evidenceStore.auditPack` asks the NA for a pack (read
  tier), `auditPackFiles` and `readAuditPackDir` give its files, and
  `verifyAuditPack` verifies it offline from the root key and the anchors you
  hold, with the reference's reason codes (`packReasons`). `checkCompleteness`
  and `parseChanges` match changes from an outside log against a pack.
- **Archives.** `evidenceStore.archives` and `recordArchive` wrap the archive
  routes; `verifyArchiveRecord` verifies an archive record.
- **Treaties.** `verifyTreatySignature` and `treatyCanonical`.

### Changed

- `evidenceStore.applyRetention(olderThanDays, { throughSequence })`:
  `olderThanDays` may be `null` when `throughSequence` is given.
  `RetentionResult.held_back` names why retention stopped short (1.5.0:
  `not_archived`).
- `EvidenceStoreStatus` lists the fields the NA already returns:
  `latest_anchor`, `unanchored_entries`, `anchoring_blocked`,
  `policy_history_started`, `registry_healthy` and `registry_problems`.
- The field registry is the 1.5.0 one (`KeySuccessionRecord`,
  `ArchiveRecord`, `AuditPackManifest` and `GenesisBlock` are roots; entry
  kinds `key_succession` and `archive`).

### Upgrading

- After an NA key succession, verify with the key history rather than a list
  of keys: a list of only the old key refuses records signed by the new one,
  and a list of both accepts either key at any time.
