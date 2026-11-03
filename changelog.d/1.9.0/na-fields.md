### Added

- **Fields the NA sends that the types lacked:**
  - `AttestationRecord.reissued_from` and `superseded_by` (1.8.0): the copy an attestation re-issues and the copy that re-issued it;
  - `AttestationRevocation.lineage_ids` (1.8.0): every copy of the re-issue lineage the revocation reached;
  - `EvidenceStoreStatus.evidence_grants`, `grants_issued`, `grants_active`, `grants_revoked` and `grant_uses` (1.6.0);
  - `AnchorSummary.chain`: the NA's own verification of its anchor chain, as `evidenceStore.verify()` returns it.
