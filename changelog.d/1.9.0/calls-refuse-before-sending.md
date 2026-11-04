### Added

- `GrantsClient.allGrants(params)` and `allGrantUses(grantId, limit)`: every grant, or a grant's whole use chain, following the pages; a cursor that does not advance throws.

### Changed

- **Arguments out of range are refused before anything is sent** (`RangeError`), where the NA refused them after a signed request:
  - `evidenceStore.anchors`: a `limit` outside 1 to 1000, or a negative `after_anchor` (so `allAnchors` too);
  - `evidenceStore.auditPack`: a `from_sequence` or `until_sequence` below 1;
  - `grants.listGrants` and `listGrantUses`: a `limit` outside 1 to 500.
- **`evidenceStore.decideReview`** refuses a waiver's end (`waive_until`) given for another verdict, or the verdict `waive_until` without one, before anything is sent.
