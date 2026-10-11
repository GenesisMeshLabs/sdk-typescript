### Fixed

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

### Changed

- New export `recordMetadataProblem(kind, record)`: the NA's metadata guard
  over an observation or a break-glass record, as the recorders apply it.
- New reasons from `verifyEvidenceEvents`: `duplicate_record`,
  `judgement_match_missing`, `retention_count_mismatch`.
