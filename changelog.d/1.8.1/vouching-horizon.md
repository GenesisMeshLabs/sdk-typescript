### Added

- **The vouching horizon (Genesis Mesh 1.8.0).** Judged for the present, a
  record signed by an NA key that has ended vouches only until that key's end,
  the 300-second hand-over and a grace of at most 24 hours. Judged at its own
  time, as audit packs and exports judge it, a record is unchanged.
  - `verifyAttestationSignature`, `verifyTreatySignature`,
    `verifyRevocationFeedSignature` and `verifyCapabilityGrant` take
    `{ now }`. Without it they judge as before.
  - New exports: `recordOutlivesKey`, `naKeysVouchingAt`,
    `SUCCESSION_VOUCHING_GRACE_SECONDS`, `NAKeyHistory.withVouchingGrace` and
    `vouchesUntilMicros`, `revocationFeedSigner`, and `naRecordRefusal` with
    its reasons (`outlives_key`, `record_malformed`). The `vouching`
    conformance suite (32 vectors) runs on every test run.
  - `verifyKeyHistoryView` and `gm.na.verifiedKeyHistory` take the NA's
    `vouching_grace_seconds` only to shorten the grace.

### Changed

- **The grant holder judges its grant and feeds for the present.** A grant of
  a key past its horizon is refused when the holder is built, and ends as
  `grant_expired` (with the usual fallback) when it passes the horizon later.
  Revocation feeds are ordered by their signer's key sequence, then by
  `sequence`. A feed with a forged high `sequence` signed by a succeeded key
  therefore no longer blocks the NA's later feeds.
- **A grant must start within 24 hours of its issue**, as the reference
  requires since 1.8.0: `validGrant` and `verifyCapabilityGrant` refuse a
  `valid_from` earlier than `issued_at` minus the 5-minute clock skew, or more
  than 24 hours and the skew after it. The NA never issued one outside that
  window.

### Upgrading

- **Upgrade the Network Authority to 1.8.0 first** and let it re-issue its
  records (`reissue_pending: false` on its `/readyz`). Only then judge records
  for the present with `{ now }`. An older NA does not re-issue, so after a
  succession its old records would stop vouching here.
