### Changed

- **`attestation.get` signs when the client can (1.10.0).** As `list` does,
  a client with a signing key signs the read and gets the record with the
  signed `attestation`. A Network Authority 1.10.0 answers a standard-tier key
  only for an attestation whose subject it is, and with 404 otherwise.
- **An unsigned read gives the status only.** Without a signing key, an NA
  1.10.0 answers with `attestation_id`, `status`, `revoked_at`,
  `revocation_reason`, `reissued_from` and `superseded_by`, and without
  `attestation`. `AttestationRecord.attestation` is optional, and
  `AttestationRecord.attestation_id` is new: the ID in an unsigned read.

### Upgrading

- **Code that reads `record.attestation` from an unsigned client** gets
  `undefined` from an NA 1.10.0. Sign the read with an operator key, or keep
  the attestation from when it was issued.
