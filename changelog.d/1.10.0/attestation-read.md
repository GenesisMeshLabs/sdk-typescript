### Added

- **`attestation.getStatus` (1.10.0).** An unsigned read of an attestation's
  status and lineage: `attestation_id`, `status`, `revoked_at`,
  `revocation_reason`, `reissued_from` and `superseded_by`, typed as the new
  `AttestationStatusRecord`. A Network Authority 1.10.0 answers an unsigned
  `GET /attestations/<id>` with these only, and gives the attestation to a
  signed read.

### Changed

- **`attestation.get` signs when the client can (1.10.0).** As `list` does,
  a client with a signing key signs the read and gets the record with the
  signed `attestation`. An NA 1.10.0 answers a standard-tier key only for an
  attestation whose subject it is, and with 404 otherwise.

### Upgrading

- **`attestation.get` without a signing key** gets no `attestation` from an
  NA 1.10.0, though the type still names it. Read the status with
  `getStatus`, sign the read with an operator key, or keep the attestation
  from when it was issued.
