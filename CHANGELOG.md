# Changelog

All notable changes to `genesis-mesh-sdk` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions align with the [Genesis Mesh release sequence](https://github.com/GenesisMeshLabs/genesismesh/blob/main/CHANGELOG.md).

---

## [1.2.0] - Unreleased

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
  alike throws `StrictJsonError` with a `reason`: `duplicate_key`,
  `non_finite_number` (`1e400`), `integer_out_of_range` (beyond 64 bits),
  `negative_zero` (the integer `-0`), `lone_surrogate` or `invalid_json`.
  This covers HTTP responses, `parseExportLines` and the export clients.

### Added

- `canonicalTimestamp`, `nonCanonicalTimestamps`, `checkStrictJson` and
  `StrictJsonError`; the shared conformance suite `canonical`.
- `unknownFields(model, record)` and `isKnownEntryKind(kind)`;
  `npm run sync:registry` regenerates the embedded registry from a new copy
  of the suite.

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
