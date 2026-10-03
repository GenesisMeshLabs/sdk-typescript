# Changelog

All notable changes to `genesis-mesh-sdk` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions align with the [Genesis Mesh release sequence](https://github.com/GenesisMeshLabs/genesismesh/blob/main/CHANGELOG.md).

---

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
