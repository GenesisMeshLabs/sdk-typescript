# Changelog

All notable changes to `genesis-mesh-sdk` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions align with the [Genesis Mesh release sequence](https://github.com/GenesisMeshLabs/genesismesh/blob/main/CHANGELOG.md).

---

## [0.53.0] — 2026-06-29

### Added

- `GenesisMeshClient` — unified entry point with 7 domain sub-clients
- `AgreementClient` — capability offer, counter, accept, verify
- `BoundaryClient` — boundary decision and verification
- `EvidenceClient` — trust evidence build and verify
- `AttestationClient` — membership attestation issue, revoke, recognition policy
- `DisclosureClient` — selective Merkle capability disclosure, nullifier
- `ConsensusClient` — validator vote, consensus proof assembly and verify
- `DataUsageClient` — data license policy, access intent, verify
- `src/auth.ts` — `canonicalJson`, `signBytes`, `buildAdminHeaders` (Ed25519 / PKCS8-DER)
- `src/client.ts` — `HttpTransport` with fetch, timeout, and typed error mapping
- `src/errors.ts` — `GenesisMeshError` and typed subclasses for all NA error codes
- `src/types.ts` — 30+ protocol interfaces matching the NA JSON wire format
- ESM and CJS dual build (`dist/esm/`, `dist/cjs/`, `dist/types/`)
- 74 Jest unit tests covering all sub-clients

[0.53.0]: https://github.com/GenesisMeshLabs/sdk-typescript/releases/tag/v0.53.0
