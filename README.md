# @genesismesh/sdk

TypeScript SDK for the Genesis Mesh Network Authority HTTP API.

**Node.js ≥ 20 required. Zero runtime dependencies.**

## Install

```bash
npm install @genesismesh/sdk
```

## Quick start

```typescript
import { GenesisMeshClient } from '@genesismesh/sdk';
import { readFileSync } from 'node:fs';

// Load operator key seed (32 bytes, base64-encoded, from operator.key file)
const signingKeyBase64 = readFileSync('/path/to/keys/operator.key', 'utf-8')
  .split('\n')
  .find(l => !l.startsWith('#'))!
  .trim();

const client = new GenesisMeshClient({
  baseUrl: 'http://127.0.0.1:9443',
  signingKeyBase64,
  keyId: 'operator-local',   // must match the NA's registered operator key
});
```

## Sub-clients

### agreement

> **Note:** `accept` requires the NA to have a recognition treaty for the
> responder sovereign. Issue one first via `/admin/recognition-treaties` (see
> [Raw admin calls](#raw-admin-calls) below).

```typescript
// Create a capability offer (admin — requires signing key)
const offer = await client.agreement.offer({
  responder_sovereign_id: 'BETA-NA',
  capabilities: ['read:data', 'write:log'],
  valid_from: '2026-01-01T00:00:00Z',
  valid_until: '2026-12-31T00:00:00Z',
  expires_at: '2026-01-15T00:00:00Z',
});

// Counter an offer
const counter = await client.agreement.counter({
  offer,
  capabilities: ['read:data'],   // narrowed scope
  valid_from: '2026-01-01T00:00:00Z',
  valid_until: '2026-06-30T00:00:00Z',
});

// Accept an offer or counter
const agreement = await client.agreement.accept({ offer });
// or: await client.agreement.accept({ counter, original_offer: offer });

// Verify agreement signatures (no auth required)
const check = await client.agreement.verify({ agreement });
console.log(check.accepted); // true | false
```

### boundary

```typescript
// Issue a boundary decision (admin)
const decision = await client.boundary.decide({
  agreement,
  requested_capability: 'read:data',
  context: { session_id: 'sess-123' },
});
console.log(decision.authorized); // true | false

// Verify a boundary decision (no auth required)
const v = await client.boundary.verify({ decision });
console.log(v.accepted, v.authorized);
```

### evidence

```typescript
// Build signed trust evidence (admin)
// verdict must be one of: "allow" | "block" | "escalate" | "warn"
const evidence = await client.evidence.build({
  decision: {
    source_sovereign_id: 'ALPHA',
    target_sovereign_id: 'BETA',
    verdict: 'allow',
    reason: 'long-standing member',
  },
});

// Verify trust evidence (no auth required)
const ev = await client.evidence.verify({ evidence });
console.log(ev.accepted, ev.verdict);
```

### attestation

```typescript
// Issue a membership attestation (admin)
// roles must use a recognized prefix:
//   role:anchor | role:bridge | role:client | role:operator | role:service:<name>
const att = await client.attestation.issue({
  subject_id: 'node-xyz',
  roles: ['role:client', 'role:anchor'],
  validity_hours: 8760,
  claims: { department: 'engineering' },
});

// Revoke an attestation (admin)
await client.attestation.revoke(att.attestation_id, { reason: 'key compromised' });

// Set recognition policy (admin)
await client.attestation.savePolicy({
  recognition_policy: {
    local_sovereign_id: 'MY-NA',
    recognized_issuers: [],   // add RecognizedIssuer entries as needed
  },
});
```

### disclosure

```typescript
// Commit to a set of capabilities (admin)
const commitment = await client.disclosure.commit({
  capabilities: ['read:data', 'write:log'],
  agreement,
});

// Generate a Merkle membership proof (no auth required)
const proof = await client.disclosure.prove({
  capability: 'read:data',
  capabilities: ['read:data', 'write:log'],
  commitment,
  prover_sovereign_id: 'BETA',
});

// Issue a one-time nullifier (admin)
const nullifier = await client.disclosure.nullifier({ proof });

// Verify the proof (no auth required)
const dv = await client.disclosure.verify({ proof, commitment });
console.log(dv.valid);
```

### consensus

```typescript
// Cast a validator vote (admin)
const vote = await client.consensus.vote({
  justification_proof: { proof_id: 'jp-001', decision_id: 'dec-001' },
  vote: true,
  reason: 'evidence satisfactory',
});

// Assemble a consensus proof (admin)
const cp = await client.consensus.proof({
  justification_proof: { proof_id: 'jp-001', decision_id: 'dec-001' },
  votes: [vote],
  required_threshold: 1,
  validator_sovereign_ids: ['ALPHA'],
});

// Verify the consensus proof (no auth required)
const cv = await client.consensus.verify({ proof: cp });
console.log(cv.valid);
```

### dataUsage

```typescript
// Create a data license policy (admin)
const pol = await client.dataUsage.createPolicy({
  licensee_sovereign_id: 'BETA',
  allowed_source_ids: ['src-a'],
  allowed_access_types: ['read', 'aggregate'],
  valid_from: '2026-01-01T00:00:00Z',
  valid_until: '2026-12-31T00:00:00Z',
  max_volume_bytes_per_session: 104857600,
  prohibited_classification_tags: ['pii'],
});

// Create a data access intent (admin)
// source_type: "personal" | "proprietary" | "public" | "synthetic"
const intent = await client.dataUsage.createIntent({
  sources: [{
    source_id: 'src-a',
    source_type: 'public',
    owner_sovereign_id: 'MY-NA',
    classification_tags: ['public'],
  }],
  access_types: ['read'],
});

// Get the active policy (no auth required)
const activePol = await client.dataUsage.getPolicy();

// Verify intent against policy (no auth required)
const dv = await client.dataUsage.verify({ intent, policy: pol });
console.log(dv.valid, dv.violations);
```

## Raw admin calls

For NA routes not yet covered by a sub-client (e.g. `/admin/recognition-treaties`),
use `buildAdminHeaders` directly:

```typescript
import { buildAdminHeaders } from '@genesismesh/sdk';

const body = {
  subject_sovereign_id: 'BETA-NA',
  subject_public_keys: ['<base64-ed25519-pubkey>'],
  scope: { allowed_roles: ['role:client'] },
  validity_hours: 24,
};

const headers = buildAdminHeaders(body, keyId, signingKeyBase64);
const res = await fetch(`${baseUrl}/admin/recognition-treaties`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', ...headers },
  body: JSON.stringify(body),
});
```

## Error handling

```typescript
import {
  UnauthorizedError,
  RateLimitError,
  ValidationError,
  NotFoundError,
  NetworkError,
} from '@genesismesh/sdk';

try {
  await client.agreement.offer({ ... });
} catch (err) {
  if (err instanceof UnauthorizedError) { /* bad signing key or stale timestamp */ }
  if (err instanceof RateLimitError)    { /* back off and retry */ }
  if (err instanceof ValidationError)   { /* inspect err.message and err.code */ }
  if (err instanceof NetworkError)      { /* connection refused or timeout */ }
}
```

## Admin authentication

Admin routes are authenticated with four HTTP headers generated from an Ed25519 operator key:

| Header | Description |
|---|---|
| `X-Admin-Key-Id` | Key identifier registered with the NA |
| `X-Admin-Signature` | Ed25519 signature over `canonicalJson({body, key_id, nonce, timestamp})` |
| `X-Admin-Timestamp` | ISO 8601 UTC timestamp (must be within NA's nonce window) |
| `X-Admin-Nonce` | UUID v4 replay-protection token (single use) |

The SDK handles all of this automatically when `signingKeyBase64` is provided.

## Build

```bash
npm run build       # ESM → dist/esm/ and CJS → dist/cjs/
npm run typecheck   # type-check without emitting
npm test            # run 74 Jest tests
```

## License

MIT
