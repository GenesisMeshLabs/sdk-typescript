# Governed SDK actions

`governedAction` composes evaluation, offline verification, a caller-supplied
callback and signed execution evidence. It does not implement cloud operations.
The NA needs evidence storage enabled, active policies, a privileged operator
for setup and a registered executor key. The client needs an evidence outbox.

```typescript
import { FileOutbox, GenesisMeshClient, ExecutionRecorder, governedAction, seedSigner } from 'genesis-mesh-sdk';

const gm = new GenesisMeshClient({
  baseUrl,
  signer: operatorSigner,
  outbox: new FileOutbox('/var/lib/controller/gm-outbox'),
});
const recorder = new ExecutionRecorder({
  executorSovereignId: 'executor',
  signer: seedSigner(executorSeedBase64, 'executor-key'),
});

const result = await governedAction(gm, recorder, {
  attestation_id: attestation.attestation_id,
  requested_capability: 'secret.rotate',
  context: {
    request_parameters: { app_id: 'app-1', lifetime_days: 30 },
    attributes: { owner: 'team-a', secret_store: 'approved-store' },
  },
  resource_id: 'store:example/resource-1',
  resource_action: 'rotate',
  verify: {
    operatorPublicKeys: [trustedNaPublicKey],
    expectedPolicies: [policy],
    expectedAttestation: attestation,
  },
}, async () => ({ execution_parameters: { secret_version: 'version-2' } }));
```

Use a trusted NA public key. `verify` and explicit `expectedPolicies` are
required. An empty policy list explicitly requires an empty policy binding.
An ALLOW under an attestation also requires `expectedAttestation`. Agreement
requests use `agreement` instead of `attestation_id` and check the agreement ID.
The helper supplies a context ID when absent and checks the response against it.
It checks expiry using the current clock, including after the resource-head
lookup. Historical `now` overrides are only available on the standalone verifier.

A verified DENY returns `authorized: false` without invoking the callback or
submitting execution evidence. Invalid, unsigned, expired or mismatched decisions
throw `DecisionVerificationError`. `summarizeDecision` separates observe-mode
failures from enforced failures and lists the applied policies.

A successful callback can return `value` for its caller, independently of the
metadata in `execution_parameters`. Only metadata enters the evidence record.
A callback exception produces failure evidence with a fixed, non-sensitive
description, then rethrows the original exception. If that failure record
cannot be signed or kept in the outbox, `GovernedActionError` preserves both
errors and the signed record as `evidence` when there is one.

## Evidence outbox

Since 1.2.0 signed evidence is written to an outbox before it is submitted, and
removed once the NA admits it. The outbox is storage the caller supplies:
`FileOutbox` keeps one JSON file per record in a private directory (`0700`, files
`0600`), written to a temporary file, synced and renamed into place; implement
`EvidenceOutbox` (`add`, `update`, `remove`, `list` in the order added) to keep
records in a database instead. It holds signed metadata, never secret values,
but it must be durable and private: a record lost from it is evidence lost.
`MemoryOutbox` keeps nothing across restarts and is meant for tests.

A failed submission never throws. The result's `submission` is the NA's
acknowledgement when the record was admitted, and otherwise the outbox entry:

| `submission.status` | Meaning |
|---|---|
| `recorded`, `duplicate` | The NA holds the record; it is no longer in the outbox. |
| `pending` | Not admitted yet: the NA was unreachable, timed out, returned `5xx` or `429`, or lost a race between instances. `flushPending` retries it. Also the status of a record waiting behind a pending record it chains from. |
| `dead_letter` | The NA refused it (any other `4xx`). `entry.last_error` holds the status and code. Kept in the outbox, never dropped. |

`gm.evidenceStore.flushPending()` submits pending records in the order they were
added. Run it at startup and on a timer. A record waits while one it chains
from is pending, and is dead-lettered with `evidence_predecessor_dead_lettered`
when that one was refused. A failed record is retried after 5 s, doubling up to
15 minutes; `{ ignoreBackoff: true }` retries at once, for example right after
the NA is back. A transient error ends the run. The result lists the records
admitted, still pending and newly dead-lettered.

A governed action on a resource with pending records chains from the newest
pending record, not from the NA's head, so a second change while the NA is away
still links correctly; both are admitted in order by the next flush. Passing
`prior_resource` overrides this. Records signed outside `governedAction` can go
through the same path with `gm.evidenceStore.enqueue(evidence)`.

Two errors mean the action ran; neither should make the caller run it again:

- `MetadataRefusedError` (`governed_action_metadata_refused`): the secret
  guard refused metadata the callback reported. The outcome is recorded with
  the accepted parameters; the refused ones are dropped and named in
  `outcome_detail` (`[secret guard dropped: client_secret]`) and in `dropped`.
  The error carries `value`, `evidence` and `submission`; `cause` is the
  guard's `SecretMaterialError`.
- `EvidenceNotKeptError` (`governed_action_evidence_unkept`): the evidence
  could not be signed or the outbox failed. It carries `value` and the signed
  `evidence` when there is one: submit it once the outbox works (resubmission
  is idempotent).

Evaluation context and submitted execution metadata are checked before HTTP
requests. The recorder also checks metadata before signing. These checks reject
obvious secret field names, PEM blocks, token-like strings and oversized metadata;
they cannot identify every possible secret. Supply identifiers, versions and
timestamps only. Do not put credentials in resource identifiers either.

The helper reads the resource head (the newest pending record, else the NA's)
unless `prior_resource` is supplied. An explicit `null` asserts that there is no
history. Identical evidence submissions are idempotent. Concurrent operations on
one resource can conflict; serialize those operations at the caller, and give
controllers that govern the same resources one outbox.

## Reconciliation

`gm.evidenceStore.resourceStates()` returns the latest recorded state and retains
the last successful metadata when a later action fails. Pass it with an observed
inventory to `reconcileResources` to identify `unmanaged`, `drifted`, `missing`,
`present_after_revoke` and `in_sync` resources. No scanning or remediation is
performed by the SDK.

Missing inventory entries only mean missing resources when `completeInventory`
is true. `scopePrefix` limits these inferred missing-resource findings. Supply
`versionKey` when versions use a field other than `secret_version`. Resources
with no successful records remaining after retention cannot have their full
state reconstructed from checkpoint digests alone.
