# Key succession, audit packs and independent verification

*Unreleased.*

From Genesis Mesh 1.5.0 the Network Authority (NA) can replace its signing
key without breaking anything it signed before, and a security team can check
a range of the evidence store years later, offline, from material it holds
itself: the root public key and its own copies of the store anchors. This
page covers the SDK side. The operator's side is described in *Governed
changes and audit*, *Key succession* and *Audit packs* in the NA runbooks; the
pack layout is the core's *Audit Pack Format* reference.

## The key history

The genesis block names the NA's first key and is signed by the root key,
which is kept offline. A `KeySuccessionRecord` names the next NA key and is
signed by the root key and by the outgoing NA key. Together they are the NA's
key history. An NA signature is accepted only when it was made by the key
valid at the record's own time:

| Key | Valid |
|---|---|
| The genesis key | From the start until the first succession takes effect; its `valid_to` is not enforced |
| A key a succession names | From its `effective_at` until the next succession takes effect, never at or after its `new_valid_to` |
| A succeeded key | Still accepted for records dated up to 300 seconds after the next key took effect (the hand-over) |

The record's time is the one its signer gave it:

| Record | Time used |
|---|---|
| Store entry (in an export or a pack) | `recorded_at` |
| Decision verified alone | `decision_made_at` |
| Anchor | `anchored_at` |
| Retention checkpoint read alone, pack manifest | `created_at` |
| Policy, attestation, treaty, revocation feed | `issued_at` |
| Justification proof | `proof_issued_at` |
| Archive record | `archived_at` |
| Agreement | `established_at` |

Fetch the history and verify it from the root key you hold. The served
`keys` and `root_public_key` are ignored: the history is rebuilt from the
genesis block down, and keys in the records prove nothing alone.

```typescript
const history = await gm.na.verifiedKeyHistory(rootPublicKey); // throws KeyHistoryError when refused
history.keysAt('2026-01-11T00:02:00Z'); // the keys a record dated then may carry
```

`gm.na.getKeyHistory()` returns the raw `GET /na/key-history` response;
`verifyKeyHistory(genesis, successions, rootPublicKey)` verifies the parts
offline.

### Passing the history to the verifiers

Every verifier that takes NA keys takes the history in their place
(`NAKeys`), among them `verifyBoundaryDecision`, `verifyEvidenceEvents`,
`verifyStoreAnchors`, `verifyRetentionCheckpoint`,
`verifyAttestationSignature`, `verifyPolicySignature`,
`verifyTreatySignature`, `verifyAgreement` and `verifyArchiveRecord`. A plain
list of keys keeps the behaviour before 1.5.0: any listed key verifies any
record, whatever its time.

```typescript
verifyBoundaryDecision(decision, { operatorPublicKeys: history, atRecordTime: true });
verifyEvidenceEvents(events, { naPublicKeys: history, executorKeys });
```

A signature by another key of the history than the one valid at the record's
time is refused as `na_key_not_valid_at_time` by `verifyBoundaryDecision`,
`verifyEvidenceEvents` and `verifyStoreAnchors`; the boolean helpers return
`false`. `atRecordTime` judges a decision as of its own `decision_made_at`:
an archived decision that has expired since it was made and used is not a
failure.

### Checks on the history

`verifyKeyHistory` refuses the genesis block with `genesis_invalid`,
`genesis_root_mismatch` or `genesis_invalid_signature`, and checks each
succession in this order:

1. `payload_invalid`
2. `invalid_signature`, `unknown_field`, `non_canonical_form` (as for every record)
3. `succession_sovereign_mismatch`
4. `succession_chain_break` (not the next position, not the current key, or not the previous succession's digest)
5. `succession_key_reused`
6. `succession_not_increasing`
7. `succession_after_expiry`
8. `succession_invalid_root_signature`
9. `succession_invalid_previous_signature`

Nothing after the first refused record is accepted.

## Exports across a succession

A `key_succession` entry is signed by its outgoing key; given the history, it
must be one of the history's successions (`succession_not_in_history`) and
signed by the root key (`succession_invalid_root_signature`). An `archive`
entry is signed by the NA. Both count in the result (`key_successions`,
`archives`).

## Anchors

`evidenceStore.allAnchors()` reads every signed store anchor; keep copies
outside the operator's reach. `verifyStoreAnchors(anchors, { naPublicKeys,
sovereignId })` checks their signatures and chain, and
`checkEventsAgainstAnchors(events, anchors, result)` checks an export against
them: an anchor proves every entry before the one it names.
`evidenceStore.anchor()` signs the store's head now. `status()` reports
`latest_anchor` and `unanchored_entries`.

## Audit packs

`evidenceStore.auditPack({ from_sequence, since, until_sequence, until })`
asks the NA for a pack (read tier; every bound optional, the range widens to
the anchors around it). The response holds the signed manifest and every
other file as text, and can be tens of megabytes (up to 50,000 entries).

```typescript
import { auditPackFiles, packReasons, verifyAuditPack } from 'genesis-mesh-sdk';

const pack = await gm.evidenceStore.auditPack();
const files = auditPackFiles(pack); // path -> bytes, manifest.json as the NA writes it
const result = verifyAuditPack(files, { rootPublicKey, heldAnchors: myAnchors });
if (!result.verified) throw new Error(packReasons(result).join(', '));
```

`readAuditPackDir(dir)` reads a pack written to disk. `verifyAuditPack` needs
no network and no private key, and checks, in order, the manifest (a pack
whose manifest fails is not checked further), the key history from the root
key, the anchors (against those you hold; without them the pack's integrity
only, with the warning `no_held_anchors`), the entries and what they cite,
and the policies, attestations, treaties and feeds the records rest on.
Executor and observer keys come only from registry records the NA signed in
the pack, or from `executorKeys` you supply; `keys/executor-keys.json` is
never trusted. Each failure names its file and reason code; `packReasons`
gives the sorted codes, which every verifier names alike.

### Completeness

With `changes` (from a cloud audit log or a ticketing export; `parseChanges`
reads JSON), `verifyAuditPack` matches each change against the pack's records,
by source event first, then by resource, action and time within 300 seconds.
A change dated inside the pack's period that no record matches fails as
`change_unmatched`. `checkCompleteness` runs the check alone.

## Archives and retention

After writing a pack to immutable storage and reading it back intact, record
it: `evidenceStore.recordArchive(pack.manifest, location)` (privileged;
`duplicate` for the same manifest again). `evidenceStore.archives()` lists
the archive records and `archived_through_sequence`. While the NA requires
archives (the default), retention removes nothing past what archives cover,
and says so in `held_back` (`not_archived`).
`applyRetention(null, { throughSequence })` stops retention at a store
position.
