/**
 * A governed rotation against a local Network Authority (NA).
 * Walkthrough: docs/walkthroughs/governed-rotation.md.
 *
 *   npm run build
 *   GM_NA_URL=http://127.0.0.1:9443 node examples/governed-rotation.ts local/.genesis-mesh
 *
 * The argument is the NA's home from `genesis-mesh init`: its `keys/` holds
 * the privileged setup key (`operator.key`), the standard controller key
 * (`controller.key`, from `genesis-mesh keygen operator`) and the root public
 * key (`root.pub`). The outbox is kept in `controller-outbox/` next to it.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  ExecutionRecorder, FileOutbox, GenesisMeshClient, governedAction, parseExportLines, publicKeyFromSeed, seedSigner,
  verifyEvidenceEvents,
} from 'genesis-mesh-sdk';

const home = process.argv[2] ?? 'local/.genesis-mesh';
const baseUrl = process.env.GM_NA_URL ?? 'http://127.0.0.1:9443';

/** The base64 value of a key file: comment lines start with '#'. */
function keyFile(name: string): string {
  return readFileSync(join(home, 'keys', name), 'utf8')
    .split('\n').map(line => line.trim()).find(line => line && !line.startsWith('#'))!;
}

const say = (line: string): void => console.log(line);
const run = randomUUID().slice(0, 8);

// 1. Setup, with the privileged key: an attestation, a policy and an executor key.
say('==> Setup with the privileged key (operator-local)');
const setup = new GenesisMeshClient({ baseUrl, signingKeyBase64: keyFile('operator.key'), keyId: 'operator-local' });
const attestation = await setup.attestation.issue({
  subject_id: `rotation-controller-${run}`, roles: ['role:client'],
  claims: { capabilities: ['secret.rotate'], apps: ['app-1'] },
});
say(`attestation ${attestation.attestation_id} for ${attestation.subject_id}`);
const now = Date.now();
const policy = await setup.policy.publish({
  policy_id: `secret-rotation-${run}`,
  valid_from: new Date(now - 60_000).toISOString(), valid_until: new Date(now + 3_600_000).toISOString(),
  selector: { parent_kinds: ['attestation'], requester_sovereign_ids: [attestation.subject_id], capabilities: ['secret.rotate'] },
  gates: [
    { gate_id: 'app', gate_type: 'attestation_claim.v1', order: 0, config: { path: 'request_parameters.app_id', claim: 'apps' } },
    { gate_id: 'lifetime', gate_type: 'max_value.v1', order: 1, config: { path: 'request_parameters.lifetime_days', max: 90 } },
  ],
});
await setup.policy.activate(policy.policy_id, policy.version);
say(`policy ${policy.policy_id} v${policy.version} active: app_id from the attestation, lifetime_days at most 90`);
const executorSeed = randomBytes(32).toString('base64');
const executorId = `executor-${run}`;
await setup.evidenceStore.registerExecutorKey({
  key_id: executorId, public_key: publicKeyFromSeed(executorSeed), executor_sovereign_id: executorId,
});
say(`executor key ${executorId} registered`);

// 2. The controller, with the standard key and an evidence outbox.
say('==> The controller key runs governedAction');
const outbox = new FileOutbox(join(home, '..', 'controller-outbox'));
const gm = new GenesisMeshClient({ baseUrl, signingKeyBase64: keyFile('controller.key'), keyId: 'controller', outbox });
const recorder = new ExecutionRecorder({ executorSovereignId: executorId, signer: seedSigner(executorSeed, executorId) });
// The NA's keys, verified from the root public key held outside the NA.
const naKeys = await gm.na.verifiedKeyHistory(keyFile('root.pub'));
const verify = { operatorPublicKeys: naKeys, expectedPolicies: [policy], expectedAttestation: attestation };
const resource = `kv:demo-vault/api-key-${run}`;

for (const lifetime of [30, 400]) {
  let ran = false;
  const result = await governedAction(gm, recorder, {
    attestation_id: attestation.attestation_id,
    requested_capability: 'secret.rotate',
    context: { request_parameters: { app_id: 'app-1', lifetime_days: lifetime } },
    resource_id: resource,
    resource_action: 'rotate',
    verify,
  }, async () => {
    ran = true; // the cloud call goes here; only metadata is recorded
    return { execution_parameters: { secret_version: 'version-2' } };
  });
  const decision = result.evaluation.decision;
  if (result.authorized) {
    say(`ALLOW  lifetime_days=${lifetime}: decision ${decision.decision_id} verified, action ran: ${ran}, evidence ${result.submission?.status}`);
  } else {
    say(`DENY   lifetime_days=${lifetime}: decision ${decision.decision_id} verified, action ran: ${ran}, failed gate: ${result.summary.enforced_failures.map(f => f.gate).join(', ')}`);
  }
}

// 3. The outbox: the NA admitted the record, so nothing is left to submit.
say('==> The evidence outbox');
const flushed = await gm.evidenceStore.flushPending();
say(`flushPending: admitted ${flushed.admitted.length}, pending ${flushed.pending.length}, dead-lettered ${flushed.dead_lettered.length}`);
say(`outbox entries: ${(await outbox.list()).length}`);

// 4. Export the store and verify it offline, from the root key's history.
say('==> Export and verify offline');
const events = parseExportLines(await gm.evidenceStore.exportText({ limit: 1000 }));
const verification = verifyEvidenceEvents(events, { naPublicKeys: naKeys, executorKeys: await gm.evidenceStore.listExecutorKeys() });
say(`exported ${events.length} entries; NA keys in the history: ${naKeys.keys.length}`);
say(`verified: ${verification.verified}${verification.failures.length ? ` (${JSON.stringify(verification.failures[0])})` : ''}`);
