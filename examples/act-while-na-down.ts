/**
 * Acting while the Network Authority (NA) is down: first under a pre-issued
 * grant, then with break-glass once the grant is spent.
 * Walkthrough: docs/walkthroughs/acting-while-the-na-is-down.md.
 *
 *   npm run build
 *   node examples/act-while-na-down.ts setup local/.genesis-mesh   # NA up
 *   node examples/act-while-na-down.ts act   local/.genesis-mesh   # NA down
 *   node examples/act-while-na-down.ts sync  local/.genesis-mesh   # NA up again
 *
 * The NA runs with EVIDENCE_OUT_OF_BAND=on and EVIDENCE_GRANTS=on. The second
 * argument is its home from `genesis-mesh init`: `keys/` holds the privileged
 * setup key (`operator.key`), the standard controller key (`controller.key`)
 * and the root public key (`root.pub`). The device keeps its state and its
 * record outbox in `device/` next to it. GM_NA_URL is the NA's address
 * (default http://127.0.0.1:9443).
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  FileRecordOutbox, GenesisMeshClient, GrantHolder, publicKeyFromSeed, seedSigner,
  type BoundaryPolicy, type GrantActResult, type GrantHolderState, type MembershipAttestation,
} from 'genesis-mesh-sdk';

const [phase, home = 'local/.genesis-mesh'] = process.argv.slice(2);
const baseUrl = process.env.GM_NA_URL ?? 'http://127.0.0.1:9443';
const deviceDir = join(home, '..', 'device');
const stateFile = join(deviceDir, 'state.json');

/** What the device holds between runs: written at setup, the holder's state updated by every use. */
interface DeviceState {
  naPublicKeys: string[];
  deviceId: string;
  deviceSeed: string;
  capability: string;
  resource: string;
  policy: BoundaryPolicy;
  attestation: MembershipAttestation;
  holder: GrantHolderState | null;
}

function keyFile(name: string): string {
  return readFileSync(join(home, 'keys', name), 'utf8')
    .split('\n').map(line => line.trim()).find(line => line && !line.startsWith('#'))!;
}
const say = (line: string): void => console.log(line);
const load = (): DeviceState => JSON.parse(readFileSync(stateFile, 'utf8')) as DeviceState;
const save = (state: DeviceState): void => writeFileSync(stateFile, JSON.stringify(state, null, 2));

/** The device: the standard controller key, and a record outbox for what the NA has not admitted. */
function device(state: DeviceState, issued?: { grant: GrantHolderState['grant']; time_token: GrantHolderState['time_token'] }) {
  const client = new GenesisMeshClient({
    baseUrl, signingKeyBase64: keyFile('controller.key'), keyId: 'controller',
    recordOutbox: new FileRecordOutbox(join(deviceDir, 'records')),
  });
  const holder = new GrantHolder({
    clients: client,
    signer: seedSigner(state.deviceSeed, state.deviceId),
    naPublicKeys: state.naPublicKeys,
    ...(issued ? { grant: issued.grant, timeToken: issued.time_token } : { state: state.holder! }),
    persist: holderState => save({ ...state, holder: holderState }),
  });
  return { client, holder };
}

function describe(n: number, result: GrantActResult<unknown>): string {
  if (result.path === 'grant') {
    return `use ${n}: under the grant (use ${result.use.use_sequence}), kept in the record outbox: ${result.queued?.state ?? result.submission?.status}`;
  }
  return `use ${n}: grant unusable (${result.unusable}), fallback took the ${result.path} path`;
}

if (phase === 'setup') {
  // With the NA up, the privileged key sets up an attestation, a policy, the device's key and a grant.
  say('==> Setup with the privileged key (operator-local)');
  const setup = new GenesisMeshClient({ baseUrl, signingKeyBase64: keyFile('operator.key'), keyId: 'operator-local' });
  const run = randomUUID().slice(0, 8);
  const capability = 'secret.rotate';
  const attestation = await setup.attestation.issue({
    subject_id: `edge-site-${run}`, roles: ['role:client'], claims: { capabilities: [capability] },
  });
  const now = Date.now();
  const policy = await setup.policy.publish({
    policy_id: `edge-rotation-${run}`,
    valid_from: new Date(now - 60_000).toISOString(), valid_until: new Date(now + 3_600_000).toISOString(),
    selector: { capabilities: [capability], requester_sovereign_ids: [attestation.subject_id] },
    gates: [{ gate_id: 'lifetime', gate_type: 'max_value.v1', order: 0, config: { path: 'request_parameters.lifetime_days', max: 90 } }],
  });
  await setup.policy.activate(policy.policy_id, policy.version);
  const deviceSeed = randomBytes(32).toString('base64');
  const deviceId = `device-${run}`;
  await setup.evidenceStore.registerExecutorKey({
    key_id: deviceId, public_key: publicKeyFromSeed(deviceSeed), executor_sovereign_id: `edge-site-${run}`,
  });
  const issued = await setup.grants.issueGrant({
    bearer_key_id: deviceId, capabilities: [capability], attestation_id: attestation.attestation_id,
    valid_until: new Date(now + 1_800_000), max_uses: 2,
    parameter_envelope: { lifetime_days: { number_range: { number_type: 'integer', minimum: 1, maximum: 60 } } },
  });
  const history = await setup.na.verifiedKeyHistory(keyFile('root.pub'));
  say(`policy ${policy.policy_id} v${policy.version} active; device key ${deviceId} registered`);
  say(`grant ${issued.grant.grant_id}: ${capability}, max_uses ${issued.grant.max_uses}, lifetime_days 1..60, until ${issued.grant.valid_until}`);
  mkdirSync(deviceDir, { recursive: true });
  const state: DeviceState = {
    naPublicKeys: history.keys.map(k => k.public_key), deviceId, deviceSeed, capability,
    resource: `kv:edge-vault/api-key-${run}`, policy, attestation, holder: null,
  };
  save(state);
  // The holder checks the grant and the time token offline before it keeps them.
  save({ ...state, holder: device(state, issued).holder.state });
  say(`device state and record outbox saved in ${deviceDir.replaceAll('\\', '/')}`);
} else if (phase === 'act') {
  // The NA is down: two uses within the grant, then a third past its budget falls back to break-glass.
  if (!existsSync(stateFile)) throw new Error('run setup first');
  const state = load();
  const { client, holder } = device(state);
  say('==> Three rotations with the NA down');
  for (const n of [1, 2, 3]) {
    const result = await holder.act({
      capability: state.capability,
      request_parameters: { lifetime_days: 30 },
      resource_id: state.resource,
      resource_action: 'rotate',
      fallback: {
        justification: 'the site is cut off and the key must rotate',
        verify: { operatorPublicKeys: state.naPublicKeys, expectedPolicies: [state.policy], expectedAttestation: state.attestation },
      },
    }, async () => ({ execution_parameters: { version_id: `v${n}` } }));
    say(describe(n, result));
  }
  const kept = await client.evidenceStore.recordOutbox!.list();
  say(`record outbox: ${kept.map(e => e.kind).join(', ')}`);
} else if (phase === 'sync') {
  // The NA is back: upload what the device did, then read how the NA recorded each change.
  const state = load();
  const { holder } = device(state);
  say('==> The NA is back: sync');
  const synced = await holder.sync({ ignoreBackoff: true });
  say(`sync: reachable ${synced.reachable}, admitted ${synced.flushed?.admitted.map(e => e.kind).join(', ')}, dead-lettered ${synced.flushed?.dead_lettered.length}`);
  const admin = new GenesisMeshClient({ baseUrl, signingKeyBase64: keyFile('controller.key'), keyId: 'controller' });
  const grant = await admin.grants.getGrant(state.holder!.grant.grant_id);
  say(`grant ${grant.status}: uses ${grant.uses}, remaining_uses ${grant.remaining_uses}`);
  say('==> resourceChanges');
  for (const change of (await admin.evidenceStore.resourceChanges(state.resource)).changes) {
    say(`#${String(change.store_sequence).padEnd(3)} ${change.kind.padEnd(15)} governed_by ${String(change.governed_by).padEnd(14)} state ${change.state}${change.verdict ? ` verdict ${change.verdict}` : ''}`);
  }
} else {
  throw new Error('usage: node examples/act-while-na-down.ts setup|act|sync <home>');
}
