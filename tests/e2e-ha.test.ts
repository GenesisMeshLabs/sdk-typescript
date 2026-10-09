import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { once } from 'node:events';
import { createInterface, type Interface } from 'node:readline';
import { randomUUID } from 'node:crypto';
import {
  GenesisMeshClient, ExecutionRecorder, seedSigner, governedAction, verifyEvidenceEvents, MemoryOutbox,
} from '../src/index.js';
import type { BoundaryPolicy, MembershipAttestation } from '../src/index.js';
import { generateTestKeyPair } from './helpers.js';

/**
 * Live HA test (v0.60): two NA instances on one PostgreSQL database behind
 * nginx, started by the core's cluster harness. Needs GM_E2E_PYTHON (core
 * installed) and GM_E2E_HA_DATABASE_URL (an empty PostgreSQL database with
 * C collation), plus nginx on PATH.
 */
const enabled = Boolean(process.env.GM_E2E_PYTHON && process.env.GM_E2E_HA_DATABASE_URL);
const suite = enabled ? describe : describe.skip;

interface ClusterInfo {
  baseUrl: string;
  instances: Record<string, string>;
  operatorSeed: string;
  operatorKeyId: string;
  naPublicKey: string;
}

suite('SDK against a two-instance HA Network Authority', () => {
  let child: ChildProcessWithoutNullStreams | undefined;
  let lines: Interface;
  let info: ClusterInfo;
  let diagnostics = '';

  const nextJson = () => new Promise<Record<string, unknown>>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`cluster did not answer: ${diagnostics}`)), 90_000);
    const onLine = (line: string) => {
      if (!line.startsWith('{')) return;
      clearTimeout(timer);
      lines.off('line', onLine);
      resolve(JSON.parse(line));
    };
    lines.on('line', onLine);
  });

  beforeAll(async () => {
    child = spawn(process.env.GM_E2E_PYTHON!, ['-m', 'genesis_mesh.tests.integration.ha_cluster',
      '--database-url', process.env.GM_E2E_HA_DATABASE_URL!], { stdio: 'pipe' });
    child.stderr.on('data', d => { diagnostics = (diagnostics + String(d)).slice(-8000); });
    lines = createInterface({ input: child.stdout });
    info = await nextJson() as unknown as ClusterInfo;
  }, 120_000);

  afterAll(async () => {
    if (child && child.exitCode === null) {
      const exited = once(child, 'exit');
      child.kill('SIGTERM');
      await exited;
    }
  });

  it('keeps governing a secret through the load balancer and direct failover when an instance dies', async () => {
    // Both clients govern the same secret, so they share one outbox.
    const outbox = new MemoryOutbox();
    const lb = new GenesisMeshClient({ baseUrl: info.baseUrl, signingKeyBase64: info.operatorSeed, keyId: info.operatorKeyId, outbox });
    const direct = new GenesisMeshClient({
      baseUrls: Object.values(info.instances), signingKeyBase64: info.operatorSeed, keyId: info.operatorKeyId, outbox,
    });

    // Every instance is ready, in HA mode, on PostgreSQL, with the same key.
    const endpoints = await direct.health.endpoints();
    expect(endpoints.every(e => e.ready)).toBe(true);
    const fingerprints = new Set(endpoints.map(e => e.readiness?.signing_key.fingerprint));
    expect(fingerprints.size).toBe(1);
    expect(endpoints[0]?.readiness).toMatchObject({ ha_mode: 'on', rate_limiter: 'database', database: { backend: 'postgres' } });

    const id = randomUUID();
    const executor = generateTestKeyPair();
    const recorder = new ExecutionRecorder({ executorSovereignId: `ctrl-${id}`, signer: seedSigner(executor.seedBase64, `ctrl-${id}`) });
    await lb.evidenceStore.registerExecutorKey({ key_id: `ctrl-${id}`, public_key: executor.pubBase64, executor_sovereign_id: `ctrl-${id}` });
    const attestation: MembershipAttestation = await lb.attestation.issue({
      subject_id: `vendor-${id}`, roles: ['role:client'], claims: { capabilities: ['secret.rotate'], apps: ['billing'] },
    });
    const policy: BoundaryPolicy = await lb.policy.publish({
      policy_id: `ha-${id}`, valid_from: new Date(Date.now() - 60_000).toISOString(),
      valid_until: new Date(Date.now() + 3600_000).toISOString(),
      selector: { parent_kinds: ['attestation'], capabilities: ['secret.*'] },
      gates: [{ gate_id: 'app', gate_type: 'attestation_claim.v1', order: 0, config: { path: 'request_parameters.app_id', claim: 'apps' } }],
    });
    await lb.policy.activate(policy.policy_id, policy.version);
    const resource = `kv:ha-${id}/secret`;
    const rotate = (client: GenesisMeshClient, version: number) => governedAction(client, recorder, {
      attestation_id: attestation.attestation_id, requested_capability: 'secret.rotate',
      context: { request_parameters: { app_id: 'billing' } }, resource_id: resource, resource_action: 'rotate',
      verify: { operatorPublicKeys: [info.naPublicKey], expectedPolicies: [policy], expectedAttestation: attestation },
    }, async () => ({ execution_parameters: { secret_version: `v${version}` } }));

    for (let v = 1; v <= 3; v++) expect((await rotate(lb, v)).submission?.status).toBe('recorded');

    // Instance A dies (SIGKILL, master and workers).
    child!.stdin.write('kill na-a\n');
    expect(await nextJson()).toEqual({ killed: 'na-a' });

    // The load balancer and the multi-endpoint client both keep working.
    for (let v = 4; v <= 6; v++) expect((await rotate(lb, v)).submission?.status).toBe('recorded');
    for (let v = 7; v <= 9; v++) expect((await rotate(direct, v)).submission?.status).toBe('recorded');
    const after = await direct.health.endpoints();
    expect(after.map(e => e.reachable)).toEqual([false, true]);
    expect((await lb.health.readiness()).ready).toBe(true);

    // One unbroken history for the secret, verified on the NA and offline.
    const history = await direct.evidenceStore.resourceHistory(resource);
    expect(history.verification.verified).toBe(true);
    const executions = history.entries.filter(e => e.entry.entry_kind === 'execution');
    expect(executions.map(e => e.entry.resource_sequence)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const events = [];
    for await (const e of direct.evidenceStore.exportAll()) events.push(e);
    const offline = verifyEvidenceEvents(events, {
      naPublicKeys: [info.naPublicKey], executorKeys: await direct.evidenceStore.listExecutorKeys(),
    });
    expect(offline.verified).toBe(true);
  }, 180_000);
});
