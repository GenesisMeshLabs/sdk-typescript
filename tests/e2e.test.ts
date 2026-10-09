import { afterAll, beforeAll, describe, expect, it, jest } from '@jest/globals';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import {
  GenesisMeshClient, ExecutionRecorder, seedSigner, governedAction, reconcileResources,
  verifyBoundaryDecision, verifyAttestationSignature, verifyPolicySignature, verifyJustificationSignature,
  verifyRevocationFeedSignature, verifyEvidenceEvents, parseExportLines, ConflictError,
  MemoryOutbox, MetadataRefusedError, executionDigest,
} from '../src/index.js';
import type { BoundaryPolicyIntent, EvidenceEvent } from '../src/index.js';
import { generateTestKeyPair } from './helpers.js';

const enabled = Boolean(process.env.GM_E2E_PYTHON || process.env.GM_E2E_BASE_URL);
const suite = enabled ? describe : describe.skip;

suite('SDK against a live Python Network Authority', () => {
  let child: ChildProcessWithoutNullStreams | undefined;
  let gm: GenesisMeshClient;
  let config: { baseUrl: string; signingKeyBase64: string; keyId: string; naPublicKey: string };
  let naPublicKey: string;
  let diagnostics = '';
  beforeAll(async () => {
    if (process.env.GM_E2E_BASE_URL) {
      const { GM_E2E_OPERATOR_SEED, GM_E2E_NA_PUBLIC_KEY } = process.env;
      if (!GM_E2E_OPERATOR_SEED || !GM_E2E_NA_PUBLIC_KEY) throw new Error('External E2E NA requires GM_E2E_OPERATOR_SEED and GM_E2E_NA_PUBLIC_KEY');
      config = { baseUrl: process.env.GM_E2E_BASE_URL, signingKeyBase64: GM_E2E_OPERATOR_SEED,
        keyId: process.env.GM_E2E_OPERATOR_KEY_ID ?? 'ops', naPublicKey: GM_E2E_NA_PUBLIC_KEY };
    } else {
      child = spawn(process.env.GM_E2E_PYTHON!, [fileURLToPath(new URL('../scripts/e2e_na.py', import.meta.url))], {
        env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }, stdio: 'pipe',
      });
      child.stderr.on('data', data => { diagnostics = (diagnostics + String(data)).slice(-8000); });
      const lines = createInterface({ input: child.stdout });
      config = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Local NA startup timed out: ' + diagnostics)), 20_000);
        child!.once('error', error => { clearTimeout(timer); reject(error); });
        child!.once('exit', code => { clearTimeout(timer); reject(new Error(`NA exited (${code}): ${diagnostics}`)); });
        lines.on('line', line => {
          if (!line.startsWith('{')) return;
          clearTimeout(timer);
          try { resolve(JSON.parse(line)); } catch (error) { reject(error); }
        });
      });
      lines.close();
    }
    naPublicKey = config.naPublicKey;
    gm = new GenesisMeshClient({ ...config, outbox: new MemoryOutbox() });
  }, 25_000);

  afterAll(async () => {
    if (child && child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit'); child.kill('SIGTERM'); await exited;
    }
  });

  it('admits, decides, records create/rotate/revoke, audits and offboards using only SDK calls', async () => {
    const id = randomUUID();
    const vendor = `sdk-zoë-${id}`;
    const resource = `kv:sdk-${id}/zoë`;
    const executor = generateTestKeyPair();
    const executorId = `executor-${id}`;
    const recorder = new ExecutionRecorder({ executorSovereignId: executorId, signer: seedSigner(executor.seedBase64, executorId) });
    const attestation = await gm.attestation.issue({ subject_id: vendor, roles: ['role:client'],
      claims: { capabilities: ['sp-secret.create', 'sp-secret.rotate', 'sp-secret.revoke'], apps: [`app-${id}`], note: 'Zoë 😀', '\uE000': 1, '😀': 2 } });
    expect(verifyAttestationSignature(attestation, [naPublicKey])).toBe(true);
    expect((await gm.attestation.get(attestation.attestation_id)).status).toBe('active');
    expect((await gm.attestation.list({ subject_id: vendor })).count).toBe(1);
    await gm.attestation.savePolicy({ recognition_policy: {
      local_sovereign_id: attestation.issuer_sovereign_id,
      recognized_issuers: [{ sovereign_id: attestation.issuer_sovereign_id, public_keys: [naPublicKey], allowed_roles: ['role:client'], accepted_statuses: ['active'] }],
      revoked_attestation_ids: [],
    } });
    expect((await gm.attestation.getPolicy()).recognized_issuers[0].allowed_roles).toEqual(['role:client']);
    expect((await gm.attestation.verify({ attestation })).accepted).toBe(true);
    const intent: BoundaryPolicyIntent = {
      policy_id: `sdk-policy-${id}`, description: 'SDK policy Zoë 😀',
      valid_from: new Date(Date.now() - 60_000).toISOString(), valid_until: new Date(Date.now() + 3600_000).toISOString(),
      selector: { parent_kinds: ['attestation'], requester_sovereign_ids: [vendor], capabilities: ['sp-secret.*'] },
      gates: [
        { gate_id: 'app', gate_type: 'attestation_claim.v1', order: 0, config: { path: 'request_parameters.app_id', claim: 'apps' } },
        { gate_id: 'owner', gate_type: 'required_parameter.v1', order: 1, mode: 'observe', config: { path: 'attributes.owner' } },
        { gate_id: 'lifetime', gate_type: 'max_value.v1', order: 2, config: { path: 'request_parameters.lifetime_days', max: 90 } },
      ],
    };
    expect((await gm.policy.validate(intent)).valid).toBe(true);
    const policy = await gm.policy.publish(intent);
    expect(verifyPolicySignature(policy, [naPublicKey])).toBe(true);
    expect((await gm.policy.verify({ policy })).valid).toBe(true);
    expect((await gm.policy.activate(policy.policy_id, policy.version)).active).toBe(true);
    expect((await gm.policy.active()).active.some(p => p.policy_id === policy.policy_id)).toBe(true);
    expect((await gm.policy.list()).some(p => p.policy_id === policy.policy_id)).toBe(true);
    await gm.evidenceStore.registerExecutorKey({ key_id: executorId, public_key: executor.pubBase64, executor_sovereign_id: executorId });
    const verify = { operatorPublicKeys: [naPublicKey], expectedPolicies: [policy], expectedAttestation: attestation };
    const context = { request_parameters: { app_id: `app-${id}`, lifetime_days: 30 }, attributes: { secret_store: 'test-store' } };
    let sequence = 0;
    for (const action of ['create', 'rotate', 'revoke'] as const) {
      const result = await governedAction(gm, recorder, {
        attestation_id: attestation.attestation_id, requested_capability: `sp-secret.${action}`,
        context, resource_id: resource, resource_action: action, verify,
      }, async () => ({ execution_parameters: { secret_version: `v${++sequence}`, owner: 'Zoë' } }));
      expect(result.authorized).toBe(true);
      expect(result.evidence?.resource_sequence).toBe(sequence);
      expect(result.summary.observed_failures).toHaveLength(1);
      expect(verifyJustificationSignature(result.evaluation.justification_proof, [naPublicKey])).toBe(true);
      expect((await gm.evidenceStore.submit(result.evidence!)).status).toBe('duplicate');
    }
    for (const request_parameters of [{ app_id: 'wrong', lifetime_days: 30 }, { app_id: `app-${id}`, lifetime_days: 91 }]) {
      const action = jest.fn(async () => ({}));
      const result = await governedAction(gm, recorder, { attestation_id: attestation.attestation_id,
        requested_capability: 'sp-secret.create', context: { request_parameters }, verify }, action);
      expect(result.authorized).toBe(false); expect(action).not.toHaveBeenCalled();
      expect(verifyBoundaryDecision(result.evaluation.decision, verify).accepted).toBe(true);
    }
    const states = await gm.evidenceStore.resourceStates();
    expect(reconcileResources([{ resource_id: resource, exists: true }], states)[0].status).toBe('present_after_revoke');
    expect((await gm.evidenceStore.resourceHistory(resource)).verification.verified).toBe(true);
    const vendorHistory = await gm.evidenceStore.vendorHistory(vendor);
    expect(vendorHistory.verification.verified).toBe(true);
    const keys = await gm.evidenceStore.listExecutorKeys();
    expect(verifyEvidenceEvents(vendorHistory.entries, { naPublicKeys: [naPublicKey], executorKeys: keys, contiguous: false }).verified).toBe(true);
    await gm.attestation.revoke(attestation.attestation_id, { reason: 'SDK test complete' });
    expect((await gm.attestation.get(attestation.attestation_id)).status).toBe('revoked');
    const revoked = await gm.boundary.evaluate({ attestation_id: attestation.attestation_id, requested_capability: 'sp-secret.create', context });
    expect(verifyBoundaryDecision(revoked.decision, verify)).toMatchObject({ accepted: true, authorized: false });
    const refused = await recorder.record({ decision: revoked.decision, executed_capability: 'sp-secret.create', outcome: 'success' });
    await expect(gm.evidenceStore.submit(refused)).rejects.toMatchObject({ code: 'evidence_decision_denied' });
    const feed = await gm.attestation.revocationFeed();
    expect(feed.revoked_attestation_ids).toContain(attestation.attestation_id);
    expect(verifyRevocationFeedSignature(feed, [naPublicKey])).toBe(true);
    expect((await gm.evidenceStore.verify()).verified).toBe(true);
    expect((await gm.evidenceStore.status()).evidence_store).toBe('on');
    const exported: EvidenceEvent[] = [];
    for await (const event of gm.evidenceStore.exportAll(0, 5)) exported.push(event);
    expect(verifyEvidenceEvents(exported, { naPublicKeys: [naPublicKey], executorKeys: keys }).verified).toBe(true);
    expect(parseExportLines(await gm.evidenceStore.exportText({ limit: 1 }))).toHaveLength(1);
    const searched: EvidenceEvent[] = [];
    for await (const event of gm.evidenceStore.iterate({ vendor_id: vendor, limit: 2 })) searched.push(event);
    expect(searched.length).toBeGreaterThan(3);
    expect((await gm.evidenceStore.applyRetention(365)).removed_count).toBe(0);
    expect(await gm.evidenceStore.latestCheckpoint()).toBeNull();
    expect((await gm.evidenceStore.retireExecutorKey(executorId)).active).toBe(false);
  }, 30_000);

  it('keeps evidence in the outbox while the NA is unreachable and admits it in order afterwards (1.2.0)', async () => {
    const id = randomUUID();
    const attestation = await gm.attestation.issue({ subject_id: id, roles: ['role:client'], claims: { capabilities: ['sdk.outbox'] } });
    const executor = generateTestKeyPair();
    const recorder = new ExecutionRecorder({ executorSovereignId: id, signer: seedSigner(executor.seedBase64, id) });
    await gm.evidenceStore.registerExecutorKey({ key_id: id, public_key: executor.pubBase64, executor_sovereign_id: id });
    // Evidence submissions fail as if the NA stopped after the action; everything else goes through.
    let offline = true;
    const outage: typeof fetch = async (input, init) => {
      if (offline && String(input).endsWith('/evidence/execution')) throw new TypeError('fetch failed');
      return fetch(input, init);
    };
    const client = new GenesisMeshClient({ ...config, fetch: outage, outbox: new MemoryOutbox() });
    const params = {
      attestation_id: attestation.attestation_id, requested_capability: 'sdk.outbox', resource_id: `sdk:${id}`,
      resource_action: 'rotate' as const, verify: { operatorPublicKeys: [naPublicKey], expectedPolicies: [], expectedAttestation: attestation },
    };
    const first = await governedAction(client, recorder, params, async () => ({ value: 1, execution_parameters: { secret_version: 'v1' } }));
    expect(first).toMatchObject({ value: 1, submission: { status: 'pending' } });
    const second = await governedAction(client, recorder, params, async () => ({ value: 2, execution_parameters: { secret_version: 'v2' } }));
    expect(second).toMatchObject({ value: 2, submission: { status: 'pending' } });
    expect(second.evidence!.prev_resource_digest).toBe(executionDigest(first.evidence!));

    offline = false;
    const flushed = await client.evidenceStore.flushPending({ ignoreBackoff: true });
    expect(flushed.admitted.map(e => e.id)).toEqual([first.evidence!.evidence_id, second.evidence!.evidence_id]);
    expect(await client.evidenceStore.outbox!.list()).toEqual([]);
    const history = await gm.evidenceStore.resourceHistory(params.resource_id);
    expect(history.verification.verified).toBe(true);
    expect(history.entries.filter(e => e.entry.entry_kind === 'execution').map(e => e.entry.resource_sequence)).toEqual([1, 2]);

    // A guard refusal after the action: the outcome is still recorded, without the refused field.
    const error = await governedAction(client, recorder, params, async () => ({
      value: 3, execution_parameters: { secret_version: 'v3', client_secret: 'not-for-evidence' },
    })).catch(e => e);
    expect(error).toBeInstanceOf(MetadataRefusedError);
    expect(error).toMatchObject({ value: 3, submission: { status: 'recorded' }, evidence: { execution_parameters: { secret_version: 'v3' } } });
  }, 30_000);

  it('supports observe/enforce, rollback, failure evidence, chain conflicts and retired keys', async () => {
    const id = randomUUID();
    const attestation = await gm.attestation.issue({ subject_id: id, roles: ['role:client'], claims: { capabilities: ['sdk.run'] } });
    const intent: BoundaryPolicyIntent = { policy_id: id, valid_from: new Date(Date.now() - 60_000).toISOString(), valid_until: new Date(Date.now() + 3600_000).toISOString(),
      selector: { requester_sovereign_ids: [id] }, gates: [{ gate_id: 'owner', gate_type: 'required_parameter.v1', mode: 'observe', order: 0, config: { path: 'attributes.owner' } }] };
    const first = await gm.policy.publish(intent); await gm.policy.activate(id, first.version);
    const second = await gm.policy.publish({ ...intent, gates: [{ ...intent.gates![0], mode: 'enforce' }] });
    await gm.policy.activate(id, second.version);
    const request = { attestation_id: attestation.attestation_id, requested_capability: 'sdk.run' };
    expect((await gm.boundary.evaluate(request)).decision.authorized).toBe(false);
    await gm.policy.activate(id, first.version);
    expect((await gm.policy.history(id)).versions).toHaveLength(2);
    const executor = generateTestKeyPair();
    const recorder = new ExecutionRecorder({ executorSovereignId: id, signer: seedSigner(executor.seedBase64, id) });
    await gm.evidenceStore.registerExecutorKey({ key_id: id, public_key: executor.pubBase64, executor_sovereign_id: id });
    const params = { ...request, resource_id: `sdk:${id}`, resource_action: 'create' as const,
      verify: { operatorPublicKeys: [naPublicKey], expectedPolicies: [first], expectedAttestation: attestation } };
    await expect(governedAction(gm, recorder, params, async () => { throw new Error('local test failure'); })).rejects.toThrow('local test failure');
    const history = await gm.evidenceStore.resourceHistory(params.resource_id);
    expect(history.entries.find(e => e.entry.entry_kind === 'execution')?.payload.outcome).toBe('failure');
    const evaluation = await gm.boundary.evaluate(request);
    const badHead = await recorder.record({ decision: evaluation.decision, executed_capability: 'sdk.run', outcome: 'success', resource_id: params.resource_id, resource_action: 'create' });
    await expect(gm.evidenceStore.submit(badHead)).rejects.toBeInstanceOf(ConflictError);
    await gm.evidenceStore.retireExecutorKey(id);
    const retired = await recorder.record({ decision: evaluation.decision, executed_capability: 'sdk.run', outcome: 'success' });
    await expect(gm.evidenceStore.submit(retired)).rejects.toMatchObject({ code: 'evidence_unknown_executor' });
    expect((await gm.policy.deactivate(id, first.version)).active).toBe(false);
    expect(verifyBoundaryDecision((await gm.boundary.evaluate(request)).decision, params.verify)).toMatchObject({ accepted: false, reason: 'policy_binding_mismatch' });
  }, 30_000);
});
