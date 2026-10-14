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
  MemoryOutbox, MetadataRefusedError, executionDigest, ObservationRecorder,
  cancelByRotatingForward, urgentAction, reviewApprovalProblem, verifyReviewRecord, verifyRemediationRecord,
  auditPackFiles, verifyAuditPack, packReasons, verifyStoreAnchors, checkEventsAgainstAnchors, verifyArchiveRecord,
  FileRecordOutbox, GrantHolder, verifyCapabilityGrant, verifyTimeToken, verifyGrantUse,
} from '../src/index.js';
import type {
  BoundaryPolicy, BoundaryPolicyIntent, BreakGlassResult, EvidenceEvent, GovernedActionParams, RecordOutboxEntry,
  GrantFallbackResult, GrantUseResult, GovernedActionResult,
} from '../src/index.js';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateTestKeyPair } from './helpers.js';

const enabled = Boolean(process.env.GM_E2E_PYTHON || process.env.GM_E2E_BASE_URL);
const suite = enabled ? describe : describe.skip;

suite('SDK against a live Python Network Authority', () => {
  let child: ChildProcessWithoutNullStreams | undefined;
  let gm: GenesisMeshClient;
  let config: {
    baseUrl: string; signingKeyBase64: string; keyId: string; naPublicKey: string; outOfBand?: boolean;
    /** 1.4.0: the NA records remediations and reviews; `reviewer` is a privileged key of another holder. */
    remediation?: boolean; reviewer?: { keyId: string; signingKeyBase64: string };
    /** 1.5.0: the key history, audit packs and archives; `rootPublicKey` signed the genesis block. */
    audit?: boolean; rootPublicKey?: string;
    /** 1.6.0: pre-issued grants (EVIDENCE_GRANTS=on); `control`: the NA stops and starts on request. */
    grants?: boolean; control?: boolean;
  };
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
    gm = new GenesisMeshClient(config);
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
    expect(first).toMatchObject({ value: 1, queued: { state: 'pending' } });
    const second = await governedAction(client, recorder, params, async () => ({ value: 2, execution_parameters: { secret_version: 'v2' } }));
    expect(second).toMatchObject({ value: 2, queued: { state: 'pending' } });
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

  it('records and judges changes made outside the controlled path, and verifies the export (1.3.0)', async () => {
    if (!config.outOfBand) return; // a core before 1.3.0
    const id = randomUUID();
    const capability = `sdk.oob.${id}`;
    const resource = `kv:oob-${id}/secret`;
    const attestation = await gm.attestation.issue({ subject_id: id, roles: ['role:client'], claims: { capabilities: [capability] } });
    const policy = await gm.policy.publish({
      policy_id: `oob-${id}`, valid_from: new Date(Date.now() - 60_000).toISOString(),
      valid_until: new Date(Date.now() + 3600_000).toISOString(), selector: { capabilities: [capability] },
      gates: [{ gate_id: 'lifetime', gate_type: 'max_value.v1', order: 0, config: { path: 'request_parameters.lifetime_days', max: 90 } }],
    });
    await gm.policy.activate(policy.policy_id, policy.version);

    const observerKey = generateTestKeyPair();
    await gm.evidenceStore.registerExecutorKey({
      key_id: `observer-${id}`, public_key: observerKey.pubBase64, executor_sovereign_id: `observer-${id}`,
      role: 'observer', resource_prefix: `kv:oob-${id}/`,
    });
    const observer = new ObservationRecorder({ observerSovereignId: `observer-${id}`, signer: seedSigner(observerKey.seedBase64, `observer-${id}`) });
    const observe = (lifetime: number, event: string) => observer.record({
      resource_id: resource, action: 'rotate', capability, changed_at: new Date(), source: 'cloud-activity-log',
      source_event_id: event, actor: 'principal-7f3a', metadata: { lifetime_days: lifetime },
    });
    const denied = await gm.evidenceStore.submitObservation(await observe(400, `${id}-1`));
    expect(denied).toMatchObject({ status: 'recorded', judgement: { payload: { verdict: 'deny', governed_by: 'after_the_fact' } } });
    const allowed = await gm.evidenceStore.submitObservations([await observe(30, `${id}-2`)]);
    expect(allowed[0]).toMatchObject({ status: 'recorded', judgement: { payload: { verdict: 'allow' } } });
    const again = await gm.evidenceStore.judgeObservation(denied.payload['observation_id'] as string);
    expect(again.status).toBe('existing');

    // Break-glass: the NA cannot be reached at all. The action runs, its record waits in the
    // outbox, and is admitted and judged once the NA is back.
    const executor = generateTestKeyPair();
    await gm.evidenceStore.registerExecutorKey({ key_id: `executor-${id}`, public_key: executor.pubBase64, executor_sovereign_id: `executor-${id}` });
    const recorder = new ExecutionRecorder({ executorSovereignId: `executor-${id}`, signer: seedSigner(executor.seedBase64, `executor-${id}`) });
    let offline = true;
    const outage: typeof fetch = async (input, init) => {
      const url = String(input);
      if (offline && (url.endsWith('/admin/boundary/evaluate') || url.endsWith('/evidence/break-glass'))) {
        throw new TypeError('fetch failed');
      }
      return fetch(input, init);
    };
    const client = new GenesisMeshClient({ ...config, fetch: outage, recordOutbox: new MemoryOutbox<RecordOutboxEntry>() });
    const params: GovernedActionParams & { breakGlass: { justification: string } } = {
      attestation_id: attestation.attestation_id, requested_capability: capability, resource_id: resource, resource_action: 'rotate',
      context: { request_parameters: { lifetime_days: 30 } }, breakGlass: { justification: 'incident drill: NA unreachable' },
      verify: { operatorPublicKeys: [naPublicKey], expectedPolicies: [policy], expectedAttestation: attestation },
    };
    const result = await governedAction(client, recorder, params,
      async decision => ({ value: decision, execution_parameters: { version_id: 'v2' } })) as BreakGlassResult<unknown>;
    expect(result).toMatchObject({ brokeGlass: true, failure: 'network_error', value: null, queued: { state: 'pending', kind: 'break_glass' } });
    offline = false;
    const flushed = await client.evidenceStore.flushRecords({ ignoreBackoff: true });
    expect(flushed.admitted.map(e => e.id)).toEqual([result.record.break_glass_id]);
    expect(await client.evidenceStore.recordOutbox!.list()).toEqual([]);

    // A DENY is never broken through, breakGlass or not.
    const denyAction = jest.fn(async () => ({}));
    const refused = await governedAction(client, recorder, { ...params, context: { request_parameters: { lifetime_days: 400 } } }, denyAction);
    expect(refused).toMatchObject({ authorized: false });
    expect(denyAction).not.toHaveBeenCalled();

    const changes = await gm.evidenceStore.resourceChanges(resource);
    // 1.4.0: with the remediation records on, the denied change shows its remediation state, and the
    // break-glass change, flagged for review, has a pending review beside its state.
    expect(changes.changes.map(c => [c.kind, c.state])).toEqual([
      ['observation', config.remediation ? 'remediation_due' : 'judged_denied'], ['observation', 'judged_allowed'],
      ['break_glass', 'judged_allowed'],
    ]);
    if (config.remediation) {
      expect(changes.changes[2]!.remediation).toMatchObject({ review_pending: true, review: { opened_for: 'flagged_for_review' } });
    }
    expect(changes.changes[2]!.justification).toBe('incident drill: NA unreachable');
    expect((await gm.evidenceStore.operatorHolders()).map(h => h.key_id)).toContain('ops');

    const exported: EvidenceEvent[] = [];
    for await (const event of gm.evidenceStore.exportAll()) exported.push(event);
    const verification = verifyEvidenceEvents(exported, { naPublicKeys: [naPublicKey], executorKeys: await gm.evidenceStore.listExecutorKeys() });
    expect(verification.failures).toEqual([]);
    expect(verification.observations).toBeGreaterThanOrEqual(2);
    expect(verification.break_glass).toBeGreaterThanOrEqual(1);
    expect(verification.judgements).toBeGreaterThanOrEqual(3);
  }, 30_000);

  /** A capability, its policy, an attestation, and executor and observer keys, for the 1.4.0 tests. */
  async function remediationSetup(policy: Partial<BoundaryPolicyIntent> = {}) {
    const id = randomUUID();
    const capability = `sdk.rem.${id}`;
    const emergency = `${capability}.emergency`;
    const attestation = await gm.attestation.issue({ subject_id: id, roles: ['role:client'], claims: { capabilities: [capability, emergency] } });
    const window = { valid_from: new Date(Date.now() - 60_000).toISOString(), valid_until: new Date(Date.now() + 3600_000).toISOString() };
    const ordinary = await gm.policy.publish({
      policy_id: `rem-${id}`, ...window, selector: { capabilities: [capability] },
      gates: [{ gate_id: 'lifetime', gate_type: 'max_value.v1', order: 0, config: { path: 'request_parameters.lifetime_days', max: 90 } }],
      ...policy,
    });
    await gm.policy.activate(ordinary.policy_id, ordinary.version);
    const executorKey = generateTestKeyPair();
    await gm.evidenceStore.registerExecutorKey({ key_id: `executor-${id}`, public_key: executorKey.pubBase64, executor_sovereign_id: `executor-${id}` });
    const recorder = new ExecutionRecorder({ executorSovereignId: `executor-${id}`, signer: seedSigner(executorKey.seedBase64, `executor-${id}`) });
    const observerKey = generateTestKeyPair();
    await gm.evidenceStore.registerExecutorKey({
      key_id: `observer-${id}`, public_key: observerKey.pubBase64, executor_sovereign_id: `observer-${id}`, role: 'observer',
    });
    const observer = new ObservationRecorder({ observerSovereignId: `observer-${id}`, signer: seedSigner(observerKey.seedBase64, `observer-${id}`) });
    const verify = { operatorPublicKeys: [naPublicKey], expectedPolicies: [ordinary], expectedAttestation: attestation };
    return { id, capability, emergency, attestation, ordinary, recorder, observer, verify, window };
  }

  it('cancels a denied change by rotating forward, tells its actor, and verifies the export (1.4.0)', async () => {
    if (!config.remediation) return; // a core before 1.4.0
    const x = await remediationSetup({ remediation: { lifetime: { mode: 'cancel', grace_seconds: 3600 } } });
    const resource = `kv:rem-${x.id}/secret`;
    // Someone rotates the secret in the console to v2 with a 400-day lifetime.
    const cloud = { current: 'v2', enabled: new Set(['v1', 'v2']) };
    const read = () => { expect(cloud.enabled.has(cloud.current)).toBe(true); return cloud.current; };
    const seen = await gm.evidenceStore.submitObservation(await x.observer.record({
      resource_id: resource, action: 'rotate', capability: x.capability, changed_at: new Date(), source: 'activity-log',
      source_event_id: `${x.id}-1`, actor: 'principal-7f3a', version_id: 'v2', metadata: { lifetime_days: 400 },
    }));
    const judgement = seen.judgement!;
    expect(judgement.payload.verdict).toBe('deny');
    expect(judgement.remediation).toMatchObject({
      state: 'remediation_due', mode: 'cancel', steps: 'rotate_forward_then_disable', guidance_source: 'gate',
      change_kind: 'observation', actor: 'principal-7f3a',
    });
    const subjectId = judgement.payload.judgement_id;

    const due: string[] = [];
    for await (const s of gm.evidenceStore.allRemediations({ state: 'remediation_due', limit: 1 })) due.push(s.subject_id);
    expect(due).toContain(subjectId);
    const noticed = await gm.evidenceStore.markNotified(subjectId, 'email');
    expect(noticed.notified_at).not.toBeNull();

    const state = (await gm.evidenceStore.remediation(subjectId));
    const result = await cancelByRotatingForward(gm, x.recorder, {
      remediation: state, deniedVersionId: 'v2',
      rotation: {
        attestation_id: x.attestation.attestation_id, requested_capability: x.capability,
        context: { request_parameters: { lifetime_days: 30 } }, verify: x.verify,
      },
      rotate: async () => { cloud.enabled.add('v3'); cloud.current = 'v3'; read(); return { version_id: 'v3' }; },
      disable: async version => { cloud.enabled.delete(version); read(); },
    });
    expect(result.submission).toMatchObject({ status: 'recorded', remediation: { state: 'remediated' } });
    expect(read()).toBe('v3');
    expect(verifyRemediationRecord(result.remediation!, [(await gm.evidenceStore.listExecutorKeys())
      .find(k => k.key_id === x.recorder.keyId)!.public_key])).toBe(true);
    expect((await gm.evidenceStore.submitRemediation(result.remediation!)).status).toBe('duplicate');
    const detail = await gm.evidenceStore.remediation(subjectId);
    expect(detail).toMatchObject({ state: 'remediated', remediation_id: result.remediation!.remediation_id });
    expect(detail.records.map(r => r.entry.entry_kind)).toEqual(['remediation']);
    expect((await gm.evidenceStore.status()).remediation?.['remediated']).toBeGreaterThanOrEqual(1);

    const exported: EvidenceEvent[] = [];
    for await (const event of gm.evidenceStore.exportAll()) exported.push(event);
    const verification = verifyEvidenceEvents(exported, { naPublicKeys: [naPublicKey], executorKeys: await gm.evidenceStore.listExecutorKeys() });
    expect(verification.failures).toEqual([]);
    expect(verification.remediations).toBeGreaterThanOrEqual(1);
  }, 30_000);

  it('reviews a judged change with a second holder, whose approval verifies offline (1.4.0)', async () => {
    if (!config.remediation) return; // a core before 1.4.0
    const x = await remediationSetup();
    const seen = await gm.evidenceStore.submitObservation(await x.observer.record({
      resource_id: `kv:rev-${x.id}/secret`, action: 'rotate', capability: x.capability, changed_at: new Date(),
      source: 'activity-log', source_event_id: `${x.id}-1`, actor: 'principal-7f3a', version_id: 'v2',
      metadata: { lifetime_days: 400 },
    }));
    const subjectId = seen.judgement!.payload.judgement_id;
    const requested = await gm.evidenceStore.requestReview({
      subject_kind: 'judgement', subject_id: subjectId, justification: 'The change was planned with the vendor',
    });
    // A pending review is a flag beside the state: the denied change stays due.
    expect(requested).toMatchObject({ state: 'remediation_due', review_pending: true });
    expect(requested.review).toMatchObject({ opened_for: 'requested', requested_by: 'ops', requester_holder: 'alice' });
    const pending: string[] = [];
    for await (const s of gm.evidenceStore.allRemediations({ state: 'review_pending' })) pending.push(s.subject_id);
    expect(pending).toContain(subjectId);
    // The requester cannot decide its own request.
    await expect(gm.evidenceStore.decideReview(requested.review_id, { verdict: 'uphold' }))
      .rejects.toMatchObject({ code: 'review_same_holder_as_requester' });

    const reviewer = new GenesisMeshClient({ ...config, ...config.reviewer! });
    const until = new Date(Date.now() + 86_400_000);
    const decided = await reviewer.evidenceStore.decideReview(requested.review_id, {
      verdict: 'waive_until', waive_until: until, note: 'Vendor migration ends tomorrow',
    });
    expect(decided).toMatchObject({ state: 'waived', review_id: requested.review_id });
    const review = decided.review.payload;
    expect(review).toMatchObject({ verdict: 'waive_until', decided_by: 'ops-2', decider_holder: 'bob', requested_by: 'ops' });
    expect(verifyReviewRecord(review, [naPublicKey])).toBe(true);
    expect(reviewApprovalProblem(review, [naPublicKey])).toBeNull();
    expect((await gm.evidenceStore.review(requested.review_id)).record?.payload.review_id).toBe(requested.review_id);

    const exported: EvidenceEvent[] = [];
    for await (const event of gm.evidenceStore.exportAll()) exported.push(event);
    const verification = verifyEvidenceEvents(exported, { naPublicKeys: [naPublicKey], executorKeys: await gm.evidenceStore.listExecutorKeys() });
    expect(verification.failures).toEqual([]);
    expect(verification.reviews).toBeGreaterThanOrEqual(1);
  }, 30_000);

  describe('urgent changes are never blocked, and each is judged (1.4.0)', () => {
    async function urgent() {
      const x = await remediationSetup();
      const policy: BoundaryPolicy = await gm.policy.publish({
        policy_id: `rem-emergency-${x.id}`, ...x.window, selector: { capabilities: [x.emergency] },
        gates: [{ gate_id: 'justified', gate_type: 'required_parameter.v1', order: 0, config: { path: 'request_parameters.justification' } }],
        emergency: { stands_for: x.capability, justification_parameter: 'justification', max_lifetime_seconds: 86400 },
      });
      await gm.policy.activate(policy.policy_id, policy.version);
      const params = {
        attestation_id: x.attestation.attestation_id, requested_capability: x.capability,
        resource_id: `kv:urgent-${x.id}/secret`, resource_action: 'rotate' as const,
        context: { request_parameters: { lifetime_days: 400 } }, verify: x.verify,
        emergency: { capability: x.emergency, justification: 'Key leaked in a public repo', expectedPolicies: [policy] },
      };
      const action = jest.fn(async (_decision: unknown) => ({ value: 'rotated', execution_parameters: { version_id: 'v5' } }));
      return { ...x, policy, params, action };
    }

    it('NA up with an ordinary DENY: the emergency capability decides before the change, and it is reviewed', async () => {
      if (!config.remediation) return;
      const x = await urgent();
      const result = await urgentAction(
        new GenesisMeshClient({ ...config, recordOutbox: new MemoryOutbox<RecordOutboxEntry>() }), x.recorder, x.params, x.action);
      expect(result).toMatchObject({ path: 'emergency', ordinaryDenial: { authorized: false }, result: { authorized: true } });
      expect(x.action).toHaveBeenCalledTimes(1);
      const decision = (result.result as { evaluation: { decision: { decision_id: string } } }).evaluation.decision;
      const state = await gm.evidenceStore.remediation(decision.decision_id);
      expect(state).toMatchObject({
        subject_kind: 'decision', state: 'recorded', review_pending: true, review: { opened_for: 'review_required' },
      });
      expect(state.lifetime_ends_at).not.toBeNull();
    }, 30_000);

    it.each([
      ['NA down', 'network_error', () => { throw new TypeError('fetch failed'); }],
      ['NA answering 503', 'server_error', () => new Response(JSON.stringify({ error: { code: 'service_unavailable', message: 'down' } }), { status: 503 })],
      ['NA answering 429', 'rate_limited', () => new Response(JSON.stringify({ error: { code: 'rate_limited', message: 'slow down' } }), { status: 429 })],
    ])('%s: break-glass names the emergency capability and is judged under its policy', async (_case, failure, answer) => {
      if (!config.remediation) return;
      const x = await urgent();
      const outage: typeof fetch = async (input, init) =>
        (String(input).endsWith('/admin/boundary/evaluate') ? answer() : fetch(input, init));
      const client = new GenesisMeshClient({ ...config, fetch: outage, recordOutbox: new MemoryOutbox<RecordOutboxEntry>() });
      const result = await urgentAction(client, x.recorder, x.params, x.action);
      expect(result.path).toBe('break_glass');
      expect(x.action).toHaveBeenCalledWith(null);
      const broke = result.result as BreakGlassResult<string>;
      expect(broke).toMatchObject({ failure, submission: { status: 'recorded' } });
      expect(broke.record).toMatchObject({
        capability: x.emergency, request_parameters: { lifetime_days: 400, justification: 'Key leaked in a public repo' },
      });
      const judgement = broke.submission!.judgement!;
      expect(judgement.payload).toMatchObject({ verdict: 'allow', capability: x.emergency });
      expect(judgement.payload.policy_binding?.policies.map(p => p.policy_id)).toContain(x.policy.policy_id);
      expect(judgement.remediation).toMatchObject({ state: 'judged_allowed', review_pending: true });
    }, 30_000);
  });

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
    // 1.3.0 names a retired key (evidence_executor_key_retired); a 1.2 core does not.
    const refusal = await gm.evidenceStore.submit(retired).then(() => null, (e: { code: string }) => e.code);
    expect(['evidence_executor_key_retired', 'evidence_unknown_executor']).toContain(refusal);
    expect((await gm.policy.deactivate(id, first.version)).active).toBe(false);
    expect(verifyBoundaryDecision((await gm.boundary.evaluate(request)).decision, params.verify)).toMatchObject({ accepted: false, reason: 'policy_binding_mismatch' });
  }, 30_000);

  it('verifies the key history from the root key, an audit pack offline, and records its archive (1.5.0)', async () => {
    if (!config.audit || !config.rootPublicKey) return; // a core before 1.5.0
    // The key history, rebuilt from the root key held out of band.
    const view = await gm.na.getKeyHistory();
    expect(view.handover_seconds).toBe(300);
    const history = await gm.na.verifiedKeyHistory(config.rootPublicKey);
    expect(history.allKeys()).toEqual([naPublicKey]);
    await expect(gm.na.verifiedKeyHistory(generateTestKeyPair().pubBase64)).rejects.toMatchObject({ code: 'genesis_root_mismatch' });

    // Records signed by the NA verify with the key valid at their time.
    const id = randomUUID();
    const attestation = await gm.attestation.issue({ subject_id: id, roles: ['role:client'], claims: { capabilities: ['sdk.audit'] } });
    expect(verifyAttestationSignature(attestation, history)).toBe(true);
    const decision = (await gm.boundary.evaluate({ attestation_id: attestation.attestation_id, requested_capability: 'sdk.audit' })).decision;
    expect(verifyBoundaryDecision(decision, { operatorPublicKeys: history, atRecordTime: true }).accepted).toBe(true);

    // Anchor the head, then hold every anchor out of band, as an auditor does.
    expect(['anchored', 'unchanged']).toContain((await gm.evidenceStore.anchor()).status);
    const held = await gm.evidenceStore.allAnchors();
    expect(verifyStoreAnchors(held, { naPublicKeys: history, sovereignId: history.sovereign_id }).failures).toEqual([]);
    const status = await gm.evidenceStore.status();
    expect(status.latest_anchor?.anchor_sequence).toBe(held[held.length - 1]!.anchor_sequence);
    expect(status.unanchored_entries).toBe(0);
    if (config.outOfBand) {
      expect(typeof status.registry_healthy).toBe('boolean');
      expect(Array.isArray(status.registry_problems)).toBe(true);
      expect(status).toHaveProperty('policy_history_started');
    }

    // The whole store verifies against the key history and the anchors held.
    const events: EvidenceEvent[] = [];
    for await (const event of gm.evidenceStore.exportAll()) events.push(event);
    const exported = verifyEvidenceEvents(events, { naPublicKeys: history, executorKeys: await gm.evidenceStore.listExecutorKeys() });
    checkEventsAgainstAnchors(events, held, exported);
    expect(exported.failures).toEqual([]);

    // An audit pack of the store, verified offline from the root key and the anchors held.
    const pack = await gm.evidenceStore.auditPack();
    const files = auditPackFiles(pack);
    const verification = verifyAuditPack(files, { rootPublicKey: config.rootPublicKey, heldAnchors: held });
    expect(packReasons(verification)).toEqual([]);
    expect(verification.verified).toBe(true);
    expect(verification.range?.through_sequence).toBe(pack.manifest.through_sequence);
    // A changed file is refused by name.
    const tampered = { ...files, 'report.md': Buffer.from('# not the report\n') };
    expect(packReasons(verifyAuditPack(tampered, { rootPublicKey: config.rootPublicKey, heldAnchors: held })))
      .toEqual(['manifest_digest_mismatch']);

    // Written to immutable storage and read back intact: the NA records the archive, once.
    const location = `archive://sdk-e2e/packs/${pack.manifest.pack_id}`;
    const recorded = await gm.evidenceStore.recordArchive(pack.manifest, location);
    expect(recorded.status).toBe('recorded');
    expect(recorded.archived_through_sequence).toBe(pack.manifest.through_sequence);
    expect(verifyArchiveRecord(recorded.archive, history)).toBe(true);
    expect((await gm.evidenceStore.recordArchive(pack.manifest, location)).status).toBe('duplicate');
    const archives = await gm.evidenceStore.archives();
    expect(archives.archives.map(a => a.pack_id)).toContain(pack.manifest.pack_id);
    expect(archives.archived_through_sequence).toBe(pack.manifest.through_sequence);
  }, 60_000);
  /** Stop or start the NA's server (its store and keys are kept), and wait until it is done (1.6.0). */
  async function control(command: 'stop' | 'start'): Promise<void> {
    const lines = createInterface({ input: child!.stdout });
    const done = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`NA ${command} timed out: ${diagnostics}`)), 20_000);
      lines.on('line', line => {
        if (!line.includes('"control"')) return;
        clearTimeout(timer);
        lines.close();
        resolve();
      });
    });
    child!.stdin.write(`${command}\n`);
    await done;
  }

  it('acts within a grant with the NA stopped, uploads every use on reconnect, refuses a revoked grant and falls back to break-glass past expiry (1.6.0)', async () => {
    if (!config.grants || !config.control || !child) return; // a core before 1.6.0, or an NA this test cannot stop
    const id = randomUUID();
    const capability = `sdk.grant.${id}`;
    const resource = `kv:grant-${id}/api-key`;
    const window = { valid_from: new Date(Date.now() - 60_000).toISOString(), valid_until: new Date(Date.now() + 3600_000).toISOString() };
    const attestation = await gm.attestation.issue({ subject_id: `vendor-${id}`, roles: ['role:client'], claims: { capabilities: [capability] } });
    const intent: BoundaryPolicyIntent = {
      policy_id: `grant-${id}`, ...window, selector: { capabilities: [capability] },
      gates: [{ gate_id: 'lifetime', gate_type: 'max_value.v1', order: 0, config: { path: 'request_parameters.lifetime_days', max: 90 } }],
    };
    const policy = await gm.policy.publish(intent);
    await gm.policy.activate(policy.policy_id, policy.version);
    const device = generateTestKeyPair();
    const deviceId = `device-${id}`;
    await gm.evidenceStore.registerExecutorKey({ key_id: deviceId, public_key: device.pubBase64, executor_sovereign_id: `site-${id}` });
    const signer = seedSigner(device.seedBase64, deviceId);
    const envelope = { lifetime_days: { number_range: { number_type: 'integer' as const, minimum: 1, maximum: 60 } } };

    // An envelope a policy could deny is not granted.
    await expect(gm.grants.issueGrant({
      bearer_key_id: deviceId, capabilities: [capability], attestation_id: attestation.attestation_id,
      valid_until: new Date(Date.now() + 60_000), max_uses: 3,
      parameter_envelope: { lifetime_days: { number_range: { number_type: 'integer', minimum: 1, maximum: 400 } } },
    })).rejects.toMatchObject({ status: 422, code: 'grant_gate_may_deny' });

    const issued = await gm.grants.issueGrant({
      bearer_key_id: deviceId, capabilities: [capability], attestation_id: attestation.attestation_id,
      valid_until: new Date(Date.now() + 1800_000), max_uses: 3, max_uses_per_time_token: 2, parameter_envelope: envelope,
    });
    expect(verifyCapabilityGrant(issued.grant, [naPublicKey])).toBe(true);
    expect(verifyTimeToken(issued.time_token, [naPublicKey])).toBe(true);
    expect(issued.grant.policy_binding.policies.map(p => p.policy_id)).toEqual([policy.policy_id]);
    expect((await gm.grants.getGrant(issued.grant.grant_id))).toMatchObject({ status: 'active', remaining_uses: 3 });

    const dir = await mkdtemp(join(tmpdir(), 'gm-sdk-grants-'));
    try {
      const device1 = new GenesisMeshClient({ ...config, recordOutbox: new FileRecordOutbox(dir) });
      const holder = new GrantHolder({
        clients: device1, signer, naPublicKeys: [naPublicKey], grant: issued.grant, timeToken: issued.time_token,
      });
      const verify = { operatorPublicKeys: [naPublicKey], expectedPolicies: [policy], expectedAttestation: attestation };
      const rotate = (lifetime: number) => ({
        capability, request_parameters: { lifetime_days: lifetime }, resource_id: resource, resource_action: 'rotate' as const,
        fallback: { justification: 'the site is cut off and the key must rotate', verify },
      });

      // The NA stops: two rotations within the grant, each kept in the outbox.
      await control('stop');
      const cloud: string[] = [];
      const uses: GrantUseResult<unknown>[] = [];
      for (const version of ['v8', 'v9']) {
        const result = await holder.act(rotate(30), async authority => {
          expect(authority.path).toBe('grant');
          cloud.push(version);
          return { execution_parameters: { version_id: version } };
        });
        expect(result).toMatchObject({ path: 'grant', queued: { state: 'pending', kind: 'grant_execution' } });
        uses.push(result as GrantUseResult<unknown>);
      }
      expect(verifyGrantUse(uses[1]!.use, device.pubBase64)).toBe(true);
      expect(cloud).toEqual(['v8', 'v9']);

      // It starts again: a fresh time token naming the chain's head, and every use admitted in order.
      await control('start');
      const synced = await holder.sync();
      expect(synced).toMatchObject({ reachable: true, unusable: null, timeToken: { use_sequence: 2 } });
      expect(synced.flushed?.admitted.map(e => e.id)).toEqual(uses.map(u => u.use.use_id));
      expect(synced.flushed?.dead_lettered).toEqual([]);
      expect(await device1.evidenceStore.recordOutbox!.list()).toEqual([]);
      expect(await gm.grants.getGrant(issued.grant.grant_id)).toMatchObject({ uses: 2, remaining_uses: 1, chain_length: 2 });
      const chain = await gm.grants.listGrantUses(issued.grant.grant_id, { limit: 1 });
      expect(chain.uses.map(u => [u.use_id, u.state, u.resource_sequence])).toEqual([[uses[1]!.use.use_id, 'admitted', 2]]);
      expect((await gm.grants.listGrantUses(issued.grant.grant_id, { before: chain.next_before! })).uses.map(u => u.use_sequence)).toEqual([1]);
      expect(await gm.evidenceStore.storedResourceHead(resource)).toMatchObject({
        resource_sequence: 2, entry_kind: 'grant_execution', record_id: uses[1]!.use.use_id,
      });
      expect((await gm.evidenceStore.search({ grant_id: issued.grant.grant_id })).entries.map(e => e.entry.record_id))
        .toEqual(uses.map(u => u.use.use_id));
      const changes = await gm.evidenceStore.resourceChanges(resource);
      expect(changes.changes.map(c => [c.kind, c.governed_by])).toEqual([['grant_execution', 'grant'], ['grant_execution', 'grant']]);
      expect((await gm.evidenceStore.resourceHistory(resource)).verification.verified).toBe(true);

      // A stricter version of the policy replaces the one the grant is bound to: the NA revokes it.
      const stricter = await gm.policy.publish({ ...intent, gates: [{ ...intent.gates![0]!, config: { path: 'request_parameters.lifetime_days', max: 20 } }] });
      await gm.policy.activate(stricter.policy_id, stricter.version);
      expect(await gm.grants.getGrant(issued.grant.grant_id)).toMatchObject({ status: 'revoked' });
      const feed = await gm.attestation.revocationFeed();
      expect(feed.revoked_grant_ids).toContain(issued.grant.grant_id);
      expect(verifyRevocationFeedSignature(feed, [naPublicKey])).toBe(true);
      expect(await holder.refreshRevocationFeed()).toBe(true);
      const stricterVerify = { ...verify, expectedPolicies: [stricter] };
      const revokedRotate = (lifetime: number) => ({ ...rotate(lifetime), fallback: { ...rotate(lifetime).fallback, verify: stricterVerify } });

      // Revoked, with the NA up: the NA decides, and its DENY is never broken through.
      const denied = jest.fn(async () => ({}));
      const deny = await holder.act(revokedRotate(30), denied) as GrantFallbackResult<unknown>;
      expect(deny).toMatchObject({ path: 'decision', unusable: 'grant_revoked', result: { authorized: false } });
      expect(denied).not.toHaveBeenCalled();
      // Revoked, with the NA down: break-glass naming the capability, recorded and judged afterwards.
      await control('stop');
      const broke = await holder.act(revokedRotate(10), async authority => {
        expect(authority).toEqual({ path: 'break_glass' });
        return { execution_parameters: { version_id: 'v10' } };
      }) as GrantFallbackResult<unknown>;
      expect(broke).toMatchObject({ path: 'break_glass', unusable: 'grant_revoked' });
      expect((broke.result as BreakGlassResult<unknown>).record).toMatchObject({ capability, resource_id: resource });
      await control('start');
      expect((await holder.sync()).flushed?.admitted.map(e => e.kind)).toEqual(['break_glass']);

      // A short grant under the stricter policy, used past its end with the NA down: break-glass again.
      const short = await gm.grants.issueGrant({
        bearer_key_id: deviceId, capabilities: [capability], attestation_id: attestation.attestation_id,
        valid_until: new Date(Date.now() + 3_000), max_uses: 1,
        parameter_envelope: { lifetime_days: { number_range: { number_type: 'integer', minimum: 1, maximum: 20 } } },
      });
      const device2 = new GenesisMeshClient({ ...config, recordOutbox: new MemoryOutbox<RecordOutboxEntry>() });
      const second = new GrantHolder({ clients: device2, signer, naPublicKeys: [naPublicKey], grant: short.grant, timeToken: short.time_token });
      await new Promise(resolve => setTimeout(resolve, Math.max(0, Date.parse(short.grant.valid_until) - Date.now() + 500)));
      await control('stop');
      const expired = await second.act({ ...revokedRotate(10) }, async () => ({ execution_parameters: { version_id: 'v11' } })) as GrantFallbackResult<unknown>;
      expect(expired).toMatchObject({ path: 'break_glass', unusable: 'grant_expired', result: { brokeGlass: true, queued: { state: 'pending' } } });
      await control('start');
      const judged = (await second.sync()).flushed!;
      expect(judged.admitted.map(e => e.kind)).toEqual(['break_glass']);
      const kinds = (await gm.evidenceStore.resourceChanges(resource)).changes.map(c => [c.kind, c.governed_by]);
      expect(kinds).toEqual([
        ['grant_execution', 'grant'], ['grant_execution', 'grant'], ['break_glass', 'after_the_fact'], ['break_glass', 'after_the_fact'],
      ]);
      expect((deny.result as GovernedActionResult<unknown>).evaluation.decision.authorized).toBe(false);
    } finally {
      if (child.exitCode === null) child.stdin.write('start\n');
      await rm(dir, { recursive: true, force: true });
    }

    // The whole store verifies offline: grants, uses at the NA's resource positions, the revocation.
    const exported: EvidenceEvent[] = [];
    for await (const event of gm.evidenceStore.exportAll()) exported.push(event);
    const verification = verifyEvidenceEvents(exported, { naPublicKeys: [naPublicKey], executorKeys: await gm.evidenceStore.listExecutorKeys() });
    expect(verification.failures).toEqual([]);
    expect(verification.grants).toBeGreaterThanOrEqual(2);
    expect(verification.grant_executions).toBeGreaterThanOrEqual(2);
    expect(verification.grant_revocations).toBeGreaterThanOrEqual(1);
    if (config.audit && config.rootPublicKey) {
      // And so does an audit pack holding them: its report, its grants' policies and attestation.
      await gm.evidenceStore.anchor();
      const held = await gm.evidenceStore.allAnchors();
      const pack = await gm.evidenceStore.auditPack();
      const files = auditPackFiles(pack);
      expect(packReasons(verifyAuditPack(files, { rootPublicKey: config.rootPublicKey, heldAnchors: held }))).toEqual([]);
      expect(String(files['report.md'])).toContain('## Grants');
    }
  }, 120_000);
});
