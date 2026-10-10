import { randomUUID } from 'node:crypto';
/**
 * Controller-side composition for governed resource lifecycles (e.g. secrets):
 * decide, act only on ALLOW, record the outcome on the resource chain, and
 * compare cloud state with the NA's history.
 */

import type { BoundaryClient, EvaluateParams } from './boundary.js';
import type { EvidenceStoreClient, RecordSubmission, ResourceState } from './evidence_store.js';
import { GenesisMeshError, NetworkError } from './errors.js';
import {
  checkMetadataOnly, MAX_METADATA_BYTES, SecretMaterialError, type ExecutionRecorder, type PriorResource,
} from './execution.js';
import { OutOfBandRecordError, type BreakGlassRecord, type EvaluationFailure } from './out-of-band.js';
import type { Delivery, OutboxEntry, RecordOutboxEntry } from './outbox.js';
import { verifyBoundaryDecision, type VerifyDecisionOptions } from './verify.js';
import type {
  BoundaryDecision,
  BoundaryEvaluation,
  BoundaryPolicy,
  EvidenceSubmission,
  ExecutionEvidence,
  ExecutionOutcome,
  ResourceAction,
} from './types.js';

// ── Decision summary ──────────────────────────────────────────────────────────

export interface GateFailure {
  gate: string;
  detail: string;
}

export interface DecisionSummary {
  decision_id: string;
  authorized: boolean;
  denial_reason: string | null;
  /** Failed gates that deny the request: built-in, attestation, policy resolution and enforce-mode policy gates. */
  enforced_failures: GateFailure[];
  /** Observe-mode policy gates that failed: recorded, not enforced. Review before switching a policy to enforce. */
  observed_failures: GateFailure[];
  /** `<policy_id>@<version>` in resolution order. */
  applied_policies: string[];
  attestation_id: string | null;
}

const OBSERVE_PREFIX = '[observe] ';

/** What a decision means for a controller and a reviewer, in one object. */
export function summarizeDecision(decision: BoundaryDecision): DecisionSummary {
  const failed = decision.gate_results.filter(g => !g.passed);
  const toFailure = (g: { gate_name: string; detail: string }) => ({
    gate: g.gate_name,
    detail: g.detail.startsWith(OBSERVE_PREFIX) ? g.detail.slice(OBSERVE_PREFIX.length) : g.detail,
  });
  return {
    decision_id: decision.decision_id,
    authorized: decision.authorized,
    denial_reason: decision.denial_reason,
    enforced_failures: failed.filter(g => !g.detail.startsWith(OBSERVE_PREFIX)).map(toFailure),
    observed_failures: failed.filter(g => g.detail.startsWith(OBSERVE_PREFIX)).map(toFailure),
    applied_policies: (decision.policy_binding?.policies ?? []).map(p => `${p.policy_id}@${p.version}`),
    attestation_id: decision.attestation_binding?.attestation_id ?? null,
  };
}

// ── Governed action ───────────────────────────────────────────────────────────

/** What the action reports back for the evidence record. Identifiers and versions only. */
export interface ActionReport<T = unknown> {
  /** Returned to the caller; never recorded. */
  value?: T;
  /** Recorded in the evidence, e.g. `{ secret_version, vault_uri, expires_on }`. */
  execution_parameters?: Record<string, unknown>;
  /** Default "success". */
  outcome?: ExecutionOutcome;
  outcome_detail?: string | null;
}

export type GovernedActionParams = EvaluateParams & {
  /** Resource acted on, e.g. `kv:<vault>/<secret>`. */
  resource_id?: string;
  resource_action?: ResourceAction;
  /**
   * The resource's previous record. Omit to read the head from the NA; pass
   * null to assert the resource has no history.
   */
  prior_resource?: PriorResource | null;
  /** Verify the decision offline before acting (signature, expiry, bindings). */
  verify: Omit<VerifyDecisionOptions, 'now' | 'expectedPolicies'> & { expectedPolicies: readonly BoundaryPolicy[] };
  /**
   * v1.3.0: run the action even when the NA cannot be reached (network error,
   * timeout, `5xx`, `429`), and record it as a break-glass record signed by
   * the executor key, with this justification. Never on a DENY. Needs a
   * record outbox (`ClientOptions.recordOutbox`) and `resource_id`.
   */
  breakGlass?: BreakGlassOptions;
};

/** An action run with `breakGlass`: the decision is null when it ran under break-glass. */
export type BreakGlassAction<T> = (decision: BoundaryDecision | null) => Promise<ActionReport<T> | void>;

export interface BreakGlassOptions {
  /** Why the change cannot wait for the NA (1 to 1024 characters; no secret values). */
  justification: string;
}

/**
 * v1.3.0: the evaluation failed transiently, and the action ran under
 * break-glass. The NA judges the record after the fact, as the failed
 * evaluation would have gone.
 */
export interface BreakGlassResult<T> {
  brokeGlass: true;
  failure: EvaluationFailure;
  /** The evaluation's error. */
  evaluationError: unknown;
  value?: T;
  record: BreakGlassRecord;
  /** The NA's acknowledgement, when it was reachable again by then. */
  submission?: RecordSubmission;
  /** The record outbox entry holding the record otherwise. */
  queued?: RecordOutboxEntry;
  /** Reported metadata the secret guard refused, left out of the record. */
  dropped?: string[];
}

export interface GovernedActionResult<T> {
  evaluation: BoundaryEvaluation;
  authorized: boolean;
  summary: DecisionSummary;
  /** Present when the action ran. */
  value?: T;
  evidence?: ExecutionEvidence;
  /** The NA's acknowledgement of the evidence, when it admitted it. */
  submission?: EvidenceSubmission;
  /**
   * With an outbox (v1.2.0): the outbox entry holding the evidence when the
   * NA has not admitted it, `pending` for `flushPending` to submit or
   * `dead_letter` when it was refused. A failed submission then never throws.
   */
  queued?: OutboxEntry;
}

/**
 * The action failed, and recording the failure also failed. `cause` is the
 * action's error; `evidence` the signed failure record when it was signed
 * (v1.2.0).
 */
export class GovernedActionError extends GenesisMeshError {
  readonly evidenceError: unknown;
  readonly evidence?: ExecutionEvidence;

  constructor(cause: unknown, evidenceError: unknown, evidence?: ExecutionEvidence) {
    super(`action failed and its failure could not be recorded: ${String(evidenceError)}`, 'governed_action_unrecorded', 0);
    this.name = 'GovernedActionError';
    this.cause = cause;
    this.evidenceError = evidenceError;
    if (evidence) this.evidence = evidence;
  }
}

/**
 * With an outbox (v1.2.0): the action ran, but the secret guard refused
 * metadata it reported. The outcome was recorded without the refused fields
 * (`dropped`), as `evidence`; `submission` or `queued` say what became of it.
 * `cause` is the guard's `SecretMaterialError`. Do not rerun the action.
 */
export class MetadataRefusedError<T = unknown> extends GenesisMeshError {
  readonly value: T | undefined;
  readonly evidence: ExecutionEvidence;
  readonly submission?: EvidenceSubmission;
  readonly queued?: OutboxEntry;
  readonly dropped: string[];

  constructor(
    cause: SecretMaterialError, value: T | undefined, evidence: ExecutionEvidence, delivery: Delivery, dropped: string[],
  ) {
    super(`the action ran; its metadata was refused and recorded without ${dropped.join(', ')}: ${cause.message}`,
      'governed_action_metadata_refused', 0);
    this.name = 'MetadataRefusedError';
    this.cause = cause;
    this.value = value;
    this.evidence = evidence;
    if (delivery.submission) this.submission = delivery.submission;
    if (delivery.queued) this.queued = delivery.queued;
    this.dropped = dropped;
  }
}

/**
 * With an outbox (v1.2.0): the action ran, but its evidence could not be
 * signed or kept in the outbox. `evidence` is the signed record when signing succeeded: submit it
 * (resubmission is idempotent) once the outbox works. `cause` is the error.
 * Do not rerun the action.
 */
export class EvidenceNotKeptError<T = unknown> extends GenesisMeshError {
  readonly value: T | undefined;
  readonly evidence?: ExecutionEvidence;

  constructor(cause: unknown, value: T | undefined, evidence?: ExecutionEvidence) {
    super(`the action ran; its evidence was not kept: ${String(cause)}`, 'governed_action_evidence_unkept', 0);
    this.name = 'EvidenceNotKeptError';
    this.cause = cause;
    this.value = value;
    if (evidence) this.evidence = evidence;
  }
}

const GUARD_NOTE = 'secret guard dropped';
const NAMEABLE = /^[A-Za-z0-9_.-]{1,64}$/;

/** The note naming what the guard dropped: plain field names only, others counted. */
function guardNote(dropped: readonly string[]): string {
  const named = dropped.filter(d => NAMEABLE.test(d));
  const others = dropped.length - named.length;
  const parts = others ? [...named, `${others} other field${others === 1 ? '' : 's'}`] : named;
  return `[${GUARD_NOTE}: ${parts.join(', ')}]`;
}

/**
 * The reported metadata without the parts the secret guard refuses: each
 * top-level parameter is checked alone, and the outcome detail names what was
 * dropped. Everything is dropped when the rest is still refused (its size).
 */
export function withoutRefusedMetadata(
  executionParameters: Record<string, unknown>,
  outcomeDetail: string | null,
): { execution_parameters: Record<string, unknown>; outcome_detail: string; dropped: string[] } {
  let kept: Record<string, unknown> = {};
  let dropped: string[] = [];
  for (const [key, value] of Object.entries(executionParameters)) {
    if (checkMetadataOnly({ [key]: value }) === null) kept[key] = value;
    else dropped.push(key);
  }
  const detail = outcomeDetail !== null && checkMetadataOnly({}, outcomeDetail) === null ? outcomeDetail : null;
  if (outcomeDetail !== null && detail === null) dropped.push('outcome_detail');
  if (checkMetadataOnly(kept, detail) !== null) {
    dropped = [...Object.keys(executionParameters), ...(outcomeDetail !== null ? ['outcome_detail'] : [])];
    kept = {};
  }
  dropped.sort();
  const note = guardNote(dropped);
  const outcome_detail = detail !== null && !dropped.includes('outcome_detail') ? `${detail} ${note}` : note;
  if (checkMetadataOnly(kept, outcome_detail) !== null) {
    const all = [...Object.keys(executionParameters), ...(outcomeDetail !== null ? ['outcome_detail'] : [])].sort();
    return { execution_parameters: {}, outcome_detail: `[${GUARD_NOTE}]`, dropped: all };
  }
  return { execution_parameters: kept, outcome_detail, dropped };
}

/** The decision did not pass offline verification; the action was not run. */
export class DecisionVerificationError extends GenesisMeshError {
  constructor(reason: string) {
    super(`decision failed verification: ${reason}`, reason, 0);
    this.name = 'DecisionVerificationError';
  }
}

export interface GovernanceClients {
  boundary: BoundaryClient;
  evidenceStore: EvidenceStoreClient;
}

/**
 * Refusals that look transient but are not: the NA throttling a caller whose
 * operator signatures keep failing, and an evaluation the NA computed (perhaps
 * a DENY) but could not store. Neither breaks the glass.
 */
const NOT_BREAKABLE: ReadonlySet<string> = new Set([
  'admin_auth_throttled', 'evidence_store_unavailable',
  // The NA answered (its decision may be a DENY) but the response could not be read.
  'response_body_unreadable',
]);

/** The transient failure an evaluation error is, or null for any other error (a DENY is not an error). */
export function evaluationFailure(err: unknown): EvaluationFailure | null {
  if (err instanceof NetworkError) {
    if (NOT_BREAKABLE.has(err.code)) return null;
    return (err.cause as { name?: unknown } | undefined)?.name === 'TimeoutError' ? 'timeout' : 'network_error';
  }
  if (err instanceof GenesisMeshError && !NOT_BREAKABLE.has(err.code)) {
    if (err.status === 429) return 'rate_limited';
    if (err.status >= 500 && err.status < 600) return 'server_error';
  }
  return null;
}

/**
 * Evaluate, run `action` only on a (verified) ALLOW, then sign and submit the
 * execution evidence. A DENY returns `authorized: false` without running the
 * action. If the action throws, a `failure` record is submitted and the
 * error is rethrown.
 *
 * With an outbox (`ClientOptions.outbox`, v1.2.0) every record is kept until
 * the NA admits it, and a failed submission does not throw: the result's
 * `queued` is the outbox entry, which `evidenceStore.flushPending` submits
 * later. A resource with pending records chains from the newest of them, not
 * from the NA's head. A guard refusal after the action records the outcome
 * without the refused fields and throws `MetadataRefusedError`; a failure to
 * keep the record throws `EvidenceNotKeptError`. Both carry the action's value.
 */
export async function governedAction<T>(
  clients: GovernanceClients,
  recorder: ExecutionRecorder,
  params: GovernedActionParams & { breakGlass: BreakGlassOptions },
  action: (decision: BoundaryDecision | null) => Promise<ActionReport<T> | void>,
): Promise<GovernedActionResult<T> | BreakGlassResult<T>>;
export async function governedAction<T>(
  clients: GovernanceClients,
  recorder: ExecutionRecorder,
  params: GovernedActionParams,
  action: (decision: BoundaryDecision) => Promise<ActionReport<T> | void>,
): Promise<GovernedActionResult<T>>;
/**
 * With `breakGlass` (v1.3.0), an evaluation that fails transiently (network
 * error, timeout, `5xx`, `429`) runs the action anyway, with a null decision,
 * and records a break-glass record in the record outbox: the result is a
 * `BreakGlassResult` (`brokeGlass: true`). A DENY, a decision that fails
 * verification, or any other error never breaks the glass.
 */
export async function governedAction<T>(
  clients: GovernanceClients,
  recorder: ExecutionRecorder,
  params: GovernedActionParams,
  action: BreakGlassAction<T> | ((decision: BoundaryDecision) => Promise<ActionReport<T> | void>),
): Promise<GovernedActionResult<T> | BreakGlassResult<T>> {
  const { resource_id, resource_action, prior_resource, verify, breakGlass, ...evaluateParams } = params;
  if ((resource_id === undefined) !== (resource_action === undefined)) {
    throw new Error('resource_id and resource_action go together');
  }
  if (!verify?.operatorPublicKeys?.length) throw new DecisionVerificationError('verification_keys_required');
  const store = clients.evidenceStore;
  const outbox = store.outbox;
  // An outbox that cannot be read fails here, before anything is evaluated or run.
  if (outbox) await outbox.list();
  if (breakGlass) await checkBreakGlass(store, params, breakGlass);
  const contextId = params.context?.context_id || randomUUID();
  const request = { ...evaluateParams, context: { ...params.context, context_id: contextId } } as EvaluateParams;
  let evaluation: BoundaryEvaluation;
  try {
    evaluation = await clients.boundary.evaluate(request);
  } catch (err) {
    const failure = breakGlass ? evaluationFailure(err) : null;
    if (!failure) throw err;
    // Only the breakGlass overload gets here, whose action takes a null decision.
    return breakTheGlass(store, recorder, params, request, failure, err, action as BreakGlassAction<T>);
  }
  const decision = evaluation.decision;
  const checkDecision = () => {
    if (!Array.isArray(verify.expectedPolicies)) throw new DecisionVerificationError('policy_expectations_required');
    if (decision.authorized && params.attestation_id !== undefined && !verify.expectedAttestation) {
      throw new DecisionVerificationError('attestation_expectation_required');
    }
    const check = verifyBoundaryDecision(decision, { ...verify, now: new Date() });
    if (!check.accepted) throw new DecisionVerificationError(check.reason);
    if (decision.context_id !== contextId) throw new DecisionVerificationError('context_binding_mismatch');
    if (params.attestation_id !== undefined && decision.attestation_binding?.attestation_id !== params.attestation_id) {
      throw new DecisionVerificationError('attestation_binding_mismatch');
    }
    if (params.agreement && decision.agreement_id !== params.agreement.agreement_id) {
      throw new DecisionVerificationError('agreement_binding_mismatch');
    }
  };
  checkDecision();
  const summary = summarizeDecision(decision);
  if (!decision.authorized) return { evaluation, authorized: false, summary };

  const prior = resource_id === undefined
    ? null
    : prior_resource !== undefined
      ? prior_resource
      : (outbox ? await store.pendingHead(resource_id) : null) ?? await store.resourceHead(resource_id);
  // Reading history may outlast the decision's validity window.
  checkDecision();

  const record = (report: ActionReport<T>) => recorder.record({
    decision,
    executed_capability: params.requested_capability,
    outcome: report.outcome ?? 'success',
    execution_parameters: report.execution_parameters,
    outcome_detail: report.outcome_detail,
    resource_id,
    resource_action,
    prior_resource: prior,
  });

  let report: ActionReport<T>;
  try {
    report = (await action(decision)) ?? {};
  } catch (err) {
    let evidence: ExecutionEvidence | undefined;
    try {
      evidence = await record({ outcome: 'failure', outcome_detail: 'action failed' });
      await (outbox ? store.enqueue(evidence) : store.submit(evidence));
    } catch (evidenceError) {
      throw new GovernedActionError(err, evidenceError, evidence);
    }
    throw err;
  }

  if (!outbox) {
    const evidence = await record(report);
    const submission = await store.submit(evidence);
    return { evaluation, authorized: true, summary, value: report.value, evidence, submission };
  }

  // The action ran: from here on its outcome is always recorded.
  let evidence: ExecutionEvidence | undefined;
  let refused: { error: SecretMaterialError; dropped: string[] } | undefined;
  let delivery: Delivery;
  try {
    try {
      evidence = await record(report);
    } catch (err) {
      if (!(err instanceof SecretMaterialError)) throw err;
      const cleaned = withoutRefusedMetadata(report.execution_parameters ?? {}, report.outcome_detail ?? null);
      evidence = await record({ ...report, ...cleaned });
      refused = { error: err, dropped: cleaned.dropped };
    }
    delivery = await store.enqueue(evidence);
  } catch (err) {
    throw new EvidenceNotKeptError(err, report.value, evidence);
  }
  if (refused) throw new MetadataRefusedError(refused.error, report.value, evidence, delivery, refused.dropped);
  return { evaluation, authorized: true, summary, value: report.value, evidence, ...delivery };
}

/** Everything break-glass needs is checked before anything is evaluated or run. */
async function checkBreakGlass(
  store: EvidenceStoreClient,
  params: GovernedActionParams,
  options: BreakGlassOptions,
): Promise<void> {
  if (!store.recordOutbox) {
    throw new GenesisMeshError('breakGlass needs a record outbox (ClientOptions.recordOutbox)', 'record_outbox_required', 0);
  }
  if (params.resource_id === undefined) throw new Error('breakGlass needs resource_id and resource_action');
  // An agreement-based evaluation rests on the agreement, which a break-glass record does
  // not carry: the NA could not judge it after the fact.
  if (typeof params.attestation_id !== 'string' || !params.attestation_id) {
    throw new OutOfBandRecordError('breakGlass needs an attestation-based evaluation (attestation_id)',
      'break_glass_malformed');
  }
  if (typeof params.requested_capability !== 'string' || !params.requested_capability) {
    throw new OutOfBandRecordError('breakGlass needs requested_capability', 'break_glass_malformed');
  }
  const justification = options.justification;
  const length = typeof justification === 'string' ? Array.from(justification).length : 0;
  if (length < 1 || length > 1024) {
    throw new OutOfBandRecordError('a justification of 1 to 1024 characters is required', 'break_glass_malformed');
  }
  // Everything the record carries besides the action's report is checked now, with room left
  // for the report, so a record can always be kept once the action has run.
  const context = params.context ?? {};
  for (const name of ['request_parameters', 'attributes'] as const) {
    const value = context[name];
    if (value !== undefined && (typeof value !== 'object' || value === null || Array.isArray(value))) {
      throw new OutOfBandRecordError(`context.${name} must be an object`, 'break_glass_malformed');
    }
  }
  const carried = { request_parameters: context.request_parameters ?? {}, attributes: context.attributes ?? {} };
  const secret = checkMetadataOnly({ ...context }) ?? checkMetadataOnly({}, justification);
  if (secret) throw new OutOfBandRecordError(secret, 'break_glass_secret_material');
  if (Buffer.byteLength(JSON.stringify({ ...carried, justification }), 'utf-8') > MAX_METADATA_BYTES - RECORD_RESERVE) {
    throw new OutOfBandRecordError(`the context and justification leave no room for the record within `
      + `${MAX_METADATA_BYTES} bytes`, 'break_glass_malformed');
  }
  await store.recordOutbox.list();
}

/** Room kept for the action's report within the metadata limit of a break-glass record. */
const RECORD_RESERVE = 2048;
/** The longest outcome detail a break-glass record carries (the reference's limit). */
const MAX_OUTCOME_DETAIL = 1024;

function clip(text: string | null | undefined, max: number): string | undefined {
  if (text === null || text === undefined) return undefined;
  const chars = Array.from(text);
  return chars.length > max ? chars.slice(0, max - 1).join('') + '…' : text;
}

/** Run the action without a decision and keep its break-glass record. */
async function breakTheGlass<T>(
  store: EvidenceStoreClient,
  recorder: ExecutionRecorder,
  params: GovernedActionParams,
  request: EvaluateParams,
  failure: EvaluationFailure,
  evaluationError: unknown,
  action: BreakGlassAction<T>,
): Promise<BreakGlassResult<T>> {
  const sign = (report: ActionReport<T>) => recorder.signBreakGlass({
    resource_id: params.resource_id!,
    resource_action: params.resource_action!,
    capability: params.requested_capability,
    attestation_id: params.attestation_id,
    request_parameters: params.context?.request_parameters,
    attributes: params.context?.attributes,
    justification: params.breakGlass!.justification,
    evaluation_request: request,
    evaluation_failure: failure,
    outcome: report.outcome ?? 'success',
    outcome_detail: clip(report.outcome_detail, MAX_OUTCOME_DETAIL),
    execution_parameters: report.execution_parameters,
  });

  let report: ActionReport<T>;
  try {
    report = (await action(null)) ?? {};
  } catch (err) {
    try {
      await store.enqueueRecord(await sign({ outcome: 'failure', outcome_detail: 'action failed' }));
    } catch (recordError) {
      throw new GovernedActionError(err, recordError);
    }
    throw err;
  }

  // The action ran: from here on its outcome is always recorded.
  let record: BreakGlassRecord | undefined;
  let dropped: string[] | undefined;
  let delivery: { submission?: RecordSubmission; queued?: RecordOutboxEntry };
  try {
    try {
      record = await sign(report);
    } catch (err) {
      if (!(err instanceof OutOfBandRecordError) || err.code !== 'break_glass_secret_material') throw err;
      const cleaned = withoutRefusedMetadata(report.execution_parameters ?? {}, report.outcome_detail ?? null);
      try {
        record = await sign({ ...report, ...cleaned });
        dropped = cleaned.dropped;
      } catch (again) {
        if (!(again instanceof OutOfBandRecordError) || again.code !== 'break_glass_secret_material') throw again;
        // The report together with the context is still refused (its size): keep the outcome alone.
        const all = [...Object.keys(report.execution_parameters ?? {}),
          ...(report.outcome_detail != null ? ['outcome_detail'] : [])].sort();
        record = await sign({ ...report, execution_parameters: {}, outcome_detail: '[secret guard dropped the report]' });
        dropped = all;
      }
    }
    delivery = await store.enqueueRecord(record);
  } catch (err) {
    throw new EvidenceNotKeptError(err, report.value);
  }
  return {
    brokeGlass: true, failure, evaluationError, value: report.value, record, ...delivery, ...(dropped ? { dropped } : {}),
  };
}

// ── Reconciliation ────────────────────────────────────────────────────────────

/** One resource as seen in the cloud (Key Vault, Entra, Secret Manager, ...). */
export interface ObservedResource {
  resource_id: string;
  /** False when the resource was looked up and is gone. */
  exists: boolean;
  /** The version seen in the cloud, compared with the recorded version parameter. */
  version?: string;
  /** Anything the controller wants back with the finding (never secret values). */
  metadata?: Record<string, unknown>;
}

export type ReconciliationStatus =
  /** Exists in the cloud with no governed history. */
  | 'unmanaged'
  /** The cloud version differs from the last governed change. */
  | 'drifted'
  /** Still present after a governed revoke or delete. */
  | 'present_after_revoke'
  /** Governed as live, but missing from the cloud. */
  | 'missing'
  /** Matches the last governed change. */
  | 'in_sync';

export interface ReconciliationFinding {
  resource_id: string;
  status: ReconciliationStatus;
  observed: ObservedResource | null;
  recorded: ResourceState | null;
  detail: string;
}

export interface ReconcileOptions {
  /** execution_parameters key holding the version the controller recorded. Default "secret_version". */
  versionKey?: string;
  /**
   * The inventory covers every governed resource in scope, so a governed live
   * resource absent from it is `missing`. Default false.
   */
  completeInventory?: boolean;
  /** Restrict `missing` checks to recorded resources with this prefix (e.g. `kv:<vault>/`). */
  scopePrefix?: string;
}

const TERMINAL_ACTIONS = new Set(['revoke', 'delete']);

/**
 * Compare a cloud inventory with the NA's governed history. Pure: the caller
 * supplies both sides (see `EvidenceStoreClient.resourceStates`). Remediation
 * of every finding should go back through `governedAction`.
 */
export function reconcileResources(
  observed: readonly ObservedResource[],
  recorded: ReadonlyMap<string, ResourceState>,
  options: ReconcileOptions = {},
): ReconciliationFinding[] {
  const versionKey = options.versionKey ?? 'secret_version';
  const findings: ReconciliationFinding[] = [];
  const seen = new Set<string>();

  for (const item of observed) {
    seen.add(item.resource_id);
    const state = recorded.get(item.resource_id) ?? null;
    const finding = (status: ReconciliationStatus, detail: string) =>
      findings.push({ resource_id: item.resource_id, status, observed: item, recorded: state, detail });
    const live = state?.last_success_action != null && !TERMINAL_ACTIONS.has(state.last_success_action);

    if (!item.exists) {
      if (live) finding('missing', `governed as ${state!.last_success_action}, not found in the cloud`);
      else finding('in_sync', state ? 'absent, as governed' : 'absent and never governed');
      continue;
    }
    if (!state || state.last_success_action === null) {
      finding('unmanaged', 'exists with no successful governed change');
      continue;
    }
    if (!live) {
      finding('present_after_revoke', `still present after governed ${state.last_success_action}`);
      continue;
    }
    const recordedVersion = state.last_success_parameters?.[versionKey];
    if (item.version !== undefined && recordedVersion !== undefined && String(recordedVersion) !== item.version) {
      finding('drifted', `cloud version ${item.version}, governed version ${String(recordedVersion)}`);
      continue;
    }
    finding('in_sync', `matches governed ${state.last_success_action}`);
  }

  if (options.completeInventory) {
    for (const state of recorded.values()) {
      if (seen.has(state.resource_id)) continue;
      if (options.scopePrefix && !state.resource_id.startsWith(options.scopePrefix)) continue;
      if (state.last_success_action != null && !TERMINAL_ACTIONS.has(state.last_success_action)) {
        findings.push({
          resource_id: state.resource_id,
          status: 'missing',
          observed: null,
          recorded: state,
          detail: `governed as ${state.last_success_action}, absent from the inventory`,
        });
      }
    }
  }
  return findings;
}
