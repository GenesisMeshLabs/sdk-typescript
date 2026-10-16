import { randomUUID } from 'node:crypto';
/**
 * Controller-side composition for governed resource lifecycles (e.g. secrets):
 * decide, act only on ALLOW, record the outcome on the resource chain, and
 * compare cloud state with the NA's history.
 */

import { canonicalJson, checkSignable } from './auth.js';
import type { BoundaryClient, EvaluateParams } from './boundary.js';
import type { EvidenceStoreClient, RecordSubmission } from './evidence_store.js';
import { GenesisMeshError, NetworkError } from './errors.js';
import {
  checkMetadataOnly, MAX_METADATA_BYTES, SecretMaterialError, type ExecutionRecorder, type PriorResource,
} from './execution.js';
import {
  breakGlassRecord, checkBreakGlassRecord, OutOfBandRecordError, type BreakGlassRecord, type EvaluationFailure,
} from './out-of-band.js';
import { StrictJsonError } from './strict-json.js';
import {
  checkRemediationRecord, nextState, remediationRecord, remediationSecretProblem, remediationSubject, stepsProblem,
  type RemediationInput, type RemediationRecord, type RemediationStatus,
} from './remediation.js';
import type { Delivery, OutboxEntry, RecordOutboxEntry } from './outbox.js';
import { naKeysAt } from './key-history.js';
import { verifyBoundaryDecision, type VerifyDecisionOptions } from './verify.js';
import type {
  BoundaryDecision,
  BoundaryEvaluation,
  BoundaryPolicy,
  EvidenceSubmission,
  ExecutionEvidence,
  ExecutionOutcome,
  ObservedResource,
  ReconciliationFinding,
  ReconciliationStatus,
  ResourceAction,
  ResourceState,
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
 * `cause` is the guard's `SecretMaterialError`, or (1.3.1) a `StrictJsonError`
 * for a value the NA would not read alike (a lone surrogate, an integer
 * beyond 64 bits, nesting too deep). Do not rerun the action.
 */
export class MetadataRefusedError<T = unknown> extends GenesisMeshError {
  readonly value: T | undefined;
  readonly evidence: ExecutionEvidence;
  readonly submission?: EvidenceSubmission;
  readonly queued?: OutboxEntry;
  readonly dropped: string[];

  constructor(
    cause: SecretMaterialError | StrictJsonError, value: T | undefined, evidence: ExecutionEvidence, delivery: Delivery,
    dropped: string[],
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
 * True when reported metadata cannot be recorded: the secret guard refuses
 * it, or (1.3.1) it is JSON the NA would not read alike (`StrictJsonError`).
 */
function unrecordable(executionParameters: Record<string, unknown>, outcomeDetail: string | null): boolean {
  if (checkMetadataOnly(executionParameters, outcomeDetail) !== null) return true;
  try {
    // As deep as a record holds them.
    checkSignable({ execution_parameters: executionParameters, outcome_detail: outcomeDetail });
    return false;
  } catch {
    return true;
  }
}

/**
 * The reported metadata without the parts the secret guard refuses, or
 * (1.3.1) that are JSON the NA would not read alike: each top-level parameter
 * is checked alone, and the outcome detail names what was dropped. Everything
 * is dropped when the rest is still refused (its size).
 */
export function withoutRefusedMetadata(
  executionParameters: Record<string, unknown>,
  outcomeDetail: string | null,
): { execution_parameters: Record<string, unknown>; outcome_detail: string; dropped: string[] } {
  let kept: Record<string, unknown> = {};
  let dropped: string[] = [];
  for (const [key, value] of Object.entries(executionParameters)) {
    if (!unrecordable({ [key]: value }, null)) kept[key] = value;
    else dropped.push(key);
  }
  const detail = outcomeDetail !== null && !unrecordable({}, outcomeDetail) ? outcomeDetail : null;
  if (outcomeDetail !== null && detail === null) dropped.push('outcome_detail');
  if (unrecordable(kept, detail)) {
    dropped = [...Object.keys(executionParameters), ...(outcomeDetail !== null ? ['outcome_detail'] : [])];
    kept = {};
  }
  dropped.sort();
  const note = guardNote(dropped);
  const outcome_detail = detail !== null && !dropped.includes('outcome_detail') ? `${detail} ${note}` : note;
  if (unrecordable(kept, outcome_detail)) {
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

/**
 * The transient failure an evaluation error is, or null for any other error
 * (a DENY is not an error). A request that got no answer is a network error
 * or a timeout; an answer is one only when it is a `5xx` or `429`. Since
 * 1.3.1 that holds for the NA public key lookup before the request too: its
 * `403` or `404` (`na_public_key_unavailable`) keeps its status.
 */
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
  if (!verify?.operatorPublicKeys || naKeysAt(verify.operatorPublicKeys, null).length === 0) {
    throw new DecisionVerificationError('verification_keys_required');
  }
  const store = clients.evidenceStore;
  const outbox = store.outbox;
  // An outbox that cannot be read fails here, before anything is evaluated or run.
  if (outbox) await outbox.list();
  if (breakGlass) await checkBreakGlass(store, recorder, params, breakGlass);
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
  let refused: { error: SecretMaterialError | StrictJsonError; dropped: string[] } | undefined;
  let delivery: Delivery;
  try {
    try {
      evidence = await record(report);
    } catch (err) {
      if (!(err instanceof SecretMaterialError) && !(err instanceof StrictJsonError)) throw err;
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
  recorder: ExecutionRecorder,
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
  // Everything the record carries besides the action's report is checked now, with room left
  // for the report, so a record can always be kept once the action has run.
  const context = params.context ?? {};
  for (const name of ['request_parameters', 'attributes'] as const) {
    const value = context[name];
    if (value !== undefined && (typeof value !== 'object' || value === null || Array.isArray(value))) {
      throw new OutOfBandRecordError(`context.${name} must be an object`, 'break_glass_malformed');
    }
  }
  const secret = checkMetadataOnly({ ...context });
  if (secret) throw new OutOfBandRecordError(secret, 'break_glass_secret_material');
  // 1.3.1: the record as it will be signed, with an empty report, passes the checks `signBreakGlass`
  // makes (the reference's), with room left for the report as the reference sizes it.
  const record = breakGlassRecord({
    executor_sovereign_id: recorder.executorSovereignId, resource_id: params.resource_id,
    resource_action: params.resource_action!, capability: params.requested_capability,
    attestation_id: params.attestation_id, request_parameters: context.request_parameters,
    attributes: context.attributes, justification, evaluation_request: {}, evaluation_failure: 'network_error',
    outcome: 'success',
  });
  checkBreakGlassRecord(record);
  const carried = {
    execution_parameters: {}, request_parameters: record.request_parameters, attributes: record.attributes,
    outcome_detail: '', justification,
  };
  if (canonicalJson(carried).length > MAX_METADATA_BYTES - RECORD_RESERVE) {
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
  // What the report can be recorded without: secret material, or (1.3.1) JSON the NA would not read alike.
  const refusedReport = (err: unknown) => err instanceof StrictJsonError
    || (err instanceof OutOfBandRecordError && err.code === 'break_glass_secret_material');
  try {
    try {
      record = await sign(report);
    } catch (err) {
      if (!refusedReport(err)) throw err;
      const cleaned = withoutRefusedMetadata(report.execution_parameters ?? {}, report.outcome_detail ?? null);
      try {
        record = await sign({ ...report, ...cleaned });
        dropped = cleaned.dropped;
      } catch (again) {
        if (!refusedReport(again)) throw again;
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

// ── Remediation: the cancel pair (v1.4.0) ─────────────────────────────────────

/** The version a forward rotation issued. */
export interface RotatedVersion<T = unknown> {
  /** Recorded as the rotation evidence's `execution_parameters.version_id`, as the NA checks it. */
  version_id: string;
  /** Returned to the caller; never recorded. */
  value?: T;
  /** Other metadata for the rotation's evidence (identifiers and versions only). */
  execution_parameters?: Record<string, unknown>;
}

export interface RotateForwardOptions<T = unknown> {
  /**
   * The remediation state from the due queue (`remediation_due` or
   * `overdue`): its subject, change and resource name the record. When it
   * carries `state`, `mode` and `steps`, they are checked before anything
   * runs: a remediation is recorded only from `remediation_due` or `overdue`
   * (a pending review does not stop it), and the plan must be `cancel` /
   * `rotate_forward_then_disable`.
   */
  remediation: Pick<RemediationStatus, 'subject_kind' | 'subject_id' | 'change_kind' | 'change_id' | 'resource_id'>
    & Partial<Pick<RemediationStatus, 'state' | 'review_pending' | 'mode' | 'steps' | 'fallback'>>;
  /** The denied version: disabled once readers have the new one. */
  deniedVersionId: string;
  /**
   * The governed rotation's evaluation and verification (capability,
   * attestation, context, `verify`), as for `governedAction`; the resource is
   * the remediation's. Not break-glass: the rotation needs a decision.
   */
  rotation: Omit<GovernedActionParams, 'resource_id' | 'resource_action' | 'breakGlass'> & {
    /** Default `rotate`. */
    resource_action?: 'rotate' | 'update';
  };
  /** Issue a new version and move the resource's readers to it (make it current); return its version ID. */
  rotate: (decision: BoundaryDecision) => Promise<RotatedVersion<T>>;
  /** Disable the denied version, once the readers have the new one. */
  disable: (deniedVersionId: string) => Promise<void>;
  /** A note for the remediation record (no secret material). */
  detail?: string;
}

export interface RotateForwardResult<T = unknown> {
  /** The governed rotation. When it was denied (`authorized: false`), nothing was rotated, disabled or recorded. */
  rotation: GovernedActionResult<T>;
  /** The signed remediation record, once the denied version was disabled. */
  remediation?: RemediationRecord;
  /** The NA's acknowledgement, when it admitted the record. */
  submission?: RecordSubmission;
  /** With a record outbox: the entry holding the record otherwise (`pending` or `dead_letter`). */
  queued?: RecordOutboxEntry;
}

/**
 * The forward rotation ran, but the remediation was not recorded: the record
 * could not be built (`remediation_malformed`, `remediation_secret_material`:
 * nothing was disabled), the disable failed, or the record could not be
 * signed, submitted or kept. `rotation` is the rotation's result; `record`
 * the signed record when there is one (submit it once the cause is fixed;
 * resubmission is idempotent). Do not rotate again.
 */
export class RemediationNotRecordedError<T = unknown> extends GenesisMeshError {
  readonly rotation: GovernedActionResult<T>;
  readonly record?: RemediationRecord;

  constructor(cause: unknown, rotation: GovernedActionResult<T>, record?: RemediationRecord) {
    super(`the forward rotation ran; the remediation was not recorded: ${String(cause)}`, 'remediation_not_recorded', 0);
    this.name = 'RemediationNotRecordedError';
    this.cause = cause;
    this.rotation = rotation;
    if (record) this.record = record;
  }
}

/**
 * Cancel a denied change to a versioned resource others read (v1.4.0), as
 * the NA states it (`rotate_forward_then_disable`): the two linked records.
 *
 * 1. A governed rotation (`governedAction`) issues a new version under a
 *    decision of its own; its execution evidence names the version
 *    (`execution_parameters.version_id`), so observers match it instead of
 *    judging it again. A DENY returns without changing anything.
 * 2. `disable` then disables the denied version: the readers already have
 *    the new one.
 * 3. The remediation record names the rotation's evidence, the new version
 *    and the disabled one, signed by the executor key and kept in the record
 *    outbox (submitted directly without one).
 *
 * A credential is never rolled back. The record is checked before the
 * denied version is disabled, so a record the NA would refuse never follows
 * a disable. The NA admits the record once it holds the rotation's evidence
 * (`remediation_rotation_missing` is retried); flush the evidence outbox
 * before the record outbox.
 */
export async function cancelByRotatingForward<T>(
  clients: GovernanceClients,
  recorder: ExecutionRecorder,
  options: RotateForwardOptions<T>,
): Promise<RotateForwardResult<T>> {
  const state = options.remediation;
  const subject = remediationSubject(state);
  if (state.mode !== undefined && state.steps !== undefined) {
    const problem = stepsProblem(state.mode, state.steps, { outcome: 'cancelled', steps: 'rotate_forward_then_disable' });
    if (problem) throw new OutOfBandRecordError(problem, 'remediation_steps_mismatch');
  }
  if (state.state !== undefined) nextState(state.state, 'record_remediation', state.review_pending ?? false);
  if (typeof options.deniedVersionId !== 'string' || !options.deniedVersionId) {
    throw new OutOfBandRecordError('the denied version is required', 'remediation_malformed');
  }
  const secret = remediationSecretProblem({ disabled_version_id: options.deniedVersionId, detail: options.detail });
  if (secret) throw new OutOfBandRecordError(secret, 'remediation_secret_material');
  // A record outbox that cannot be read fails here, before anything runs.
  if (clients.evidenceStore.recordOutbox) await clients.evidenceStore.recordOutbox.list();

  let rotated: RotatedVersion<T> | undefined;
  const { resource_action = 'rotate', ...rotation } = options.rotation;
  const result = await governedAction(clients, recorder, {
    ...rotation, resource_id: subject.resource_id, resource_action,
  } as GovernedActionParams, async (decision: BoundaryDecision) => {
    rotated = await options.rotate(decision);
    return {
      value: rotated.value,
      execution_parameters: { ...rotated.execution_parameters, version_id: rotated.version_id },
    };
  });
  if (!result.authorized) return { rotation: result };

  const input: RemediationInput = {
    ...subject, steps: 'rotate_forward_then_disable', rotation_evidence_id: result.evidence!.evidence_id,
    version_id: rotated!.version_id, disabled_version_id: options.deniedVersionId,
    ...(options.detail !== undefined ? { detail: options.detail } : {}),
  };
  try {
    checkRemediationRecord(remediationRecord({ ...input, executor_sovereign_id: recorder.executorSovereignId }));
  } catch (err) {
    throw new RemediationNotRecordedError(err, result);
  }
  let record: RemediationRecord | undefined;
  try {
    await options.disable(options.deniedVersionId);
    record = await recorder.signRemediation(input);
    const store = clients.evidenceStore;
    if (store.recordOutbox) return { rotation: result, remediation: record, ...await store.enqueueRecord(record) };
    return { rotation: result, remediation: record, submission: await store.submitRemediation(record) };
  } catch (err) {
    throw new RemediationNotRecordedError(err, result, record);
  }
}

// ── Urgent changes (v1.4.0) ───────────────────────────────────────────────────

export interface EmergencyOptions {
  /** The emergency capability: the one capability a policy with an `emergency` section selects. */
  capability: string;
  /**
   * Why the change cannot wait (1 to 1024 characters; no secret values): the
   * emergency policy's justification parameter, and a break-glass record's
   * justification.
   */
  justification: string;
  /** The emergency policy's `justification_parameter`. Default `justification`. */
  justificationParameter?: string;
  /** The policies the emergency capability's decision must bind (`verify.expectedPolicies` for it). */
  expectedPolicies: readonly BoundaryPolicy[];
}

export interface UrgentActionResult<T> {
  /**
   * How the change went: under the ordinary capability's ALLOW (`ordinary`),
   * under the emergency capability's decision (`emergency`; `authorized`
   * false when that is a DENY too), or under break-glass naming the
   * emergency capability, the NA not answering (`break_glass`).
   */
  path: 'ordinary' | 'emergency' | 'break_glass';
  result: GovernedActionResult<T> | BreakGlassResult<T>;
  /** The ordinary capability's DENY, when the emergency capability was requested after it. */
  ordinaryDenial?: GovernedActionResult<T>;
}

/**
 * An urgent change (v1.4.0): never blocked, always governed and judged.
 *
 * - The ordinary capability is evaluated first (`params`), as
 *   `governedAction` does; an ALLOW runs the action under it.
 * - On a DENY, the emergency capability is requested, with the justification
 *   in its justification parameter; the NA decides under the emergency
 *   policy before the change, and reviews it after.
 * - When the NA cannot be reached, times out or answers `5xx` or `429`, the
 *   action runs under break-glass naming the emergency capability (with the
 *   justification parameter in its request parameters), and the NA judges it
 *   under the emergency policy once it is back.
 *
 * Break-glass needs a record outbox, an attestation-based evaluation and
 * `resource_id`; all of it is checked before anything is evaluated. The
 * emergency capability's own decision is verified against
 * `emergency.expectedPolicies`.
 */
export async function urgentAction<T>(
  clients: GovernanceClients,
  recorder: ExecutionRecorder,
  params: GovernedActionParams & { emergency: EmergencyOptions },
  action: BreakGlassAction<T>,
): Promise<UrgentActionResult<T>> {
  const { emergency, breakGlass: _ignored, ...ordinary } = params;
  const parameter = emergency.justificationParameter ?? 'justification';
  const urgent: GovernedActionParams & { breakGlass: BreakGlassOptions } = {
    ...ordinary,
    requested_capability: emergency.capability,
    context: {
      ...ordinary.context,
      request_parameters: { ...ordinary.context?.request_parameters, [parameter]: emergency.justification },
    },
    verify: { ...ordinary.verify, expectedPolicies: emergency.expectedPolicies },
    breakGlass: { justification: emergency.justification },
  };
  await checkBreakGlass(clients.evidenceStore, recorder, urgent, urgent.breakGlass);

  // Only an evaluation that got no answer, or a 5xx or 429, goes to break-glass; any other error
  // (after the action ran, or a decision that fails verification) is the caller's.
  let evaluationError: unknown;
  const boundary = {
    evaluate: (request: EvaluateParams) => clients.boundary.evaluate(request).catch((err: unknown) => {
      evaluationError = err;
      throw err;
    }),
  } as unknown as BoundaryClient;
  let ordinaryDenial: GovernedActionResult<T> | undefined;
  try {
    const result = await governedAction({ boundary, evidenceStore: clients.evidenceStore }, recorder, ordinary,
      action as (decision: BoundaryDecision) => Promise<ActionReport<T> | void>);
    if (result.authorized) return { path: 'ordinary', result };
    ordinaryDenial = result;
  } catch (err) {
    if (err !== evaluationError || evaluationFailure(err) === null) throw err;
  }
  const result = await governedAction(clients, recorder, urgent, action);
  return {
    path: 'brokeGlass' in result ? 'break_glass' : 'emergency', result, ...(ordinaryDenial ? { ordinaryDenial } : {}),
  };
}

// ── Reconciliation ────────────────────────────────────────────────────────────

export type { ObservedResource, ReconciliationFinding, ReconciliationStatus } from './types.js';

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
