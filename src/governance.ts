import { randomUUID } from 'node:crypto';
/**
 * Controller-side composition for governed resource lifecycles (e.g. secrets):
 * decide, act only on ALLOW, record the outcome on the resource chain, and
 * compare cloud state with the NA's history.
 */

import type { BoundaryClient, EvaluateParams } from './boundary.js';
import type { EvidenceStoreClient, ResourceState } from './evidence_store.js';
import { GenesisMeshError } from './errors.js';
import { checkMetadataOnly, SecretMaterialError, type ExecutionRecorder, type PriorResource } from './execution.js';
import type { Delivery, OutboxEntry } from './outbox.js';
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
};

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
  params: GovernedActionParams,
  action: (decision: BoundaryDecision) => Promise<ActionReport<T> | void>,
): Promise<GovernedActionResult<T>> {
  const { resource_id, resource_action, prior_resource, verify, ...evaluateParams } = params;
  if ((resource_id === undefined) !== (resource_action === undefined)) {
    throw new Error('resource_id and resource_action go together');
  }
  if (!verify?.operatorPublicKeys?.length) throw new DecisionVerificationError('verification_keys_required');
  const store = clients.evidenceStore;
  const outbox = store.outbox;
  // An outbox that cannot be read fails here, before anything is evaluated or run.
  if (outbox) await outbox.list();
  const contextId = params.context?.context_id || randomUUID();
  const evaluation = await clients.boundary.evaluate({
    ...evaluateParams, context: { ...params.context, context_id: contextId },
  } as EvaluateParams);
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
