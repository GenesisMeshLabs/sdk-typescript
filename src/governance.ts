import { randomUUID } from 'node:crypto';
/**
 * Controller-side composition for governed resource lifecycles (e.g. secrets):
 * decide, act only on ALLOW, record the outcome on the resource chain, and
 * compare cloud state with the NA's history.
 */

import type { BoundaryClient, EvaluateParams } from './boundary.js';
import type { EvidenceStoreClient, ResourceState } from './evidence_store.js';
import { GenesisMeshError } from './errors.js';
import type { ExecutionRecorder, PriorResource } from './execution.js';
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
  submission?: EvidenceSubmission;
}

/** The action failed, and recording the failure also failed. `cause` is the action's error. */
export class GovernedActionError extends GenesisMeshError {
  readonly evidenceError: unknown;

  constructor(cause: unknown, evidenceError: unknown) {
    super(`action failed and its failure could not be recorded: ${String(evidenceError)}`, 'governed_action_unrecorded', 0);
    this.name = 'GovernedActionError';
    this.cause = cause;
    this.evidenceError = evidenceError;
  }
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
    : prior_resource !== undefined ? prior_resource : await clients.evidenceStore.resourceHead(resource_id);
  // Reading history may outlast the decision's validity window.
  checkDecision();

  const recordAndSubmit = async (report: ActionReport<T>) => {
    const evidence = await recorder.record({
      decision,
      executed_capability: params.requested_capability,
      outcome: report.outcome ?? 'success',
      execution_parameters: report.execution_parameters,
      outcome_detail: report.outcome_detail,
      resource_id,
      resource_action,
      prior_resource: prior,
    });
    const submission = await clients.evidenceStore.submit(evidence);
    return { evidence, submission };
  };

  let report: ActionReport<T>;
  try {
    report = (await action(decision)) ?? {};
  } catch (err) {
    try {
      await recordAndSubmit({ outcome: 'failure', outcome_detail: 'action failed' });
    } catch (evidenceError) {
      throw new GovernedActionError(err, evidenceError);
    }
    throw err;
  }
  const { evidence, submission } = await recordAndSubmit(report);
  return { evaluation, authorized: true, summary, value: report.value, evidence, submission };
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
