/**
 * Execution evidence: build and sign records exactly as the Python reference
 * `record_execution` does, and refuse secret material before anything is signed.
 */

import { signBreakGlass, type BreakGlassInput, type BreakGlassRecord } from './out-of-band.js';
import { signRemediation, type RemediationInput, type RemediationRecord } from './remediation.js';
import { randomUUID } from 'node:crypto';
import { checkSignable, pythonTimestamp, signCanonical, type Signer } from './auth.js';
import { executionCanonical, executionDigest } from './canonical.js';
import { checkMetadataOnly, SecretMaterialError } from './metadata.js';
import type {
  BoundaryDecision,
  ExecutionEvidence,
  ExecutionOutcome,
  ResourceAction,
  ResourceHead,
} from './types.js';

export { checkMetadataOnly, MAX_METADATA_BYTES, SecretMaterialError, secretMaterial } from './metadata.js';

/** The previous record of a resource: the record itself, or its head (e.g. from a retention checkpoint). */
export type PriorResource = ExecutionEvidence | ResourceHead;

function resourceHeadOf(prior: PriorResource): ResourceHead {
  if ('record_digest' in prior) return prior;
  return { resource_sequence: prior.resource_sequence ?? 0, record_digest: executionDigest(prior) };
}

export interface RecordExecutionParams {
  /** The decision that authorized this execution. */
  decision: Pick<BoundaryDecision, 'decision_id' | 'context_id' | 'agreement_id'> &
    Partial<Pick<BoundaryDecision, 'decision_made_at'>>;
  executed_capability: string;
  outcome: ExecutionOutcome;
  execution_parameters?: Record<string, unknown>;
  outcome_detail?: string | null;
  /** Previous record under the same decision (sets sequence_no and prev_evidence_digest). */
  prior_record?: ExecutionEvidence | null;
  /** Resource acted on, e.g. `kv:<vault>/<secret>`. An identifier, never a value. */
  resource_id?: string;
  resource_action?: ResourceAction;
  /** Previous record for the same resource, from any decision; null or absent for its first record. */
  prior_resource?: PriorResource | null;
  executed_at?: Date;
  evidence_id?: string;
}

export interface ExecutionRecorderOptions {
  /** Sovereign performing the execution; must match the registered executor key. */
  executorSovereignId: string;
  /** Executor signer; its keyId must be registered with the NA. */
  signer: Signer;
}

/**
 * Now, but never before the decision (1.1.0). The NA refuses evidence stamped
 * before `decision_made_at`, which it writes in microseconds while `Date` has
 * milliseconds: evidence recorded in the decision's millisecond came out up
 * to a millisecond early, and so did evidence from a host whose clock is
 * behind the NA's. The decision time is rounded up to the next millisecond.
 */
function notBeforeDecision(decisionMadeAt: string | undefined): Date {
  const now = Date.now();
  if (decisionMadeAt === undefined) return new Date(now);
  const decided = Date.parse(decisionMadeAt);
  if (Number.isNaN(decided)) return new Date(now);
  const fraction = /\.(\d+)/.exec(decisionMadeAt)?.[1] ?? '';
  const subMillisecond = /[1-9]/.test(fraction.slice(3));
  return new Date(Math.max(now, subMillisecond ? decided + 1 : decided));
}

/** Builds and signs ExecutionEvidence for one executor. */
export class ExecutionRecorder {
  readonly executorSovereignId: string;
  private readonly signer: Signer;

  constructor(options: ExecutionRecorderOptions) {
    this.executorSovereignId = options.executorSovereignId;
    this.signer = options.signer;
  }

  get keyId(): string {
    return this.signer.keyId;
  }

  /**
   * Sign a break-glass record with this executor's key (v1.3.0).
   * `governedAction` with `breakGlass` calls it when evaluation fails
   * transiently.
   */
  signBreakGlass(input: Omit<BreakGlassInput, 'executor_sovereign_id'>): Promise<BreakGlassRecord> {
    return signBreakGlass({ ...input, executor_sovereign_id: this.executorSovereignId }, this.signer);
  }

  /**
   * Sign a remediation record with this executor's key (v1.4.0): what the
   * controller did about a judged change. Refused before signing as the NA
   * would refuse it (`remediation_malformed`, `remediation_secret_material`,
   * `StrictJsonError`). See `cancelByRotatingForward` for the cancel pair.
   */
  signRemediation(input: RemediationInput): Promise<RemediationRecord> {
    return signRemediation({ ...input, executor_sovereign_id: this.executorSovereignId }, this.signer);
  }

  async record(params: RecordExecutionParams): Promise<ExecutionEvidence> {
    if ((params.resource_id === undefined) !== (params.resource_action === undefined)) {
      throw new Error('resource_id and resource_action go together');
    }
    const execution_parameters = params.execution_parameters ?? {};
    const outcome_detail = params.outcome_detail ?? null;
    const secret = checkMetadataOnly(execution_parameters, outcome_detail);
    if (secret) throw new SecretMaterialError(secret);

    const prior = params.prior_record ?? null;
    const record: ExecutionEvidence = {
      evidence_id: params.evidence_id ?? randomUUID(),
      sequence_no: prior ? prior.sequence_no + 1 : 1,
      decision_id: params.decision.decision_id,
      context_id: params.decision.context_id,
      agreement_id: params.decision.agreement_id,
      executor_sovereign_id: this.executorSovereignId,
      executed_capability: params.executed_capability,
      execution_parameters,
      executed_at: pythonTimestamp(params.executed_at ?? notBeforeDecision(params.decision.decision_made_at)),
      outcome: params.outcome,
      outcome_detail,
      prev_evidence_digest: prior ? executionDigest(prior) : null,
      signature: null,
    };
    if (params.resource_id !== undefined && params.resource_action !== undefined) {
      const head = params.prior_resource ? resourceHeadOf(params.prior_resource) : null;
      record.resource_id = params.resource_id;
      record.resource_action = params.resource_action;
      record.resource_sequence = head ? head.resource_sequence + 1 : 1;
      record.prev_resource_digest = head ? head.record_digest : null;
    }
    // 1.3.1: a value the NA would refuse as `invalid_json` is refused before signing (`StrictJsonError`).
    checkSignable(record);
    record.signature = await signCanonical(executionCanonical(record), this.signer);
    return record;
  }
}
