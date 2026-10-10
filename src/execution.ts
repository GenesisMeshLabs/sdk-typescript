/**
 * Execution evidence: build and sign records exactly as the Python reference
 * `record_execution` does, and refuse secret material before anything is signed.
 */

import { signBreakGlass, type BreakGlassInput, type BreakGlassRecord } from './out-of-band.js';
import { randomUUID } from 'node:crypto';
import { pythonTimestamp, signCanonical, type Signer } from './auth.js';
import { executionCanonical, executionDigest } from './canonical.js';
import { GenesisMeshError } from './errors.js';
import type {
  BoundaryDecision,
  ExecutionEvidence,
  ExecutionOutcome,
  ResourceAction,
  ResourceHead,
} from './types.js';

/** Limit on execution_parameters + outcome_detail, as enforced by the NA. */
export const MAX_METADATA_BYTES = 16 * 1024;

const SECRET_KEYS = new Set([
  'value', 'secret', 'secretvalue', 'password', 'passwd', 'passphrase', 'token',
  'accesstoken', 'refreshtoken', 'bearer', 'privatekey', 'keymaterial',
  'credential', 'credentials', 'clientsecret', 'apikey', 'pem', 'connectionstring',
]);
const LONG_OPAQUE = /^[A-Za-z0-9+/=_-]{120,}$/;
const JWT = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

/** Thrown before signing when a record would carry secret material; the NA would refuse it. */
export class SecretMaterialError extends GenesisMeshError {
  constructor(message: string) {
    super(message, 'evidence_secret_material', 0);
    this.name = 'SecretMaterialError';
  }
}

function normaliseKey(key: string): string {
  return key.toLowerCase().replace(/[-_.]/g, '');
}

function secretMaterial(value: unknown, path = ''): string | null {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const found = secretMaterial(value[i], `${path}${i}.`);
      if (found) return found;
    }
  } else if (value !== null && typeof value === 'object') {
    for (const [key, inner] of Object.entries(value)) {
      if (SECRET_KEYS.has(normaliseKey(key))) return `field '${path}${key}' is not allowed in evidence metadata`;
      const found = secretMaterial(inner, `${path}${key}.`);
      if (found) return found;
    }
  } else if (typeof value === 'string') {
    const field = path.replace(/\.$/, '');
    if (value.includes('-----BEGIN')) return `field '${field}' contains a PEM block`;
    if (LONG_OPAQUE.test(value) || JWT.test(value)) return `field '${field}' looks like key or token material`;
  }
  return null;
}

/**
 * Why the metadata would be refused as secret material, or null. A guard, not a
 * guarantee: send identifiers, versions and timestamps, never secret values.
 */
export function checkMetadataOnly(
  executionParameters: Record<string, unknown>,
  outcomeDetail: string | null = null,
): string | null {
  const size = Buffer.byteLength(
    JSON.stringify({ execution_parameters: executionParameters, outcome_detail: outcomeDetail }),
    'utf-8',
  );
  if (size > MAX_METADATA_BYTES) return `metadata is ${size} bytes, over the ${MAX_METADATA_BYTES}-byte limit`;
  return secretMaterial(executionParameters) ?? (outcomeDetail ? secretMaterial({ outcome_detail: outcomeDetail }) : null);
}

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
    record.signature = await signCanonical(executionCanonical(record), this.signer);
    return record;
  }
}
