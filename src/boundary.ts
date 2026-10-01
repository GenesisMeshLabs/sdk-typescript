import { checkMetadataOnly, SecretMaterialError } from './execution.js';
import type { HttpTransport } from './client.js';
import type {
  AgreementRecord,
  BoundaryDecision,
  BoundaryEvaluation,
  BoundaryVerification,
} from './types.js';

export interface DecideParams {
  agreement: AgreementRecord;
  requested_capability: string;
  context?: Record<string, unknown>;
}

/** Request context for policy-aware evaluation. Never put secret values in it. */
export interface EvaluationContext {
  request_parameters?: Record<string, unknown>;
  /** Normalized facts for policy gates, e.g. `owner`, `environment`, `secret_store`. */
  attributes?: Record<string, unknown>;
  /** Defaults to the attestation subject (attestation basis) or the agreement responder. */
  requester_sovereign_id?: string;
  provider_sovereign_id?: string;
  context_id?: string;
  context_freshness_seq?: number;
  /** Agreement basis only: "direct" (default), "agreement" or "delegation". */
  parent_kind?: string;
}

interface EvaluateCommon {
  requested_capability: string;
  context?: EvaluationContext;
}

/** Evaluate under an NA-issued MembershipAttestation (v0.58.1). */
export interface EvaluateAttestationParams extends EvaluateCommon {
  attestation_id: string;
  agreement?: never;
}

/** Evaluate under a signed AgreementRecord (v0.58). */
export interface EvaluateAgreementParams extends EvaluateCommon {
  agreement: AgreementRecord;
  attestation_id?: never;
}

export type EvaluateParams = EvaluateAttestationParams | EvaluateAgreementParams;

export interface VerifyBoundaryParams {
  decision: BoundaryDecision;
  operator_public_keys?: string[];
}

export class BoundaryClient {
  constructor(private readonly http: HttpTransport) {}

  /**
   * Legacy agreement-only decision without policy (admin). Refused with
   * `boundary_policy_required` when the NA requires policy enforcement; use `evaluate`.
   */
  decide(params: DecideParams): Promise<BoundaryDecision> {
    return this.http.adminPost<BoundaryDecision>('/admin/boundary/decide', params);
  }

  /**
   * Policy-aware evaluation under exactly one basis - an `attestation_id` or an
   * `agreement` (admin). Returns the signed decision and its justification proof.
   * A denial is a signed decision with `authorized: false`, not an error.
   */
  async evaluate(params: EvaluateParams): Promise<BoundaryEvaluation> {
    if ((params.attestation_id !== undefined) === (params.agreement !== undefined)) {
      throw new Error('exactly one of agreement or attestation_id is required');
    }
    const reason = checkMetadataOnly({ ...params.context });
    if (reason) throw new SecretMaterialError(reason);
    return this.http.adminPost<BoundaryEvaluation>('/admin/boundary/evaluate', params);
  }

  /** Verify a boundary decision signature (unauthenticated). */
  verify(params: VerifyBoundaryParams): Promise<BoundaryVerification> {
    return this.http.publicPost<BoundaryVerification>('/boundary/verify', params, true);
  }
}
