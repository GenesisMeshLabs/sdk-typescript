import type { HttpTransport } from './client.js';
import type {
  ActivePolicyStatus,
  BoundaryPolicy,
  BoundaryPolicyIntent,
  PolicyActivation,
  PolicyHistory,
  PolicyValidation,
  PolicyVerification,
  PolicyVersionSummary,
} from './types.js';

export interface VerifyPolicyParams {
  policy: BoundaryPolicy;
  /** Defaults to the NA's own key. */
  issuer_public_keys?: string[];
}

/** Declarative boundary policy lifecycle (v0.58). */
export class PolicyClient {
  constructor(private readonly http: HttpTransport) {}

  /** Dry-run validation of policy intent against the NA's gate registry (admin). */
  validate(intent: BoundaryPolicyIntent): Promise<PolicyValidation> {
    return this.http.adminPost<PolicyValidation>('/admin/boundary-policies/validate', intent);
  }

  /**
   * Validate, sign and store a new inactive version (admin, privileged).
   * Fails with `boundary_policy_invalid` and the issues in `error.details`.
   */
  publish(intent: BoundaryPolicyIntent): Promise<BoundaryPolicy> {
    return this.http.adminPost<BoundaryPolicy>('/admin/boundary-policies', intent);
  }

  /** Every stored version of every policy (admin). */
  async list(): Promise<PolicyVersionSummary[]> {
    const body = await this.http.adminGet<{ policies: PolicyVersionSummary[] }>('/admin/boundary-policies');
    return body.policies;
  }

  /** Active set, its health, and the enforcement mode (admin). */
  active(): Promise<ActivePolicyStatus> {
    return this.http.adminGet<ActivePolicyStatus>('/admin/boundary-policies/active');
  }

  /** Every version of one policy, newest first, with the signed bodies (admin). */
  history(policyId: string): Promise<PolicyHistory> {
    return this.http.adminGet<PolicyHistory>(`/admin/boundary-policies/${encodeURIComponent(policyId)}/history`);
  }

  /** Activate a version; activating an older version is the rollback (admin, privileged). */
  activate(policyId: string, version: number): Promise<PolicyActivation> {
    return this.http.adminPost<PolicyActivation>(
      `/admin/boundary-policies/${encodeURIComponent(policyId)}/activate`,
      { version },
    );
  }

  /** Deactivate an active version (admin, privileged). */
  deactivate(policyId: string, version: number): Promise<PolicyActivation> {
    return this.http.adminPost<PolicyActivation>(
      `/admin/boundary-policies/${encodeURIComponent(policyId)}/deactivate`,
      { version },
    );
  }

  /** Verify a policy signature (unauthenticated). */
  verify(params: VerifyPolicyParams): Promise<PolicyVerification> {
    return this.http.publicPost<PolicyVerification>('/boundary-policies/verify', params, true);
  }
}
