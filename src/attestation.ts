import type { HttpTransport } from './client.js';
import type {
  AttestationRevocation,
  MembershipAttestation,
  RecognitionPolicyRecord,
} from './types.js';

export interface IssueAttestationParams {
  subject_id: string;
  roles: string[];
  validity_hours?: number;
  issuer_sovereign_id?: string;
  subject_public_key?: string;
  claims?: Record<string, unknown>;
}

export interface RevokeAttestationParams {
  reason?: string;
}

export interface SaveRecognitionPolicyParams {
  recognition_policy: Record<string, unknown>;
  policy_id?: string;
}

export class AttestationClient {
  constructor(private readonly http: HttpTransport) {}

  /** Issue a signed membership attestation (admin). */
  issue(params: IssueAttestationParams): Promise<MembershipAttestation> {
    return this.http.adminPost<MembershipAttestation>('/admin/attestations', params);
  }

  /** Revoke a membership attestation by ID (admin). */
  revoke(
    attestationId: string,
    params: RevokeAttestationParams = {},
  ): Promise<AttestationRevocation> {
    return this.http.adminPost<AttestationRevocation>(
      `/admin/attestations/${attestationId}/revoke`,
      params,
    );
  }

  /** Set the active recognition policy for this sovereign (admin). */
  savePolicy(params: SaveRecognitionPolicyParams): Promise<RecognitionPolicyRecord> {
    return this.http.adminPost<RecognitionPolicyRecord>('/admin/recognition-policy', params);
  }
}
