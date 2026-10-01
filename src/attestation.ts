import type { HttpTransport } from './client.js';
import type {
  AttestationList,
  AttestationRecord,
  AttestationRevocation,
  AttestationStatus,
  AttestationVerification,
  MembershipAttestation,
  RecognitionPolicy,
  RecognitionPolicyRecord,
  SovereignRevocationFeed,
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

export interface ListAttestationsParams {
  issuer_sovereign_id?: string;
  subject_id?: string;
  status?: AttestationStatus;
}

export interface VerifyAttestationParams {
  attestation: MembershipAttestation;
  /** Defaults to the NA's active recognition policy. */
  recognition_policy?: RecognitionPolicy | Record<string, unknown>;
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
      `/admin/attestations/${encodeURIComponent(attestationId)}/revoke`,
      params,
    );
  }

  /** Set the active recognition policy for this sovereign (admin). */
  savePolicy(params: SaveRecognitionPolicyParams): Promise<RecognitionPolicyRecord> {
    return this.http.adminPost<RecognitionPolicyRecord>('/admin/recognition-policy', params);
  }

  /** A stored attestation with its current status (unauthenticated). */
  get(attestationId: string): Promise<AttestationRecord> {
    return this.http.publicGet<AttestationRecord>(`/attestations/${encodeURIComponent(attestationId)}`);
  }

  /** Stored attestations, optionally filtered by issuer, subject or status (unauthenticated). */
  list(params: ListAttestationsParams = {}): Promise<AttestationList> {
    return this.http.publicGet<AttestationList>('/attestations', { ...params });
  }

  /** Verify an attestation against a recognition policy (unauthenticated). */
  verify(params: VerifyAttestationParams): Promise<AttestationVerification> {
    return this.http.publicPost<AttestationVerification>('/attestations/verify', params, true);
  }

  /** The NA's active recognition policy (unauthenticated). */
  getPolicy(): Promise<RecognitionPolicy> {
    return this.http.publicGet<RecognitionPolicy>('/recognition-policy');
  }

  /** Signed feed of revoked attestations for an issuer; defaults to this NA (unauthenticated). */
  revocationFeed(issuerSovereignId?: string): Promise<SovereignRevocationFeed> {
    return this.http.publicGet<SovereignRevocationFeed>('/sovereign-revocation-feed', {
      issuer_sovereign_id: issuerSovereignId,
    });
  }
}
