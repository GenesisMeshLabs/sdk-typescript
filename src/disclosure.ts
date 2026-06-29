import type { HttpTransport } from './client.js';
import type {
  AgreementRecord,
  CapabilityCommitment,
  CapabilityMembershipProof,
  CapabilityNullifier,
  DisclosureVerification,
} from './types.js';

export interface CommitParams {
  capabilities: string[];
  agreement: AgreementRecord;
}

export interface NullifierParams {
  proof: CapabilityMembershipProof;
}

export interface ProveParams {
  capability: string;
  capabilities: string[];
  commitment: CapabilityCommitment;
  prover_sovereign_id: string;
}

export interface VerifyDisclosureParams {
  proof: CapabilityMembershipProof;
  commitment: CapabilityCommitment;
  issuer_public_keys?: string[];
}

export class DisclosureClient {
  constructor(private readonly http: HttpTransport) {}

  /** Commit to a set of capabilities under an agreement (admin). */
  commit(params: CommitParams): Promise<CapabilityCommitment> {
    return this.http.adminPost<CapabilityCommitment>('/admin/disclosure/commit', params);
  }

  /** Issue a one-time nullifier for a proof (admin). */
  nullifier(params: NullifierParams): Promise<CapabilityNullifier> {
    return this.http.adminPost<CapabilityNullifier>('/admin/disclosure/nullifier', params);
  }

  /** Generate a Merkle membership proof (unauthenticated). */
  prove(params: ProveParams): Promise<CapabilityMembershipProof> {
    return this.http.publicPost<CapabilityMembershipProof>('/disclosure/prove', params);
  }

  /** Verify a capability membership proof (unauthenticated). */
  verify(params: VerifyDisclosureParams): Promise<DisclosureVerification> {
    return this.http.publicPost<DisclosureVerification>('/disclosure/verify', params);
  }
}
