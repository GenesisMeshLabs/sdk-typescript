import type { HttpTransport } from './client.js';
import type { EvidenceVerification, TrustDecision, TrustEvidence } from './types.js';

export interface BuildEvidenceParams {
  decision: TrustDecision;
  graph_digest?: string;
}

export interface VerifyEvidenceParams {
  evidence: TrustEvidence;
  issuer_public_keys?: string[];
  expected_graph_digest?: string;
}

export class EvidenceClient {
  constructor(private readonly http: HttpTransport) {}

  /** Build and sign trust evidence from a trust decision (admin). */
  build(params: BuildEvidenceParams): Promise<TrustEvidence> {
    return this.http.adminPost<TrustEvidence>('/admin/trust-evidence', params);
  }

  /** Verify trust evidence signatures (unauthenticated). */
  verify(params: VerifyEvidenceParams): Promise<EvidenceVerification> {
    return this.http.publicPost<EvidenceVerification>('/trust-evidence/verify', params);
  }
}
