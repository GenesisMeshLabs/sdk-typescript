import type { HttpTransport } from './client.js';
import type { AgreementRecord, BoundaryDecision, BoundaryVerification } from './types.js';

export interface DecideParams {
  agreement: AgreementRecord;
  requested_capability: string;
  context?: Record<string, unknown>;
}

export interface VerifyBoundaryParams {
  decision: BoundaryDecision;
  operator_public_keys?: string[];
}

export class BoundaryClient {
  constructor(private readonly http: HttpTransport) {}

  /** Issue a signed boundary decision for a capability request (admin). */
  decide(params: DecideParams): Promise<BoundaryDecision> {
    return this.http.adminPost<BoundaryDecision>('/admin/boundary/decide', params);
  }

  /** Verify a boundary decision signature (unauthenticated). */
  verify(params: VerifyBoundaryParams): Promise<BoundaryVerification> {
    return this.http.publicPost<BoundaryVerification>('/boundary/verify', params);
  }
}
