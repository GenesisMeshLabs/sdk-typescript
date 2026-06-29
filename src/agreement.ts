import type { HttpTransport } from './client.js';
import type {
  AgreementRecord,
  AgreementVerification,
  CapabilityCounter,
  CapabilityOffer,
} from './types.js';

export interface OfferParams {
  responder_sovereign_id: string;
  capabilities: string[];
  valid_from: string;
  valid_until: string;
  expires_at: string;
  scope?: Record<string, unknown>;
}

export interface CounterParams {
  offer: CapabilityOffer;
  capabilities: string[];
  valid_from: string;
  valid_until: string;
  scope?: Record<string, unknown>;
}

export interface AcceptOfferParams {
  offer: CapabilityOffer;
}

export interface AcceptCounterParams {
  counter: CapabilityCounter;
  original_offer: CapabilityOffer;
}

export interface VerifyAgreementParams {
  agreement: AgreementRecord;
  offerer_public_keys?: string[];
  responder_public_keys?: string[];
}

export class AgreementClient {
  constructor(private readonly http: HttpTransport) {}

  /** Create and sign a capability offer (admin). */
  offer(params: OfferParams): Promise<CapabilityOffer> {
    return this.http.adminPost<CapabilityOffer>('/admin/agreements/offer', params);
  }

  /** Create and sign a counter-offer (admin). */
  counter(params: CounterParams): Promise<CapabilityCounter> {
    return this.http.adminPost<CapabilityCounter>('/admin/agreements/counter', params);
  }

  /** Accept an offer or counter (admin). */
  accept(params: AcceptOfferParams | AcceptCounterParams): Promise<AgreementRecord> {
    return this.http.adminPost<AgreementRecord>('/admin/agreements/accept', params);
  }

  /** Verify agreement signatures (unauthenticated). */
  verify(params: VerifyAgreementParams): Promise<AgreementVerification> {
    return this.http.publicPost<AgreementVerification>('/agreements/verify', params);
  }
}
