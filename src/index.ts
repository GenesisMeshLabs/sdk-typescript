import { HttpTransport, type ClientOptions } from './client.js';
import { AgreementClient } from './agreement.js';
import { BoundaryClient } from './boundary.js';
import { EvidenceClient } from './evidence.js';
import { AttestationClient } from './attestation.js';
import { DisclosureClient } from './disclosure.js';
import { ConsensusClient } from './consensus.js';
import { DataUsageClient } from './data_usage.js';

export class GenesisMeshClient {
  readonly agreement: AgreementClient;
  readonly boundary: BoundaryClient;
  readonly evidence: EvidenceClient;
  readonly attestation: AttestationClient;
  readonly disclosure: DisclosureClient;
  readonly consensus: ConsensusClient;
  readonly dataUsage: DataUsageClient;

  constructor(options: ClientOptions) {
    const http = new HttpTransport(options);
    this.agreement   = new AgreementClient(http);
    this.boundary    = new BoundaryClient(http);
    this.evidence    = new EvidenceClient(http);
    this.attestation = new AttestationClient(http);
    this.disclosure  = new DisclosureClient(http);
    this.consensus   = new ConsensusClient(http);
    this.dataUsage   = new DataUsageClient(http);
  }
}

// Sub-client classes (for composition / dependency injection)
export { AgreementClient } from './agreement.js';
export { BoundaryClient } from './boundary.js';
export { EvidenceClient } from './evidence.js';
export { AttestationClient } from './attestation.js';
export { DisclosureClient } from './disclosure.js';
export { ConsensusClient } from './consensus.js';
export { DataUsageClient } from './data_usage.js';

// Transport
export { HttpTransport } from './client.js';
export type { ClientOptions } from './client.js';

// Auth utilities (canonical JSON, admin header signing)
export { canonicalJson, signBytes, buildAdminHeaders } from './auth.js';
export type { AdminHeaders } from './auth.js';

// Errors
export {
  GenesisMeshError,
  UnauthorizedError,
  ValidationError,
  NotFoundError,
  RateLimitError,
  NetworkError,
  BadRequestError,
} from './errors.js';

// Types
export type * from './types.js';

// Sub-client param types
export type * from './agreement.js';
export type * from './boundary.js';
export type * from './evidence.js';
export type * from './attestation.js';
export type * from './disclosure.js';
export type * from './consensus.js';
export type * from './data_usage.js';
