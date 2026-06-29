import type { HttpTransport } from './client.js';
import type {
  DataAccessIntent,
  DataLicensePolicy,
  DataSourceDescriptor,
  DataUsageVerification,
} from './types.js';

export interface CreatePolicyParams {
  licensee_sovereign_id: string;
  allowed_source_ids: string[];
  allowed_access_types: string[];
  valid_from: string;
  valid_until: string;
  max_volume_bytes_per_session?: number;
  prohibited_classification_tags?: string[];
}

export interface CreateIntentParams {
  sources: DataSourceDescriptor[];
  access_types: string[];
  decision_id?: string;
  estimated_volume_bytes?: number;
}

export interface VerifyDataUsageParams {
  intent: DataAccessIntent;
  policy: DataLicensePolicy;
  agent_public_keys?: string[];
}

export class DataUsageClient {
  constructor(private readonly http: HttpTransport) {}

  /** Create and sign a data license policy (admin). */
  createPolicy(params: CreatePolicyParams): Promise<DataLicensePolicy> {
    return this.http.adminPost<DataLicensePolicy>('/admin/data-usage/policy', params);
  }

  /** Create and sign a data access intent (admin). */
  createIntent(params: CreateIntentParams): Promise<DataAccessIntent> {
    return this.http.adminPost<DataAccessIntent>('/admin/data-usage/intent', params);
  }

  /** Get the currently active data license policy (unauthenticated). */
  getPolicy(): Promise<DataLicensePolicy> {
    return this.http.publicGet<DataLicensePolicy>('/data-usage/policy');
  }

  /** Verify a data access intent against a policy (unauthenticated). */
  verify(params: VerifyDataUsageParams): Promise<DataUsageVerification> {
    return this.http.publicPost<DataUsageVerification>('/data-usage/verify', params);
  }
}
