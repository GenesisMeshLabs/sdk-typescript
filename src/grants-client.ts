/**
 * Pre-issued grants (v1.6.0, beta routes): issuing, reading and revoking
 * grants (admin), and the holder's calls, authenticated by the grant's bearer
 * key: time tokens and uses. With `EVIDENCE_GRANTS=off` (the NA's default)
 * every route answers `404 grants_disabled`.
 */

import type { Signer } from './auth.js';
import type { HttpTransport } from './client.js';
import type { RecordSubmission } from './evidence_store.js';
import {
  signTimeTokenRequest,
  type CapabilityGrant,
  type EnvelopeParameterInput,
  type GrantExecutionEvidence,
  type GrantRevocationRecord,
  type TimeToken,
  type TimeTokenRequest,
  type TimeTokenRequestInput,
} from './grants.js';
import type { AgreementRecord, EvidenceStoreEntry } from './types.js';

/** `POST /admin/grants`: exactly one basis, `attestation_id` or `agreement`. */
export interface IssueGrantParams {
  /** A registered, active executor key: the only key that can use the grant. */
  bearer_key_id: string;
  /** Exact capability IDs (1 to 16). */
  capabilities: string[];
  /** An attestation this NA issued. */
  attestation_id?: string;
  /** An agreement this NA trusts. */
  agreement?: AgreementRecord;
  /** With an agreement basis only. */
  context_freshness_seq?: number;
  /** Default: now. RFC 3339 with an offset; within now and 24 hours from now. */
  valid_from?: string | Date;
  /** RFC 3339 with an offset; at most 24 hours (and the NA's limit) after `valid_from`. */
  valid_until: string | Date;
  /** The budget (at most the NA's `NA_GRANT_MAX_USES`). */
  max_uses: number;
  /** Default: the NA's limit, or `max_uses` when lower. */
  max_uses_per_time_token?: number;
  /** The closed envelope: every request parameter a use may carry. */
  parameter_envelope?: Record<string, EnvelopeParameterInput>;
}

/** An issued grant: the signed grant, its first time token (`use_sequence` 0) and its store entry. */
export interface IssuedGrant {
  grant: CapabilityGrant;
  time_token: TimeToken;
  entry: EvidenceStoreEntry;
  entry_digest: string;
}

export type GrantStatus = 'active' | 'scheduled' | 'exhausted' | 'expired' | 'revoked';

/** A grant as `GET /admin/grants` lists it. */
export interface GrantSummary {
  grant_id: string;
  status: GrantStatus;
  bearer_key_id: string;
  bearer_sovereign_id: string;
  capabilities: string[];
  basis_kind: 'agreement' | 'attestation';
  basis_id: string;
  valid_from: string;
  valid_until: string;
  max_uses: number;
  /** Uses the NA admitted. */
  uses: number;
  issued_at: string;
  issued_by_operator: string;
  store_sequence: number;
  revoked_at: string | null;
  revocation_reason: string | null;
}

export interface GrantListParams {
  /** `active` (not revoked, not past its end: also `scheduled` and `exhausted` grants), `expired` or `revoked`. */
  status?: 'active' | 'expired' | 'revoked';
  bearer_key_id?: string;
  /** 1 to 500, default 100. */
  limit?: number;
  /** The previous page's `next_before`: the ID of its last grant (an unknown one is `400 invalid_page`). */
  before?: string;
}

/** Grants, newest first by `issued_at`, then `grant_id`. */
export interface GrantList {
  grants: GrantSummary[];
  next_before: string | null;
}

/** One grant: its summary, the uses left, the signed grant, its policy versions and its revocation. */
export interface GrantDetail extends GrantSummary {
  remaining_uses: number;
  /** The positions of its use chain: admitted uses and quarantined uses that continued it. */
  chain_length: number;
  grant: CapabilityGrant;
  policy_versions: Array<{ policy_id: string; version: number }>;
  revocation: GrantRevocationRecord | null;
}

/** One position of a grant's use chain (`GET /admin/grants/<id>/uses`). */
export interface GrantUseSummary {
  use_id: string;
  use_sequence: number;
  /** `quarantined`: a use the NA refused that continued the chain. */
  state: 'admitted' | 'quarantined';
  /** Null when admitted. */
  rejection_code: string | null;
  executed_at: string;
  recorded_at: string;
  store_sequence: number;
  resource_id: string | null;
  /** The position the NA assigned in the resource's chain; null when quarantined or without a resource. */
  resource_sequence: number | null;
  outcome: string;
}

export interface GrantUsesParams {
  /** 1 to 500, default 100. */
  limit?: number;
  /** The previous page's `next_before`: a `use_sequence`. */
  before?: number;
}

/** A grant's use chain, newest first. */
export interface GrantUses {
  grant_id: string;
  uses: GrantUseSummary[];
  next_before: number | null;
}

export interface GrantRevoked {
  grant_id: string;
  status: 'revoked';
  revocation: GrantRevocationRecord;
  entry: EvidenceStoreEntry;
  entry_digest: string;
}

/** The NA's answer to a grant use: `201 recorded` with its resource position, or `200 duplicate`. */
export interface GrantUseSubmission extends RecordSubmission {
  payload: GrantExecutionEvidence & Record<string, unknown>;
  resource_sequence?: number | null;
}

function time(value: string | Date | undefined): string | undefined {
  return value instanceof Date ? value.toISOString() : value;
}

/** Pre-issued grants (v1.6.0). */
export class GrantsClient {
  constructor(private readonly http: HttpTransport) {}

  /**
   * Issue a grant (admin, privileged). The NA checks the basis and every
   * active policy over the whole envelope and validity, and refuses with
   * `422` and the first problem's reason (`grant_basis_invalid` ...
   * `grant_gate_may_deny`; every problem in `details.problems`). `409
   * grant_issuance_conflict`: what the grant rests on changed meanwhile;
   * retry (`isRetryableConflict`).
   */
  issueGrant(params: IssueGrantParams): Promise<IssuedGrant> {
    const body: Record<string, unknown> = { ...params, valid_until: time(params.valid_until) };
    if (params.valid_from !== undefined) body['valid_from'] = time(params.valid_from);
    return this.http.adminPost<IssuedGrant>('/admin/grants', body);
  }

  /** Grants, newest first (admin, read tier). Follow `next_before`. */
  listGrants(params: GrantListParams = {}): Promise<GrantList> {
    return this.http.adminGet<GrantList>('/admin/grants', { ...params });
  }

  /** One grant, its state and its revocation (admin, read tier); `404 grant_not_found`. */
  getGrant(grantId: string): Promise<GrantDetail> {
    return this.http.adminGet<GrantDetail>(`/admin/grants/${encodeURIComponent(grantId)}`);
  }

  /**
   * A grant's use chain, newest first (admin, read tier; beta): admitted uses
   * and quarantined uses that continued it. Follow `next_before`. A use refused
   * as a conflict or a chain mismatch is not in the chain.
   */
  listGrantUses(grantId: string, params: GrantUsesParams = {}): Promise<GrantUses> {
    return this.http.adminGet<GrantUses>(`/admin/grants/${encodeURIComponent(grantId)}/uses`, { ...params });
  }

  /**
   * Revoke a grant now (admin, privileged): uses executed from now on are
   * refused. `reason` (1 to 1024 characters) is recorded as the revocation's
   * `detail`; the revocation's `reason` is `operator`. `409 grant_already_revoked`.
   */
  revokeGrant(grantId: string, reason?: string): Promise<GrantRevoked> {
    return this.http.adminPost<GrantRevoked>(`/admin/grants/${encodeURIComponent(grantId)}/revoke`,
      reason === undefined ? {} : { reason });
  }

  /**
   * A time token for the grant's holder (`POST /grants/time-tokens`), bound
   * to the head of its use chain: `use_sequence` uses made, the last one's
   * digest `use_head_digest`. The request is signed by `signer`, the bearer
   * key. `409 grant_expired`, `grant_revoked` or `grant_budget_exhausted`
   * mean the grant can no longer be used (a holder falls back to break-glass
   * when the NA cannot be reached later).
   */
  async requestTimeToken(input: TimeTokenRequestInput | TimeTokenRequest, signer?: Signer): Promise<TimeToken> {
    const request = 'signature' in input && input.signature ? input as TimeTokenRequest
      : await signTimeTokenRequest(input as TimeTokenRequestInput, requireSigner(signer));
    const body = await this.http.publicPost<{ time_token: TimeToken }>('/grants/time-tokens', { request }, true);
    return body.time_token;
  }

  /**
   * Submit one signed use (`POST /evidence/grant-executions`), authenticated
   * by its bearer key's signature. A refusal of an authentic use no retry
   * overcomes names its quarantine entry in `details.quarantine_id` (the same
   * one when the use is uploaded again); `grant_use_chain_gap` asks for the
   * earlier uses first, and `grant_use_in_future` to retry later.
   */
  submitGrantUse(evidence: GrantExecutionEvidence): Promise<GrantUseSubmission> {
    return this.http.publicPost<GrantUseSubmission>('/evidence/grant-executions', { evidence }, true);
  }
}

function requireSigner(signer: Signer | undefined): Signer {
  if (!signer) throw new Error('requestTimeToken needs the bearer key\'s signer to sign the request');
  return signer;
}
