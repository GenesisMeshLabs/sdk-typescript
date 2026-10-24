/**
 * The vouching horizon for NA-signed records (Genesis Mesh 1.8.0): port of
 * the reference's `trust.key_succession.na_record_refusal`, pinned by the
 * `vouching` conformance suite.
 *
 * A record is placed at the time its kind names (`NA_VOUCHING_TIME_FIELDS`),
 * its signature checked over the record as received with the NA keys valid
 * then, and, when `now` is given, the horizon applied: a record whose key ended
 * more than the hand-over and the grace before `now` no longer vouches for the
 * present (`outlives_key`). Without `now` the record is judged at its own
 * time only, as audit packs and exports judge it.
 */

import { validGrant } from './grants.js';
import { type NAKeyHistory, recordOutlivesKey } from './key-history.js';
import { signedAsReceived, strictRefusal } from './strict.js';
import { isObject, timestampMicros, validAttestationRecord, validFeed, validTreaty } from './validation.js';

/** The record kinds the horizon applies to, and the field each is placed at. */
export const NA_VOUCHING_TIME_FIELDS: Readonly<Record<string, string>> = Object.freeze({
  CapabilityGrant: 'issued_at',
  MembershipAttestation: 'issued_at',
  RecognitionTreaty: 'issued_at',
  SovereignRevocationFeed: 'issued_at',
});

/** Why an NA-signed record does not verify (`naRecordRefusal`), in the order it is checked. */
export type NARecordRefusal =
  | 'unknown_field' | 'non_canonical_form' | 'na_key_not_valid_at_time' | 'invalid_signature'
  | 'record_malformed' | 'outlives_key';

function window(r: Record<string, unknown>): boolean {
  const from = timestampMicros(String(r['valid_from']));
  const expires = timestampMicros(String(r['expires_at']));
  return expires > from && timestampMicros(String(r['issued_at'])) <= expires;
}

/** True when the reference's model of `model` reads `record`: its shape and its own rules. */
export function modelAccepts(model: string, record: unknown): boolean {
  switch (model) {
    case 'CapabilityGrant': return validGrant(record);
    case 'MembershipAttestation': return validAttestationRecord(record) && window(record as Record<string, unknown>);
    case 'RecognitionTreaty': return validTreaty(record) && window(record as Record<string, unknown>);
    case 'SovereignRevocationFeed': return validFeed(record);
    default: return true;
  }
}

/**
 * Why an NA-signed record of `model` does not verify, or `null` (1.8.0).
 * Reasons, in order: `unknown_field` or `non_canonical_form`,
 * `na_key_not_valid_at_time`, `invalid_signature`, `record_malformed` (signed,
 * but its model refuses it), `outlives_key` (only with `now`).
 */
export function naRecordRefusal(
  model: string, raw: unknown, history: NAKeyHistory, options: { now?: string | Date } = {},
): NARecordRefusal | null {
  const field = NA_VOUCHING_TIME_FIELDS[model];
  if (field === undefined) throw new RangeError(`${model} is not a kind the vouching horizon applies to`);
  if (!isObject(raw) || typeof raw[field] !== 'string') return 'invalid_signature';
  const at = timestampMicros(raw[field] as string);
  if (Number.isNaN(at)) return 'invalid_signature';
  const keys = history.keysAtMicros(at);
  const signer = keys.find(k => signedAsReceived(model, raw, [k]));
  if (signer === undefined) {
    const others = history.allKeys().filter(k => !keys.includes(k));
    return others.length > 0 && signedAsReceived(model, raw, others) ? 'na_key_not_valid_at_time' : 'invalid_signature';
  }
  const refusal = strictRefusal(model, raw, [signer]);
  if (refusal !== null) return refusal as NARecordRefusal;
  if (!modelAccepts(model, raw)) return 'record_malformed';
  if (options.now !== undefined && recordOutlivesKey(history, signer, options.now)) return 'outlives_key';
  return null;
}
