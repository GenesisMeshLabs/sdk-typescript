/**
 * The NA's key history (Genesis Mesh 1.5.0): the genesis block and its key
 * successions, verified from the root public key a verifier holds out of
 * band. Port of the reference's `models/key_succession.py` and
 * `trust/key_succession.py`, with the same reason codes.
 *
 * A `KeySuccessionRecord` names the NA's next key, signed by the root key
 * (kept offline), by the new key (proof that it is held) and by the outgoing
 * NA key. Every NA signature then verifies
 * with the key that was valid at the record's own time, so records signed
 * before and after a succession keep verifying:
 *
 * - the genesis key is valid from the start until the first succession takes
 *   effect; its `valid_to` is not enforced;
 * - a key a succession names is valid from its `effective_at` until the next
 *   succession takes effect, and never at or after its own `new_valid_to`;
 * - a succeeded key is still accepted for records dated up to 300 seconds
 *   after the next key took effect (the hand-over).
 *
 * The vouching horizon (1.8.0): judged for the present, a record signed by a
 * key that has ended vouches only until that key's end, the hand-over and a
 * grace of at most 24 hours (`recordOutlivesKey`, `naKeysVouchingAt`). The
 * Network Authority re-issues what is still valid under the new key. Judged at
 * its own time, as audit packs and exports judge it, a record is unchanged.
 *
 * Pure functions; no network access.
 */

import { createHash } from 'node:crypto';
import { receivedCanonical, signedAsReceived, strictRefusal, withoutUnknownFields } from './strict.js';
import type { Signature } from './types.js';
import { isObject, timestampMicros, validGenesis, validKeySuccession } from './validation.js';

/** How long after a succession takes effect the outgoing key is still accepted (seconds). */
export const SUCCESSION_HANDOVER_SECONDS = 300;
const HANDOVER_MICROS = SUCCESSION_HANDOVER_SECONDS * 1_000_000;

/**
 * A succession takes effect at least this long after the store records it
 * (seconds): a `key_succession` entry recorded later than `effective_at` minus
 * this is `succession_backdated`.
 */
export const SUCCESSION_MIN_LEAD_SECONDS = 60;

/**
 * The longest lifetime of a decision the NA issues (seconds). A decision
 * signed by a key with an end is refused (`decision_outlives_key`) when it
 * stays valid past that end, the hand-over and this lifetime.
 */
export const MAX_DECISION_LIFETIME_SECONDS = 300;

/**
 * The vouching horizon's grace (1.8.0, seconds): how long past its end and
 * the hand-over a record of a key that has ended still vouches for the
 * present. Also the most any verifier allows; `withVouchingGrace` only
 * shortens it.
 */
export const SUCCESSION_VOUCHING_GRACE_SECONDS = 86_400;

/**
 * How far an export entry's `recorded_at` may fall behind an earlier entry's
 * (seconds) before it is `recorded_at_out_of_order`; entries retention carried
 * forward are exempt.
 */
export const RECORD_TIME_TOLERANCE_SECONDS = 300;

/**
 * The time an NA-signed record is placed at in the key history when it is
 * read alone, outside the store (in the store every entry is placed at its
 * envelope's `recorded_at`).
 */
export const NA_RECORD_TIME_FIELDS: Readonly<Record<string, string>> = Object.freeze({
  ArchiveRecord: 'archived_at',
  AuditPackManifest: 'created_at',
  BoundaryDecision: 'decision_made_at',
  BoundaryPolicy: 'issued_at',
  // v1.6.0: a grant, its revocation, and a time token (read alone, or nested in a use).
  CapabilityGrant: 'issued_at',
  GrantRevocationRecord: 'revoked_at',
  JudgementRecord: 'judged_at',
  JustificationProof: 'proof_issued_at',
  MembershipAttestation: 'issued_at',
  QuarantineRecord: 'quarantined_at',
  RecognitionTreaty: 'issued_at',
  RegistryRecord: 'effective_at',
  RetentionCheckpoint: 'created_at',
  ReviewRecord: 'decided_at',
  StoreAnchor: 'anchored_at',
  TimeToken: 'issued_at',
});

/** The signed genesis block: the network's constitution, signed by the root key. */
export interface GenesisBlock {
  network_name: string;
  network_version: string;
  root_public_key: string;
  network_authority: { public_key: string; valid_from: string; valid_to: string };
  allowed_crypto_suites?: string[];
  allowed_transports?: string[];
  policy_manifest: { hash: string; url?: string | null };
  bootstrap_anchors?: Array<{ id: string; endpoint: string }>;
  signatures: Signature[];
  [key: string]: unknown;
}

/**
 * The NA's next key (v1.5.0), signed over one form by the root key
 * (`key_id` `root`), the new key (`key_id` = `new_key_id`, its proof of
 * possession) and the outgoing NA key, which the NA adds when it records it.
 */
export interface KeySuccessionRecord {
  succession_id: string;
  sovereign_id: string;
  /** The new key's position in the history; the genesis key is 1. */
  key_sequence: number;
  previous_key_id: string;
  previous_public_key: string;
  /** The previous succession's digest; absent for the first. */
  previous_succession_digest?: string | null;
  new_key_id: string;
  new_public_key: string;
  effective_at: string;
  new_valid_to: string;
  /** When the root key signed the record, offline. */
  issued_at: string;
  signatures: Signature[];
}

/** One key of the history and the times it is valid at (the reference's `NAKey.to_dict()`). */
export interface NAKey {
  key_sequence: number;
  key_id: string | null;
  public_key: string;
  /** Null for the genesis key: valid from the start of the network. */
  valid_from: string | null;
  /** The next succession's `effective_at`; null while the key is current. */
  succeeded_at: string | null;
  valid_to: string | null;
  /** False for the genesis key. */
  valid_to_enforced: boolean;
}

/** A timestamp as the reference writes it back: six fraction digits when not zero, `Z` for UTC. */
function pythonIso(value: string | null): string | null {
  if (value === null) return null;
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})?$/.exec(value);
  if (!m) return value;
  const fraction = (m[2] ?? '').padEnd(6, '0');
  const zone = m[3] === undefined || m[3] === 'Z' || m[3] === '+00:00' || m[3] === '-00:00' ? 'Z' : m[3];
  return `${m[1]}${/^0+$/.test(fraction) ? '' : `.${fraction}`}${zone}`;
}

/** Microseconds since the epoch of a timestamp or a Date. */
function at(value: string | Date): number {
  return typeof value === 'string' ? timestampMicros(value) : value.getTime() * 1000;
}

interface Window {
  from: number | null;
  succeeded: number | null;
  to: number | null;
}

function windowOf(key: NAKey): Window {
  return {
    from: key.valid_from === null ? null : at(key.valid_from),
    succeeded: key.succeeded_at === null ? null : at(key.succeeded_at),
    to: key.valid_to_enforced && key.valid_to !== null ? at(key.valid_to) : null,
  };
}

/** True when a record dated `when` (microseconds) may carry this key's signature, with the hand-over. */
function accepts(w: Window, when: number): boolean {
  if (w.from !== null && when < w.from) return false;
  if (w.succeeded !== null && when >= w.succeeded + HANDOVER_MICROS) return false;
  return !(w.to !== null && when >= w.to);
}

/** True when the NA may sign with this key at `when` (no hand-over). */
function signs(w: Window, when: number): boolean {
  if (w.from !== null && when < w.from) return false;
  if (w.succeeded !== null && when >= w.succeeded) return false;
  return !(w.to !== null && when >= w.to);
}

/**
 * The NA's keys in order, from a verified genesis block and successions
 * (`verifyKeyHistory`), or a list of keys valid at every time (`ofKeys`,
 * what a list of NA keys meant before 1.5.0).
 */
export class NAKeyHistory {
  private readonly windows: readonly Window[];

  constructor(
    readonly sovereign_id: string,
    readonly root_public_key: string | null,
    readonly keys: readonly NAKey[],
    readonly successions: readonly KeySuccessionRecord[] = [],
    /** The vouching horizon's grace (1.8.0): 0 to `SUCCESSION_VOUCHING_GRACE_SECONDS`. */
    readonly vouching_grace_seconds: number = SUCCESSION_VOUCHING_GRACE_SECONDS,
  ) {
    if (!(vouching_grace_seconds >= 0 && vouching_grace_seconds <= SUCCESSION_VOUCHING_GRACE_SECONDS)) {
      throw new RangeError(`vouching_grace_seconds must be 0 to ${SUCCESSION_VOUCHING_GRACE_SECONDS}`);
    }
    this.windows = keys.map(windowOf);
  }

  /**
   * This history with a shorter grace (1.8.0): a longer one is clamped to the
   * current grace, and `null` or `undefined` keeps it. Use it for the NA's
   * unsigned `vouching_grace_seconds` hint, which may only shorten the grace.
   */
  withVouchingGrace(graceSeconds: number | null | undefined): NAKeyHistory {
    if (graceSeconds === null || graceSeconds === undefined || Number.isNaN(graceSeconds)) return this;
    const grace = Math.min(Math.max(graceSeconds, 0), SUCCESSION_VOUCHING_GRACE_SECONDS, this.vouching_grace_seconds);
    return new NAKeyHistory(this.sovereign_id, this.root_public_key, this.keys, this.successions, grace);
  }

  /**
   * Until when a record signed by `publicKey` vouches for the present
   * (1.8.0, microseconds since the epoch): its end, the hand-over and the
   * grace. `null` for a key with no end, or not in this history.
   */
  vouchesUntilMicros(publicKey: string): number | null {
    const index = this.keys.findIndex(k => k.public_key === publicKey);
    if (index < 0) return null;
    const w = this.windows[index]!;
    const ends = [w.succeeded, w.to].filter((t): t is number => t !== null);
    if (ends.length === 0) return null;
    return Math.min(...ends) + HANDOVER_MICROS + this.vouching_grace_seconds * 1_000_000;
  }

  /** Keys valid at every time: a list of NA keys as verifiers took them before 1.5.0. */
  static ofKeys(publicKeys: readonly string[], sovereignId = ''): NAKeyHistory {
    return new NAKeyHistory(sovereignId, null, publicKeys.map((public_key, i) => ({
      key_sequence: i + 1, key_id: null, public_key, valid_from: null, succeeded_at: null, valid_to: null,
      valid_to_enforced: false,
    })));
  }

  /** Every public key of the history, in order. */
  allKeys(): string[] {
    return this.keys.map(k => k.public_key);
  }

  /** The public keys a record dated `time` may be signed with (with the 300-second hand-over). */
  keysAt(time: string | Date): string[] {
    return this.keysAtMicros(at(time));
  }

  /** `keysAt` for a time in microseconds since the epoch. */
  keysAtMicros(when: number): string[] {
    if (Number.isNaN(when)) return [];
    return this.keys.filter((_, i) => accepts(this.windows[i]!, when)).map(k => k.public_key);
  }

  keyFor(publicKey: string): NAKey | undefined {
    return this.keys.find(k => k.public_key === publicKey);
  }

  /** The key the NA signs with at `time` (none in a gap after an enforced end). */
  signingKeyAt(time: string | Date): NAKey | undefined {
    const when = at(time);
    return this.keys.find((_, i) => signs(this.windows[i]!, when));
  }
}

/**
 * NA public keys as a verifier takes them: a list, valid at every time (the
 * behaviour before 1.5.0, kept when no key history is supplied), or the NA's
 * key history, read at each record's own time.
 */
export type NAKeys = readonly string[] | NAKeyHistory;

/** The NA public keys a record dated `time` may be signed with; every key when `time` is null. */
export function naKeysAt(keys: NAKeys, time: string | Date | null): string[] {
  if (keys instanceof NAKeyHistory) return time === null ? keys.allKeys() : keys.keysAt(time);
  return [...keys];
}

/**
 * True when a decision signed by `publicKey` stays valid past what that key
 * may vouch for: its end (its succession, or its enforced `valid_to`), the
 * hand-over and `MAX_DECISION_LIFETIME_SECONDS`. A list of keys has no ends.
 */
export function decisionOutlivesKey(keys: NAKeys, publicKey: string, validUntil: string): boolean {
  if (!(keys instanceof NAKeyHistory)) return false;
  const key = keys.keyFor(publicKey);
  if (key === undefined) return false;
  const ends = [key.succeeded_at, key.valid_to_enforced ? key.valid_to : null]
    .filter((t): t is string => t !== null).map(at);
  if (ends.length === 0) return false;
  return at(validUntil) > Math.min(...ends) + HANDOVER_MICROS + MAX_DECISION_LIFETIME_SECONDS * 1_000_000;
}

/**
 * True when a record signed by `publicKey` no longer vouches for the present
 * at `now` (1.8.0): its key ended more than the hand-over and the grace ago.
 * The dynamic twin of `decisionOutlivesKey`; a list of keys has no ends.
 */
export function recordOutlivesKey(keys: NAKeys, publicKey: string, now: string | Date): boolean {
  if (!(keys instanceof NAKeyHistory)) return false;
  const until = keys.vouchesUntilMicros(publicKey);
  return until !== null && at(now) >= until;
}

/**
 * The NA keys a record dated `time` may be signed with and that still vouch
 * at `now` (1.8.0): `naKeysAt` without the keys whose horizon has passed.
 */
export function naKeysVouchingAt(keys: NAKeys, time: string | Date | null, now: string | Date): string[] {
  return naKeysAt(keys, time).filter(k => !recordOutlivesKey(keys, k, now));
}

/**
 * Whether `signedBy` holds for an NA key valid at `time` (v1.5.0): `ok`;
 * `na_key_not_valid_at_time` when only another key of the history signed it;
 * otherwise `invalid_signature`.
 */
export function naSignatureAt(
  signedBy: (keys: readonly string[]) => boolean,
  keys: NAKeys,
  time: string | Date | null,
): 'ok' | 'na_key_not_valid_at_time' | 'invalid_signature' {
  const valid = naKeysAt(keys, time);
  if (signedBy(valid)) return 'ok';
  const others = naKeysAt(keys, null).filter(k => !valid.includes(k));
  return others.length > 0 && signedBy(others) ? 'na_key_not_valid_at_time' : 'invalid_signature';
}

/** The form both signers sign: every field but `signatures`, an absent previous digest left out. */
export function successionCanonical(record: KeySuccessionRecord): string {
  return receivedCanonical('KeySuccessionRecord', record as unknown as Record<string, unknown>);
}

/** SHA-256 of the signed form; the next succession links to it. */
export function successionDigest(record: KeySuccessionRecord): string {
  return createHash('sha256').update(successionCanonical(record), 'utf-8').digest('hex');
}

/** True when one of the record's signatures verifies with `publicKey`. */
export function successionSignedBy(record: KeySuccessionRecord, publicKey: string): boolean {
  return signedAsReceived('KeySuccessionRecord', record, [publicKey]);
}

/** True when `value` is a base64 Ed25519 public key (32 bytes). */
export function validPublicKey(value: unknown): boolean {
  if (typeof value !== 'string' || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return false;
  return Buffer.from(value, 'base64').length === 32;
}

export interface KeyHistoryFailure {
  /** The position of the refused key: 1 for the genesis block. */
  key_sequence: number | null;
  reason: string;
  detail: string;
}

export interface KeyHistoryVerification {
  verified: boolean;
  /** The accepted history; null when anything was refused. */
  history: NAKeyHistory | null;
  failures: KeyHistoryFailure[];
}

/**
 * Why a genesis block is refused, or null: it does not parse
 * (`genesis_invalid`), names another root key than the one held
 * (`genesis_root_mismatch`), carries a field this SDK does not know or is not
 * in canonical form, signed so by the root key (`unknown_field`,
 * `non_canonical_form`), or no signature over it as received verifies with
 * that key (`genesis_invalid_signature`).
 */
export function genesisRefusal(raw: unknown, rootPublicKey?: string | null): string | null {
  if (!isObject(raw) || !validGenesis(withoutUnknownFields('GenesisBlock', raw))) return 'genesis_invalid';
  const root = rootPublicKey || (raw['root_public_key'] as string);
  if (raw['root_public_key'] !== root) return 'genesis_root_mismatch';
  const form = strictRefusal('GenesisBlock', raw, [root]);
  if (form === 'unknown_field' || form === 'non_canonical_form') return form;
  return form === null && signedAsReceived('GenesisBlock', raw, [root]) ? null : 'genesis_invalid_signature';
}

function genesisKey(genesis: GenesisBlock): NAKey {
  return {
    key_sequence: 1, key_id: null, public_key: genesis.network_authority.public_key, valid_from: null,
    succeeded_at: null, valid_to: pythonIso(genesis.network_authority.valid_to), valid_to_enforced: false,
  };
}

/** The key one succession must succeed, and what it is checked against. */
export interface SuccessionContext {
  previous: NAKey;
  previousDigest: string | null;
  sovereignId: string;
  rootPublicKey: string;
  heldKeys: readonly string[];
  /** False when the NA checks a record before it countersigns it. Default true. */
  requirePreviousSignature?: boolean;
}

/** The record parsed with its unknown fields set aside, or null (`payload_invalid`). */
function parsedSuccession(raw: unknown): KeySuccessionRecord | null {
  if (!isObject(raw)) return null;
  const known = withoutUnknownFields('KeySuccessionRecord', raw);
  return validKeySuccession(known) ? known as unknown as KeySuccessionRecord : null;
}

/**
 * Why one succession record is refused, or null, in the contract's order:
 * `payload_invalid` (its unknown fields set aside); `unknown_field` (signed so
 * by one of its signers) or `invalid_signature`; `non_canonical_form`;
 * `succession_sovereign_mismatch`; `succession_chain_break` (not the next
 * position, not the current key as the previous one, or not the previous
 * succession's digest); `succession_key_reused` (a key the history held, or
 * the root key); `succession_backdated` (issued after it takes effect);
 * `succession_not_increasing`; `succession_after_expiry`;
 * `succession_invalid_root_signature`; `succession_invalid_new_key_signature`;
 * `succession_invalid_previous_signature`.
 */
export function successionRefusal(raw: unknown, context: SuccessionContext): string | null {
  const { previous, rootPublicKey } = context;
  const parsed = parsedSuccession(raw);
  if (parsed === null) return 'payload_invalid';
  const signers = [rootPublicKey, previous.public_key];
  if (validPublicKey(parsed.new_public_key)) signers.push(parsed.new_public_key);
  const form = strictRefusal('KeySuccessionRecord', raw, signers);
  if (form !== null) return form;
  const record = raw as KeySuccessionRecord;
  if (record.sovereign_id !== context.sovereignId) return 'succession_sovereign_mismatch';
  if (record.key_sequence !== previous.key_sequence + 1 || record.previous_public_key !== previous.public_key
    || (record.previous_succession_digest ?? null) !== context.previousDigest) {
    return 'succession_chain_break';
  }
  if (!validPublicKey(record.new_public_key) || context.heldKeys.includes(record.new_public_key)
    || record.new_public_key === rootPublicKey) {
    return 'succession_key_reused';
  }
  if (at(record.issued_at) > at(record.effective_at)) return 'succession_backdated';
  const effective = at(record.effective_at);
  if ((previous.valid_from !== null && effective <= at(previous.valid_from)) || at(record.new_valid_to) <= effective) {
    return 'succession_not_increasing';
  }
  if (previous.valid_to_enforced && previous.valid_to !== null && effective > at(previous.valid_to)) {
    return 'succession_after_expiry';
  }
  if (!successionSignedBy(record, rootPublicKey)) return 'succession_invalid_root_signature';
  if (!successionSignedBy(record, record.new_public_key)) return 'succession_invalid_new_key_signature';
  if ((context.requirePreviousSignature ?? true) && !successionSignedBy(record, previous.public_key)) {
    return 'succession_invalid_previous_signature';
  }
  return null;
}

/** The key windows of a genesis key and its successions, in order (their signatures checked elsewhere). */
function buildKeys(genesis: NAKey, successions: readonly KeySuccessionRecord[]): NAKey[] {
  const keys = [genesis];
  for (const record of successions) {
    const previous = keys[keys.length - 1]!;
    const effective = pythonIso(record.effective_at);
    keys[keys.length - 1] = { ...previous, key_id: previous.key_id ?? record.previous_key_id, succeeded_at: effective };
    keys.push({
      key_sequence: record.key_sequence, key_id: record.new_key_id, public_key: record.new_public_key,
      valid_from: effective, succeeded_at: null, valid_to: pythonIso(record.new_valid_to), valid_to_enforced: true,
    });
  }
  return keys;
}

/**
 * Verify a genesis block and its successions, in order, and build the key
 * history. `rootPublicKey` is the root key the verifier holds out of band;
 * without it the genesis block's own root key is used. Keys in the records
 * prove nothing by themselves: the history is accepted only from the root key
 * down, and nothing after the first refused record is accepted.
 */
export function verifyKeyHistory(
  genesis: unknown,
  successions: readonly unknown[],
  rootPublicKey?: string | null,
): KeyHistoryVerification {
  const result: KeyHistoryVerification = { verified: true, history: null, failures: [] };
  const fail = (keySequence: number | null, reason: string) => {
    result.verified = false;
    result.failures.push({ key_sequence: keySequence, reason, detail: '' });
    return result;
  };
  const refusal = genesisRefusal(genesis, rootPublicKey);
  if (refusal !== null) return fail(1, refusal);
  const block = genesis as GenesisBlock;
  const root = block.root_public_key;
  const first = genesisKey(block);
  const records: KeySuccessionRecord[] = [];
  let keys = [first];
  let previousDigest: string | null = null;
  for (const raw of successions) {
    const previous = keys[keys.length - 1]!;
    const reason = successionRefusal(raw, {
      previous, previousDigest, sovereignId: block.network_name, rootPublicKey: root, heldKeys: keys.map(k => k.public_key),
    });
    if (reason !== null) {
      const parsed = parsedSuccession(raw);
      return fail(parsed !== null ? parsed.key_sequence : previous.key_sequence + 1, reason);
    }
    const record = raw as KeySuccessionRecord;
    records.push(record);
    keys = buildKeys(first, records);
    previousDigest = successionDigest(record);
  }
  result.history = new NAKeyHistory(block.network_name, root, buildKeys(first, records), records);
  return result;
}

/** `GET /na/key-history`: everything a verifier needs, given the root key it holds. */
export interface KeyHistoryView {
  sovereign_id: string;
  /** The root key the NA names: compare it with the one you hold, never trust it alone. */
  root_public_key: string | null;
  handover_seconds: number;
  genesis: GenesisBlock;
  successions: KeySuccessionRecord[];
  keys: Array<NAKey & { current: boolean }>;
  signing_key_sequence: number | null;
  /**
   * 1.8.0: the NA's vouching grace (`NA_SUCCESSION_VOUCHING_GRACE_SECONDS`).
   * Unsigned: `verifyKeyHistoryView` takes it only to shorten the grace.
   */
  vouching_grace_seconds?: number;
}

/**
 * Verify a key history the NA served (`getKeyHistory()`) from the root key
 * held out of band: the served `keys` and `root_public_key` are ignored and
 * the history is rebuilt from the genesis block and successions.
 */
export function verifyKeyHistoryView(view: KeyHistoryView, rootPublicKey: string): KeyHistoryVerification {
  const successions = isObject(view) && Array.isArray(view.successions) ? view.successions : [];
  const result = verifyKeyHistory(isObject(view) ? view.genesis : undefined, successions, rootPublicKey);
  // 1.8.0: the NA's grace hint, unsigned, can only shorten the grace (a missing or unreadable one keeps it).
  const hint = isObject(view) ? (view as unknown as Record<string, unknown>)['vouching_grace_seconds'] : undefined;
  if (result.history !== null && typeof hint === 'number' && Number.isFinite(hint) && hint >= 0) {
    result.history = result.history.withVouchingGrace(hint);
  }
  return result;
}
