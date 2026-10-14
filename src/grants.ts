/**
 * Pre-issued grants (Genesis Mesh 1.6.0, Stage 5): the records and the rules
 * every implementation applies to them.
 *
 * Break-glass (1.3.0) records a change made while the Network Authority (NA)
 * cannot be reached and judges it afterwards. A grant authorises it
 * beforehand: the NA signs, in advance, a bounded authorisation one holder may
 * use while the NA is unreachable, after checking that every policy that
 * applies allows every request the grant permits.
 *
 * - `CapabilityGrant` (entry kind `grant`, NA-signed): one bearer key, the
 *   capabilities, a basis, a validity of at most 24 hours, a budget of uses
 *   and a closed parameter envelope.
 * - `TimeToken` (NA-signed): a time the NA signed for the holder, bound to the
 *   head of its use chain when it asked. A use is never dated before it, and
 *   only so many uses may cite one.
 * - `TimeTokenRequest` (beta, signed by the bearer key): the holder's request
 *   for a time token.
 * - `GrantExecutionEvidence` (entry kind `grant_execution`, signed by the
 *   bearer key): one use, in a per-grant use chain. The NA assigns it its
 *   resource position when it admits it.
 * - `GrantRevocationRecord` (entry kind `grant_revocation`, NA-signed).
 *
 * Each record signs every field but `signature`; an absent optional field is
 * left out, at the top level and for a time token's `use_head_digest` nested
 * in a use. The forms are frozen from 1.6.0 and match the Python reference
 * byte for byte (conformance suite `grants`).
 *
 * Numbers in an envelope follow one rule everywhere: an integral number is an
 * integer (`5.0` is `5`), integers fit 64 bits, comparisons are exact,
 * booleans are never numbers, and set membership is type-strict (`true` is
 * not `1`, `1` is `1.0`).
 */

import { createHash, randomUUID } from 'node:crypto';
import { checkSignable, compareCodePoints, signCanonical, verifyCanonical, type Signer } from './auth.js';
import { GenesisMeshError } from './errors.js';
import { naKeysAt, type NAKeys } from './key-history.js';
import { metadataProblem, outOfBandCanonical, timeOf, wire } from './out-of-band.js';
import {
  nonCanonicalFields, receivedCanonical, signedAsReceived, unknownFields, withoutUnknownFields,
} from './strict.js';
import { isObject, timestamp, timestampMicros } from './validation.js';
import type { AppliedPolicy, GateResult, ResourceAction, Signature } from './types.js';

// ── Limits ───────────────────────────────────────────────────────────────────

/** The longest a grant may be valid, whatever the NA's configuration. */
export const GRANT_MAX_VALIDITY_SECONDS = 86_400;
/** The largest budget a grant may carry. */
export const GRANT_MAX_USES = 10_000;
/** The most uses one time token may anchor. */
export const GRANT_MAX_USES_PER_TIME_TOKEN = 1_000;
/** How far a use may be dated after the time its entry is recorded (fixed, so every verifier applies one rule). */
export const GRANT_CLOCK_SKEW_SECONDS = 300;
/** Most capabilities and envelope parameters one grant may name. */
export const MAX_GRANT_CAPABILITIES = 16;
export const MAX_ENVELOPE_PARAMETERS = 64;
/** Most values a `one_of` or `subset_of` may list. */
export const MAX_ENVELOPE_VALUES = 256;

/** An envelope parameter's name: one segment of `request_parameters`. */
const PARAMETER_NAME = /^[A-Za-z0-9_-]{1,64}$/;
const MIN_INTEGER = -(2n ** 63n);
const MAX_INTEGER = 2n ** 64n - 1n;
const SKEW_MICROS = GRANT_CLOCK_SKEW_SECONDS * 1_000_000;

// ── Records ──────────────────────────────────────────────────────────────────

/** A number as an envelope holds it: a `bigint` for an integer beyond 2^53. */
export type GrantNumber = number | bigint;
/** A scalar an envelope compares type-strictly. */
export type GrantScalar = string | boolean | GrantNumber | null;

export type GrantBasisKind = 'agreement' | 'attestation';
export type GrantRevocationReason =
  'operator' | 'attestation_revoked' | 'policy_deactivated' | 'policy_activated' | 'bearer_key_retired';
export type GrantUseOutcome = 'success' | 'failure' | 'partial';
/** How a gate was decided over a grant's whole envelope and validity. */
export type GrantGateDecision = 'pass' | 'may_fail' | 'undecidable';

/** A typed numeric range: `integer` (integral numbers) or `number` (any finite number) within the bounds. */
export interface NumericRange {
  number_type: 'integer' | 'number';
  minimum: GrantNumber;
  maximum: GrantNumber;
  exclusive_minimum: boolean;
  exclusive_maximum: boolean;
}

/**
 * One parameter a grant's uses may carry: exactly one of `one_of` (a finite
 * set of scalars), `subset_of` (a list of strings drawn from a set) and
 * `number_range`. `required` (default true): every use carries it.
 */
export interface EnvelopeParameter {
  required: boolean;
  one_of: GrantScalar[] | null;
  subset_of: string[] | null;
  number_range: NumericRange | null;
}

/** An envelope parameter as an issuance request may give it: the defaults may be left out. */
export interface EnvelopeParameterInput {
  required?: boolean;
  one_of?: GrantScalar[] | null;
  subset_of?: string[] | null;
  number_range?: {
    number_type: 'integer' | 'number';
    minimum: GrantNumber;
    maximum: GrantNumber;
    exclusive_minimum?: boolean;
    exclusive_maximum?: boolean;
  } | null;
}

/** How one gate of an applied policy was decided over a grant's envelope. */
export interface GrantGateOutcome {
  capability: string;
  policy_id: string;
  policy_version: number;
  gate_id: string;
  gate_type: string;
  mode: 'enforce' | 'observe';
  outcome: GrantGateDecision;
  detail: string;
}

/** The policy versions a grant was checked against, in resolution order. */
export interface GrantPolicyBinding {
  policies: AppliedPolicy[];
  policy_set_digest: string;
  gate_outcomes: GrantGateOutcome[];
  registry_gate_types: string[];
}

/** A bounded authorisation the NA signs in advance for one bearer key. */
export interface CapabilityGrant {
  grant_id: string;
  bearer_key_id: string;
  bearer_public_key: string;
  bearer_sovereign_id: string;
  capabilities: string[];
  basis_kind: GrantBasisKind;
  basis_id: string;
  /** SHA-256 of the basis's signed form. */
  basis_digest: string;
  requester_sovereign_id: string;
  provider_sovereign_id: string;
  valid_from: string;
  valid_until: string;
  max_uses: number;
  max_uses_per_time_token: number;
  parameter_envelope: Record<string, EnvelopeParameter>;
  basis_checks: GateResult[];
  policy_binding: GrantPolicyBinding;
  issued_at: string;
  issuer_sovereign_id: string;
  issued_by: string;
  signature?: Signature | null;
}

/**
 * A time the NA signed for a grant's holder, bound to the head of its use
 * chain: `use_sequence` uses made, the last one's digest `use_head_digest`
 * (left out before the first use).
 */
export interface TimeToken {
  time_token_id: string;
  grant_id: string;
  use_sequence: number;
  use_head_digest?: string;
  issued_at: string;
  issuer_sovereign_id: string;
  issued_by: string;
  signature?: Signature | null;
}

/** A holder's request for a time token, signed by the grant's bearer key (beta). */
export interface TimeTokenRequest {
  grant_id: string;
  use_sequence: number;
  use_head_digest?: string;
  requested_at: string;
  signature?: Signature | null;
}

/** One use of a grant, signed by its bearer key. */
export interface GrantExecutionEvidence {
  use_id: string;
  grant_id: string;
  /** SHA-256 of the grant's signed form. */
  grant_digest: string;
  use_sequence: number;
  /** The previous use's digest; left out for the first use. */
  prev_use_digest?: string;
  executor_sovereign_id: string;
  capability: string;
  request_parameters: Record<string, unknown>;
  resource_id?: string;
  resource_action?: ResourceAction;
  executed_at: string;
  /** The latest time token the holder saw, exactly as the NA signed it. */
  time_token: TimeToken;
  outcome: GrantUseOutcome;
  outcome_detail?: string;
  execution_parameters: Record<string, unknown>;
  signature?: Signature | null;
}

/** The NA's revocation of a grant from `revoked_at`. */
export interface GrantRevocationRecord {
  revocation_id: string;
  grant_id: string;
  grant_digest: string;
  reason: GrantRevocationReason;
  detail?: string;
  revoked_by?: string;
  revoked_at: string;
  issuer_sovereign_id: string;
  issued_by: string;
  signature?: Signature | null;
}

/** Why a use is refused at admission, in the order the NA checks; each verifier names the same. */
export const GRANT_USE_REJECTION_CODES = [
  'grant_use_malformed',
  'grant_not_found',
  'grant_use_invalid_signature',
  'grant_bearer_mismatch',
  'grant_use_secret_material',
  'grant_bearer_key_retired',
  'grant_mismatch',
  'grant_use_conflict',
  'grant_use_chain_gap',
  'grant_use_chain_mismatch',
  'grant_capability_mismatch',
  'grant_envelope_mismatch',
  'grant_budget_exhausted',
  'grant_time_token_invalid',
  'grant_time_token_mismatch',
  'grant_time_token_regressed',
  'grant_time_token_exhausted',
  'grant_use_before_time_token',
  'grant_use_out_of_order',
  'grant_use_outside_validity',
  'grant_use_in_future',
  'grant_use_uploaded_late',
  'grant_revoked',
] as const;
export type GrantUseRejectionCode = (typeof GRANT_USE_REJECTION_CODES)[number];

/**
 * Refusals of an authentic use the NA keeps as a quarantine entry: the use
 * happened, and no retry overcomes them. Not a chain gap (the holder uploads
 * the earlier uses first) nor secret material (never stored).
 */
export const QUARANTINED_USE_CODES: ReadonlySet<string> = new Set([
  'grant_bearer_mismatch', 'grant_bearer_key_retired', 'grant_mismatch', 'grant_use_conflict',
  'grant_use_chain_mismatch', 'grant_capability_mismatch', 'grant_envelope_mismatch', 'grant_budget_exhausted',
  'grant_time_token_invalid', 'grant_time_token_mismatch', 'grant_time_token_regressed',
  'grant_time_token_exhausted', 'grant_use_before_time_token', 'grant_use_out_of_order',
  'grant_use_outside_validity', 'grant_use_in_future', 'grant_use_uploaded_late', 'grant_revoked',
]);

/**
 * Thrown before signing when a record would be refused: an envelope the NA
 * would not read (`invalid_grant_envelope`), a use or request its model does
 * not take (`grant_use_malformed`, `time_token_request_malformed`) or a use
 * carrying secret material (`grant_use_secret_material`). JSON the NA would
 * refuse to read throws `StrictJsonError` instead.
 */
export class GrantRecordError extends GenesisMeshError {
  constructor(message: string, code: string) {
    super(message, code, 0);
    this.name = 'GrantRecordError';
  }
}

// ── Numbers and sets ─────────────────────────────────────────────────────────

/** A finite number (never a boolean), or an integer read as a `bigint`. */
function isNumber(value: unknown): value is GrantNumber {
  return (typeof value === 'number' && Number.isFinite(value)) || typeof value === 'bigint';
}

function isIntegral(value: GrantNumber): boolean {
  return typeof value === 'bigint' || Number.isInteger(value);
}

/** A scalar an envelope may hold: null, a string, a boolean or a number. */
function isScalar(value: unknown): value is GrantScalar {
  return value === null || typeof value === 'string' || typeof value === 'boolean' || isNumber(value);
}

/**
 * A number as an envelope holds it: an integral number as an integer (`5.0`
 * is `5`; a `bigint` beyond 2^53), within 64 bits. Throws for a boolean, a
 * non-finite number or an integer beyond 64 bits.
 */
export function normalizeNumber(value: unknown): GrantNumber {
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new RangeError('numbers must be finite');
    if (!Number.isInteger(value)) return value;
  } else if (typeof value !== 'bigint') {
    throw new TypeError('a number is expected');
  }
  const integer = BigInt(value);
  if (integer < MIN_INTEGER || integer > MAX_INTEGER) throw new RangeError('integers must fit in 64 bits');
  const small = Number(integer);
  return Number.isSafeInteger(small) ? small : integer;
}

function normalizeScalar(value: GrantScalar): GrantScalar {
  return value === null || typeof value === 'string' || typeof value === 'boolean' ? value : normalizeNumber(value);
}

/** A type-strict identity for a scalar: `true` is not `1`, `"1"` is not `1`, `1` is `1.0`. */
function scalarKey(value: GrantScalar): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return `boolean:${value}`;
  if (typeof value === 'string') return `string:${value}`;
  // Exact: an integral value by its digits (a double and a bigint alike), any other by its shortest form.
  return `number:${isIntegral(value) ? BigInt(value).toString() : String(value)}`;
}

/** Type-strict scalar equality (`true` is not `1`, `"1"` is not `1`, `1` is `1.0`); exact for numbers. */
export function scalarEquals(a: unknown, b: unknown): boolean {
  return isScalar(a) && isScalar(b) && scalarKey(a) === scalarKey(b);
}

/** `a < b`, `a == b` or `a > b` for numbers, exactly (a double and a `bigint` compare by value). */
function compare(a: GrantNumber, b: GrantNumber): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** (lowest value, attained, highest value, attained) of a range; an integer range's ends are integers. */
function bounds(range: NumericRange): [GrantNumber, boolean, GrantNumber, boolean] {
  if (range.number_type === 'integer') {
    const low = BigInt(range.minimum) + (range.exclusive_minimum ? 1n : 0n);
    const high = BigInt(range.maximum) - (range.exclusive_maximum ? 1n : 0n);
    return [low, true, high, true];
  }
  return [range.minimum, !range.exclusive_minimum, range.maximum, !range.exclusive_maximum];
}

/** Whether a value is within a range: a number (never a boolean), integral for an integer range. */
export function inRange(value: unknown, range: NumericRange): boolean {
  if (!isNumber(value)) return false;
  if (range.number_type === 'integer' && !isIntegral(value)) return false;
  const [low, lowIn, high, highIn] = bounds(range);
  const above = compare(value, low);
  const below = compare(value, high);
  return (above > 0 || (above === 0 && lowIn)) && (below < 0 || (below === 0 && highIn));
}

const PARAMETER_FIELDS = new Set(['required', 'one_of', 'subset_of', 'number_range']);
const RANGE_FIELDS = new Set(['number_type', 'minimum', 'maximum', 'exclusive_minimum', 'exclusive_maximum']);

function numericRange(raw: unknown): NumericRange {
  if (!isObject(raw) || Object.keys(raw).some(k => !RANGE_FIELDS.has(k))) {
    throw new Error('number_range takes number_type, minimum, maximum, exclusive_minimum and exclusive_maximum');
  }
  const type = raw['number_type'];
  if (type !== 'integer' && type !== 'number') throw new Error('number_type is integer or number');
  const flag = (name: string): boolean => {
    const value = Object.hasOwn(raw, name) ? raw[name] : false;
    if (typeof value !== 'boolean') throw new Error(`${name} is a boolean`);
    return value;
  };
  const range: NumericRange = {
    number_type: type,
    minimum: normalizeNumber(Object.hasOwn(raw, 'minimum') ? raw['minimum'] : undefined),
    maximum: normalizeNumber(Object.hasOwn(raw, 'maximum') ? raw['maximum'] : undefined),
    exclusive_minimum: flag('exclusive_minimum'),
    exclusive_maximum: flag('exclusive_maximum'),
  };
  if (type === 'integer') {
    if (!isIntegral(range.minimum) || !isIntegral(range.maximum)) throw new Error('an integer range has integer bounds');
    const [low, , high] = bounds(range);
    if (compare(low, high) > 0) throw new Error('the range holds no integer');
  } else {
    const order = compare(range.minimum, range.maximum);
    if (order > 0 || (order === 0 && (range.exclusive_minimum || range.exclusive_maximum))) {
      throw new Error('the range holds no number');
    }
  }
  return range;
}

/**
 * An envelope parameter as the reference reads it, normalized (defaults
 * filled in, integral numbers as integers), or throws `GrantRecordError`
 * (`invalid_grant_envelope`) naming why.
 */
export function envelopeParameter(raw: unknown): EnvelopeParameter {
  try {
    if (!isObject(raw)) throw new Error('an envelope parameter is an object');
    const unknown = Object.keys(raw).filter(k => !PARAMETER_FIELDS.has(k));
    if (unknown.length > 0) throw new Error(`unknown field ${unknown.sort(compareCodePoints).join(', ')}`);
    const given = (name: string) => (Object.hasOwn(raw, name) ? raw[name] : null) ?? null;
    const required = Object.hasOwn(raw, 'required') ? raw['required'] : true;
    if (typeof required !== 'boolean') throw new Error('required is a boolean');
    let oneOf: GrantScalar[] | null = null;
    const rawOneOf = given('one_of');
    if (rawOneOf !== null) {
      if (!Array.isArray(rawOneOf) || rawOneOf.length < 1 || rawOneOf.length > MAX_ENVELOPE_VALUES) {
        throw new Error(`one_of is a list of 1 to ${MAX_ENVELOPE_VALUES} scalars`);
      }
      if (!rawOneOf.every(isScalar)) throw new Error('one_of holds scalars only');
      oneOf = rawOneOf.map(normalizeScalar);
      if (new Set(oneOf.map(scalarKey)).size !== oneOf.length) throw new Error('one_of repeats a value');
    }
    let subsetOf: string[] | null = null;
    const rawSubset = given('subset_of');
    if (rawSubset !== null) {
      if (!Array.isArray(rawSubset) || rawSubset.length < 1 || rawSubset.length > MAX_ENVELOPE_VALUES
        || !rawSubset.every(v => typeof v === 'string')) {
        throw new Error(`subset_of is a list of 1 to ${MAX_ENVELOPE_VALUES} strings`);
      }
      subsetOf = [...rawSubset];
      if (new Set(subsetOf).size !== subsetOf.length) throw new Error('subset_of repeats a value');
    }
    const rawRange = given('number_range');
    const range = rawRange === null ? null : numericRange(rawRange);
    if ([oneOf, subsetOf, range].filter(v => v !== null).length !== 1) {
      throw new Error('give exactly one of one_of, subset_of and number_range');
    }
    return { required, one_of: oneOf, subset_of: subsetOf, number_range: range };
  } catch (err) {
    if (err instanceof GrantRecordError) throw err;
    throw new GrantRecordError(`invalid envelope parameter: ${(err as Error).message}`, 'invalid_grant_envelope');
  }
}

/** Why a parameter envelope cannot be a grant's (its names, its size, each parameter), or null. */
export function envelopeShapeProblem(envelope: unknown): string | null {
  if (!isObject(envelope)) return 'parameter_envelope is an object of parameter names';
  const names = Object.keys(envelope);
  if (names.length > MAX_ENVELOPE_PARAMETERS) return `at most ${MAX_ENVELOPE_PARAMETERS} envelope parameters`;
  for (const name of names) {
    if (!PARAMETER_NAME.test(name)) return 'envelope parameter names match [A-Za-z0-9_-]{1,64}';
    try {
      envelopeParameter(envelope[name]);
    } catch (err) {
      return `${name}: ${(err as Error).message}`;
    }
  }
  return null;
}

/** Why one parameter value is outside its envelope parameter, or null. */
export function parameterValueProblem(name: string, value: unknown, spec: EnvelopeParameter): string | null {
  if (spec.one_of !== null) {
    if (!isScalar(value)) return `request_parameters.${name} is not a scalar`;
    const keys = new Set(spec.one_of.map(scalarKey));
    return keys.has(scalarKey(value)) ? null : `request_parameters.${name} is not one of its values`;
  }
  if (spec.subset_of !== null) {
    if (!Array.isArray(value) || !value.every(v => typeof v === 'string')) {
      return `request_parameters.${name} is not a list of strings`;
    }
    const allowed = new Set(spec.subset_of);
    return value.every(v => allowed.has(v)) ? null : `request_parameters.${name} has an item outside its set`;
  }
  return inRange(value, spec.number_range!) ? null : `request_parameters.${name} is outside its range`;
}

/**
 * Why a use's `request_parameters` are outside a grant's closed envelope, or
 * null (`grant_envelope_mismatch` otherwise). A parameter the envelope does
 * not name is refused; a required one must be present; a present one must be
 * inside its parameter. The envelope's parameters are read as
 * `envelopeParameter` reads them.
 */
export function envelopeProblem(envelope: Record<string, unknown>, parameters: unknown): string | null {
  if (!isObject(parameters)) return 'request_parameters is not an object';
  const outside = Object.keys(parameters).filter(k => !Object.hasOwn(envelope, k)).sort(compareCodePoints);
  if (outside.length > 0) return `request_parameters.${outside[0]} is not in the envelope`;
  for (const name of Object.keys(envelope).sort(compareCodePoints)) {
    let spec: EnvelopeParameter;
    try {
      spec = envelopeParameter(envelope[name]);
    } catch {
      return `parameter_envelope.${name} is not an envelope parameter`;
    }
    if (!Object.hasOwn(parameters, name)) {
      if (spec.required) return `request_parameters.${name} is required`;
      continue;
    }
    const problem = parameterValueProblem(name, parameters[name], spec);
    if (problem !== null) return problem;
  }
  return null;
}

// ── Shapes (as the reference's models read them) ────────────────────────────

type Check = (value: unknown) => boolean;
const own = (v: Record<string, unknown>, k: string): unknown => (Object.hasOwn(v, k) ? v[k] : undefined);
const absent = (v: unknown) => v === undefined || v === null;
const text = (max: number, min = 1): Check => v => {
  if (typeof v !== 'string') return false;
  const length = Array.from(v).length;
  return length >= min && length <= max;
};
const sha256 = text(64, 64);
const string: Check = v => typeof v === 'string';
const boolean: Check = v => typeof v === 'boolean';
const between = (min: number, max: number): Check => v => Number.isSafeInteger(v) && (v as number) >= min && (v as number) <= max;
const integer: Check = v => Number.isSafeInteger(v);
const utc: Check = v => timestamp(v) && /(?:Z|[+-]00:00)$/.test(v as string);
const oneOf = (...values: unknown[]): Check => v => values.includes(v);
const optional = (check: Check): Check => v => absent(v) || check(v);
/** Fields the reference fills when absent: left out, the record is not in its form (`non_canonical_form`). */
const filled = (check: Check): Check => v => v === undefined || check(v);
const list = (check: Check, min = 0, max = Infinity): Check => v =>
  Array.isArray(v) && v.length >= min && v.length <= max && v.every(check);
const shape = (fields: Record<string, Check>): Check => v =>
  isObject(v) && Object.entries(fields).every(([k, check]) => check(own(v, k)));
const signatureShape: Check = v => v === undefined || v === null || shape({ key_id: string, sig: string })(v);
const action = oneOf('create', 'rotate', 'revoke', 'update', 'delete');

const gateResult = shape({ gate_name: string, passed: boolean, detail: string });
const appliedPolicy = shape({ policy_id: string, version: integer, policy_digest: string, signed_by: string });
const gateOutcome = shape({
  capability: string, policy_id: string, policy_version: integer, gate_id: string, gate_type: string,
  mode: oneOf('enforce', 'observe'), outcome: oneOf('pass', 'may_fail', 'undecidable'), detail: text(1024, 0),
});
const policyBinding = shape({
  policies: filled(list(appliedPolicy)), policy_set_digest: string, gate_outcomes: filled(list(gateOutcome)),
  registry_gate_types: filled(list(string)),
});
const capabilities: Check = v => list(c => typeof c === 'string' && text(256)(c) && !c.includes('*'), 1,
  MAX_GRANT_CAPABILITIES)(v) && new Set(v as string[]).size === (v as string[]).length;

const grantFields = shape({
  grant_id: filled(text(128)), bearer_key_id: text(256), bearer_public_key: text(256), bearer_sovereign_id: text(256),
  capabilities, basis_kind: oneOf('agreement', 'attestation'), basis_id: text(128), basis_digest: sha256,
  requester_sovereign_id: text(256), provider_sovereign_id: text(256), valid_from: utc, valid_until: utc,
  max_uses: between(1, GRANT_MAX_USES), max_uses_per_time_token: between(1, GRANT_MAX_USES_PER_TIME_TOKEN),
  parameter_envelope: filled(v => envelopeShapeProblem(v) === null), basis_checks: filled(list(gateResult)),
  policy_binding: policyBinding, issued_at: utc, issuer_sovereign_id: string, issued_by: string,
  signature: signatureShape,
});

/** A grant in the shape the reference reads: a validity of at most 24 hours, each envelope parameter readable. */
export const validGrant: Check = v => {
  if (!grantFields(v)) return false;
  const r = v as Record<string, unknown>;
  const from = timestampMicros(r['valid_from'] as string);
  const until = timestampMicros(r['valid_until'] as string);
  return from < until && until - from <= GRANT_MAX_VALIDITY_SECONDS * 1_000_000;
};

const headFields = (v: Record<string, unknown>) => (own(v, 'use_sequence') === 0) === absent(own(v, 'use_head_digest'));

/** A time token in the shape the reference reads: `use_head_digest` exactly when `use_sequence` is 1 or more. */
export const validTimeToken: Check = v => shape({
  time_token_id: filled(text(128)), grant_id: text(128), use_sequence: between(0, GRANT_MAX_USES),
  use_head_digest: optional(sha256), issued_at: utc, issuer_sovereign_id: string, issued_by: string,
  signature: signatureShape,
})(v) && headFields(v as Record<string, unknown>);

/** A time token request in the shape the reference reads. */
export const validTimeTokenRequest: Check = v => shape({
  grant_id: text(128), use_sequence: between(0, GRANT_MAX_USES), use_head_digest: optional(sha256),
  requested_at: utc, signature: signatureShape,
})(v) && headFields(v as Record<string, unknown>);

/**
 * A grant use in the shape the reference reads: `prev_use_digest` exactly
 * when `use_sequence` is 2 or more, `resource_id` and `resource_action`
 * together, its time token a time token.
 */
export const validGrantUse: Check = v => {
  if (!shape({
    use_id: filled(text(128)), grant_id: text(128), grant_digest: sha256, use_sequence: between(1, GRANT_MAX_USES),
    prev_use_digest: optional(sha256), executor_sovereign_id: text(256), capability: text(256),
    request_parameters: filled(isObject), resource_id: optional(text(256)), resource_action: optional(action),
    executed_at: utc, time_token: validTimeToken, outcome: oneOf('success', 'failure', 'partial'),
    outcome_detail: optional(text(1024, 0)), execution_parameters: filled(isObject), signature: signatureShape,
  })(v)) return false;
  const r = v as Record<string, unknown>;
  return absent(r['resource_id']) === absent(r['resource_action'])
    && (r['use_sequence'] === 1) === absent(r['prev_use_digest']);
};

/** A grant revocation in the shape the reference reads. */
export const validGrantRevocation: Check = shape({
  revocation_id: filled(text(128)), grant_id: text(128), grant_digest: sha256,
  reason: oneOf('operator', 'attestation_revoked', 'policy_deactivated', 'policy_activated', 'bearer_key_retired'),
  detail: optional(text(1024)), revoked_by: optional(text(256)), revoked_at: utc, issuer_sovereign_id: string,
  issued_by: string, signature: signatureShape,
});

// ── Signed forms ─────────────────────────────────────────────────────────────

/** The signed form of a Stage 5 record: every field but `signature`, absent optional fields left out. */
export function grantRecordCanonical(record: object): string {
  return outOfBandCanonical(record);
}

/**
 * SHA-256 of a record's signed form as received, unknown fields set aside:
 * the digest a grant use names its grant by (`grant_digest`) and the previous
 * use by (`prev_use_digest`), as the reference computes it.
 */
export function grantRecordDigest(
  model: 'CapabilityGrant' | 'GrantExecutionEvidence' | 'GrantRevocationRecord' | 'TimeToken' | 'TimeTokenRequest',
  record: object,
): string {
  const body = receivedCanonical(model, withoutUnknownFields(model, record as Record<string, unknown>));
  return createHash('sha256').update(body, 'utf-8').digest('hex');
}

/** `CapabilityGrant.digest()`: what a use's and a revocation's `grant_digest` name. */
export function grantDigest(grant: CapabilityGrant): string {
  return grantRecordDigest('CapabilityGrant', grant);
}

/** `GrantExecutionEvidence.digest()`: what the next use's `prev_use_digest` and a time token's head name. */
export function grantUseDigest(use: GrantExecutionEvidence): string {
  return grantRecordDigest('GrantExecutionEvidence', use);
}

function signedForm(model: string, record: Record<string, unknown>, keys: readonly string[]): boolean {
  const sig = record['signature'] as Signature | null | undefined;
  return !!sig && typeof sig.sig === 'string' && verifyCanonical(outOfBandCanonical(record), sig.sig, keys)
    && unknownFields(model, record).length === 0 && nonCanonicalFields(model, record).length === 0;
}

/** A record signed by one of the NA keys valid at its own time (`field`), in the reference's form, with no unknown field. */
function naSigned(model: string, valid: Check, field: string, record: unknown, naPublicKeys: NAKeys): boolean {
  if (!valid(record)) return false;
  const at = (record as Record<string, unknown>)[field] as string;
  return signedForm(model, record as Record<string, unknown>, naKeysAt(naPublicKeys, at));
}

/**
 * True when a grant is well formed and signed by the NA over the grant as
 * received (given the NA's key history, by the key valid at its `issued_at`),
 * in the reference's form and with no field this SDK does not know.
 */
export function verifyCapabilityGrant(grant: CapabilityGrant, naPublicKeys: NAKeys): boolean {
  return naSigned('CapabilityGrant', validGrant, 'issued_at', grant, naPublicKeys);
}

/** As `verifyCapabilityGrant`, for a time token (read alone, at its `issued_at`). */
export function verifyTimeToken(token: TimeToken, naPublicKeys: NAKeys): boolean {
  return naSigned('TimeToken', validTimeToken, 'issued_at', token, naPublicKeys);
}

/** As `verifyCapabilityGrant`, for a grant revocation (at its `revoked_at`). */
export function verifyGrantRevocation(record: GrantRevocationRecord, naPublicKeys: NAKeys): boolean {
  return naSigned('GrantRevocationRecord', validGrantRevocation, 'revoked_at', record, naPublicKeys);
}

/** True when a grant use is well formed and signed by the bearer key over the use as received. */
export function verifyGrantUse(use: GrantExecutionEvidence, bearerPublicKey: string): boolean {
  return validGrantUse(use) && signedForm('GrantExecutionEvidence', use as unknown as Record<string, unknown>, [bearerPublicKey]);
}

/** True when a time token request is well formed and signed by the bearer key. */
export function verifyTimeTokenRequest(request: TimeTokenRequest, bearerPublicKey: string): boolean {
  return validTimeTokenRequest(request)
    && signedForm('TimeTokenRequest', request as unknown as Record<string, unknown>, [bearerPublicKey]);
}

/** Whether a time token, as received inside a use, carries a signature by one of `keys` (the reference's check). */
export function tokenSignatureValid(rawToken: unknown, keys: readonly string[]): boolean {
  return isObject(rawToken) && signedAsReceived('TimeToken', rawToken, keys);
}

// ── Uses ─────────────────────────────────────────────────────────────────────

/** The use before this one in the grant's chain, as the NA, a verifier or a holder holds it. */
export interface PreviousUse {
  digest: string;
  executed_at: string;
  time_token_id: string;
  time_token_issued_at: string;
  /** How many uses up to and including this one cite its time token (they are consecutive). */
  token_uses: number;
}

/** What `useProblem` checks a use against: whatever the caller holds of its grant and chain. */
export interface UseCheck {
  /** The grant; null skips the checks that need it. */
  grant: CapabilityGrant | null;
  /** The use before it in the chain; null for the first use or when it is not held. */
  previous: PreviousUse | null;
  /** The digest and time of the use the time token names, when held. */
  tokenHead: { digest: string; executed_at: string } | null;
  /** The NA keys valid at the token's `issued_at`. */
  tokenKeys: readonly string[];
  /** The time token as received (default: the use's). */
  rawToken?: unknown;
  /** The grant's revocation recorded before the use. */
  revokedAt: string | null;
  /** The use's time in the store; null before it is stored. */
  recordedAt: string | null;
}

export interface UseProblem {
  code: GrantUseRejectionCode;
  detail: string;
}

function micros(value: string): number {
  return timestampMicros(value);
}

/** A time as the reference prints it: UTC, microseconds when not zero, `Z`. */
function iso(at: number): string {
  const base = new Date(Math.floor(at / 1000)).toISOString().slice(0, 19);
  const fraction = at - Math.floor(at / 1_000_000) * 1_000_000;
  return fraction === 0 ? `${base}Z` : `${base}.${String(fraction).padStart(6, '0')}Z`;
}

/**
 * The first rule a use breaks, or null, in the order every implementation
 * checks (the reference's `use_problem`): the capability, the envelope, the
 * budget, the time token's signature and grant, the token's head, a regressed
 * token, the token's use limit, before the token, out of order, outside the
 * validity, in the future, uploaded late, revoked. Run after the use's
 * signature, bearer key, grant digest and chain position are checked.
 */
export function useProblem(use: GrantExecutionEvidence, check: UseCheck): UseProblem | null {
  const { grant, previous } = check;
  const token = use.time_token;
  const executed = micros(use.executed_at);
  const tokenIssued = micros(token.issued_at);
  if (grant !== null) {
    if (!grant.capabilities.includes(use.capability)) {
      return { code: 'grant_capability_mismatch', detail: `${use.capability} is not one of the grant's capabilities` };
    }
    const problem = envelopeProblem(grant.parameter_envelope, use.request_parameters);
    if (problem !== null) return { code: 'grant_envelope_mismatch', detail: problem };
    if (use.use_sequence > grant.max_uses) {
      return { code: 'grant_budget_exhausted', detail: `use ${use.use_sequence} of a budget of ${grant.max_uses}` };
    }
  }
  const raw = check.rawToken === undefined ? token : check.rawToken;
  if (token.grant_id !== use.grant_id || !tokenSignatureValid(raw, check.tokenKeys)) {
    return { code: 'grant_time_token_invalid', detail: "the time token is not the NA's for this grant" };
  }
  if (token.use_sequence >= use.use_sequence) {
    return {
      code: 'grant_time_token_mismatch',
      detail: `the time token was issued after use ${token.use_sequence}, not before use ${use.use_sequence}`,
    };
  }
  const head = check.tokenHead;
  if (head !== null && (head.digest !== (token.use_head_digest ?? null)
    || micros(head.executed_at) > tokenIssued + SKEW_MICROS)) {
    return { code: 'grant_time_token_mismatch', detail: `use ${token.use_sequence} is not the one the time token names` };
  }
  if (previous !== null) {
    if (tokenIssued < micros(previous.time_token_issued_at)) {
      return { code: 'grant_time_token_regressed', detail: "the time token is older than the previous use's" };
    }
    if (grant !== null && previous.time_token_id === token.time_token_id
      && previous.token_uses >= grant.max_uses_per_time_token) {
      return {
        code: 'grant_time_token_exhausted',
        detail: `${grant.max_uses_per_time_token} uses already cite time token ${token.time_token_id}`,
      };
    }
  }
  if (executed < tokenIssued) {
    return {
      code: 'grant_use_before_time_token',
      detail: `executed at ${iso(executed)}, before the time token's ${iso(tokenIssued)}`,
    };
  }
  if (previous !== null && executed < micros(previous.executed_at)) {
    return { code: 'grant_use_out_of_order', detail: `executed at ${iso(executed)}, before the previous use` };
  }
  if (grant !== null && (executed < micros(grant.valid_from) || executed > micros(grant.valid_until))) {
    return {
      code: 'grant_use_outside_validity',
      detail: `executed at ${iso(executed)}, outside [${iso(micros(grant.valid_from))}, ${iso(micros(grant.valid_until))}]`,
    };
  }
  if (check.recordedAt !== null) {
    const recorded = micros(check.recordedAt);
    if (executed > recorded + SKEW_MICROS) {
      return { code: 'grant_use_in_future', detail: `executed at ${iso(executed)}, after it was recorded at ${iso(recorded)}` };
    }
    if (grant !== null) {
      const validity = micros(grant.valid_until) - micros(grant.valid_from);
      if (recorded - executed > validity) {
        return {
          code: 'grant_use_uploaded_late',
          detail: `recorded at ${iso(recorded)}, longer after it was executed than the grant's validity `
            + `(${Math.floor(validity / 1_000_000)} s)`,
        };
      }
    }
  }
  if (check.revokedAt !== null && executed >= micros(check.revokedAt)) {
    return { code: 'grant_revoked', detail: `the grant was revoked at ${iso(micros(check.revokedAt))}` };
  }
  return null;
}

/** The chain's state after a use (its digest `digest`): what the next use is checked against. */
export function nextPreviousUse(use: GrantExecutionEvidence, digest: string, previous: PreviousUse | null): PreviousUse {
  const token = use.time_token;
  const same = previous !== null && previous.time_token_id === token.time_token_id;
  return {
    digest, executed_at: use.executed_at, time_token_id: token.time_token_id,
    time_token_issued_at: token.issued_at, token_uses: same ? previous.token_uses + 1 : 1,
  };
}

/** Why a use may carry secret material, or null: the metadata guard over its parameters and outcome detail. */
export function useSecretProblem(use: Pick<GrantExecutionEvidence, 'execution_parameters' | 'request_parameters'
  | 'outcome_detail'>): string | null {
  return metadataProblem({
    execution_parameters: use.execution_parameters ?? {},
    request_parameters: use.request_parameters ?? {},
    outcome_detail: use.outcome_detail ?? '',
  });
}

// ── Building and signing (the holder's side) ─────────────────────────────────

export interface GrantUseInput {
  grant: CapabilityGrant;
  /** 1 for the first use of the grant. */
  use_sequence: number;
  /** The previous use (or its digest); null for the first use. */
  previous: GrantExecutionEvidence | string | null;
  capability: string;
  request_parameters?: Record<string, unknown>;
  resource_id?: string;
  resource_action?: ResourceAction;
  executed_at?: Date | string;
  /** The latest time token the holder saw, exactly as received. */
  time_token: TimeToken;
  outcome: GrantUseOutcome;
  outcome_detail?: string;
  execution_parameters?: Record<string, unknown>;
  use_id?: string;
}

/** The unsigned use for `input`, executed by the grant's bearer sovereign. */
export function grantUseRecord(input: GrantUseInput): GrantExecutionEvidence {
  const previous = input.previous;
  const record: GrantExecutionEvidence = {
    use_id: input.use_id ?? randomUUID(),
    grant_id: input.grant.grant_id,
    grant_digest: grantDigest(input.grant),
    use_sequence: input.use_sequence,
    executor_sovereign_id: input.grant.bearer_sovereign_id,
    capability: input.capability,
    request_parameters: input.request_parameters ?? {},
    executed_at: timeOf(input.executed_at ?? new Date(), 'executed_at', 'grant_use_malformed')!,
    time_token: input.time_token,
    outcome: input.outcome,
    execution_parameters: input.execution_parameters ?? {},
  };
  if (previous !== null) record.prev_use_digest = typeof previous === 'string' ? previous : grantUseDigest(previous);
  if (input.resource_id !== undefined) record.resource_id = input.resource_id;
  if (input.resource_action !== undefined) record.resource_action = input.resource_action;
  if (input.outcome_detail !== undefined) record.outcome_detail = input.outcome_detail;
  return record;
}

/**
 * Throw what the NA would refuse an unsigned use for, in its order: JSON it
 * cannot read (`StrictJsonError`), a use its model does not take
 * (`grant_use_malformed`), then secret material (`grant_use_secret_material`).
 */
export function checkGrantUse(record: GrantExecutionEvidence): void {
  checkSignable(record);
  if (!validGrantUse(record)) {
    throw new GrantRecordError('the use does not match the GrantExecutionEvidence model (a field missing, empty, '
      + 'too long or of another type)', 'grant_use_malformed');
  }
  const secret = useSecretProblem(record);
  if (secret !== null) throw new GrantRecordError(secret, 'grant_use_secret_material');
}

/** Build and sign a use with the bearer key's signer; refused first as the NA would refuse it. */
export async function signGrantUse(input: GrantUseInput, signer: Signer): Promise<GrantExecutionEvidence> {
  const record = grantUseRecord(input);
  checkGrantUse(record);
  return wire(record, await signCanonical(grantRecordCanonical(record), signer));
}

export interface TimeTokenRequestInput {
  grant_id: string;
  /** The uses the holder has made (0 before the first). */
  use_sequence: number;
  /** The digest of the last of them; left out for none. */
  use_head_digest?: string | null;
  /** Default: now. Must be within 300 seconds of the NA's clock. */
  requested_at?: Date | string;
}

/** Build and sign a time token request with the bearer key's signer (beta). */
export async function signTimeTokenRequest(input: TimeTokenRequestInput, signer: Signer): Promise<TimeTokenRequest> {
  const request: TimeTokenRequest = {
    grant_id: input.grant_id,
    use_sequence: input.use_sequence,
    requested_at: timeOf(input.requested_at ?? new Date(), 'requested_at', 'time_token_request_malformed')!,
  };
  if (input.use_head_digest !== undefined && input.use_head_digest !== null) request.use_head_digest = input.use_head_digest;
  checkSignable(request);
  if (!validTimeTokenRequest(request)) {
    throw new GrantRecordError('the request does not match the TimeTokenRequest model', 'time_token_request_malformed');
  }
  return wire(request, await signCanonical(grantRecordCanonical(request), signer));
}
