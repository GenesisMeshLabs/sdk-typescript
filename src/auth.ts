/**
 * Key operations for Genesis Mesh: canonical JSON, digests, Ed25519 signing
 * and verification, and admin request authentication.
 *
 * The NA verifies admin requests via four HTTP headers:
 *   X-Admin-Key-Id        - which operator key was used
 *   X-Admin-Signature     - Ed25519(canonicalJson({body,key_id,nonce,timestamp}))
 *   X-Admin-Timestamp     - ISO 8601 UTC timestamp
 *   X-Admin-Nonce         - UUID v4 replay-protection token
 *
 * Canonical JSON matches Python json.dumps(..., sort_keys=True, separators=(",",":"))
 * applied to the value the NA parses: keys recursively sorted, compact output,
 * non-ASCII escaped (ensure_ascii), and non-integer numbers in Python float repr.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';

/** Escape every non-ASCII UTF-16 unit as \uXXXX, as Python's ensure_ascii does. */
function asciiString(value: string): string {
  return JSON.stringify(value).replace(
    /[^\x00-\x7e]/g,
    ch => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0'),
  );
}

function pythonFloatRepr(value: number): string {
  if (Object.is(value, -0)) return '-0.0';
  const [mantissa, expText] = value.toExponential().split('e');
  const exp = Number(expText);
  if (exp >= -4 && exp < 16) {
    const negative = mantissa.startsWith('-');
    const digits = mantissa.replace('-', '').replace('.', '');
    const point = exp + 1;
    let fixed: string;
    if (point <= 0) fixed = '0.' + '0'.repeat(-point) + digits;
    else if (point >= digits.length) fixed = digits + '0'.repeat(point - digits.length) + '.0';
    else fixed = digits.slice(0, point) + '.' + digits.slice(point);
    return (negative ? '-' : '') + fixed;
  }
  const sign = exp < 0 ? '-' : '+';
  return `${mantissa}e${sign}${String(Math.abs(exp)).padStart(2, '0')}`;
}

/**
 * The text Python's json.dumps produces for the value the NA parses from this
 * number's JSON. Integral text stays an int; anything else is a Python float.
 * `pythonFloat` forces float repr for an integral value the NA sent as a float.
 */
function pythonNumber(value: number, pythonFloat = false): string {
  if (!Number.isFinite(value)) throw new Error('canonical JSON cannot encode a non-finite number');
  const text = JSON.stringify(value);
  if (!pythonFloat && /^-?\d+$/.test(text)) return text;
  return pythonFloatRepr(value);
}

/**
 * Holder objects/arrays → keys whose value the NA sent as an integral float
 * (`90.0`). JSON.parse yields the number 90; canonical JSON must emit 90.0 or
 * an NA signature over it would not verify.
 */
const PYTHON_FLOATS = new WeakMap<object, Set<string>>();

/**
 * JSON.parse that remembers integral-valued floats so canonicalJson reproduces
 * them. Use it for any NA JSON that will be verified or digested. Requires
 * JSON.parse source text access (Node.js 22+).
 */
export function parseJson(text: string): unknown {
  return JSON.parse(text, function (this: object, key: string, value: unknown, context?: { source?: string }) {
    if (typeof value === 'number' && Number.isInteger(value) && context?.source && /[.eE]/.test(context.source)) {
      let keys = PYTHON_FLOATS.get(this);
      if (!keys) PYTHON_FLOATS.set(this, (keys = new Set()));
      keys.add(key);
    }
    return value;
  });
}

function canonicalMember(holder: object, key: string, value: unknown): string {
  if (typeof value === 'number') return pythonNumber(value, PYTHON_FLOATS.get(holder)?.has(key) ?? false);
  return canonicalJson(value);
}

/** Python orders strings by Unicode code point, not UTF-16 code unit. */
export function compareCodePoints(a: string, b: string): number {
  const left = Array.from(a, c => c.codePointAt(0)!);
  const right = Array.from(b, c => c.codePointAt(0)!);
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return left.length - right.length;
}

/** Compact sorted JSON, byte-identical to the Python canonical form. */
export function canonicalJson(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'string') return asciiString(value);
  if (typeof value === 'number') return pythonNumber(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (Array.isArray(value)) return '[' + value.map((v, i) => canonicalMember(value, String(i), v)).join(',') + ']';
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).filter(k => record[k] !== undefined).sort(compareCodePoints);
    return '{' + keys.map(k => `${asciiString(k)}:${canonicalMember(record, k, record[k])}`).join(',') + '}';
  }
  throw new Error(`canonical JSON cannot encode a ${typeof value}`);
}

/** SHA-256 hex of a string's UTF-8 bytes. */
export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf-8').digest('hex');
}

/** SHA-256 hex of a value's canonical JSON - every GM `digest()`. */
export function canonicalDigest(value: unknown): string {
  return sha256Hex(canonicalJson(value));
}

/**
 * PKCS8 DER prefix for an Ed25519 private key.
 * Layout: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING <seed> } }
 * Concatenate with the 32-byte seed to form a valid PKCS8 DER buffer.
 */
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/**
 * SPKI DER prefix for an Ed25519 public key.
 * Layout: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { <32-byte key> } }
 */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** Sign raw bytes with an Ed25519 seed (32-byte base64-encoded private key seed). */
export function signBytes(message: Buffer, seedBase64: string): Buffer {
  const seed = Buffer.from(seedBase64, 'base64');
  if (seed.length !== 32) throw new Error('Ed25519 seed must be 32 bytes');
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  return cryptoSign(null, message, privateKey);
}

/** Verify an Ed25519 signature (base64) with a raw 32-byte public key (base64). */
export function verifyBytes(message: Buffer, signatureBase64: string, publicKeyBase64: string): boolean {
  const raw = Buffer.from(publicKeyBase64, 'base64');
  const sig = Buffer.from(signatureBase64, 'base64');
  if (raw.length !== 32 || sig.length !== 64) return false;
  const publicKey = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
  return cryptoVerify(null, message, publicKey, sig);
}

/** Raw 32-byte public key (base64) for an Ed25519 seed (base64). */
export function publicKeyFromSeed(seedBase64: string): string {
  const seed = Buffer.from(seedBase64, 'base64');
  if (seed.length !== 32) throw new Error('Ed25519 seed must be 32 bytes');
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const spki = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  return spki.subarray(ED25519_SPKI_PREFIX.length).toString('base64');
}

/**
 * An Ed25519 signer. `sign` returns the 64-byte signature; it may be async so
 * the key can live in an HSM or a cloud key service.
 */
export interface Signer {
  readonly keyId: string;
  sign(message: Buffer): Buffer | Promise<Buffer>;
}

/** A Signer backed by a raw Ed25519 seed held in memory. */
export function seedSigner(seedBase64: string, keyId: string): Signer {
  return { keyId, sign: (message: Buffer) => signBytes(message, seedBase64) };
}

/** Sign a canonical body with a Signer; returns the GM `{key_id, sig}` pair. */
export async function signCanonical(
  canonical: string,
  signer: Signer,
): Promise<{ key_id: string; sig: string }> {
  const sig = await signer.sign(Buffer.from(canonical, 'utf-8'));
  if (sig.length !== 64) throw new Error('signer returned a signature that is not 64 bytes');
  return { key_id: signer.keyId, sig: Buffer.from(sig).toString('base64') };
}

/** True when `sig` verifies the canonical body under any of the public keys. */
export function verifyCanonical(canonical: string, sig: string, publicKeys: readonly string[]): boolean {
  const message = Buffer.from(canonical, 'utf-8');
  return publicKeys.some(key => verifyBytes(message, sig, key));
}

/**
 * A UTC timestamp in the form Pydantic re-serialises unchanged: microsecond
 * precision, `Z` suffix, fraction omitted when zero. `toISOString()` output
 * (`.561Z`) would come back as `.561000Z` and break a signature over it.
 */
export function pythonTimestamp(date: Date = new Date()): string {
  const iso = date.toISOString();
  const ms = date.getUTCMilliseconds();
  const base = iso.slice(0, 19);
  return ms === 0 ? `${base}Z` : `${base}.${String(ms).padStart(3, '0')}000Z`;
}

export interface AdminHeaders extends Record<string, string> {
  'X-Admin-Key-Id': string;
  'X-Admin-Signature': string;
  'X-Admin-Timestamp': string;
  'X-Admin-Nonce': string;
}

function adminMessage(body: unknown, keyId: string): { canonical: string; timestamp: string; nonce: string } {
  const timestamp = new Date().toISOString();
  const nonce = randomUUID();
  return { canonical: canonicalJson({ body, key_id: keyId, nonce, timestamp }), timestamp, nonce };
}

/** Build the four admin auth headers for a given request body. */
export function buildAdminHeaders(
  body: unknown,
  keyId: string,
  signingKeyBase64: string,
): AdminHeaders {
  const { canonical, timestamp, nonce } = adminMessage(body, keyId);
  const sig = signBytes(Buffer.from(canonical, 'utf-8'), signingKeyBase64);
  return {
    'X-Admin-Key-Id': keyId,
    'X-Admin-Signature': sig.toString('base64'),
    'X-Admin-Timestamp': timestamp,
    'X-Admin-Nonce': nonce,
  };
}

/** Build the four admin auth headers with a Signer (key id taken from the signer). */
export async function buildAdminHeadersWithSigner(body: unknown, signer: Signer): Promise<AdminHeaders> {
  const { canonical, timestamp, nonce } = adminMessage(body, signer.keyId);
  const { sig } = await signCanonical(canonical, signer);
  return {
    'X-Admin-Key-Id': signer.keyId,
    'X-Admin-Signature': sig,
    'X-Admin-Timestamp': timestamp,
    'X-Admin-Nonce': nonce,
  };
}
