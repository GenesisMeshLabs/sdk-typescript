import { describe, expect, it, jest } from '@jest/globals';
import fc from 'fast-check';
import {
  AttestationClient, buildPath, canonicalJson, envelopeShapeProblem, EvidenceStoreClient, parseJson, StrictJsonError,
} from '../src/index.js';
import { compareCodePoints } from '../src/auth.js';
import { checkStrictJson, MAX_DEPTH } from '../src/strict-json.js';
import { buildTransport, mockFetch } from './helpers.js';

/**
 * Property tests (fast-check) for the strict JSON reader, the canonical form and the path
 * segments the clients build. Each property runs GM_PROPERTY_RUNS cases (default 200, a few
 * seconds in all) from a fixed seed, so CI is deterministic: GM_PROPERTY_SEED overrides it
 * with another number, or `random` for a new seed each run (to look for failures locally).
 * A failure prints the seed and the shrunk counterexample to replay it.
 */
const RUNS = Number(process.env.GM_PROPERTY_RUNS ?? 200);
const SEED_SETTING = process.env.GM_PROPERTY_SEED ?? '20261016';
if (SEED_SETTING !== 'random' && !Number.isSafeInteger(Number(SEED_SETTING))) {
  throw new Error(`GM_PROPERTY_SEED is a whole number or "random", not ${JSON.stringify(SEED_SETTING)}`);
}
const params: fc.Parameters<unknown> = SEED_SETTING === 'random'
  ? { numRuns: RUNS }
  : { numRuns: RUNS, seed: Number(SEED_SETTING) };

const MIN_I64 = -(2n ** 63n);
const MAX_U64 = 2n ** 64n - 1n;

/** The reason `parseJson` refuses `text` with, or null when it accepts it. */
function refusal(text: string): string | null {
  try {
    parseJson(text);
    return null;
  } catch (err) {
    if (!(err instanceof StrictJsonError)) throw err;
    return err.reason;
  }
}

/** Every UTF-16 unit of `s` as a `\uXXXX` escape. */
const escaped = (s: string) => [...Array(s.length).keys()]
  .map(i => `\\u${s.charCodeAt(i).toString(16).padStart(4, '0')}`).join('');

/** Strings over all of Unicode, without lone surrogates (well-formed). */
const text = fc.string({ unit: 'grapheme', maxLength: 12 });

/**
 * Numbers that JSON.stringify writes in a lexeme strict JSON accepts and that read back as the
 * same JavaScript number: safe integers, and doubles that are not integers or are written with
 * an exponent (an integral double in [2^53, 1e21) is written as an integer literal, read as bigint).
 */
const number = fc.oneof(
  fc.maxSafeInteger(),
  fc.double({ noNaN: true, noDefaultInfinity: true })
    .filter(d => !Number.isInteger(d) || Number.isSafeInteger(d) || Math.abs(d) >= 1e21),
);

/** JSON values with Unicode strings and keys, nested a few levels. */
const json = fc.letrec<{ value: unknown }>(tie => ({
  value: fc.oneof(
    { depthSize: 'small', withCrossShrink: true },
    fc.constant(null), fc.boolean(), number, text,
    fc.array(tie('value'), { maxLength: 5 }),
    fc.dictionary(text, tie('value'), { maxKeys: 5 }),
  ),
})).value;

describe('strict JSON (parseJson) properties', () => {
  it('accepts what JSON.stringify writes and reads it as JSON.parse does', () => {
    fc.assert(fc.property(json, value => {
      const written = JSON.stringify(value);
      expect(parseJson(written)).toEqual(JSON.parse(written));
    }), params);
  });

  it('never accepts text JSON.parse refuses, and refuses only with StrictJsonError', () => {
    // Valid JSON with one character inserted, deleted or replaced, and arbitrary text.
    const mutated = fc.tuple(json, fc.nat(), fc.string({ unit: 'binary', maxLength: 2 }), fc.nat({ max: 2 }))
      .map(([value, at, insert, drop]) => {
        const written = JSON.stringify(value) ?? 'null';
        const i = at % (written.length + 1);
        return written.slice(0, i) + insert + written.slice(i + drop);
      });
    fc.assert(fc.property(fc.oneof(mutated, fc.string({ unit: 'binary', maxLength: 40 })), input => {
      let strict = true;
      try {
        checkStrictJson(input);
      } catch (err) {
        expect(err).toBeInstanceOf(StrictJsonError);
        strict = false;
      }
      if (strict) expect(() => JSON.parse(input)).not.toThrow();
    }), params);
  });

  it('refuses a key named twice in any object, however it is escaped', () => {
    fc.assert(fc.property(text, json, fc.boolean(), fc.nat({ max: 3 }), (key, value, escapeSecond, depth) => {
      const first = JSON.stringify(key);
      const second = escapeSecond ? `"${escaped(key)}"` : first;
      const object = `{${first}:${JSON.stringify(value) ?? 'null'},${second}:1}`;
      const nested = '['.repeat(depth) + object + ']'.repeat(depth);
      expect(refusal(nested)).toBe('duplicate_key');
    }), params);
  });

  it('reads any string, escaped unit by unit or not, as the same string', () => {
    fc.assert(fc.property(text, s => {
      expect(parseJson(JSON.stringify(s))).toBe(s);
      expect(parseJson(`"${escaped(s)}"`)).toBe(s);
    }), params);
  });

  it('refuses half of a surrogate pair, raw or escaped', () => {
    const high = fc.integer({ min: 0xd800, max: 0xdbff });
    const low = fc.integer({ min: 0xdc00, max: 0xdfff });
    const lone = fc.oneof(
      high.map(u => ({ unit: u, after: 'x' })),
      low.map(u => ({ unit: u, after: '' })),
    );
    fc.assert(fc.property(text, lone, fc.boolean(), (s, { unit, after }, raw) => {
      const half = raw ? String.fromCharCode(unit) : `\\u${unit.toString(16)}`;
      expect(refusal(`["${escaped(s)}${half}${after}"]`)).toBe('lone_surrogate');
      expect(refusal(`{"${half}${after}":0}`)).toBe('lone_surrogate');
    }), params);
  });

  it('keeps every integer lexeme in 64 bits and refuses the rest', () => {
    const integer = fc.oneof(
      fc.bigInt({ min: MIN_I64, max: MAX_U64 }),
      fc.bigInt({ min: MAX_U64 + 1n, max: 10n ** 22n }),
      fc.bigInt({ min: -(10n ** 22n), max: MIN_I64 - 1n }),
    );
    fc.assert(fc.property(integer, n => {
      const lexeme = n.toString();
      if (n < MIN_I64 || n > MAX_U64) {
        expect(refusal(`[${lexeme}]`)).toBe('integer_out_of_range');
        return;
      }
      const [read] = parseJson(`[${lexeme}]`) as [number | bigint];
      expect(BigInt(read)).toBe(n);
      expect(canonicalJson([read])).toBe(`[${lexeme}]`);
    }), params);
  });

  it('keeps an integral float a float in the canonical form (90.0, 1e3)', () => {
    const lexeme = fc.tuple(fc.integer({ min: -1_000_000, max: 1_000_000 }), fc.constantFrom('.0', '.00', 'e0', 'E+0', '.0e0'))
      .filter(([n]) => n !== 0)
      .map(([n, suffix]) => ({ n, text: `${n}${suffix}` }));
    fc.assert(fc.property(lexeme, ({ n, text: written }) => {
      const parsed = parseJson(`{"a":${written}}`) as { a: number };
      expect(parsed.a).toBe(n);
      expect(canonicalJson(parsed)).toBe(`{"a":${n}.0}`);
    }), params);
  });

  it('refuses nesting deeper than MAX_DEPTH and accepts it up to MAX_DEPTH', () => {
    fc.assert(fc.property(fc.integer({ min: 1, max: MAX_DEPTH + 8 }), fc.boolean(), (depth, objects) => {
      const open = objects ? '{"k":' : '[';
      const close = objects ? '}' : ']';
      const nested = open.repeat(depth) + '0' + close.repeat(depth);
      expect(refusal(nested)).toBe(depth > MAX_DEPTH ? 'invalid_json' : null);
    }), { ...params, numRuns: Math.min(RUNS, 100) });
  });
});

describe('canonical form (canonicalJson) properties', () => {
  it('is a fixed point: canonical text reads back to the same canonical text', () => {
    fc.assert(fc.property(json, value => {
      const canonical = canonicalJson(parseJson(JSON.stringify(value)));
      expect(canonicalJson(parseJson(canonical))).toBe(canonical);
    }), params);
  });

  it('is ASCII, strict JSON, and the value JSON.parse reads from JSON.stringify', () => {
    fc.assert(fc.property(json, value => {
      const canonical = canonicalJson(value);
      expect(canonical).toMatch(/^[\x20-\x7e]*$/);
      expect(() => checkStrictJson(canonical)).not.toThrow();
      expect(JSON.parse(canonical)).toEqual(JSON.parse(JSON.stringify(value)));
    }), params);
  });

  it('does not depend on key order, and sorts keys by code point', () => {
    const entries = fc.uniqueArray(fc.tuple(text, json), { selector: ([key]) => key, maxLength: 8 });
    fc.assert(fc.property(entries, fc.nat(), (pairs, shift) => {
      const rotated = pairs.map((_, i) => pairs[(i + shift) % pairs.length]!);
      const canonical = canonicalJson(Object.fromEntries(pairs));
      expect(canonicalJson(Object.fromEntries(rotated))).toBe(canonical);
      // The order is read from the canonical text itself: a parsed object would list
      // integer-like keys ("0") first, whatever order the text has.
      const sorted = [...pairs].sort(([a], [b]) => compareCodePoints(a, b));
      expect(canonical).toBe(`{${sorted.map(([key, value]) => `${canonicalJson(key)}:${canonicalJson(value)}`).join(',')}}`);
    }), params);
  });

  it('keeps the number a double reads as', () => {
    fc.assert(fc.property(fc.double({ noNaN: true, noDefaultInfinity: true }), d => {
      const [read] = JSON.parse(canonicalJson([d])) as [number];
      expect(read === d || (read === 0 && d === 0)).toBe(true);
    }), params);
  });
});

describe('path segment properties', () => {
  /** IDs a caller may pass, except the dot segments `.` and `..`, which the transport refuses. */
  const id = fc.string({ unit: 'grapheme', minLength: 1, maxLength: 24 }).filter(s => s !== '.' && s !== '..');

  async function requested(call: (fetch: jest.Mock) => Promise<unknown>): Promise<URL> {
    const fetch = mockFetch({ status: 200, body: {} });
    await call(fetch).catch(() => undefined);
    return new URL(fetch.mock.calls[0]![0] as string);
  }

  it('sends an ID as exactly one path segment that decodes to the ID', async () => {
    await fc.assert(fc.asyncProperty(id, async attestationId => {
      const url = await requested(fetch => new AttestationClient(buildTransport(fetch)).get(attestationId));
      const segments = url.pathname.split('/');
      expect(segments.slice(0, 2)).toEqual(['', 'attestations']);
      expect(segments.slice(2).map(decodeURIComponent)).toEqual([attestationId]);
      expect(url.search).toBe('');
    }), params);
  });

  it('sends a resource ID as its own segments under the resource route', async () => {
    // A resource ID is a path (`vaults/kv/secrets/name`): each segment is encoded, `/` is kept.
    // Dot segments are left out: the transport refuses them (tests/path-segments.test.ts).
    const segment = fc.string({ unit: 'grapheme', minLength: 1, maxLength: 8 })
      .filter(s => !s.includes('/') && s !== '.' && s !== '..');
    await fc.assert(fc.asyncProperty(fc.array(segment, { minLength: 1, maxLength: 4 }), async parts => {
      const resourceId = parts.join('/');
      const url = await requested(fetch => new EvidenceStoreClient(buildTransport(fetch)).resourceHistory(resourceId));
      const segments = url.pathname.split('/');
      expect(segments.slice(0, 4)).toEqual(['', 'admin', 'evidence', 'resources']);
      expect(segments.slice(4).map(decodeURIComponent)).toEqual(parts);
    }), params);
  });

  it('builds a query that reads back as the parameters given, without undefined or null', () => {
    const query = fc.dictionary(text, fc.oneof(text, fc.integer(), fc.boolean(), fc.constant(undefined), fc.constant(null)),
      { maxKeys: 6 });
    fc.assert(fc.property(query, q => {
      const url = new URL(buildPath('/admin/evidence/search', q), 'http://127.0.0.1');
      expect(url.pathname).toBe('/admin/evidence/search');
      const sent = Object.entries(q).filter(([, v]) => v !== undefined && v !== null).map(([k, v]) => [k, String(v)]);
      expect([...url.searchParams.entries()]).toEqual(sent);
    }), params);
  });

  it('accepts an envelope parameter name only when it is one [A-Za-z0-9_-]{1,64} segment', () => {
    const name = fc.oneof(
      fc.stringMatching(/^[A-Za-z0-9_-]{1,64}$/),
      fc.string({ unit: 'grapheme', maxLength: 70 }),
      fc.stringMatching(/^[A-Za-z0-9_-]{65,70}$/),
    );
    fc.assert(fc.property(name, parameter => {
      const problem = envelopeShapeProblem({ [parameter]: { one_of: ['a'] } });
      expect(problem === null).toBe(/^[A-Za-z0-9_-]{1,64}$/.test(parameter));
    }), params);
  });
});
