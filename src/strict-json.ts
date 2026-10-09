/**
 * Strict JSON input (v1.2.0): refuse what parsers read differently.
 *
 * The canonical form of a signed record is computed from parsed JSON, so every
 * implementation must parse a record to the same value. Some JSON does not
 * parse alike: `JSON.parse` keeps the last of two duplicate keys where .NET
 * keeps both, keeps a lone surrogate that Go replaces, and Rust reads an
 * integer beyond 64 bits as a float. `parseJson` refuses such input, as every
 * implementation does, by a named reason (the conformance suite `canonical`).
 */

import { GenesisMeshError } from './errors.js';

export type StrictJsonReason =
  /** Not JSON, including `NaN` and `Infinity`. */
  | 'invalid_json'
  /** An object names a key twice. */
  | 'duplicate_key'
  /** A number overflows a 64-bit float (`1e400`). */
  | 'non_finite_number'
  /** An integer outside `-2**63 .. 2**64 - 1`. */
  | 'integer_out_of_range'
  /** The integer `-0`. */
  | 'negative_zero'
  /** A string or key holds half of a UTF-16 surrogate pair. */
  | 'lone_surrogate';

/** JSON refused as input to a signed record; `reason` names why (also the `code`). */
export class StrictJsonError extends GenesisMeshError {
  readonly reason: StrictJsonReason;

  constructor(reason: StrictJsonReason, detail: string) {
    super(`${reason}: ${detail}`, reason, 0);
    this.name = 'StrictJsonError';
    this.reason = reason;
  }
}

const MIN_INTEGER = -(2n ** 63n);
const MAX_INTEGER = 2n ** 64n - 1n;
const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
const ESCAPES: Readonly<Record<string, number>> = { '"': 0x22, '\\': 0x5c, '/': 0x2f, b: 8, f: 12, n: 10, r: 13, t: 9 };

/** Throw `StrictJsonError` unless `text` is JSON every implementation reads alike. */
export function checkStrictJson(text: string): void {
  let i = 0;
  const fail = (reason: StrictJsonReason, detail: string): never => {
    throw new StrictJsonError(reason, detail);
  };
  const space = () => {
    while (i < text.length && ' \t\n\r'.includes(text[i]!)) i++;
  };
  /** Read a string at `i`; return its text when `keep`, so keys can be compared. */
  const string = (keep: boolean): string => {
    i++;
    const units: number[] = [];
    let pending = -1; // a high surrogate waiting for its low half
    for (;;) {
      if (i >= text.length) fail('invalid_json', 'a string is not closed');
      let unit = text.charCodeAt(i);
      if (unit === 0x22) {
        i++;
        break;
      }
      if (unit < 0x20) fail('invalid_json', 'a control character in a string');
      if (unit === 0x5c) {
        const escape = text[i + 1] ?? '';
        if (escape === 'u') {
          const hex = text.slice(i + 2, i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('invalid_json', 'a malformed \\u escape');
          unit = parseInt(hex, 16);
          i += 6;
        } else {
          if (!(escape in ESCAPES)) fail('invalid_json', 'an unknown escape');
          unit = ESCAPES[escape]!;
          i += 2;
        }
      } else {
        i++;
      }
      if (pending >= 0) {
        if (unit < 0xdc00 || unit > 0xdfff) fail('lone_surrogate', 'a high surrogate without its low half');
        pending = -1;
      } else if (unit >= 0xd800 && unit <= 0xdbff) {
        pending = unit;
      } else if (unit >= 0xdc00 && unit <= 0xdfff) {
        fail('lone_surrogate', 'a low surrogate without its high half');
      }
      if (keep) units.push(unit);
    }
    if (pending >= 0) fail('lone_surrogate', 'a high surrogate without its low half');
    let out = '';
    for (let k = 0; k < units.length; k += 4096) out += String.fromCharCode(...units.slice(k, k + 4096));
    return out;
  };
  const number = () => {
    NUMBER.lastIndex = i;
    const match = NUMBER.exec(text);
    if (!match) return fail('invalid_json', 'a malformed number');
    const literal = match[0];
    i += literal.length;
    if (/^-?\d+$/.test(literal)) {
      if (literal === '-0') fail('negative_zero', 'the integer -0');
      const value = BigInt(literal);
      if (value < MIN_INTEGER || value > MAX_INTEGER) fail('integer_out_of_range', `${literal} is outside the 64-bit range`);
    } else if (!Number.isFinite(Number(literal))) {
      fail('non_finite_number', `${literal} overflows a 64-bit float`);
    }
  };
  const value = (): void => {
    space();
    const c = text[i];
    if (c === '{') {
      i++;
      space();
      if (text[i] === '}') {
        i++;
        return;
      }
      const keys = new Set<string>();
      for (;;) {
        space();
        if (text[i] !== '"') fail('invalid_json', 'expected a key');
        const key = string(true);
        if (keys.has(key)) fail('duplicate_key', `key ${JSON.stringify(key)} appears twice`);
        keys.add(key);
        space();
        if (text[i] !== ':') fail('invalid_json', 'expected ":"');
        i++;
        value();
        space();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === '}') {
          i++;
          return;
        }
        fail('invalid_json', 'expected "," or "}"');
      }
    }
    if (c === '[') {
      i++;
      space();
      if (text[i] === ']') {
        i++;
        return;
      }
      for (;;) {
        value();
        space();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === ']') {
          i++;
          return;
        }
        fail('invalid_json', 'expected "," or "]"');
      }
    }
    if (c === '"') {
      string(false);
      return;
    }
    if (c === '-' || (c !== undefined && c >= '0' && c <= '9')) {
      number();
      return;
    }
    for (const literal of ['true', 'false', 'null']) {
      if (text.startsWith(literal, i)) {
        i += literal.length;
        return;
      }
    }
    fail('invalid_json', c === undefined ? 'no value' : `unexpected ${JSON.stringify(c)}`);
  };
  try {
    value();
  } catch (err) {
    if (err instanceof RangeError) fail('invalid_json', 'nested too deeply');
    throw err;
  }
  space();
  if (i !== text.length) fail('invalid_json', 'text after the value');
}
