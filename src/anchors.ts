/**
 * Store anchors (v1.2.0 in the core; offline verification here since 1.5.0):
 * NA-signed statements of the evidence store's head. Port of the reference's
 * `verify_store_anchors` and `check_events_against_anchors`
 * (trust/evidence_store.py), with the same reason codes.
 *
 * The store chain is hashed, not signed: whoever can write the database can
 * remove entries and rebuild the links. An anchor signs the head's
 * `store_sequence` and entry digest, and anchors form their own chain. An
 * auditor keeps copies of the anchors outside the operator's reach and checks
 * an export or an audit pack against them. v1.5.0: given the NA's key
 * history, each anchor must be signed by the key valid at its `anchored_at`.
 */

import { canonicalJson, copyPythonFloats, defineMember, sha256Hex, verifyCanonical } from './auth.js';
import { entryDigest } from './canonical.js';
import { naSignatureAt, type NAKeys } from './key-history.js';
import type { AnchorSummary, EvidenceEvent, EvidenceStoreVerification, RetentionCheckpoint, Signature } from './types.js';

export type { AnchorSummary } from './types.js';
import { timestampMicros, validAnchor, validCheckpoint } from './validation.js';

/** A signed statement of the store's head (`GET /admin/evidence/anchors`). */
export interface StoreAnchor {
  anchor_sequence: number;
  sovereign_id: string;
  store_sequence: number;
  /** The anchored entry's digest. */
  entry_digest: string;
  anchored_at: string;
  /** The previous anchor's digest; absent for the first. */
  previous_anchor_digest?: string | null;
  issued_by: string;
  signature?: Signature | null;
}

/** The form the NA signs: every field but `signature`, an absent previous digest left out. */
export function anchorCanonical(anchor: StoreAnchor): string {
  const body: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(anchor)) {
    if (key !== 'signature' && value !== undefined && value !== null) defineMember(body, key, value);
  }
  copyPythonFloats(anchor, body);
  return canonicalJson(body);
}

/** SHA-256 of the signed form; the next anchor links to it. */
export function anchorDigest(anchor: StoreAnchor): string {
  return sha256Hex(anchorCanonical(anchor));
}

export interface AnchorFailure {
  anchor_sequence: number | null;
  reason: string;
  detail: string;
}

export interface AnchorVerification {
  verified: boolean;
  checked_anchors: number;
  first_anchor_sequence: number | null;
  last_anchor_sequence: number | null;
  anchored_through_sequence: number | null;
  failures: AnchorFailure[];
}

export interface VerifyAnchorsOptions {
  /**
   * NA keys (a list, valid at every time, or the NA's key history: the key
   * valid at each anchor's `anchored_at`). Null skips the signatures and
   * checks everything else.
   */
  naPublicKeys: NAKeys | null;
  /** Whose anchors these are (`anchor_sovereign_mismatch`). */
  sovereignId?: string;
}

/** Check that every item is a well-formed anchor; throws otherwise (parse anchors before verifying them). */
export function parseAnchors(items: readonly unknown[]): StoreAnchor[] {
  for (const item of items) {
    if (!validAnchor(item)) throw new Error('invalid store anchor');
  }
  return items as StoreAnchor[];
}

/**
 * Verify a run of anchors ordered by `anchor_sequence`: signatures
 * (`anchor_invalid_signature`; v1.5.0 `na_key_not_valid_at_time`), the
 * sovereign (`anchor_sovereign_mismatch`), the anchor chain
 * (`anchor_sequence_gap`, `anchor_chain_break`) and increasing heads
 * (`anchor_not_increasing`). The run need not start at 1 (an auditor may hold
 * only recent anchors); one that starts at 1 starts with no previous anchor.
 * Throws when an anchor is not well formed.
 */
export function verifyStoreAnchors(anchors: readonly StoreAnchor[], options: VerifyAnchorsOptions): AnchorVerification {
  parseAnchors(anchors);
  const result: AnchorVerification = {
    verified: true, checked_anchors: 0, first_anchor_sequence: null, last_anchor_sequence: null,
    anchored_through_sequence: null, failures: [],
  };
  const fail = (n: number, reason: string, detail = '') => {
    result.verified = false;
    result.failures.push({ anchor_sequence: n, reason, detail });
  };
  let prev: StoreAnchor | null = null;
  for (const anchor of anchors) {
    const n = anchor.anchor_sequence;
    result.checked_anchors += 1;
    result.first_anchor_sequence ??= n;
    result.last_anchor_sequence = n;
    if (options.naPublicKeys !== null) {
      const sig = anchor.signature;
      const signedBy = (keys: readonly string[]) => typeof sig?.sig === 'string' && verifyCanonical(anchorCanonical(anchor), sig.sig, keys);
      const outcome = naSignatureAt(signedBy, options.naPublicKeys, anchor.anchored_at);
      if (outcome !== 'ok') fail(n, outcome === 'invalid_signature' ? 'anchor_invalid_signature' : outcome);
    }
    if (options.sovereignId !== undefined && anchor.sovereign_id !== options.sovereignId) {
      fail(n, 'anchor_sovereign_mismatch', anchor.sovereign_id);
    }
    if (prev === null) {
      if (n === 1 && (anchor.previous_anchor_digest ?? null) !== null) {
        fail(n, 'anchor_chain_break', 'the first anchor names a previous anchor');
      }
    } else {
      if (n !== prev.anchor_sequence + 1) fail(n, 'anchor_sequence_gap', `after ${prev.anchor_sequence}`);
      else if ((anchor.previous_anchor_digest ?? null) !== anchorDigest(prev)) fail(n, 'anchor_chain_break');
      if (anchor.store_sequence <= prev.store_sequence
        || timestampMicros(anchor.anchored_at) < timestampMicros(prev.anchored_at)) {
        fail(n, 'anchor_not_increasing');
      }
    }
    result.anchored_through_sequence = Math.max(result.anchored_through_sequence ?? 0, anchor.store_sequence);
    prev = anchor;
  }
  return result;
}

export interface CheckAnchorsOptions {
  /** A deliberate slice: neither end of the run is checked. */
  partial?: boolean;
  /** The run may start right after a held anchor whose digest its first entry names. */
  fromAnchor?: boolean;
}

/** The retention checkpoint in a run that explains where it starts, or null. */
export function startingCheckpoint(events: readonly EvidenceEvent[], first: EvidenceEvent): RetentionCheckpoint | null {
  for (const event of events) {
    if (event.entry.entry_kind !== 'retention_checkpoint' || !validCheckpoint(event.payload)) continue;
    const cp = event.payload as unknown as RetentionCheckpoint;
    if (cp.removed_through_sequence === first.entry.store_sequence - 1
      && cp.last_removed_entry_digest === first.entry.prev_entry_digest) {
      return cp;
    }
  }
  return null;
}

/**
 * Check a contiguous run of entries against anchors held out of band, into
 * `result` (from `verifyEvidenceEvents`). The run is tied at its start (entry
 * 1, a retention checkpoint in the run, or with `fromAnchor` a held anchor its
 * first entry continues from; otherwise `export_not_linked_to_anchors`) and at
 * its end (`export_ends_before_anchor` for an anchor after its last entry);
 * inside it, each anchor names its entry's digest (`anchor_mismatch`,
 * `anchor_entry_missing`).
 */
export function checkEventsAgainstAnchors(
  events: readonly EvidenceEvent[],
  anchors: readonly StoreAnchor[],
  result: EvidenceStoreVerification,
  options: CheckAnchorsOptions = {},
): void {
  const fail = (seq: number | null, reason: string, detail = '') => {
    result.verified = false;
    result.failures.push({ store_sequence: seq, reason, detail });
  };
  const bySequence = new Map(events.map(e => [e.entry.store_sequence, e]));
  const ordered = [...events].sort((a, b) => a.entry.store_sequence - b.entry.store_sequence);
  const first = ordered[0];
  const lastSeq = ordered.length > 0 ? ordered[ordered.length - 1]!.entry.store_sequence : null;
  const firstSeq = first ? first.entry.store_sequence : null;
  let matched = 0;
  let before = 0;
  let beyond = 0;
  let anchoredThrough: number | null = null;
  let linkedStart = first !== undefined && (firstSeq === 1 || startingCheckpoint(ordered, first) !== null);
  let afterAnchor: number | null = null;
  for (const anchor of anchors) {
    const seq = anchor.store_sequence;
    if (first === undefined || lastSeq === null || firstSeq === null || seq > lastSeq) {
      beyond += 1;
      continue;
    }
    if (seq === firstSeq - 1) {
      if (first.entry.prev_entry_digest === anchor.entry_digest) {
        afterAnchor = anchor.anchor_sequence;
        linkedStart = linkedStart || !!options.fromAnchor;
        matched += 1;
        anchoredThrough = Math.max(anchoredThrough ?? 0, seq);
      } else {
        fail(firstSeq, 'anchor_mismatch', `the run does not continue from anchor ${anchor.anchor_sequence}`);
      }
      continue;
    }
    if (seq < firstSeq) {
      before += 1;
      continue;
    }
    const event = bySequence.get(seq);
    if (event === undefined) {
      fail(seq, 'anchor_entry_missing', `anchor ${anchor.anchor_sequence}`);
    } else if (event.entry_digest !== anchor.entry_digest || entryDigest(event.entry) !== anchor.entry_digest) {
      fail(seq, 'anchor_mismatch', `anchor ${anchor.anchor_sequence}`);
    } else {
      matched += 1;
      anchoredThrough = Math.max(anchoredThrough ?? 0, seq);
    }
  }
  if (anchors.length > 0 && first !== undefined && !linkedStart && !options.partial) {
    const why = afterAnchor !== null
      ? `the export starts right after held anchor ${afterAnchor}, which proves the entries before it existed, not `
        + 'that they are kept: export from entry 1 (with the retention checkpoint that removed entries, if any), or '
        + 'verify it as an export since that anchor (fromAnchor)'
      : `the export starts at entry ${firstSeq} and holds neither entry 1 nor the retention checkpoint that removed the `
        + `entries before it (${before} held anchor(s) before it): export from entry 1, or include that checkpoint's entry`;
    fail(firstSeq, 'export_not_linked_to_anchors', why);
  }
  if (beyond > 0 && !options.partial) fail(lastSeq, 'export_ends_before_anchor', `${beyond} anchor(s) after the last entry`);
  const floor = anchoredThrough ?? 0;
  result.anchors = {
    anchors_checked: anchors.length,
    anchors_matched: matched,
    anchors_before_export: before,
    anchors_after_export: beyond,
    linked_start: linkedStart,
    anchored_through_sequence: anchoredThrough,
    unanchored_entries: [...bySequence.keys()].filter(seq => seq > floor).length,
  };
}
