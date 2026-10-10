/**
 * HTTP transport layer for the Genesis Mesh SDK.
 * Handles request dispatch, response parsing, error mapping and opt-in retries.
 * Admin-route authentication is delegated to auth.ts.
 */

import { buildAdminHeadersWithSigner, canonicalJson, parseJson, seedSigner, type Signer } from './auth.js';
import { fromHttpError, GenesisMeshError, NetworkError } from './errors.js';
import type { EvidenceOutbox, RecordOutbox } from './outbox.js';
import { decodeUtf8, StrictJsonError } from './strict-json.js';

/** JSON refused for its form (a duplicate key, ...): the reason is kept; a body that is not JSON stays a NetworkError. */
const refusedForm = (err: unknown): boolean => err instanceof StrictJsonError && err.reason !== 'invalid_json';

export interface RetryOptions {
  /** Extra attempts after the first. 0 disables retries. */
  attempts: number;
  /** First backoff delay in milliseconds, doubled per attempt. Default 200. */
  baseDelayMs?: number;
}

export interface ClientOptions {
  /** Base URL of the NA (or its load balancer), e.g. "http://127.0.0.1:9443". No trailing slash needed. */
  baseUrl?: string;
  /**
   * Several NA instances sharing one database (v0.60 HA), used without a load
   * balancer. Requests go to one instance; idempotent requests move to the next
   * on a transport failure or 502/503/504. A non-idempotent request moves only
   * when the connection was refused or unreachable (it never reached the NA);
   * otherwise it is not replayed and the next request starts elsewhere.
   */
  baseUrls?: string[];
  /** Base64-encoded raw Ed25519 seed (32 bytes, from operator.key). Required for admin routes unless `signer` is set. */
  signingKeyBase64?: string;
  /** Key ID sent in X-Admin-Key-Id - must match a key registered with the NA. Ignored when `signer` is set. */
  keyId?: string;
  /** Operator signer for admin routes (e.g. backed by an HSM). Takes precedence over `signingKeyBase64`. */
  signer?: Signer;
  /**
   * The NA's public key, which admin signatures name as their audience. When
   * omitted it is read once from the NA's public `/sovereign.json`
   * (`network_authority.public_key`).
   */
  audience?: string;
  /** Request timeout in milliseconds. Default 10 000. */
  timeout?: number;
  /** Retries for idempotent requests on network errors, 429, 502, 503 and 504. Off by default. */
  retry?: RetryOptions;
  /** Extra headers on every request (e.g. for an API gateway in front of the NA). */
  headers?: Record<string, string>;
  /** Override fetch implementation for testing. */
  fetch?: typeof globalThis.fetch;
  /**
   * Durable storage for signed execution records not yet admitted (v1.2.0),
   * e.g. `new FileOutbox('/var/lib/app/gm-outbox')`. With one,
   * `governedAction` keeps every record until the NA admits it; see
   * `evidenceStore.flushPending`.
   */
  outbox?: EvidenceOutbox;
  /**
   * Durable storage for signed observations and break-glass records not yet
   * admitted (v1.3.0), e.g. `new FileRecordOutbox('/var/lib/app/gm-records')`,
   * in a directory of its own. `governedAction` with `breakGlass` needs one;
   * see `evidenceStore.flushRecords`.
   */
  recordOutbox?: RecordOutbox;
}

export type Query = Record<string, string | number | boolean | undefined | null>;

interface RequestSpec {
  method: 'GET' | 'POST';
  path: string;
  query?: Query;
  body?: unknown;
  admin: boolean;
  idempotent: boolean;
}

type BufferedResponse = Pick<Response, 'ok' | 'status' | 'text'>;

const RETRYABLE_STATUS = new Set([429, 502, 503, 504]);

/** The query parameters `buildPath` sends, as strings (undefined and null are not sent). */
function sentQuery(query?: Query): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== null) out[key] = String(value);
  }
  return out;
}

export function buildPath(path: string, query?: Query): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null) params.append(key, String(value));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

const FAILOVER_STATUS = new Set([502, 503, 504]);

/** Errors meaning no connection was made, so the request was never sent. */
const CONNECT_FAILURE_CODES = new Set([
  'ECONNREFUSED', 'ENOTFOUND', 'EHOSTUNREACH', 'ENETUNREACH', 'EAI_AGAIN', 'UND_ERR_CONNECT_TIMEOUT',
]);

function isConnectFailure(err: unknown): boolean {
  const cause = (err as { cause?: { code?: unknown; errors?: { code?: unknown }[] } } | undefined)?.cause;
  if (!cause) return false;
  if (typeof cause.code === 'string' && CONNECT_FAILURE_CODES.has(cause.code)) return true;
  return Array.isArray(cause.errors) && cause.errors.length > 0
    && cause.errors.every(e => typeof e?.code === 'string' && CONNECT_FAILURE_CODES.has(e.code));
}

export class HttpTransport {
  /** Every configured NA endpoint, in preference order. */
  readonly baseUrls: readonly string[];
  private active = 0;
  /** Key ID sent in X-Admin-Key-Id. */
  readonly keyId: string;
  private readonly signer?: Signer;
  private audience?: Promise<string>;
  private readonly timeout: number;
  private readonly retry: Required<RetryOptions>;
  private readonly headers: Record<string, string>;
  private readonly _fetch: typeof globalThis.fetch;

  constructor(options: ClientOptions) {
    const urls = options.baseUrls ?? (options.baseUrl !== undefined ? [options.baseUrl] : []);
    if (urls.length === 0 || urls.some(u => typeof u !== 'string' || !/^https?:\/\//.test(u))) {
      throw new Error('baseUrl or baseUrls must give at least one http(s) URL');
    }
    if (options.baseUrl !== undefined && options.baseUrls !== undefined) {
      throw new Error('pass either baseUrl or baseUrls, not both');
    }
    this.baseUrls = Object.freeze(urls.map(u => u.replace(/\/$/, '')));
    this.signer = options.signer
      ?? (options.signingKeyBase64
        ? seedSigner(options.signingKeyBase64, options.keyId ?? 'operator-local')
        : undefined);
    this.keyId = this.signer?.keyId ?? options.keyId ?? 'operator-local';
    if (options.audience !== undefined) this.audience = Promise.resolve(options.audience);
    this.timeout = options.timeout ?? 10_000;
    this.retry = { attempts: options.retry?.attempts ?? 0, baseDelayMs: options.retry?.baseDelayMs ?? 200 };
    if (!Number.isSafeInteger(this.retry.attempts) || this.retry.attempts < 0 || this.retry.attempts > 10
      || !Number.isFinite(this.retry.baseDelayMs) || this.retry.baseDelayMs < 0 || this.retry.baseDelayMs > 60_000) {
      throw new Error('retry requires 0..10 attempts and a finite baseDelayMs between 0 and 60000');
    }
    this.headers = options.headers ?? {};
    this._fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** The endpoint requests currently go to. */
  get baseUrl(): string {
    return this.baseUrls[this.active] as string;
  }

  /** Move to the next endpoint (no-op with one endpoint). */
  private failover(): void {
    if (this.baseUrls.length > 1) this.active = (this.active + 1) % this.baseUrls.length;
  }

  /** Whether this client has an operator signer for admin requests. */
  get canSign(): boolean {
    return this.signer !== undefined;
  }

  /** Signed admin POST. Not retried unless `idempotent` is set. */
  async adminPost<T>(path: string, body: unknown, idempotent = false): Promise<T> {
    const response = await this._send({ method: 'POST', path, body, admin: true, idempotent });
    return this._parse<T>(response);
  }

  /** Signed admin GET (the NA verifies the signature over an empty body). */
  async adminGet<T>(path: string, query?: Query): Promise<T> {
    const response = await this._send({ method: 'GET', path, query, admin: true, idempotent: true });
    return this._parse<T>(response);
  }

  /** Signed admin GET returning the raw response text (e.g. NDJSON export). */
  async adminGetText(path: string, query?: Query): Promise<string> {
    const response = await this._send({ method: 'GET', path, query, admin: true, idempotent: true });
    if (!response.ok) return this._parse<never>(response);
    return response.text();
  }

  /** Unauthenticated POST. Verification routes are idempotent; pass `true` to allow retries. */
  async publicPost<T>(path: string, body: unknown, idempotent = false): Promise<T> {
    const response = await this._send({ method: 'POST', path, body, admin: false, idempotent });
    return this._parse<T>(response);
  }

  async publicGet<T>(path: string, query?: Query): Promise<T> {
    const response = await this._send({ method: 'GET', path, query, admin: false, idempotent: true });
    return this._parse<T>(response);
  }

  private async _send(spec: RequestSpec): Promise<BufferedResponse> {
    // Idempotent requests may try every other endpoint once, plus the
    // configured retries (with backoff). Non-idempotent requests move to
    // another endpoint only when the connection was never established; after
    // any other failure they are not replayed, and the next request starts at
    // another endpoint.
    const failovers = this.baseUrls.length - 1;
    const retries = spec.idempotent ? this.retry.attempts : 0;
    let failoversLeft = failovers;
    let retriesUsed = 0;
    for (;;) {
      let response: BufferedResponse | undefined;
      let error: unknown;
      try {
        response = await this._attempt(spec);
      } catch (err) {
        if (!(err instanceof NetworkError)) throw err;
        error = err;
      }
      const failoverWorthy = error !== undefined || (response !== undefined && FAILOVER_STATUS.has(response.status));
      if (failoverWorthy) this.failover();
      // A request that may have reached an instance is replayed elsewhere only
      // if it is idempotent; one that never connected can always move on.
      const mayMove = spec.idempotent || (error instanceof NetworkError && error.connectFailed);
      if (failoverWorthy && mayMove && failoversLeft > 0) {
        failoversLeft -= 1;
        continue;
      }
      const retryable = error !== undefined || (response !== undefined && RETRYABLE_STATUS.has(response.status));
      if (retryable && retriesUsed < retries) {
        await this._backoff(retriesUsed);
        retriesUsed += 1;
        failoversLeft = failovers;
        continue;
      }
      if (error !== undefined) throw error;
      return response as BufferedResponse;
    }
  }

  /** One request to the active endpoint, with the body fully read (a dropped body is a NetworkError). */
  private async _attempt(spec: RequestSpec): Promise<BufferedResponse> {
    const res = await this._once(spec);
    let body: string | ArrayBuffer;
    try {
      // The bytes, so a body that is not UTF-8 is refused rather than repaired.
      body = typeof res.arrayBuffer === 'function' ? await res.arrayBuffer() : await res.text();
    } catch {
      throw new NetworkError(`Failed to read response body (${spec.method} ${spec.path})`);
    }
    return { ok: res.ok, status: res.status, text: async () => (typeof body === 'string' ? body : decodeUtf8(body)) };
  }

  /** Unauthenticated GET against one specific endpoint (no failover), e.g. per-instance readiness. */
  async publicGetAt<T>(baseUrl: string, path: string): Promise<{ status: number; body: T }> {
    const url = baseUrl.replace(/\/$/, '') + path;
    let response: Response;
    try {
      response = await this._fetch(url, { method: 'GET', headers: { ...this.headers }, signal: AbortSignal.timeout(this.timeout) });
    } catch (err) {
      throw new NetworkError(`GET ${url} failed: ${(err as Error).message}`);
    }
    try {
      const text = typeof response.arrayBuffer === 'function' ? decodeUtf8(await response.arrayBuffer()) : await response.text();
      return { status: response.status, body: parseJson(text) as T };
    } catch (err) {
      if (refusedForm(err)) throw err;
      throw new NetworkError(`Failed to parse response body from ${url} (HTTP ${response.status})`);
    }
  }

  private async _once(spec: RequestSpec): Promise<Response> {
    const headers: Record<string, string> = { ...this.headers };
    if (spec.admin) {
      if (!this.signer) {
        throw new Error('signingKeyBase64 is required for admin routes (or pass a signer)');
      }
      let audience: string;
      try {
        audience = await this._audience();
      } catch (err) {
        // The request itself was never sent, so it may move to another
        // instance like a refused connection, idempotent or not.
        const error = new NetworkError(
          `${spec.method} ${spec.path} not sent: ${(err as Error).message}`,
        );
        error.connectFailed = true;
        throw error;
      }
      Object.assign(headers, await buildAdminHeadersWithSigner({
        method: spec.method,
        path: decodeURIComponent(spec.path),
        query: sentQuery(spec.query),
        audience,
        body: spec.method === 'GET' ? {} : spec.body,
      }, this.signer));
    }
    const init: RequestInit = { method: spec.method, headers, signal: AbortSignal.timeout(this.timeout) };
    if (spec.method === 'POST') {
      headers['Content-Type'] = 'application/json';
      init.body = canonicalJson(spec.body);
    }
    const path = buildPath(spec.path, spec.query);
    try {
      return await this._fetch(this.baseUrl + path, init);
    } catch (err) {
      const error = new NetworkError(`${spec.method} ${spec.path} failed: ${(err as Error).message}`);
      error.connectFailed = isConnectFailure(err);
      error.cause = err;
      throw error;
    }
  }

  /** The NA's public key for admin signatures, read once from `/sovereign.json`. */
  private _audience(): Promise<string> {
    if (!this.audience) {
      const pending = this.publicGetAt<{ network_authority?: { public_key?: unknown } }>(this.baseUrl, '/sovereign.json').then(({ status, body }) => {
        const key = body?.network_authority?.public_key;
        if (status !== 200 || typeof key !== 'string' || !key) {
          throw new GenesisMeshError(
            `Could not read the NA public key from /sovereign.json (HTTP ${status})`, 'unknown', status,
          );
        }
        return key;
      });
      // A failed lookup is retried by the next admin request.
      this.audience = pending.catch(err => { this.audience = undefined; throw err; });
    }
    return this.audience;
  }

  private _backoff(attempt: number): Promise<void> {
    const delay = Math.min(60_000, this.retry.baseDelayMs * 2 ** attempt);
    return new Promise(resolve => setTimeout(resolve, delay));
  }

  private async _parse<T>(response: BufferedResponse): Promise<T> {
    let data: unknown;
    try {
      data = parseJson(await response.text());
    } catch (err) {
      if (response.ok && refusedForm(err)) throw err;
      if (!response.ok) {
        throw new GenesisMeshError(`HTTP ${response.status} with a non-JSON body`, 'unknown', response.status);
      }
      throw new NetworkError(`Failed to parse response body (HTTP ${response.status})`);
    }
    if (!response.ok) {
      throw fromHttpError(response.status, (data ?? {}) as Record<string, unknown>);
    }
    return data as T;
  }
}
