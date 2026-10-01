/**
 * HTTP transport layer for the Genesis Mesh SDK.
 * Handles request dispatch, response parsing, error mapping and opt-in retries.
 * Admin-route authentication is delegated to auth.ts.
 */

import { buildAdminHeadersWithSigner, canonicalJson, parseJson, seedSigner, type Signer } from './auth.js';
import { fromHttpError, GenesisMeshError, NetworkError } from './errors.js';

export interface RetryOptions {
  /** Extra attempts after the first. 0 disables retries. */
  attempts: number;
  /** First backoff delay in milliseconds, doubled per attempt. Default 200. */
  baseDelayMs?: number;
}

export interface ClientOptions {
  /** Base URL of the NA, e.g. "http://127.0.0.1:9443". No trailing slash needed. */
  baseUrl: string;
  /** Base64-encoded raw Ed25519 seed (32 bytes, from operator.key). Required for admin routes unless `signer` is set. */
  signingKeyBase64?: string;
  /** Key ID sent in X-Admin-Key-Id - must match a key registered with the NA. Ignored when `signer` is set. */
  keyId?: string;
  /** Operator signer for admin routes (e.g. backed by an HSM). Takes precedence over `signingKeyBase64`. */
  signer?: Signer;
  /** Request timeout in milliseconds. Default 10 000. */
  timeout?: number;
  /** Retries for idempotent requests on network errors, 429, 502, 503 and 504. Off by default. */
  retry?: RetryOptions;
  /** Extra headers on every request (e.g. for an API gateway in front of the NA). */
  headers?: Record<string, string>;
  /** Override fetch implementation for testing. */
  fetch?: typeof globalThis.fetch;
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

export function buildPath(path: string, query?: Query): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null) params.append(key, String(value));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

export class HttpTransport {
  readonly baseUrl: string;
  /** Key ID sent in X-Admin-Key-Id. */
  readonly keyId: string;
  private readonly signer?: Signer;
  private readonly timeout: number;
  private readonly retry: Required<RetryOptions>;
  private readonly headers: Record<string, string>;
  private readonly _fetch: typeof globalThis.fetch;

  constructor(options: ClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.signer = options.signer
      ?? (options.signingKeyBase64
        ? seedSigner(options.signingKeyBase64, options.keyId ?? 'operator-local')
        : undefined);
    this.keyId = this.signer?.keyId ?? options.keyId ?? 'operator-local';
    this.timeout = options.timeout ?? 10_000;
    this.retry = { attempts: options.retry?.attempts ?? 0, baseDelayMs: options.retry?.baseDelayMs ?? 200 };
    if (!Number.isSafeInteger(this.retry.attempts) || this.retry.attempts < 0 || this.retry.attempts > 10
      || !Number.isFinite(this.retry.baseDelayMs) || this.retry.baseDelayMs < 0 || this.retry.baseDelayMs > 60_000) {
      throw new Error('retry requires 0..10 attempts and a finite baseDelayMs between 0 and 60000');
    }
    this.headers = options.headers ?? {};
    this._fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
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
    const attempts = spec.idempotent ? this.retry.attempts : 0;
    for (let attempt = 0; ; attempt++) {
      try {
        const response = await this._once(spec);
        if (attempt < attempts && RETRYABLE_STATUS.has(response.status)) {
          await this._backoff(attempt);
          continue;
        }
        let body: string;
        try {
          body = await response.text();
        } catch {
          throw new NetworkError(`Failed to read response body (${spec.method} ${spec.path})`);
        }
        return { ok: response.ok, status: response.status, text: async () => body };
      } catch (err) {
        if (attempt < attempts && err instanceof NetworkError) {
          await this._backoff(attempt);
          continue;
        }
        throw err;
      }
    }
  }

  private async _once(spec: RequestSpec): Promise<Response> {
    const headers: Record<string, string> = { ...this.headers };
    if (spec.admin) {
      if (!this.signer) {
        throw new Error('signingKeyBase64 is required for admin routes (or pass a signer)');
      }
      Object.assign(headers, await buildAdminHeadersWithSigner(spec.method === 'GET' ? {} : spec.body, this.signer));
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
      throw new NetworkError(`${spec.method} ${spec.path} failed: ${(err as Error).message}`);
    }
  }

  private _backoff(attempt: number): Promise<void> {
    const delay = Math.min(60_000, this.retry.baseDelayMs * 2 ** attempt);
    return new Promise(resolve => setTimeout(resolve, delay));
  }

  private async _parse<T>(response: BufferedResponse): Promise<T> {
    let data: unknown;
    try {
      data = parseJson(await response.text());
    } catch {
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
