/**
 * HTTP transport layer for the Genesis Mesh SDK.
 * Handles request dispatch, response parsing, and error mapping.
 * Admin-route authentication is delegated to auth.ts.
 */

import { buildAdminHeaders } from './auth.js';
import { fromHttpError, NetworkError } from './errors.js';

export interface ClientOptions {
  /** Base URL of the NA, e.g. "http://127.0.0.1:9443". No trailing slash needed. */
  baseUrl: string;
  /** Base64-encoded raw Ed25519 seed (32 bytes, from operator.key). Required for admin routes. */
  signingKeyBase64?: string;
  /** Key ID sent in X-Admin-Key-Id — must match a key registered with the NA. */
  keyId?: string;
  /** Request timeout in milliseconds. Default 10 000. */
  timeout?: number;
  /** Override fetch implementation for testing. */
  fetch?: typeof globalThis.fetch;
}

export class HttpTransport {
  readonly baseUrl: string;
  private readonly signingKeyBase64?: string;
  private readonly keyId: string;
  private readonly timeout: number;
  private readonly _fetch: typeof globalThis.fetch;

  constructor(options: ClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.signingKeyBase64 = options.signingKeyBase64;
    this.keyId = options.keyId ?? 'operator-local';
    this.timeout = options.timeout ?? 10_000;
    this._fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  async adminPost<T>(path: string, body: unknown): Promise<T> {
    if (!this.signingKeyBase64) {
      throw new Error('signingKeyBase64 is required for admin routes');
    }
    const adminHeaders = buildAdminHeaders(body, this.keyId, this.signingKeyBase64);
    return this._post<T>(path, body, adminHeaders);
  }

  async publicPost<T>(path: string, body: unknown): Promise<T> {
    return this._post<T>(path, body, {});
  }

  async publicGet<T>(path: string): Promise<T> {
    const url = this.baseUrl + path;
    let response: Response;
    try {
      response = await this._fetch(url, {
        method: 'GET',
        signal: AbortSignal.timeout(this.timeout),
      });
    } catch (err) {
      throw new NetworkError(`GET ${path} failed: ${(err as Error).message}`);
    }
    return this._parse<T>(response);
  }

  private async _post<T>(
    path: string,
    body: unknown,
    extraHeaders: Record<string, string>,
  ): Promise<T> {
    const url = this.baseUrl + path;
    let response: Response;
    try {
      response = await this._fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...extraHeaders },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeout),
      });
    } catch (err) {
      throw new NetworkError(`POST ${path} failed: ${(err as Error).message}`);
    }
    return this._parse<T>(response);
  }

  private async _parse<T>(response: Response): Promise<T> {
    let data: unknown;
    try {
      data = await response.json();
    } catch {
      throw new NetworkError(`Failed to parse response body (HTTP ${response.status})`);
    }
    if (!response.ok) {
      throw fromHttpError(response.status, data as Record<string, unknown>);
    }
    return data as T;
  }
}
