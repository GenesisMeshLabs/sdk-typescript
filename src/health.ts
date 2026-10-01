import type { HttpTransport } from './client.js';
import { ServiceUnavailableError } from './errors.js';
import type { EndpointReadiness, HealthStatus, Readiness } from './types.js';

function normalise(body: Record<string, unknown>, ready: boolean): Readiness {
  return { ...(body as unknown as Readiness), status: ready ? 'ready' : 'not_ready', ready };
}

/** Liveness, readiness and health of the Network Authority (v0.60). */
export class HealthClient {
  constructor(private readonly http: HttpTransport) {}

  /** Process liveness only (`GET /healthz`). */
  liveness(): Promise<{ status: string }> {
    return this.http.publicGet<{ status: string }>('/healthz');
  }

  /**
   * Readiness (`GET /readyz`): database writable at the expected schema, key
   * loaded, shared state in HA mode. A not-ready NA (503 `service_not_ready`)
   * is returned as `ready: false` with the failing checks, not thrown. With
   * several `baseUrls`, a not-ready instance is skipped for the next one.
   */
  async readiness(): Promise<Readiness> {
    try {
      return normalise(await this.http.publicGet<Record<string, unknown>>('/readyz'), true);
    } catch (err) {
      if (err instanceof ServiceUnavailableError && err.code === 'service_not_ready') {
        return normalise(err.details, false);
      }
      throw err;
    }
  }

  /** Network, version, boundary policy health and evidence store mode (`GET /health`). */
  health(): Promise<HealthStatus> {
    return this.http.publicGet<HealthStatus>('/health');
  }

  /** Probe every configured endpoint's `/readyz` directly, for monitoring an HA deployment. */
  async endpoints(): Promise<EndpointReadiness[]> {
    return Promise.all(this.http.baseUrls.map(async (baseUrl): Promise<EndpointReadiness> => {
      try {
        const { status, body } = await this.http.publicGetAt<Record<string, unknown>>(baseUrl, '/readyz');
        if (status === 200) return { base_url: baseUrl, reachable: true, ready: true, readiness: normalise(body, true) };
        const details = (body?.['error'] as { details?: Record<string, unknown> } | undefined)?.details;
        return {
          base_url: baseUrl, reachable: true, ready: false,
          ...(details ? { readiness: normalise(details, false) } : {}),
          error: `HTTP ${status}`,
        };
      } catch (err) {
        return { base_url: baseUrl, reachable: false, ready: false, error: (err as Error).message };
      }
    }));
  }
}
