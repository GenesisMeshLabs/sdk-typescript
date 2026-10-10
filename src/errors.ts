/** Typed error classes mirroring the NA HTTP error surface. */

export class GenesisMeshError extends Error {
  readonly code: string;
  readonly status: number;
  /** Structured `error.details` from the NA envelope (empty when absent). */
  details: Record<string, unknown> = {};
  /** `error.request_id` from the NA envelope, for correlating with NA logs. */
  requestId: string | null = null;
  /** Seconds to wait before trying again, from the response's `Retry-After` header (1.3.1); null without one. */
  retryAfterSeconds: number | null = null;

  constructor(message: string, code: string, status: number) {
    super(message);
    this.name = 'GenesisMeshError';
    this.code = code;
    this.status = status;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class UnauthorizedError extends GenesisMeshError {
  constructor(message = 'Unauthorized', code = 'unauthorized') {
    super(message, code, 401);
    this.name = 'UnauthorizedError';
  }
}

export class ValidationError extends GenesisMeshError {
  constructor(message: string, code = 'validation_error') {
    super(message, code, 422);
    this.name = 'ValidationError';
  }
}

export class ForbiddenError extends GenesisMeshError {
  constructor(message = 'Forbidden', code = 'forbidden') {
    super(message, code, 403);
    this.name = 'ForbiddenError';
  }
}

/** 409: the request conflicts with stored state (e.g. `evidence_conflict`, `executor_key_exists`). */
export class ConflictError extends GenesisMeshError {
  constructor(message: string, code = 'conflict') {
    super(message, code, 409);
    this.name = 'ConflictError';
  }
}

export class ServiceUnavailableError extends GenesisMeshError {
  constructor(message = 'Service unavailable', code = 'service_unavailable') {
    super(message, code, 503);
    this.name = 'ServiceUnavailableError';
  }
}

export class NotFoundError extends GenesisMeshError {
  constructor(message: string, code = 'not_found') {
    super(message, code, 404);
    this.name = 'NotFoundError';
  }
}

export class RateLimitError extends GenesisMeshError {
  constructor(message = 'Rate limit exceeded', code = 'rate_limit_exceeded') {
    super(message, code, 429);
    this.name = 'RateLimitError';
  }
}

export class NetworkError extends GenesisMeshError {
  /**
   * True when the connection could not be established (refused, unresolvable,
   * unreachable): the request never reached the NA, so another instance may
   * take it even when it is not idempotent (v0.60).
   */
  connectFailed = false;

  constructor(message: string, code = 'network_error') {
    super(message, code, 0);
    this.name = 'NetworkError';
  }
}

export class BadRequestError extends GenesisMeshError {
  constructor(message: string, code = 'bad_request') {
    super(message, code, 400);
    this.name = 'BadRequestError';
  }
}

/** Seconds a `Retry-After` header asks for (delay-seconds or an HTTP date), or null when it says nothing usable. */
export function retryAfterSeconds(header: string | null | undefined, now = Date.now()): number | null {
  const value = header?.trim();
  if (!value) return null;
  if (/^\d+$/.test(value)) return Number(value);
  const at = Date.parse(value);
  return Number.isNaN(at) ? null : Math.max(0, Math.ceil((at - now) / 1000));
}

/** Maps an HTTP error response body to the appropriate typed error.
 *
 * Handles both flat format  { error: "string", code: "..." }
 * and nested format         { error: { message: "...", code: "..." } }
 * as produced by the Genesis Mesh NA.
 */
export function fromHttpError(status: number, body: Record<string, unknown>): GenesisMeshError {
  const errorField = body['error'];
  let message: string;
  let code: string;
  let details: unknown;
  let requestId: unknown;

  if (typeof errorField === 'object' && errorField !== null) {
    const nested = errorField as Record<string, unknown>;
    message = String(nested['message'] ?? 'Unknown error');
    code = String(nested['code'] ?? 'unknown');
    details = nested['details'];
    requestId = nested['request_id'];
  } else {
    message = String(errorField ?? body['message'] ?? 'Unknown error');
    code = String(body['code'] ?? 'unknown');
  }

  const error = errorForStatus(status, message, code);
  if (typeof details === 'object' && details !== null && !Array.isArray(details)) {
    error.details = details as Record<string, unknown>;
  }
  if (typeof requestId === 'string') error.requestId = requestId;
  return error;
}

function errorForStatus(status: number, message: string, code: string): GenesisMeshError {
  switch (status) {
    case 400: return new BadRequestError(message, code);
    case 401: return new UnauthorizedError(message, code);
    case 403: return new ForbiddenError(message, code);
    case 404: return new NotFoundError(message, code);
    case 409: return new ConflictError(message, code);
    case 422: return new ValidationError(message, code);
    case 429: return new RateLimitError(message, code);
    case 503: return new ServiceUnavailableError(message, code);
    default:  return new GenesisMeshError(message, code, status);
  }
}

const HA_CONFLICT_CODES: ReadonlySet<string> = new Set([
  'boundary_policy_activation_conflict',
  'boundary_policy_version_conflict',
  'crl_publish_contention',
  'retention_in_progress',
]);

/**
 * True for a 409 that only means another NA instance won a race the database
 * decided (v0.60). The request changed nothing and can be retried.
 */
export function isRetryableConflict(err: unknown): err is ConflictError {
  return err instanceof ConflictError && HA_CONFLICT_CODES.has(err.code);
}
