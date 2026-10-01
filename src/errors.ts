/** Typed error classes mirroring the NA HTTP error surface. */

export class GenesisMeshError extends Error {
  readonly code: string;
  readonly status: number;
  /** Structured `error.details` from the NA envelope (empty when absent). */
  details: Record<string, unknown> = {};
  /** `error.request_id` from the NA envelope, for correlating with NA logs. */
  requestId: string | null = null;

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
