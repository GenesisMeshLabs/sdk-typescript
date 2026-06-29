/** Typed error classes mirroring the NA HTTP error surface. */

export class GenesisMeshError extends Error {
  readonly code: string;
  readonly status: number;

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

  if (typeof errorField === 'object' && errorField !== null) {
    const nested = errorField as Record<string, unknown>;
    message = String(nested['message'] ?? 'Unknown error');
    code = String(nested['code'] ?? 'unknown');
  } else {
    message = String(errorField ?? body['message'] ?? 'Unknown error');
    code = String(body['code'] ?? 'unknown');
  }

  switch (status) {
    case 400: return new BadRequestError(message, code);
    case 401: return new UnauthorizedError(message, code);
    case 404: return new NotFoundError(message, code);
    case 422: return new ValidationError(message, code);
    case 429: return new RateLimitError(message, code);
    default:  return new GenesisMeshError(message, code, status);
  }
}
