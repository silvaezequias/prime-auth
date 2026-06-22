export class PrimeAuthError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly status?: number,
    public readonly detail?: unknown,
  ) {
    super(message)
    this.name = 'PrimeAuthError'
  }
}

export class TokenExpiredError extends PrimeAuthError {
  constructor() {
    super('Access token expirado.', 'token_expired', 401)
    this.name = 'TokenExpiredError'
  }
}

export class InvalidTokenError extends PrimeAuthError {
  constructor(detail?: string) {
    super(detail ?? 'Token inválido.', 'invalid_token', 401)
    this.name = 'InvalidTokenError'
  }
}

export class InsufficientScopeError extends PrimeAuthError {
  constructor(required: string[]) {
    super(`Escopos insuficientes. Necessário: ${required.join(', ')}.`, 'insufficient_scope', 403)
    this.name = 'InsufficientScopeError'
  }
}

export class ServerError extends PrimeAuthError {
  constructor(message: string, status: number, detail?: unknown) {
    super(message, 'server_error', status, detail)
    this.name = 'ServerError'
  }
}
