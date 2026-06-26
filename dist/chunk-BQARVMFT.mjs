// src/errors.ts
var PrimeAuthError = class extends Error {
  constructor(message, code, status, detail) {
    super(message);
    this.code = code;
    this.status = status;
    this.detail = detail;
    this.name = "PrimeAuthError";
  }
};
var TokenExpiredError = class extends PrimeAuthError {
  constructor() {
    super("Access token expirado.", "token_expired", 401);
    this.name = "TokenExpiredError";
  }
};
var InvalidTokenError = class extends PrimeAuthError {
  constructor(detail) {
    super(detail ?? "Token inv\xE1lido.", "invalid_token", 401);
    this.name = "InvalidTokenError";
  }
};
var InsufficientScopeError = class extends PrimeAuthError {
  constructor(required) {
    super(`Escopos insuficientes. Necess\xE1rio: ${required.join(", ")}.`, "insufficient_scope", 403);
    this.name = "InsufficientScopeError";
  }
};
var ServerError = class extends PrimeAuthError {
  constructor(message, status, detail) {
    super(message, "server_error", status, detail);
    this.name = "ServerError";
  }
};

export {
  PrimeAuthError,
  TokenExpiredError,
  InvalidTokenError,
  InsufficientScopeError,
  ServerError
};
