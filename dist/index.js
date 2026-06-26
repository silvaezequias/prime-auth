"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  InsufficientScopeError: () => InsufficientScopeError,
  InvalidTokenError: () => InvalidTokenError,
  PrimeAuth: () => PrimeAuth,
  PrimeAuthError: () => PrimeAuthError,
  ServerError: () => ServerError,
  TokenExpiredError: () => TokenExpiredError,
  generateCodeChallenge: () => generateCodeChallenge,
  generateCodeVerifier: () => generateCodeVerifier,
  generateState: () => generateState
});
module.exports = __toCommonJS(index_exports);

// src/client.ts
var import_crypto = require("crypto");
var import_jose = require("jose");

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

// src/client.ts
var DEFAULT_SCOPES = ["openid", "profile", "email"];
var PrimeAuth = class {
  constructor(config) {
    const serverUrl = config.serverUrl ?? process.env["PRIME_AUTH_SERVER_URL"];
    if (!serverUrl) throw new PrimeAuthError(
      "serverUrl n\xE3o configurado. Defina no construtor ou em PRIME_AUTH_SERVER_URL.",
      "config_error"
    );
    if (!config.clientId) throw new PrimeAuthError("clientId \xE9 obrigat\xF3rio.", "config_error");
    if (!config.clientSecret) throw new PrimeAuthError("clientSecret \xE9 obrigat\xF3rio.", "config_error");
    if (!config.redirectUri) throw new PrimeAuthError("redirectUri \xE9 obrigat\xF3rio.", "config_error");
    this._serverUrl = serverUrl.replace(/\/$/, "");
    this._clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this._redirectUri = config.redirectUri;
    this._scopes = config.scopes ?? DEFAULT_SCOPES;
    this._timeoutMs = config.timeoutMs ?? 1e4;
    this.cookieName = config.cookieName ?? "prime_auth_session";
    this.cookieMaxAge = config.cookieMaxAge ?? 60 * 60 * 24 * 7;
  }
  // ─── Getters ──────────────────────────────────────────────────────────────
  get serverUrl() {
    return this._serverUrl;
  }
  get clientId() {
    return this._clientId;
  }
  get redirectUri() {
    return this._redirectUri;
  }
  get scopes() {
    return this._scopes;
  }
  // ─── Authorization URL ────────────────────────────────────────────────────
  getAuthorizationUrl(extra) {
    const state = (0, import_crypto.randomBytes)(16).toString("hex");
    const query = new URLSearchParams({
      response_type: "code",
      client_id: this._clientId,
      redirect_uri: this._redirectUri,
      scope: this._scopes.join(" "),
      state,
      ...extra
    });
    return { url: `${this._serverUrl}/oauth/authorize?${query}`, state };
  }
  // ─── Token Exchange ───────────────────────────────────────────────────────
  async exchangeCode(code, codeVerifier) {
    const body = {
      grant_type: "authorization_code",
      code,
      redirect_uri: this._redirectUri,
      client_id: this._clientId,
      client_secret: this.clientSecret
    };
    if (codeVerifier) body["code_verifier"] = codeVerifier;
    return this._tokenRequest(body);
  }
  async refreshToken(refreshToken) {
    return this._tokenRequest({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: this._clientId,
      client_secret: this.clientSecret
    });
  }
  async revokeToken(token, hint = "access_token") {
    await this._fetch(`${this._serverUrl}/oauth/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token, token_type_hint: hint }).toString()
    });
  }
  // ─── UserInfo ─────────────────────────────────────────────────────────────
  async getUserInfo(accessToken) {
    const info = await this._fetch(`${this._serverUrl}/oauth/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    return {
      sub: String(info.sub),
      username: info.username,
      name: info.name,
      email: info.email,
      avatar: info.avatar ?? info.picture,
      scope: String(info.scope ?? ""),
      accessToken
    };
  }
  // ─── Token helpers ────────────────────────────────────────────────────────
  decodeToken(accessToken) {
    try {
      return (0, import_jose.decodeJwt)(accessToken);
    } catch {
      throw new InvalidTokenError("N\xE3o foi poss\xEDvel decodificar o token.");
    }
  }
  isTokenExpired(accessToken) {
    try {
      const { exp } = this.decodeToken(accessToken);
      if (!exp) return false;
      return Date.now() >= exp * 1e3;
    } catch {
      return true;
    }
  }
  // ─── Privados ─────────────────────────────────────────────────────────────
  async _tokenRequest(body) {
    const data = await this._fetch(`${this._serverUrl}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString()
    });
    return {
      access_token: data["access_token"],
      token_type: data["token_type"] ?? "Bearer",
      expires_in: data["expires_in"] ?? 3600,
      refresh_token: data["refresh_token"],
      scope: data["scope"],
      expires_at: Date.now() + (data["expires_in"] ?? 3600) * 1e3
    };
  }
  async _fetch(url, init = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeoutMs);
    let res;
    try {
      res = await fetch(url, { ...init, signal: controller.signal });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new PrimeAuthError(`Falha de rede: ${msg}`, "network_error");
    } finally {
      clearTimeout(timer);
    }
    if (res.status === 204) return null;
    const ct = res.headers.get("content-type") ?? "";
    let body;
    try {
      body = ct.includes("application/json") ? await res.json() : await res.text();
    } catch {
      body = null;
    }
    if (!res.ok) {
      const e = body;
      const message = String(e?.["error_description"] ?? e?.["error"] ?? `Erro ${res.status}`);
      if (res.status === 401) throw new InvalidTokenError(message);
      throw new ServerError(message, res.status, body);
    }
    return body;
  }
};

// src/pkce.ts
var import_crypto2 = require("crypto");
function generateCodeVerifier() {
  return (0, import_crypto2.randomBytes)(32).toString("base64url");
}
function generateCodeChallenge(verifier) {
  return (0, import_crypto2.createHash)("sha256").update(verifier).digest("base64url");
}
function generateState() {
  return (0, import_crypto2.randomBytes)(16).toString("hex");
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  InsufficientScopeError,
  InvalidTokenError,
  PrimeAuth,
  PrimeAuthError,
  ServerError,
  TokenExpiredError,
  generateCodeChallenge,
  generateCodeVerifier,
  generateState
});
