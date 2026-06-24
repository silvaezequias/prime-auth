import {
  InsufficientScopeError,
  InvalidTokenError,
  PrimeAuthError,
  ServerError,
  TokenExpiredError
} from "./chunk-BQARVMFT.mjs";

// src/client.ts
import { randomBytes } from "crypto";
import { decodeJwt } from "jose";
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
    const state = randomBytes(16).toString("hex");
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
      return decodeJwt(accessToken);
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
import { createHash, randomBytes as randomBytes2 } from "crypto";
function generateCodeVerifier() {
  return randomBytes2(32).toString("base64url");
}
function generateCodeChallenge(verifier) {
  return createHash("sha256").update(verifier).digest("base64url");
}
function generateState() {
  return randomBytes2(16).toString("hex");
}
export {
  InsufficientScopeError,
  InvalidTokenError,
  PrimeAuth,
  PrimeAuthError,
  ServerError,
  TokenExpiredError,
  generateCodeChallenge,
  generateCodeVerifier,
  generateState
};
