import {
  InsufficientScopeError,
  InvalidTokenError,
  PrimeAuthError,
  ServerError,
  TokenExpiredError
} from "./chunk-BQARVMFT.mjs";
import {
  configureLogger,
  log
} from "./chunk-UQJ5ES24.mjs";

// src/client.ts
import { randomBytes } from "crypto";
import { decodeJwt } from "jose";
var DEFAULT_SCOPES = ["openid", "profile", "email"];
var PrimeAuth = class {
  constructor(config) {
    const serverUrl = config.serverUrl ?? process.env["PRIME_AUTH_SERVER_URL"];
    if (!serverUrl) {
      log("error", "serverUrl n\xE3o configurado. Defina no construtor ou em PRIME_AUTH_SERVER_URL no .env.");
      throw new PrimeAuthError("serverUrl n\xE3o configurado.", "config_error");
    }
    if (!config.clientId) {
      log("error", "clientId n\xE3o informado. Verifique a configura\xE7\xE3o do PrimeAuth.");
      throw new PrimeAuthError("clientId \xE9 obrigat\xF3rio.", "config_error");
    }
    if (!config.clientSecret) {
      log("error", "clientSecret n\xE3o informado. Verifique a configura\xE7\xE3o do PrimeAuth.");
      throw new PrimeAuthError("clientSecret \xE9 obrigat\xF3rio.", "config_error");
    }
    if (!config.redirectUri) {
      log("error", "redirectUri n\xE3o informado. Defina a URI de redirecionamento registrada na aplica\xE7\xE3o.");
      throw new PrimeAuthError("redirectUri \xE9 obrigat\xF3rio.", "config_error");
    }
    this._serverUrl = serverUrl.replace(/\/$/, "");
    this._clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this._redirectUri = config.redirectUri;
    this._scopes = config.scopes ?? DEFAULT_SCOPES;
    this._timeoutMs = config.timeoutMs ?? 1e4;
    this.cookieName = config.cookieName ?? "prime_auth_session";
    this.cookieMaxAge = config.cookieMaxAge ?? 60 * 60 * 24 * 7;
    log("info", "PrimeAuth inicializado.", {
      serverUrl: this._serverUrl,
      clientId: this._clientId,
      redirectUri: this._redirectUri,
      scopes: this._scopes
    });
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
    const url = `${this._serverUrl}/oauth/authorize?${query}`;
    log("debug", "URL de autoriza\xE7\xE3o gerada.", { url, scopes: this._scopes.join(" ") });
    return { url, state };
  }
  // ─── Token Exchange ───────────────────────────────────────────────────────
  async exchangeCode(code, codeVerifier) {
    log("info", "Trocando authorization code por tokens...", { hasPKCE: !!codeVerifier });
    const body = {
      grant_type: "authorization_code",
      code,
      redirect_uri: this._redirectUri,
      client_id: this._clientId,
      client_secret: this.clientSecret
    };
    if (codeVerifier) body["code_verifier"] = codeVerifier;
    try {
      const tokenSet = await this._tokenRequest(body);
      log("info", "Authorization code trocado com sucesso.", {
        tokenType: tokenSet.token_type,
        expiresIn: tokenSet.expires_in,
        hasRefreshToken: !!tokenSet.refresh_token,
        scope: tokenSet.scope
      });
      return tokenSet;
    } catch (err) {
      log("error", "Falha ao trocar authorization code por tokens.", { error: String(err) });
      throw err;
    }
  }
  async refreshToken(refreshToken) {
    log("info", "Renovando access token via refresh token...");
    try {
      const tokenSet = await this._tokenRequest({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: this._clientId,
        client_secret: this.clientSecret
      });
      log("info", "Access token renovado com sucesso.", {
        expiresIn: tokenSet.expires_in,
        hasRefreshToken: !!tokenSet.refresh_token
      });
      return tokenSet;
    } catch (err) {
      log("error", "Falha ao renovar access token. Verifique se o refresh token ainda \xE9 v\xE1lido.", { error: String(err) });
      throw err;
    }
  }
  async revokeToken(token, hint = "access_token") {
    log("info", `Revogando ${hint}...`);
    try {
      await this._fetch(`${this._serverUrl}/oauth/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token, token_type_hint: hint }).toString()
      });
      log("info", `${hint} revogado com sucesso.`);
    } catch (err) {
      log("error", `Falha ao revogar ${hint}.`, { error: String(err) });
      throw err;
    }
  }
  // ─── UserInfo ─────────────────────────────────────────────────────────────
  async getUserInfo(accessToken) {
    log("debug", "Buscando informa\xE7\xF5es do usu\xE1rio em /oauth/userinfo...");
    try {
      const info = await this._fetch(`${this._serverUrl}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      if (!info.sub) {
        log("warn", 'O servidor retornou userinfo sem o campo "sub". Verifique se o escopo "openid" foi concedido.');
      }
      const user = {
        sub: String(info.sub),
        username: info.username,
        name: info.name,
        email: info.email,
        avatar: info.avatar ?? info.picture,
        scope: String(info.scope ?? ""),
        accessToken
      };
      log("debug", "Dados do usu\xE1rio obtidos com sucesso.", {
        sub: user.sub,
        username: user.username,
        name: user.name,
        email: user.email,
        hasAvatar: !!user.avatar,
        scope: user.scope
      });
      return user;
    } catch (err) {
      log("error", "Falha ao buscar informa\xE7\xF5es do usu\xE1rio. Verifique se o access token \xE9 v\xE1lido.", { error: String(err) });
      throw err;
    }
  }
  // ─── Token helpers ────────────────────────────────────────────────────────
  decodeToken(accessToken) {
    try {
      const payload = decodeJwt(accessToken);
      log("debug", "Token JWT decodificado localmente.", {
        sub: payload.sub,
        exp: payload.exp ? new Date(payload.exp * 1e3).toISOString() : void 0
      });
      return payload;
    } catch (err) {
      log("error", "N\xE3o foi poss\xEDvel decodificar o JWT. O token pode estar malformado.", { error: String(err) });
      throw new InvalidTokenError("N\xE3o foi poss\xEDvel decodificar o token.");
    }
  }
  isTokenExpired(accessToken) {
    try {
      const { exp } = this.decodeToken(accessToken);
      if (!exp) {
        log("warn", 'Token JWT n\xE3o possui campo "exp". Assumindo que n\xE3o est\xE1 expirado.');
        return false;
      }
      const expired = Date.now() >= exp * 1e3;
      if (expired) log("debug", "Token JWT est\xE1 expirado.", { expiredAt: new Date(exp * 1e3).toISOString() });
      return expired;
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
    const method = (init.method ?? "GET").toUpperCase();
    log("debug", `HTTP ${method} \u2192 ${url}`);
    const controller = new AbortController();
    const timer = setTimeout(() => {
      log("warn", `Requisi\xE7\xE3o para ${url} excedeu o timeout de ${this._timeoutMs}ms.`);
      controller.abort();
    }, this._timeoutMs);
    let res;
    try {
      res = await fetch(url, { ...init, signal: controller.signal });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const isAbort = err instanceof Error && err.name === "AbortError";
      if (isAbort) {
        log("error", `Timeout ao conectar em ${url}. Verifique se o servidor est\xE1 acess\xEDvel em: ${this._serverUrl}`);
      } else {
        log("error", `Falha de rede ao conectar em ${url}. Verifique a vari\xE1vel PRIME_AUTH_SERVER_URL e se o servidor est\xE1 rodando.`, { error: msg });
      }
      throw new PrimeAuthError(`Falha de rede: ${msg}`, "network_error");
    } finally {
      clearTimeout(timer);
    }
    log("debug", `HTTP ${method} \u2190 ${url}`, { status: res.status, ok: res.ok });
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
      if (res.status === 401) {
        log("warn", `Servidor retornou 401 em ${url}. O token pode ser inv\xE1lido ou expirado.`, { error: e?.["error"], description: e?.["error_description"] });
        throw new InvalidTokenError(message);
      }
      if (res.status === 400) {
        log("warn", `Servidor retornou 400 em ${url}. Verifique os par\xE2metros enviados.`, { error: e?.["error"], description: e?.["error_description"] });
      } else if (res.status >= 500) {
        log("error", `Servidor retornou ${res.status} em ${url}. O servidor de autentica\xE7\xE3o pode estar com problema.`, { body });
      } else {
        log("warn", `Servidor retornou ${res.status} em ${url}.`, { error: message });
      }
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
  configureLogger,
  generateCodeChallenge,
  generateCodeVerifier,
  generateState
};
