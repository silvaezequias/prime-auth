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
  configureLogger: () => configureLogger,
  extractTenantFromHost: () => extractTenantFromHost,
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

// src/logger.ts
var LEVELS = { debug: 0, info: 1, warn: 2, error: 3, silent: 4 };
var COLORS = {
  debug: "\x1B[36m",
  // ciano
  info: "\x1B[32m",
  // verde
  warn: "\x1B[33m",
  // amarelo
  error: "\x1B[31m",
  // vermelho
  reset: "\x1B[0m"
};
var PREFIX = "[prime-auth]";
var currentLevel = process.env["NODE_ENV"] === "production" ? "warn" : "info";
var customFn = null;
function configureLogger(opts) {
  if (opts.level !== void 0) currentLevel = opts.level;
  if (opts.fn !== void 0) customFn = opts.fn;
}
function log(level, message, context) {
  if (LEVELS[level] < LEVELS[currentLevel]) return;
  if (customFn) {
    customFn(level, message, context);
    return;
  }
  const color = COLORS[level];
  const reset = COLORS.reset;
  const label = `${color}${PREFIX}[${level.toUpperCase()}]${reset}`;
  const output = context ? `${message} ${JSON.stringify(context)}` : message;
  if (level === "error") console.error(label, output);
  else if (level === "warn") console.warn(label, output);
  else if (level === "debug") console.debug(label, output);
  else console.info(label, output);
}

// src/client.ts
var DEFAULT_SCOPES = ["openid", "profile", "email"];
var APP_INFO_CACHE_MS = 5 * 60 * 1e3;
var PrimeAuth = class {
  constructor(config) {
    this._appInfoCache = null;
    this._appInfoPromise = null;
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
    this._serverUrl = serverUrl.replace(/\/$/, "").replace(/\/api$/i, "");
    this._clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this._redirectUri = config.redirectUri;
    this._scopes = config.scopes ?? DEFAULT_SCOPES;
    this._timeoutMs = config.timeoutMs ?? 1e4;
    this.cookieName = config.cookieName ?? "prime_auth_session";
    this.cookieMaxAge = config.cookieMaxAge ?? 60 * 60 * 24 * 7;
    this._tenant = config.tenant;
    this._companyApiKey = config.companyApiKey;
    log("info", "PrimeAuth inicializado.", {
      serverUrl: this._serverUrl,
      clientId: this._clientId,
      redirectUri: this._redirectUri,
      scopes: this._scopes,
      tenant: this._tenant
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
  get tenant() {
    return this._tenant;
  }
  // ─── Authorization URL ────────────────────────────────────────────────────
  /**
   * Monta a URL de autorização para redirecionar o usuário.
   *
   * Se um tenant estiver disponível (via `tenantOverride` ou `config.tenant`),
   * usa o atalho `GET /oauth2/<tenant>` do servidor, que resolve o client_id
   * e o redirect_uri automaticamente a partir do tenant cadastrado. Caso
   * contrário, monta a URL tradicional em `/oauth/login` com os parâmetros
   * OAuth2 explícitos.
   */
  getAuthorizationUrl(extra, tenantOverride) {
    const state = (0, import_crypto.randomBytes)(16).toString("hex");
    const tenant = tenantOverride ?? this._tenant;
    if (tenant) {
      const query2 = new URLSearchParams({ state, ...extra });
      const url2 = `${this._serverUrl}/oauth2/${encodeURIComponent(tenant)}?${query2}`;
      log("debug", "URL de autoriza\xE7\xE3o gerada via tenant.", { url: url2, tenant });
      return { url: url2, state };
    }
    const query = new URLSearchParams({
      response_type: "code",
      client_id: this._clientId,
      redirect_uri: this._redirectUri,
      scope: this._scopes.join(" "),
      state,
      ...extra
    });
    const url = `${this._serverUrl}/oauth/login?${query}`;
    log("debug", "URL de autoriza\xE7\xE3o gerada.", { url, scopes: this._scopes.join(" ") });
    return { url, state };
  }
  /**
   * Busca informações públicas da aplicação (nome, empresa, logos e o
   * `tenantSlug` cadastrado, se houver) a partir do `clientId` configurado.
   * Não requer autenticação. O resultado é cacheado em memória por alguns
   * minutos para não bater na rede a cada chamada.
   */
  async getAppInfo() {
    const now = Date.now();
    if (this._appInfoCache && this._appInfoCache.expiresAt > now) {
      return this._appInfoCache.value;
    }
    if (this._appInfoPromise) return this._appInfoPromise;
    this._appInfoPromise = (async () => {
      log("debug", "Buscando informa\xE7\xF5es da aplica\xE7\xE3o em /api/oauth/app-info...");
      try {
        const query = new URLSearchParams({ client_id: this._clientId });
        const info = await this._fetch(`${this._serverUrl}/api/oauth/app-info?${query}`);
        this._appInfoCache = { value: info, expiresAt: now + APP_INFO_CACHE_MS };
        log("debug", "Informa\xE7\xF5es da aplica\xE7\xE3o obtidas.", { appId: info.appId, tenantSlug: info.tenantSlug });
        return info;
      } catch (err) {
        log("error", "Falha ao buscar informa\xE7\xF5es da aplica\xE7\xE3o.", { error: String(err) });
        throw err;
      } finally {
        this._appInfoPromise = null;
      }
    })();
    return this._appInfoPromise;
  }
  // ─── Company API (leitura de usuários entre aplicações) ───────────────────
  /**
   * Lista usuários de todas as aplicações da empresa, usando a chave de API
   * da empresa (`config.companyApiKey`) — não o `clientSecret` da aplicação.
   * Útil quando a mesma empresa tem mais de um tenant/aplicação e você
   * precisa reconhecer usuários independente de qual deles foi usado no login.
   */
  async listCompanyUsers(opts) {
    this._requireCompanyApiKey();
    const query = new URLSearchParams();
    if (opts?.limit) query.set("limit", String(opts.limit));
    if (opts?.cursor) query.set("cursor", opts.cursor);
    const qs = query.toString();
    return this._fetch(`${this._serverUrl}/api/company/v1/users${qs ? `?${qs}` : ""}`, {
      headers: { Authorization: `Bearer ${this._companyApiKey}` }
    });
  }
  /** Busca um usuário específico (por `sub`) em qualquer aplicação da empresa. Retorna `null` se não encontrado. */
  async getCompanyUser(sub) {
    this._requireCompanyApiKey();
    try {
      return await this._fetch(`${this._serverUrl}/api/company/v1/users/${encodeURIComponent(sub)}`, {
        headers: { Authorization: `Bearer ${this._companyApiKey}` }
      });
    } catch (err) {
      if (err instanceof ServerError && err.status === 404) return null;
      throw err;
    }
  }
  _requireCompanyApiKey() {
    if (!this._companyApiKey) {
      log("error", "companyApiKey n\xE3o configurada. Defina em `new PrimeAuth({ companyApiKey: ... })`.");
      throw new PrimeAuthError("companyApiKey n\xE3o configurada.", "config_error");
    }
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
      await this._fetch(`${this._serverUrl}/api/oauth/revoke`, {
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
      const info = await this._fetch(`${this._serverUrl}/api/oauth/userinfo`, {
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
      const payload = (0, import_jose.decodeJwt)(accessToken);
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
    const data = await this._fetch(`${this._serverUrl}/api/oauth/token`, {
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

// src/tenant.ts
var IGNORED_SUBDOMAINS = /* @__PURE__ */ new Set(["www"]);
function extractTenantFromHost(hostname) {
  const host = hostname.split(":")[0] ?? "";
  const labels = host.split(".").filter(Boolean);
  if (labels.length < 3) return void 0;
  const candidate = labels[0];
  if (!candidate || IGNORED_SUBDOMAINS.has(candidate)) return void 0;
  return candidate;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  InsufficientScopeError,
  InvalidTokenError,
  PrimeAuth,
  PrimeAuthError,
  ServerError,
  TokenExpiredError,
  configureLogger,
  extractTenantFromHost,
  generateCodeChallenge,
  generateCodeVerifier,
  generateState
});
