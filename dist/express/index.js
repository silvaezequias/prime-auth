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

// src/express/index.ts
var express_exports = {};
__export(express_exports, {
  createRouter: () => createRouter,
  requireAuth: () => requireAuth
});
module.exports = __toCommonJS(express_exports);

// src/express/router.ts
var import_express = require("express");

// src/session.ts
var import_crypto = require("crypto");

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

// src/session.ts
var SEP = ".";
function sign(payload, secret) {
  return (0, import_crypto.createHmac)("sha256", secret).update(payload).digest("base64url");
}
function encodeSession(data, secret) {
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
  const sig = sign(payload, secret);
  log("debug", "Sess\xE3o codificada no cookie.", {
    expiresAt: new Date(data.expiresAt).toISOString(),
    hasRefreshToken: !!data.refreshToken
  });
  return `${payload}${SEP}${sig}`;
}
function decodeSession(cookie, secret) {
  const dotIdx = cookie.lastIndexOf(SEP);
  if (dotIdx === -1) {
    log("warn", "Cookie de sess\xE3o malformado (separador ausente). A sess\xE3o ser\xE1 ignorada.");
    return null;
  }
  const payload = cookie.slice(0, dotIdx);
  const sig = cookie.slice(dotIdx + 1);
  try {
    const expected = Buffer.from(sign(payload, secret));
    const sigBuf = Buffer.from(sig);
    if (expected.length !== sigBuf.length || !(0, import_crypto.timingSafeEqual)(expected, sigBuf)) {
      log("warn", "Assinatura do cookie de sess\xE3o inv\xE1lida. Poss\xEDvel adultera\xE7\xE3o ou clientSecret incorreto.");
      return null;
    }
  } catch (err) {
    log("error", "Erro ao verificar assinatura do cookie de sess\xE3o.", { error: String(err) });
    return null;
  }
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    log("debug", "Sess\xE3o decodificada com sucesso.", {
      expiresAt: new Date(data.expiresAt).toISOString(),
      expired: Date.now() >= data.expiresAt
    });
    return data;
  } catch (err) {
    log("error", "Erro ao desserializar dados da sess\xE3o.", { error: String(err) });
    return null;
  }
}

// src/tenant.ts
var IGNORED_SUBDOMAINS = /* @__PURE__ */ new Set(["www"]);
function extractTenantFromHost(hostname) {
  const host = hostname.split(":")[0] ?? "";
  const labels = host.split(".").filter(Boolean);
  const isLocalhostSubdomain = labels.length === 2 && labels[1] === "localhost";
  if (labels.length < 3 && !isLocalhostSubdomain) return void 0;
  const candidate = labels[0];
  if (!candidate || IGNORED_SUBDOMAINS.has(candidate)) return void 0;
  return candidate;
}

// src/express/router.ts
function createRouter(auth, opts = {}) {
  const successRedirect = opts.successRedirect ?? "/";
  const errorRedirect = opts.errorRedirect ?? "/auth/login";
  const loginPath = opts.loginPath ?? "/auth/login";
  const isProduction = process.env["NODE_ENV"] === "production";
  log("info", "[express] Router OAuth2 configurado.", { successRedirect, errorRedirect, loginPath });
  const router = (0, import_express.Router)();
  router.get("/auth/login", async (req, res) => {
    try {
      const returnTo = req.query["returnTo"];
      let tenant = req.query["tenant"] ?? (opts.tenantFromSubdomain ? extractTenantFromHost(req.hostname) : void 0);
      if (!tenant && opts.autoTenant) {
        try {
          tenant = (await auth.getAppInfo()).tenantSlug ?? void 0;
        } catch (err) {
          log("warn", "[express] autoTenant: falha ao buscar o tenant via getAppInfo(). Prosseguindo sem tenant.", { error: String(err) });
        }
      }
      log("info", "[express] Iniciando fluxo de login.", { returnTo, tenant, ip: req.ip });
      const { url, state } = auth.getAuthorizationUrl(void 0, tenant);
      res.cookie("_pa_state", state, { httpOnly: true, sameSite: "lax", maxAge: 10 * 60 * 1e3, secure: isProduction });
      if (returnTo) {
        res.cookie("_pa_return", returnTo, { httpOnly: true, sameSite: "lax", maxAge: 10 * 60 * 1e3, secure: isProduction });
      }
      log("debug", "[express] Redirecionando para o servidor de autentica\xE7\xE3o.", { url });
      res.redirect(url);
    } catch (err) {
      log("error", "[express] Falha ao iniciar fluxo de login.", { error: String(err) });
      res.status(500).send("Erro ao iniciar login.");
    }
  });
  router.get("/auth/callback", async (req, res) => {
    const { code, state, error, error_description } = req.query;
    log("info", "[express] Callback OAuth2 recebido.", { hasCode: !!code, hasState: !!state, error: error ?? void 0 });
    if (error) {
      log("error", "[express] Servidor de autentica\xE7\xE3o retornou erro no callback. Verifique as configura\xE7\xF5es da aplica\xE7\xE3o no painel.", {
        error,
        description: error_description
      });
      return res.redirect(`${errorRedirect}?error=${encodeURIComponent(error)}`);
    }
    if (!code) {
      log("error", '[express] Callback recebido sem o par\xE2metro "code". O servidor deveria ter enviado o authorization code.');
      return res.redirect(`${errorRedirect}?error=missing_code`);
    }
    const savedState = req.cookies?.["_pa_state"];
    const returnTo = req.cookies?.["_pa_return"];
    res.clearCookie("_pa_state");
    res.clearCookie("_pa_return");
    if (savedState && state !== savedState) {
      log("warn", "[express] State CSRF n\xE3o confere. A requisi\xE7\xE3o pode ter sido interceptada ou o cookie expirou.", {
        expected: savedState,
        received: state
      });
      return res.redirect(`${errorRedirect}?error=state_mismatch`);
    }
    if (!savedState) {
      log("warn", "[express] Cookie de state n\xE3o encontrado. Pode ter expirado (10 min) ou o navegador bloqueou cookies.");
    }
    let user;
    try {
      log("info", "[express] Trocando authorization code por tokens...");
      const tokenSet = await auth.exchangeCode(code);
      log("info", "[express] Buscando dados do usu\xE1rio...");
      user = await auth.getUserInfo(tokenSet.access_token);
      res.cookie(auth.cookieName, encodeSession({
        accessToken: tokenSet.access_token,
        refreshToken: tokenSet.refresh_token,
        expiresAt: tokenSet.expires_at
      }, auth.sessionSecret), {
        httpOnly: true,
        sameSite: "lax",
        maxAge: auth.cookieMaxAge * 1e3,
        secure: isProduction
      });
      log("info", "[express] Login conclu\xEDdo com sucesso. Redirecionando.", {
        sub: user.sub,
        username: user.username,
        redirectTo: returnTo ?? successRedirect
      });
      if (opts.onSuccess) {
        log("debug", "[express] Executando callback onSuccess...");
        await opts.onSuccess(user, req, res);
      }
      res.redirect(returnTo ?? successRedirect);
    } catch (err) {
      log("error", "[express] Falha ao processar callback OAuth2. Verifique as credenciais e se o servidor est\xE1 acess\xEDvel.", {
        error: String(err),
        serverUrl: auth.serverUrl
      });
      res.redirect(`${errorRedirect}?error=callback_failed`);
    }
  });
  router.get("/auth/logout", (req, res) => {
    log("info", "[express] Usu\xE1rio deslogado. Sess\xE3o encerrada.", { ip: req.ip });
    res.clearCookie(auth.cookieName);
    res.redirect(loginPath);
  });
  router.get("/auth/me", async (req, res) => {
    log("debug", "[express] /auth/me \u2014 verificando sess\xE3o do usu\xE1rio.");
    const raw = req.cookies?.[auth.cookieName];
    if (!raw) {
      log("debug", "[express] /auth/me \u2014 nenhum cookie de sess\xE3o encontrado. Retornando null.");
      return res.json(null);
    }
    const session = decodeSession(raw, auth.sessionSecret);
    if (!session) {
      log("warn", "[express] /auth/me \u2014 cookie de sess\xE3o presente mas inv\xE1lido. Pode ter sido adulterado.");
      return res.json(null);
    }
    if (Date.now() >= session.expiresAt) {
      log("warn", "[express] /auth/me \u2014 sess\xE3o expirada.", { expiredAt: new Date(session.expiresAt).toISOString() });
      return res.json(null);
    }
    try {
      const user = await auth.getUserInfo(session.accessToken);
      log("debug", "[express] /auth/me \u2014 usu\xE1rio retornado.", { sub: user.sub });
      res.json(user);
    } catch (err) {
      log("error", "[express] /auth/me \u2014 falha ao buscar dados do usu\xE1rio com o access token salvo.", { error: String(err) });
      res.json(null);
    }
  });
  return router;
}

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
var InsufficientScopeError = class extends PrimeAuthError {
  constructor(required) {
    super(`Escopos insuficientes. Necess\xE1rio: ${required.join(", ")}.`, "insufficient_scope", 403);
    this.name = "InsufficientScopeError";
  }
};

// src/express/middleware.ts
function requireAuth(auth, opts = {}) {
  const loginPath = "/auth/login";
  const isProduction = process.env["NODE_ENV"] === "production";
  return async function primeAuthGuard(req, res, next) {
    const raw = req.cookies?.[auth.cookieName];
    const fail = (code, message, status = 401) => {
      if (opts.json) {
        log("warn", `[express:requireAuth] Acesso negado (${status}).`, { code, path: req.path });
        return res.status(status).json({ error: code, error_description: message });
      }
      const returnTo = encodeURIComponent(req.originalUrl ?? "/");
      log("warn", `[express:requireAuth] Acesso negado \u2014 redirecionando para login.`, { code, path: req.path, returnTo: req.originalUrl });
      res.redirect(`${loginPath}?returnTo=${returnTo}`);
    };
    if (!raw) {
      log("debug", `[express:requireAuth] Nenhum cookie de sess\xE3o encontrado.`, { path: req.path });
      return fail("unauthenticated", "Sess\xE3o n\xE3o encontrada.");
    }
    let session = decodeSession(raw, auth.sessionSecret);
    if (!session) {
      log("warn", `[express:requireAuth] Cookie de sess\xE3o inv\xE1lido ou adulterado.`, { path: req.path });
      return fail("invalid_session", "Sess\xE3o inv\xE1lida.");
    }
    if (Date.now() >= session.expiresAt - 6e4) {
      if (!session.refreshToken) {
        log("warn", "[express:requireAuth] Sess\xE3o expirada e sem refresh token. Usu\xE1rio precisar\xE1 fazer login novamente.", {
          path: req.path,
          expiredAt: new Date(session.expiresAt).toISOString()
        });
        res.clearCookie(auth.cookieName);
        return fail("session_expired", "Sess\xE3o expirada.");
      }
      log("info", "[express:requireAuth] Access token prestes a expirar. Renovando automaticamente...");
      try {
        const tokenSet = await auth.refreshToken(session.refreshToken);
        session = {
          accessToken: tokenSet.access_token,
          refreshToken: tokenSet.refresh_token ?? session.refreshToken,
          expiresAt: tokenSet.expires_at
        };
        res.cookie(auth.cookieName, encodeSession(session, auth.sessionSecret), {
          httpOnly: true,
          sameSite: "lax",
          maxAge: auth.cookieMaxAge * 1e3,
          secure: isProduction
        });
        log("info", "[express:requireAuth] Token renovado com sucesso.");
      } catch (err) {
        log("error", "[express:requireAuth] Falha ao renovar token. Encerrando sess\xE3o.", { error: String(err) });
        res.clearCookie(auth.cookieName);
        return fail("session_expired", "Sess\xE3o expirada.");
      }
    }
    let user;
    try {
      user = await auth.getUserInfo(session.accessToken);
    } catch (err) {
      log("error", "[express:requireAuth] Falha ao buscar dados do usu\xE1rio. O access token pode ter sido revogado.", {
        path: req.path,
        error: String(err)
      });
      res.clearCookie(auth.cookieName);
      return fail("invalid_token", "Token inv\xE1lido.");
    }
    if (opts.scopes?.length) {
      const granted = user.scope.split(" ");
      const missing = opts.scopes.filter((s) => !granted.includes(s));
      if (missing.length) {
        const e = new InsufficientScopeError(missing);
        log("warn", "[express:requireAuth] Escopos insuficientes.", {
          required: opts.scopes,
          granted,
          missing,
          path: req.path
        });
        if (opts.json) return res.status(403).json({ error: e.code, error_description: e.message });
        return res.status(403).send(e.message);
      }
    }
    log("debug", "[express:requireAuth] Acesso permitido.", { sub: user.sub, path: req.path });
    req.user = user;
    next();
  };
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  createRouter,
  requireAuth
});
