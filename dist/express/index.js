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
var SEP = ".";
function sign(payload, secret) {
  return (0, import_crypto.createHmac)("sha256", secret).update(payload).digest("base64url");
}
function encodeSession(data, secret) {
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
  const sig = sign(payload, secret);
  return `${payload}${SEP}${sig}`;
}
function decodeSession(cookie, secret) {
  const dotIdx = cookie.lastIndexOf(SEP);
  if (dotIdx === -1) return null;
  const payload = cookie.slice(0, dotIdx);
  const sig = cookie.slice(dotIdx + 1);
  const expected = sign(payload, secret);
  try {
    const expectedBuf = Buffer.from(expected);
    const sigBuf = Buffer.from(sig);
    if (expectedBuf.length !== sigBuf.length) return null;
    if (!(0, import_crypto.timingSafeEqual)(expectedBuf, sigBuf)) return null;
  } catch {
    return null;
  }
  try {
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

// src/express/router.ts
function createRouter(auth, opts = {}) {
  const successRedirect = opts.successRedirect ?? "/";
  const errorRedirect = opts.errorRedirect ?? "/auth/login";
  const loginPath = opts.loginPath ?? "/auth/login";
  const isProduction = process.env["NODE_ENV"] === "production";
  const router = (0, import_express.Router)();
  router.get("/auth/login", (req, res) => {
    const returnTo = req.query["returnTo"];
    const { url, state } = auth.getAuthorizationUrl();
    res.cookie("_pa_state", state, {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 10 * 60 * 1e3,
      secure: isProduction
    });
    if (returnTo) {
      res.cookie("_pa_return", returnTo, {
        httpOnly: true,
        sameSite: "lax",
        maxAge: 10 * 60 * 1e3,
        secure: isProduction
      });
    }
    res.redirect(url);
  });
  router.get("/auth/callback", async (req, res) => {
    const { code, state, error, error_description } = req.query;
    if (error) {
      console.error("[prime-auth] Servidor retornou erro:", error, error_description);
      return res.redirect(`${errorRedirect}?error=${encodeURIComponent(error)}`);
    }
    if (!code) return res.redirect(`${errorRedirect}?error=missing_code`);
    const savedState = req.cookies?.["_pa_state"];
    const returnTo = req.cookies?.["_pa_return"];
    res.clearCookie("_pa_state");
    res.clearCookie("_pa_return");
    if (savedState && state !== savedState) {
      return res.redirect(`${errorRedirect}?error=state_mismatch`);
    }
    let user;
    try {
      const tokenSet = await auth.exchangeCode(code);
      user = await auth.getUserInfo(tokenSet.access_token);
      res.cookie(auth.cookieName, encodeSession({
        accessToken: tokenSet.access_token,
        refreshToken: tokenSet.refresh_token,
        expiresAt: tokenSet.expires_at
      }, auth.clientSecret), {
        httpOnly: true,
        sameSite: "lax",
        maxAge: auth.cookieMaxAge * 1e3,
        secure: isProduction
      });
      if (opts.onSuccess) await opts.onSuccess(user, req, res);
      res.redirect(returnTo ?? successRedirect);
    } catch (err) {
      console.error("[prime-auth] Erro no callback:", err);
      res.redirect(`${errorRedirect}?error=callback_failed`);
    }
  });
  router.get("/auth/logout", (req, res) => {
    res.clearCookie(auth.cookieName);
    res.redirect(loginPath);
  });
  router.get("/auth/me", async (req, res) => {
    const raw = req.cookies?.[auth.cookieName];
    if (!raw) return res.json(null);
    const session = decodeSession(raw, auth.clientSecret);
    if (!session || Date.now() >= session.expiresAt) return res.json(null);
    try {
      const user = await auth.getUserInfo(session.accessToken);
      res.json(user);
    } catch {
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
      if (opts.json) return res.status(status).json({ error: code, error_description: message });
      const returnTo = encodeURIComponent(req.originalUrl ?? "/");
      res.redirect(`${loginPath}?returnTo=${returnTo}`);
    };
    if (!raw) return fail("unauthenticated", "Sess\xE3o n\xE3o encontrada.");
    let session = decodeSession(raw, auth.clientSecret);
    if (!session) return fail("invalid_session", "Sess\xE3o inv\xE1lida.");
    if (Date.now() >= session.expiresAt - 6e4) {
      if (!session.refreshToken) return fail("session_expired", "Sess\xE3o expirada.");
      try {
        const tokenSet = await auth.refreshToken(session.refreshToken);
        session = {
          accessToken: tokenSet.access_token,
          refreshToken: tokenSet.refresh_token ?? session.refreshToken,
          expiresAt: tokenSet.expires_at
        };
        res.cookie(auth.cookieName, encodeSession(session, auth.clientSecret), {
          httpOnly: true,
          sameSite: "lax",
          maxAge: auth.cookieMaxAge * 1e3,
          secure: isProduction
        });
      } catch {
        res.clearCookie(auth.cookieName);
        return fail("session_expired", "Sess\xE3o expirada.");
      }
    }
    let user;
    try {
      user = await auth.getUserInfo(session.accessToken);
    } catch {
      res.clearCookie(auth.cookieName);
      return fail("invalid_token", "Token inv\xE1lido.");
    }
    if (opts.scopes?.length) {
      const granted = user.scope.split(" ");
      const missing = opts.scopes.filter((s) => !granted.includes(s));
      if (missing.length) {
        const e = new InsufficientScopeError(missing);
        if (opts.json) return res.status(403).json({ error: e.code, error_description: e.message });
        return res.status(403).send(e.message);
      }
    }
    req.user = user;
    next();
  };
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  createRouter,
  requireAuth
});
