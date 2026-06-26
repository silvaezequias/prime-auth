import {
  InsufficientScopeError
} from "../chunk-BQARVMFT.mjs";
import {
  decodeSession,
  encodeSession
} from "../chunk-NQRGQ7TS.mjs";

// src/express/router.ts
import { Router } from "express";
function createRouter(auth, opts = {}) {
  const successRedirect = opts.successRedirect ?? "/";
  const errorRedirect = opts.errorRedirect ?? "/auth/login";
  const loginPath = opts.loginPath ?? "/auth/login";
  const isProduction = process.env["NODE_ENV"] === "production";
  const router = Router();
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
export {
  createRouter,
  requireAuth
};
