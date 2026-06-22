"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
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
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/next/index.ts
var next_exports = {};
__export(next_exports, {
  createCallbackHandler: () => createCallbackHandler,
  createHandlers: () => createHandlers,
  createLoginHandler: () => createLoginHandler,
  createLogoutHandler: () => createLogoutHandler,
  createMeHandler: () => createMeHandler,
  createMiddleware: () => createMiddleware,
  getUser: () => getUser,
  requireUser: () => requireUser
});
module.exports = __toCommonJS(next_exports);

// src/next/handlers.ts
var import_server = require("next/server");

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

// src/next/handlers.ts
function createHandlers(auth, opts = {}) {
  const { GET: loginGET } = createLoginHandler(auth);
  const { GET: callbackGET } = createCallbackHandler(auth, opts);
  const { GET: logoutGET } = createLogoutHandler(auth);
  const { GET: meGET } = createMeHandler(auth);
  async function GET(request) {
    const action = request.nextUrl.pathname.split("/").at(-1);
    switch (action) {
      case "login":
        return loginGET(request);
      case "callback":
        return callbackGET(request);
      case "logout":
        return logoutGET(request);
      case "me":
        return meGET(request);
      default:
        return import_server.NextResponse.json({ error: "not_found" }, { status: 404 });
    }
  }
  return { GET };
}
function createLoginHandler(auth) {
  const isProduction = process.env["NODE_ENV"] === "production";
  function GET(request) {
    const returnTo = request.nextUrl.searchParams.get("returnTo");
    const { url, state } = auth.getAuthorizationUrl();
    const res = import_server.NextResponse.redirect(url);
    res.cookies.set("_pa_state", state, {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 600,
      secure: isProduction,
      path: "/"
    });
    if (returnTo) {
      res.cookies.set("_pa_return", returnTo, {
        httpOnly: true,
        sameSite: "lax",
        maxAge: 600,
        secure: isProduction,
        path: "/"
      });
    }
    return res;
  }
  return { GET };
}
function createCallbackHandler(auth, opts = {}) {
  const successRedirect = opts.successRedirect ?? "/";
  const errorRedirect = opts.errorRedirect ?? "/auth/login";
  const isProduction = process.env["NODE_ENV"] === "production";
  async function GET(request) {
    const { searchParams } = request.nextUrl;
    const code = searchParams.get("code");
    const state = searchParams.get("state");
    const error = searchParams.get("error");
    const errorDesc = searchParams.get("error_description");
    if (error) {
      console.error("[prime-auth] Servidor retornou erro:", error, errorDesc);
      return import_server.NextResponse.redirect(
        new URL(`${errorRedirect}?error=${encodeURIComponent(error)}`, request.url)
      );
    }
    if (!code) {
      return import_server.NextResponse.redirect(
        new URL(`${errorRedirect}?error=missing_code`, request.url)
      );
    }
    const savedState = request.cookies.get("_pa_state")?.value;
    if (savedState && state !== savedState) {
      return import_server.NextResponse.redirect(
        new URL(`${errorRedirect}?error=state_mismatch`, request.url)
      );
    }
    const returnTo = request.cookies.get("_pa_return")?.value;
    let user;
    try {
      const tokenSet = await auth.exchangeCode(code);
      user = await auth.getUserInfo(tokenSet.access_token);
      const session = encodeSession({
        accessToken: tokenSet.access_token,
        refreshToken: tokenSet.refresh_token,
        expiresAt: tokenSet.expires_at
      }, auth.clientSecret);
      const redirectTo = returnTo ?? successRedirect;
      const res = import_server.NextResponse.redirect(new URL(redirectTo, request.url));
      res.cookies.set(auth.cookieName, session, {
        httpOnly: true,
        sameSite: "lax",
        maxAge: auth.cookieMaxAge,
        secure: isProduction,
        path: "/"
      });
      res.cookies.delete("_pa_state");
      res.cookies.delete("_pa_return");
      if (opts.onSuccess) {
        const result = await opts.onSuccess(user);
        if (result === false) return res;
      }
      return res;
    } catch (err) {
      console.error("[prime-auth] Erro no callback:", err);
      return import_server.NextResponse.redirect(
        new URL(`${errorRedirect}?error=callback_failed`, request.url)
      );
    }
  }
  return { GET };
}
function createLogoutHandler(auth, opts = {}) {
  function GET(request) {
    const redirectTo = opts.redirectTo ?? "/auth/login";
    const res = import_server.NextResponse.redirect(new URL(redirectTo, request.url));
    res.cookies.delete(auth.cookieName);
    return res;
  }
  return { GET };
}
function createMeHandler(auth) {
  async function GET(request) {
    const cookie = request.cookies.get(auth.cookieName)?.value;
    if (!cookie) return import_server.NextResponse.json(null);
    const session = decodeSession(cookie, auth.clientSecret);
    if (!session || Date.now() >= session.expiresAt) return import_server.NextResponse.json(null);
    try {
      const user = await auth.getUserInfo(session.accessToken);
      return import_server.NextResponse.json(user);
    } catch {
      return import_server.NextResponse.json(null);
    }
  }
  return { GET };
}

// src/next/middleware.ts
var import_server2 = require("next/server");
function createMiddleware(auth, opts = {}) {
  const loginPath = opts.loginPath ?? "/auth/login";
  const protectedPaths = opts.protectedPaths ?? ["/dashboard"];
  return function middleware(request) {
    const { pathname } = request.nextUrl;
    const isProtected = protectedPaths.some((pattern) => matchPath(pattern, pathname));
    if (!isProtected) return import_server2.NextResponse.next();
    const cookie = request.cookies.get(auth.cookieName)?.value;
    if (!cookie) return redirectToLogin(request, loginPath);
    const session = decodeSession(cookie, auth.clientSecret);
    if (!session) return redirectToLogin(request, loginPath);
    if (Date.now() >= session.expiresAt) {
      if (!session.refreshToken) return redirectToLogin(request, loginPath);
    }
    return import_server2.NextResponse.next();
  };
}
function redirectToLogin(request, loginPath) {
  const loginUrl = new URL(loginPath, request.url);
  loginUrl.searchParams.set("returnTo", request.nextUrl.pathname);
  return import_server2.NextResponse.redirect(loginUrl);
}
function matchPath(pattern, pathname) {
  if (pattern === pathname) return true;
  const base = pattern.replace(/\/?\*.*$/, "");
  return pathname.startsWith(base + "/");
}

// src/next/server.ts
async function getUser(auth) {
  const cookieStore = await getCookies();
  const raw = cookieStore.get(auth.cookieName)?.value;
  if (!raw) return null;
  const session = decodeSession(raw, auth.clientSecret);
  if (!session) return null;
  let activeSession = session;
  if (Date.now() >= session.expiresAt - 6e4) {
    if (!session.refreshToken) return null;
    try {
      const tokenSet = await auth.refreshToken(session.refreshToken);
      activeSession = {
        accessToken: tokenSet.access_token,
        refreshToken: tokenSet.refresh_token ?? session.refreshToken,
        expiresAt: tokenSet.expires_at
      };
      const isProduction = process.env["NODE_ENV"] === "production";
      cookieStore.set(auth.cookieName, encodeSession(activeSession, auth.clientSecret), {
        httpOnly: true,
        sameSite: "lax",
        maxAge: auth.cookieMaxAge,
        secure: isProduction,
        path: "/"
      });
    } catch {
      return null;
    }
  }
  try {
    return await auth.getUserInfo(activeSession.accessToken);
  } catch {
    return null;
  }
}
async function requireUser(auth, loginPath = "/auth/login") {
  const { redirect } = await import("next/navigation");
  const user = await getUser(auth);
  if (!user) redirect(loginPath);
  return user;
}
async function getCookies() {
  const { cookies } = await import("next/headers");
  const result = cookies();
  return result instanceof Promise ? await result : result;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  createCallbackHandler,
  createHandlers,
  createLoginHandler,
  createLogoutHandler,
  createMeHandler,
  createMiddleware,
  getUser,
  requireUser
});
