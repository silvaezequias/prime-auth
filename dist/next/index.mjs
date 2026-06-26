import {
  decodeSession,
  encodeSession
} from "../chunk-NQRGQ7TS.mjs";

// src/next/handlers.ts
import { NextResponse } from "next/server";
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
        return NextResponse.json({ error: "not_found" }, { status: 404 });
    }
  }
  return { GET };
}
function createLoginHandler(auth) {
  const isProduction = process.env["NODE_ENV"] === "production";
  function GET(request) {
    const returnTo = request.nextUrl.searchParams.get("returnTo");
    const { url, state } = auth.getAuthorizationUrl();
    const res = NextResponse.redirect(url);
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
      return NextResponse.redirect(
        new URL(`${errorRedirect}?error=${encodeURIComponent(error)}`, request.url)
      );
    }
    if (!code) {
      return NextResponse.redirect(
        new URL(`${errorRedirect}?error=missing_code`, request.url)
      );
    }
    const savedState = request.cookies.get("_pa_state")?.value;
    if (savedState && state !== savedState) {
      return NextResponse.redirect(
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
      const res = NextResponse.redirect(new URL(redirectTo, request.url));
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
      return NextResponse.redirect(
        new URL(`${errorRedirect}?error=callback_failed`, request.url)
      );
    }
  }
  return { GET };
}
function createLogoutHandler(auth, opts = {}) {
  function GET(request) {
    const redirectTo = opts.redirectTo ?? "/auth/login";
    const res = NextResponse.redirect(new URL(redirectTo, request.url));
    res.cookies.delete(auth.cookieName);
    return res;
  }
  return { GET };
}
function createMeHandler(auth) {
  async function GET(request) {
    const cookie = request.cookies.get(auth.cookieName)?.value;
    if (!cookie) return NextResponse.json(null);
    const session = decodeSession(cookie, auth.clientSecret);
    if (!session || Date.now() >= session.expiresAt) return NextResponse.json(null);
    try {
      const user = await auth.getUserInfo(session.accessToken);
      return NextResponse.json(user);
    } catch {
      return NextResponse.json(null);
    }
  }
  return { GET };
}

// src/next/middleware.ts
import { NextResponse as NextResponse2 } from "next/server";
function createMiddleware(auth, opts = {}) {
  const loginPath = opts.loginPath ?? "/auth/login";
  const protectedPaths = opts.protectedPaths ?? ["/dashboard"];
  return function middleware(request) {
    const { pathname } = request.nextUrl;
    const isProtected = protectedPaths.some((pattern) => matchPath(pattern, pathname));
    if (!isProtected) return NextResponse2.next();
    const cookie = request.cookies.get(auth.cookieName)?.value;
    if (!cookie) return redirectToLogin(request, loginPath);
    const session = decodeSession(cookie, auth.clientSecret);
    if (!session) return redirectToLogin(request, loginPath);
    if (Date.now() >= session.expiresAt) {
      if (!session.refreshToken) return redirectToLogin(request, loginPath);
    }
    return NextResponse2.next();
  };
}
function redirectToLogin(request, loginPath) {
  const loginUrl = new URL(loginPath, request.url);
  loginUrl.searchParams.set("returnTo", request.nextUrl.pathname);
  return NextResponse2.redirect(loginUrl);
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
export {
  createCallbackHandler,
  createHandlers,
  createLoginHandler,
  createLogoutHandler,
  createMeHandler,
  createMiddleware,
  getUser,
  requireUser
};
