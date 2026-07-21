import {
  decodeSession,
  encodeSession
} from "../chunk-UTLJNX76.mjs";
import {
  extractTenantFromHost,
  log
} from "../chunk-XAE6UXTH.mjs";

// src/next/handlers.ts
import { NextResponse } from "next/server";
function createHandlers(auth, opts = {}) {
  const { GET: loginGET } = createLoginHandler(auth, opts);
  const { GET: callbackGET } = createCallbackHandler(auth, opts);
  const { GET: logoutGET } = createLogoutHandler(auth);
  const { GET: meGET } = createMeHandler(auth);
  async function GET(request) {
    const action = request.nextUrl.pathname.split("/").at(-1);
    log("debug", `[next] Route handler acionado.`, { action, pathname: request.nextUrl.pathname });
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
        log("warn", `[next] Rota n\xE3o reconhecida no catch-all.`, { pathname: request.nextUrl.pathname });
        return NextResponse.json({ error: "not_found" }, { status: 404 });
    }
  }
  return { GET };
}
function createLoginHandler(auth, opts = {}) {
  const isProduction = process.env["NODE_ENV"] === "production";
  async function GET(request) {
    const returnTo = request.nextUrl.searchParams.get("returnTo");
    let tenant = request.nextUrl.searchParams.get("tenant") ?? (opts.tenantFromSubdomain ? extractTenantFromHost(request.nextUrl.hostname) : void 0);
    if (!tenant && opts.autoTenant) {
      try {
        tenant = (await auth.getAppInfo()).tenantSlug ?? void 0;
      } catch (err) {
        log("warn", "[next] autoTenant: falha ao buscar o tenant via getAppInfo(). Prosseguindo sem tenant.", { error: String(err) });
      }
    }
    log("info", "[next] Iniciando fluxo de login.", { returnTo: returnTo ?? void 0, tenant: tenant ?? void 0 });
    const { url, state } = auth.getAuthorizationUrl(void 0, tenant ?? void 0);
    const res = NextResponse.redirect(url);
    res.cookies.set("_pa_state", state, { httpOnly: true, sameSite: "lax", maxAge: 600, secure: isProduction, path: "/" });
    if (returnTo) {
      res.cookies.set("_pa_return", returnTo, { httpOnly: true, sameSite: "lax", maxAge: 600, secure: isProduction, path: "/" });
    }
    log("debug", "[next] Redirecionando para o servidor de autentica\xE7\xE3o.", { url });
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
    log("info", "[next] Callback OAuth2 recebido.", { hasCode: !!code, hasState: !!state, error: error ?? void 0 });
    if (error) {
      log("error", `[next] Servidor de autentica\xE7\xE3o retornou erro no callback. Verifique as configura\xE7\xF5es da aplica\xE7\xE3o no painel.`, {
        error,
        description: errorDesc
      });
      return NextResponse.redirect(new URL(`${errorRedirect}?error=${encodeURIComponent(error)}`, request.url));
    }
    if (!code) {
      log("error", '[next] Callback recebido sem o par\xE2metro "code". O servidor deveria ter enviado o authorization code.');
      return NextResponse.redirect(new URL(`${errorRedirect}?error=missing_code`, request.url));
    }
    const savedState = request.cookies.get("_pa_state")?.value;
    const returnTo = request.cookies.get("_pa_return")?.value;
    if (savedState && state !== savedState) {
      log("warn", "[next] State CSRF n\xE3o confere. A requisi\xE7\xE3o pode ter sido interceptada ou o cookie expirou.", {
        expected: savedState,
        received: state
      });
      return NextResponse.redirect(new URL(`${errorRedirect}?error=state_mismatch`, request.url));
    }
    if (!savedState) {
      log("warn", "[next] Cookie de state n\xE3o encontrado. Pode ter expirado (10 min) ou o navegador bloqueou cookies.");
    }
    let user;
    try {
      log("info", "[next] Trocando authorization code por tokens...");
      const tokenSet = await auth.exchangeCode(code);
      log("info", "[next] Buscando dados do usu\xE1rio...");
      user = await auth.getUserInfo(tokenSet.access_token);
      const session = encodeSession({
        accessToken: tokenSet.access_token,
        refreshToken: tokenSet.refresh_token,
        expiresAt: tokenSet.expires_at
      }, auth.sessionSecret);
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
      log("info", "[next] Login conclu\xEDdo com sucesso. Redirecionando.", {
        user: user.sub,
        username: user.username,
        redirectTo
      });
      if (opts.onSuccess) {
        log("debug", "[next] Executando callback onSuccess...");
        const result = await opts.onSuccess(user);
        if (result === false) {
          log("debug", "[next] onSuccess retornou false \u2014 redirect assumido pelo callback.");
          return res;
        }
      }
      return res;
    } catch (err) {
      log("error", "[next] Falha ao processar callback OAuth2. Verifique as credenciais e se o servidor est\xE1 acess\xEDvel.", {
        error: String(err),
        serverUrl: auth.serverUrl
      });
      return NextResponse.redirect(new URL(`${errorRedirect}?error=callback_failed`, request.url));
    }
  }
  return { GET };
}
function createLogoutHandler(auth, opts = {}) {
  function GET(request) {
    const redirectTo = opts.redirectTo ?? "/auth/login";
    log("info", "[next] Usu\xE1rio deslogado. Sess\xE3o encerrada.", { redirectTo });
    const res = NextResponse.redirect(new URL(redirectTo, request.url));
    res.cookies.delete(auth.cookieName);
    return res;
  }
  return { GET };
}
function createMeHandler(auth) {
  async function GET(request) {
    log("debug", "[next] /auth/me \u2014 verificando sess\xE3o do usu\xE1rio.");
    const cookie = request.cookies.get(auth.cookieName)?.value;
    if (!cookie) {
      log("debug", "[next] /auth/me \u2014 nenhum cookie de sess\xE3o encontrado. Retornando null.");
      return NextResponse.json(null);
    }
    const session = decodeSession(cookie, auth.sessionSecret);
    if (!session) {
      log("warn", "[next] /auth/me \u2014 cookie de sess\xE3o presente mas inv\xE1lido. Pode ter sido adulterado.");
      return NextResponse.json(null);
    }
    if (Date.now() >= session.expiresAt) {
      log("warn", "[next] /auth/me \u2014 sess\xE3o expirada.", { expiredAt: new Date(session.expiresAt).toISOString() });
      return NextResponse.json(null);
    }
    try {
      const user = await auth.getUserInfo(session.accessToken);
      log("debug", "[next] /auth/me \u2014 usu\xE1rio retornado.", { sub: user.sub });
      return NextResponse.json(user);
    } catch (err) {
      log("error", "[next] /auth/me \u2014 falha ao buscar dados do usu\xE1rio com o access token salvo.", { error: String(err) });
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
  log("info", "[next:middleware] Middleware de prote\xE7\xE3o configurado.", { protectedPaths, loginPath });
  return function middleware(request) {
    const { pathname } = request.nextUrl;
    const isProtected = protectedPaths.some((pattern) => matchPath(pattern, pathname));
    if (!isProtected) {
      log("debug", `[next:middleware] Rota n\xE3o protegida, passando adiante.`, { pathname });
      return NextResponse2.next();
    }
    log("debug", `[next:middleware] Rota protegida detectada.`, { pathname });
    const cookie = request.cookies.get(auth.cookieName)?.value;
    if (!cookie) {
      log("warn", `[next:middleware] Acesso negado \u2014 sem cookie de sess\xE3o.`, { pathname });
      return redirectToLogin(request, loginPath);
    }
    const session = decodeSession(cookie, auth.sessionSecret);
    if (!session) {
      log("warn", `[next:middleware] Cookie de sess\xE3o inv\xE1lido ou adulterado.`, { pathname });
      return redirectToLogin(request, loginPath);
    }
    if (Date.now() >= session.expiresAt) {
      if (!session.refreshToken) {
        log("warn", `[next:middleware] Sess\xE3o expirada e sem refresh token. Redirecionando para login.`, {
          pathname,
          expiredAt: new Date(session.expiresAt).toISOString()
        });
        return redirectToLogin(request, loginPath);
      }
      log("info", `[next:middleware] Sess\xE3o expirada mas refresh token dispon\xEDvel. Deixando passar para renova\xE7\xE3o.`, { pathname });
    }
    log("debug", `[next:middleware] Acesso permitido.`, { pathname });
    return NextResponse2.next();
  };
}
function redirectToLogin(request, loginPath) {
  const loginUrl = new URL(loginPath, request.url);
  loginUrl.searchParams.set("returnTo", request.nextUrl.pathname);
  log("info", `[next:middleware] Redirecionando para login.`, { loginUrl: loginUrl.toString() });
  return NextResponse2.redirect(loginUrl);
}
function matchPath(pattern, pathname) {
  if (pattern === pathname) return true;
  const base = pattern.replace(/\/?\*.*$/, "");
  return pathname.startsWith(base + "/");
}

// src/next/server.ts
async function getUser(auth) {
  log("debug", "[next:server] getUser() \u2014 lendo sess\xE3o do cookie.");
  const cookieStore = await getCookies();
  const raw = cookieStore.get(auth.cookieName)?.value;
  if (!raw) {
    log("debug", "[next:server] getUser() \u2014 nenhum cookie de sess\xE3o encontrado.");
    return null;
  }
  const session = decodeSession(raw, auth.sessionSecret);
  if (!session) {
    log("warn", "[next:server] getUser() \u2014 cookie de sess\xE3o inv\xE1lido. Poss\xEDvel adultera\xE7\xE3o ou clientSecret diferente.");
    return null;
  }
  if (Date.now() >= session.expiresAt - 6e4) {
    if (!session.refreshToken) {
      log("warn", "[next:server] getUser() \u2014 sess\xE3o expirada e sem refresh token. Usu\xE1rio precisar\xE1 fazer login novamente.", {
        expiredAt: new Date(session.expiresAt).toISOString()
      });
      return null;
    }
    log("info", "[next:server] getUser() \u2014 access token prestes a expirar. Renovando automaticamente...");
    try {
      const tokenSet = await auth.refreshToken(session.refreshToken);
      const newSession = {
        accessToken: tokenSet.access_token,
        refreshToken: tokenSet.refresh_token ?? session.refreshToken,
        expiresAt: tokenSet.expires_at
      };
      const isProduction = process.env["NODE_ENV"] === "production";
      cookieStore.set(auth.cookieName, encodeSession(newSession, auth.sessionSecret), {
        httpOnly: true,
        sameSite: "lax",
        maxAge: auth.cookieMaxAge,
        secure: isProduction,
        path: "/"
      });
      log("info", "[next:server] getUser() \u2014 token renovado com sucesso.");
      try {
        return await auth.getUserInfo(newSession.accessToken);
      } catch (err) {
        log("error", "[next:server] getUser() \u2014 token renovado mas falha ao buscar userinfo.", { error: String(err) });
        return null;
      }
    } catch (err) {
      log("error", "[next:server] getUser() \u2014 falha ao renovar token. Usu\xE1rio precisar\xE1 fazer login novamente.", { error: String(err) });
      return null;
    }
  }
  try {
    const user = await auth.getUserInfo(session.accessToken);
    log("debug", "[next:server] getUser() \u2014 usu\xE1rio obtido com sucesso.", { sub: user.sub });
    return user;
  } catch (err) {
    log("error", "[next:server] getUser() \u2014 falha ao buscar dados do usu\xE1rio. O access token pode ter sido revogado.", { error: String(err) });
    return null;
  }
}
async function requireUser(auth, loginPath = "/auth/login") {
  log("debug", "[next:server] requireUser() \u2014 verificando autentica\xE7\xE3o.");
  const { redirect } = await import("next/navigation");
  const user = await getUser(auth);
  if (!user) {
    log("warn", "[next:server] requireUser() \u2014 usu\xE1rio n\xE3o autenticado. Redirecionando para login.", { loginPath });
    redirect(loginPath);
  }
  log("debug", "[next:server] requireUser() \u2014 usu\xE1rio autenticado.", { sub: user.sub });
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
