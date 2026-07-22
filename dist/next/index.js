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

// src/next/handlers.ts
async function resolveAuth(source, request) {
  return typeof source === "function" ? await source(request) : source;
}
function createHandlers(authSource, opts = {}) {
  const { GET: loginGET } = createLoginHandler(authSource, opts);
  const { GET: callbackGET } = createCallbackHandler(authSource, opts);
  const { GET: logoutGET } = createLogoutHandler(authSource);
  const { GET: meGET } = createMeHandler(authSource);
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
        return import_server.NextResponse.json({ error: "not_found" }, { status: 404 });
    }
  }
  return { GET };
}
function createLoginHandler(authSource, opts = {}) {
  async function GET(request) {
    const secure = request.nextUrl.protocol === "https:";
    const auth = await resolveAuth(authSource, request);
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
    const res = import_server.NextResponse.redirect(url);
    res.cookies.set("_pa_state", state, { httpOnly: true, sameSite: "lax", maxAge: 600, secure, path: "/" });
    if (returnTo) {
      res.cookies.set("_pa_return", returnTo, { httpOnly: true, sameSite: "lax", maxAge: 600, secure, path: "/" });
    }
    log("debug", "[next] Redirecionando para o servidor de autentica\xE7\xE3o.", { url });
    return res;
  }
  return { GET };
}
function createCallbackHandler(authSource, opts = {}) {
  const successRedirect = opts.successRedirect ?? "/";
  const errorRedirect = opts.errorRedirect ?? "/auth/login";
  async function GET(request) {
    const secure = request.nextUrl.protocol === "https:";
    const auth = await resolveAuth(authSource, request);
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
      return import_server.NextResponse.redirect(new URL(`${errorRedirect}?error=${encodeURIComponent(error)}`, request.url));
    }
    if (!code) {
      log("error", '[next] Callback recebido sem o par\xE2metro "code". O servidor deveria ter enviado o authorization code.');
      return import_server.NextResponse.redirect(new URL(`${errorRedirect}?error=missing_code`, request.url));
    }
    const savedState = request.cookies.get("_pa_state")?.value;
    const returnTo = request.cookies.get("_pa_return")?.value;
    if (savedState && state !== savedState) {
      log("warn", "[next] State CSRF n\xE3o confere. A requisi\xE7\xE3o pode ter sido interceptada ou o cookie expirou.", {
        expected: savedState,
        received: state
      });
      return import_server.NextResponse.redirect(new URL(`${errorRedirect}?error=state_mismatch`, request.url));
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
      const res = import_server.NextResponse.redirect(new URL(redirectTo, request.url));
      res.cookies.set(auth.cookieName, session, {
        httpOnly: true,
        sameSite: "lax",
        maxAge: auth.cookieMaxAge,
        secure,
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
      return import_server.NextResponse.redirect(new URL(`${errorRedirect}?error=callback_failed`, request.url));
    }
  }
  return { GET };
}
function createLogoutHandler(authSource, opts = {}) {
  async function GET(request) {
    const auth = await resolveAuth(authSource, request);
    const redirectTo = opts.redirectTo ?? "/auth/login";
    log("info", "[next] Usu\xE1rio deslogado. Sess\xE3o encerrada.", { redirectTo });
    const res = import_server.NextResponse.redirect(new URL(redirectTo, request.url));
    res.cookies.delete(auth.cookieName);
    return res;
  }
  return { GET };
}
function createMeHandler(authSource) {
  async function GET(request) {
    const auth = await resolveAuth(authSource, request);
    log("debug", "[next] /auth/me \u2014 verificando sess\xE3o do usu\xE1rio.");
    const cookie = request.cookies.get(auth.cookieName)?.value;
    if (!cookie) {
      log("debug", "[next] /auth/me \u2014 nenhum cookie de sess\xE3o encontrado. Retornando null.");
      return import_server.NextResponse.json(null);
    }
    const session = decodeSession(cookie, auth.sessionSecret);
    if (!session) {
      log("warn", "[next] /auth/me \u2014 cookie de sess\xE3o presente mas inv\xE1lido. Pode ter sido adulterado.");
      return import_server.NextResponse.json(null);
    }
    if (Date.now() >= session.expiresAt) {
      log("warn", "[next] /auth/me \u2014 sess\xE3o expirada.", { expiredAt: new Date(session.expiresAt).toISOString() });
      return import_server.NextResponse.json(null);
    }
    try {
      const user = await auth.getUserInfo(session.accessToken);
      log("debug", "[next] /auth/me \u2014 usu\xE1rio retornado.", { sub: user.sub });
      return import_server.NextResponse.json(user);
    } catch (err) {
      log("error", "[next] /auth/me \u2014 falha ao buscar dados do usu\xE1rio com o access token salvo.", { error: String(err) });
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
  log("info", "[next:middleware] Middleware de prote\xE7\xE3o configurado.", { protectedPaths, loginPath });
  return function middleware(request) {
    const { pathname } = request.nextUrl;
    const isProtected = protectedPaths.some((pattern) => matchPath(pattern, pathname));
    if (!isProtected) {
      log("debug", `[next:middleware] Rota n\xE3o protegida, passando adiante.`, { pathname });
      return import_server2.NextResponse.next();
    }
    log("debug", `[next:middleware] Rota protegida detectada.`, { pathname });
    const cookie = request.cookies.get(auth.cookieName)?.value;
    if (!cookie) {
      log("warn", `[next:middleware] Acesso negado \u2014 sem cookie de sess\xE3o.`, { pathname });
      return redirectToLogin(request, loginPath, auth);
    }
    const session = decodeSession(cookie, auth.sessionSecret);
    if (!session) {
      log("warn", `[next:middleware] Cookie de sess\xE3o inv\xE1lido ou adulterado.`, { pathname });
      return redirectToLogin(request, loginPath, auth);
    }
    if (Date.now() >= session.expiresAt) {
      if (!session.refreshToken) {
        log("warn", `[next:middleware] Sess\xE3o expirada e sem refresh token. Redirecionando para login.`, {
          pathname,
          expiredAt: new Date(session.expiresAt).toISOString()
        });
        return redirectToLogin(request, loginPath, auth);
      }
      log("info", `[next:middleware] Sess\xE3o expirada mas refresh token dispon\xEDvel. Deixando passar para renova\xE7\xE3o.`, { pathname });
    }
    log("debug", `[next:middleware] Acesso permitido.`, { pathname });
    return import_server2.NextResponse.next();
  };
}
function redirectToLogin(request, loginPath, auth) {
  const hostHeader = request.headers.get("host") ?? request.nextUrl.hostname;
  const tenant = extractTenantFromHost(hostHeader);
  let base = request.url;
  if (tenant) {
    try {
      const appUrl = new URL(auth.redirectUri);
      appUrl.hostname = `${tenant}.${appUrl.hostname}`;
      base = appUrl.toString();
    } catch (err) {
      log("warn", "[next:middleware] redirectUri inv\xE1lido ao montar URL de login com tenant. Usando o host da requisi\xE7\xE3o.", { error: String(err) });
    }
  }
  const loginUrl = new URL(loginPath, base);
  loginUrl.searchParams.set("returnTo", request.nextUrl.pathname);
  log("info", `[next:middleware] Redirecionando para login.`, { loginUrl: loginUrl.toString(), tenant: tenant ?? void 0 });
  return import_server2.NextResponse.redirect(loginUrl);
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
      cookieStore.set(auth.cookieName, encodeSession(newSession, auth.sessionSecret), {
        httpOnly: true,
        sameSite: "lax",
        maxAge: auth.cookieMaxAge,
        secure: await isSecureRequest(),
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
async function isSecureRequest() {
  const { headers } = await import("next/headers");
  const h = await headers();
  return h.get("x-forwarded-proto") === "https";
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
