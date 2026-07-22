import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import { PrimeAuth } from '../client.js'
import { MiddlewareOptions } from '../types.js'
import { decodeSession } from '../session.js'
import { extractTenantFromHost } from '../tenant.js'
import { log } from '../logger.js'

export function createMiddleware(auth: PrimeAuth, opts: MiddlewareOptions = {}) {
  const loginPath      = opts.loginPath     ?? '/auth/login'
  const protectedPaths = opts.protectedPaths ?? ['/dashboard']

  log('info', '[next:middleware] Middleware de proteção configurado.', { protectedPaths, loginPath })

  return function middleware(request: NextRequest) {
    const { pathname } = request.nextUrl

    const isProtected = protectedPaths.some(pattern => matchPath(pattern, pathname))
    if (!isProtected) {
      log('debug', `[next:middleware] Rota não protegida, passando adiante.`, { pathname })
      return NextResponse.next()
    }

    log('debug', `[next:middleware] Rota protegida detectada.`, { pathname })

    const cookie = request.cookies.get(auth.cookieName)?.value
    if (!cookie) {
      log('warn', `[next:middleware] Acesso negado — sem cookie de sessão.`, { pathname })
      return redirectToLogin(request, loginPath, auth)
    }

    const session = decodeSession(cookie, auth.sessionSecret)
    if (!session) {
      log('warn', `[next:middleware] Cookie de sessão inválido ou adulterado.`, { pathname })
      return redirectToLogin(request, loginPath, auth)
    }

    if (Date.now() >= session.expiresAt) {
      if (!session.refreshToken) {
        log('warn', `[next:middleware] Sessão expirada e sem refresh token. Redirecionando para login.`, {
          pathname,
          expiredAt: new Date(session.expiresAt).toISOString(),
        })
        return redirectToLogin(request, loginPath, auth)
      }
      // Sessão expirada mas há refresh token — deixa passar para o Server Component renovar
      log('info', `[next:middleware] Sessão expirada mas refresh token disponível. Deixando passar para renovação.`, { pathname })
    }

    log('debug', `[next:middleware] Acesso permitido.`, { pathname })
    return NextResponse.next()
  }
}

/**
 * Monta a URL de login preservando o tenant. Não confia em `request.url`
 * (pode não refletir o subdomínio real atrás de proxy/CDN, ou já ter
 * perdido o tenant por algum outro motivo) — em vez disso, quando há um
 * tenant no host da requisição, monta a URL a partir do `redirectUri`
 * configurado (a base é o APP_URL do .env) com o tenant inserido como
 * subdomínio. Sem tenant detectável, cai no comportamento antigo.
 */
function redirectToLogin(request: NextRequest, loginPath: string, auth: PrimeAuth) {
  // Em Proxy/Middleware, `request.nextUrl.hostname` nem sempre reflete o
  // header Host real da requisição (observado no Next.js 16 — ali ele pode
  // reportar o host interno do servidor em vez do host que o cliente usou).
  // O header Host bruto é confiável nesse contexto, então é ele que usamos
  // aqui — diferente do login/callback (Route Handlers), onde `nextUrl`
  // já reflete o host corretamente.
  const hostHeader = request.headers.get('host') ?? request.nextUrl.hostname
  const tenant = extractTenantFromHost(hostHeader)

  let base = request.url
  if (tenant) {
    try {
      const appUrl = new URL(auth.redirectUri)
      appUrl.hostname = `${tenant}.${appUrl.hostname}`
      base = appUrl.toString()
    } catch (err) {
      log('warn', '[next:middleware] redirectUri inválido ao montar URL de login com tenant. Usando o host da requisição.', { error: String(err) })
    }
  }

  const loginUrl = new URL(loginPath, base)
  loginUrl.searchParams.set('returnTo', request.nextUrl.pathname)
  log('info', `[next:middleware] Redirecionando para login.`, { loginUrl: loginUrl.toString(), tenant: tenant ?? undefined })
  return NextResponse.redirect(loginUrl)
}

function matchPath(pattern: string, pathname: string): boolean {
  if (pattern === pathname) return true
  const base = pattern.replace(/\/?\*.*$/, '')
  return pathname.startsWith(base + '/')
}
