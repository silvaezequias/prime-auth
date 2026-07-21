import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import { PrimeAuth } from '../client.js'
import { MiddlewareOptions } from '../types.js'
import { decodeSession } from '../session.js'
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
      return redirectToLogin(request, loginPath)
    }

    const session = decodeSession(cookie, auth.sessionSecret)
    if (!session) {
      log('warn', `[next:middleware] Cookie de sessão inválido ou adulterado.`, { pathname })
      return redirectToLogin(request, loginPath)
    }

    if (Date.now() >= session.expiresAt) {
      if (!session.refreshToken) {
        log('warn', `[next:middleware] Sessão expirada e sem refresh token. Redirecionando para login.`, {
          pathname,
          expiredAt: new Date(session.expiresAt).toISOString(),
        })
        return redirectToLogin(request, loginPath)
      }
      // Sessão expirada mas há refresh token — deixa passar para o Server Component renovar
      log('info', `[next:middleware] Sessão expirada mas refresh token disponível. Deixando passar para renovação.`, { pathname })
    }

    log('debug', `[next:middleware] Acesso permitido.`, { pathname })
    return NextResponse.next()
  }
}

function redirectToLogin(request: NextRequest, loginPath: string) {
  const loginUrl = new URL(loginPath, request.url)
  loginUrl.searchParams.set('returnTo', request.nextUrl.pathname)
  log('info', `[next:middleware] Redirecionando para login.`, { loginUrl: loginUrl.toString() })
  return NextResponse.redirect(loginUrl)
}

function matchPath(pattern: string, pathname: string): boolean {
  if (pattern === pathname) return true
  const base = pattern.replace(/\/?\*.*$/, '')
  return pathname.startsWith(base + '/')
}
