import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import { PrimeAuth } from '../client.js'
import { MiddlewareOptions } from '../types.js'
import { decodeSession } from '../session.js'

/**
 * Cria o middleware do Next.js para proteger rotas automaticamente.
 *
 * Use em `middleware.ts` na raiz do projeto:
 *
 * @example
 * // middleware.ts
 * import { createMiddleware } from 'prime-auth/next'
 * import { auth } from './lib/auth'
 *
 * export const middleware = createMiddleware(auth, {
 *   protectedPaths: ['/dashboard', '/settings'],
 * })
 *
 * export const config = {
 *   matcher: ['/dashboard/:path*', '/settings/:path*'],
 * }
 */
export function createMiddleware(auth: PrimeAuth, opts: MiddlewareOptions = {}) {
  const loginPath     = opts.loginPath ?? '/auth/login'
  const protectedPaths = opts.protectedPaths ?? ['/dashboard']

  return function middleware(request: NextRequest) {
    const { pathname } = request.nextUrl

    const isProtected = protectedPaths.some(pattern => matchPath(pattern, pathname))
    if (!isProtected) return NextResponse.next()

    const cookie = request.cookies.get(auth.cookieName)?.value
    if (!cookie) return redirectToLogin(request, loginPath)

    const session = decodeSession(cookie, auth.clientSecret)
    if (!session) return redirectToLogin(request, loginPath)

    // Verificação leve de expiração (sem chamada de rede — o middleware roda no Edge)
    if (Date.now() >= session.expiresAt) {
      if (!session.refreshToken) return redirectToLogin(request, loginPath)
      // Deixa passar: o Server Component ou getUser() vai renovar o token
    }

    return NextResponse.next()
  }
}

function redirectToLogin(request: NextRequest, loginPath: string) {
  const loginUrl = new URL(loginPath, request.url)
  loginUrl.searchParams.set('returnTo', request.nextUrl.pathname)
  return NextResponse.redirect(loginUrl)
}

function matchPath(pattern: string, pathname: string): boolean {
  if (pattern === pathname) return true
  // Suporte a /dashboard/:path* e /dashboard/*
  const base = pattern.replace(/\/?\*.*$/, '')
  return pathname.startsWith(base + '/')
}
