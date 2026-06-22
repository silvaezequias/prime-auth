import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import { PrimeAuth } from '../client.js'
import { NextHandlersOptions, AuthenticatedUser } from '../types.js'
import { encodeSession, decodeSession } from '../session.js'

// ─── Catch-all handler (recomendado) ─────────────────────────────────────────

/**
 * Cria um único Route Handler que serve todas as rotas OAuth2.
 * Use em `app/auth/[...prime]/route.ts`.
 *
 * Rotas criadas automaticamente:
 *  GET /auth/login    → redireciona para o servidor de autenticação
 *  GET /auth/callback → troca o code por tokens e salva a sessão
 *  GET /auth/logout   → apaga a sessão
 *  GET /auth/me       → retorna o usuário atual em JSON
 */
export function createHandlers(auth: PrimeAuth, opts: NextHandlersOptions = {}) {
  const { GET: loginGET }    = createLoginHandler(auth)
  const { GET: callbackGET } = createCallbackHandler(auth, opts)
  const { GET: logoutGET }   = createLogoutHandler(auth)
  const { GET: meGET }       = createMeHandler(auth)

  async function GET(request: NextRequest) {
    const action = request.nextUrl.pathname.split('/').at(-1)
    switch (action) {
      case 'login':    return loginGET(request)
      case 'callback': return callbackGET(request)
      case 'logout':   return logoutGET(request)
      case 'me':       return meGET(request)
      default:
        return NextResponse.json({ error: 'not_found' }, { status: 404 })
    }
  }

  return { GET }
}

// ─── Handlers individuais ─────────────────────────────────────────────────────

/**
 * Handler para a rota de login.
 * Redireciona o usuário para o servidor de autenticação.
 *
 * @example
 * // app/auth/login/route.ts
 * import { createLoginHandler } from 'prime-auth/next'
 * import { auth } from '@/lib/auth'
 * export const { GET } = createLoginHandler(auth)
 */
export function createLoginHandler(auth: PrimeAuth) {
  const isProduction = process.env['NODE_ENV'] === 'production'

  function GET(request: NextRequest) {
    const returnTo = request.nextUrl.searchParams.get('returnTo')
    const { url, state } = auth.getAuthorizationUrl()
    const res = NextResponse.redirect(url)

    res.cookies.set('_pa_state', state, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 600,
      secure: isProduction,
      path: '/',
    })

    if (returnTo) {
      res.cookies.set('_pa_return', returnTo, {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 600,
        secure: isProduction,
        path: '/',
      })
    }

    return res
  }

  return { GET }
}

/**
 * Handler para a rota de callback OAuth2.
 *
 * Recebe o `code` enviado pelo servidor após o login, troca pelo par
 * access_token/refresh_token, busca os dados do usuário e salva a sessão
 * em um cookie httpOnly assinado.
 *
 * Parâmetros de query recebidos pelo servidor:
 *  - `code`  → authorization code (obrigatório)
 *  - `state` → valor anti-CSRF para validar (deve coincidir com o cookie `_pa_state`)
 *  - `error` + `error_description` → em caso de recusa/erro no servidor
 *
 * @example
 * // app/auth/callback/route.ts
 * import { createCallbackHandler } from 'prime-auth/next'
 * import { auth } from '@/lib/auth'
 *
 * export const { GET } = createCallbackHandler(auth, {
 *   successRedirect: '/dashboard',
 *   onSuccess: async (user) => {
 *     // Salve ou atualize o usuário no seu banco de dados
 *     await db.user.upsert({
 *       where: { sub: user.sub },
 *       update: { name: user.name, email: user.email, avatar: user.avatar },
 *       create: { sub: user.sub, name: user.name, email: user.email, avatar: user.avatar },
 *     })
 *   },
 * })
 */
export function createCallbackHandler(auth: PrimeAuth, opts: NextHandlersOptions = {}) {
  const successRedirect = opts.successRedirect ?? '/'
  const errorRedirect   = opts.errorRedirect   ?? '/auth/login'
  const isProduction    = process.env['NODE_ENV'] === 'production'

  async function GET(request: NextRequest) {
    const { searchParams } = request.nextUrl
    const code      = searchParams.get('code')
    const state     = searchParams.get('state')
    const error     = searchParams.get('error')
    const errorDesc = searchParams.get('error_description')

    // O servidor recusou ou o usuário cancelou o login
    if (error) {
      console.error('[prime-auth] Servidor retornou erro:', error, errorDesc)
      return NextResponse.redirect(
        new URL(`${errorRedirect}?error=${encodeURIComponent(error)}`, request.url),
      )
    }

    if (!code) {
      return NextResponse.redirect(
        new URL(`${errorRedirect}?error=missing_code`, request.url),
      )
    }

    // Valida o state para prevenir CSRF
    const savedState = request.cookies.get('_pa_state')?.value
    if (savedState && state !== savedState) {
      return NextResponse.redirect(
        new URL(`${errorRedirect}?error=state_mismatch`, request.url),
      )
    }

    const returnTo = request.cookies.get('_pa_return')?.value

    let user: AuthenticatedUser
    try {
      // 1. Troca o code pelo par de tokens
      const tokenSet = await auth.exchangeCode(code)

      // 2. Busca os dados do usuário (nome, e-mail, avatar, etc.)
      user = await auth.getUserInfo(tokenSet.access_token)

      // 3. Salva a sessão em cookie httpOnly assinado
      const session = encodeSession({
        accessToken:  tokenSet.access_token,
        refreshToken: tokenSet.refresh_token,
        expiresAt:    tokenSet.expires_at,
      }, auth.clientSecret)

      const redirectTo = returnTo ?? successRedirect
      const res = NextResponse.redirect(new URL(redirectTo, request.url))

      res.cookies.set(auth.cookieName, session, {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: auth.cookieMaxAge,
        secure: isProduction,
        path: '/',
      })
      res.cookies.delete('_pa_state')
      res.cookies.delete('_pa_return')

      // 4. Hook opcional — use para salvar o usuário no banco de dados
      if (opts.onSuccess) {
        const result = await opts.onSuccess(user)
        if (result === false) return res
      }

      return res
    } catch (err) {
      console.error('[prime-auth] Erro no callback:', err)
      return NextResponse.redirect(
        new URL(`${errorRedirect}?error=callback_failed`, request.url),
      )
    }
  }

  return { GET }
}

/**
 * Handler para a rota de logout.
 * Apaga o cookie de sessão e redireciona para `/auth/login`.
 *
 * @example
 * // app/auth/logout/route.ts
 * import { createLogoutHandler } from 'prime-auth/next'
 * import { auth } from '@/lib/auth'
 * export const { GET } = createLogoutHandler(auth)
 */
export function createLogoutHandler(auth: PrimeAuth, opts: { redirectTo?: string } = {}) {
  function GET(request: NextRequest) {
    const redirectTo = opts.redirectTo ?? '/auth/login'
    const res = NextResponse.redirect(new URL(redirectTo, request.url))
    res.cookies.delete(auth.cookieName)
    return res
  }
  return { GET }
}

/**
 * Handler para a rota `/auth/me`.
 * Retorna o usuário atual em JSON — usado pelo `UserFetchProvider` em Client Components.
 *
 * @example
 * // app/auth/me/route.ts
 * import { createMeHandler } from 'prime-auth/next'
 * import { auth } from '@/lib/auth'
 * export const { GET } = createMeHandler(auth)
 */
export function createMeHandler(auth: PrimeAuth) {
  async function GET(request: NextRequest) {
    const cookie = request.cookies.get(auth.cookieName)?.value
    if (!cookie) return NextResponse.json(null)

    const session = decodeSession(cookie, auth.clientSecret)
    if (!session || Date.now() >= session.expiresAt) return NextResponse.json(null)

    try {
      const user = await auth.getUserInfo(session.accessToken)
      return NextResponse.json(user)
    } catch {
      return NextResponse.json(null)
    }
  }
  return { GET }
}
