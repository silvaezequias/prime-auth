import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import { PrimeAuth } from '../client.js'
import { NextHandlersOptions, AuthenticatedUser } from '../types.js'
import { encodeSession, decodeSession } from '../session.js'
import { extractTenantFromHost } from '../tenant.js'
import { log } from '../logger.js'

// ─── Catch-all handler ────────────────────────────────────────────────────────

export function createHandlers(auth: PrimeAuth, opts: NextHandlersOptions = {}) {
  const { GET: loginGET }    = createLoginHandler(auth, opts)
  const { GET: callbackGET } = createCallbackHandler(auth, opts)
  const { GET: logoutGET }   = createLogoutHandler(auth)
  const { GET: meGET }       = createMeHandler(auth)

  async function GET(request: NextRequest) {
    const action = request.nextUrl.pathname.split('/').at(-1)
    log('debug', `[next] Route handler acionado.`, { action, pathname: request.nextUrl.pathname })
    switch (action) {
      case 'login':    return loginGET(request)
      case 'callback': return callbackGET(request)
      case 'logout':   return logoutGET(request)
      case 'me':       return meGET(request)
      default:
        log('warn', `[next] Rota não reconhecida no catch-all.`, { pathname: request.nextUrl.pathname })
        return NextResponse.json({ error: 'not_found' }, { status: 404 })
    }
  }

  return { GET }
}

// ─── Login ────────────────────────────────────────────────────────────────────

export function createLoginHandler(auth: PrimeAuth, opts: NextHandlersOptions = {}) {
  const isProduction = process.env['NODE_ENV'] === 'production'

  function GET(request: NextRequest) {
    const returnTo = request.nextUrl.searchParams.get('returnTo')
    const tenant = request.nextUrl.searchParams.get('tenant')
      ?? (opts.tenantFromSubdomain ? extractTenantFromHost(request.nextUrl.hostname) : undefined)
    log('info', '[next] Iniciando fluxo de login.', { returnTo: returnTo ?? undefined, tenant: tenant ?? undefined })

    const { url, state } = auth.getAuthorizationUrl(undefined, tenant ?? undefined)
    const res = NextResponse.redirect(url)

    res.cookies.set('_pa_state', state, { httpOnly: true, sameSite: 'lax', maxAge: 600, secure: isProduction, path: '/' })
    if (returnTo) {
      res.cookies.set('_pa_return', returnTo, { httpOnly: true, sameSite: 'lax', maxAge: 600, secure: isProduction, path: '/' })
    }

    log('debug', '[next] Redirecionando para o servidor de autenticação.', { url })
    return res
  }

  return { GET }
}

// ─── Callback ─────────────────────────────────────────────────────────────────

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

    log('info', '[next] Callback OAuth2 recebido.', { hasCode: !!code, hasState: !!state, error: error ?? undefined })

    if (error) {
      log('error', `[next] Servidor de autenticação retornou erro no callback. Verifique as configurações da aplicação no painel.`, {
        error,
        description: errorDesc,
      })
      return NextResponse.redirect(new URL(`${errorRedirect}?error=${encodeURIComponent(error)}`, request.url))
    }

    if (!code) {
      log('error', '[next] Callback recebido sem o parâmetro "code". O servidor deveria ter enviado o authorization code.')
      return NextResponse.redirect(new URL(`${errorRedirect}?error=missing_code`, request.url))
    }

    const savedState = request.cookies.get('_pa_state')?.value
    const returnTo   = request.cookies.get('_pa_return')?.value

    if (savedState && state !== savedState) {
      log('warn', '[next] State CSRF não confere. A requisição pode ter sido interceptada ou o cookie expirou.', {
        expected: savedState,
        received: state,
      })
      return NextResponse.redirect(new URL(`${errorRedirect}?error=state_mismatch`, request.url))
    }

    if (!savedState) {
      log('warn', '[next] Cookie de state não encontrado. Pode ter expirado (10 min) ou o navegador bloqueou cookies.')
    }

    let user: AuthenticatedUser
    try {
      log('info', '[next] Trocando authorization code por tokens...')
      const tokenSet = await auth.exchangeCode(code)

      log('info', '[next] Buscando dados do usuário...')
      user = await auth.getUserInfo(tokenSet.access_token)

      const session = encodeSession({
        accessToken:  tokenSet.access_token,
        refreshToken: tokenSet.refresh_token,
        expiresAt:    tokenSet.expires_at,
      }, auth.clientSecret)

      const redirectTo = returnTo ?? successRedirect
      const res = NextResponse.redirect(new URL(redirectTo, request.url))

      res.cookies.set(auth.cookieName, session, {
        httpOnly: true, sameSite: 'lax', maxAge: auth.cookieMaxAge, secure: isProduction, path: '/',
      })
      res.cookies.delete('_pa_state')
      res.cookies.delete('_pa_return')

      log('info', '[next] Login concluído com sucesso. Redirecionando.', {
        user: user.sub,
        username: user.username,
        redirectTo,
      })

      if (opts.onSuccess) {
        log('debug', '[next] Executando callback onSuccess...')
        const result = await opts.onSuccess(user)
        if (result === false) {
          log('debug', '[next] onSuccess retornou false — redirect assumido pelo callback.')
          return res
        }
      }

      return res
    } catch (err) {
      log('error', '[next] Falha ao processar callback OAuth2. Verifique as credenciais e se o servidor está acessível.', {
        error: String(err),
        serverUrl: auth.serverUrl,
      })
      return NextResponse.redirect(new URL(`${errorRedirect}?error=callback_failed`, request.url))
    }
  }

  return { GET }
}

// ─── Logout ───────────────────────────────────────────────────────────────────

export function createLogoutHandler(auth: PrimeAuth, opts: { redirectTo?: string } = {}) {
  function GET(request: NextRequest) {
    const redirectTo = opts.redirectTo ?? '/auth/login'
    log('info', '[next] Usuário deslogado. Sessão encerrada.', { redirectTo })
    const res = NextResponse.redirect(new URL(redirectTo, request.url))
    res.cookies.delete(auth.cookieName)
    return res
  }
  return { GET }
}

// ─── Me ───────────────────────────────────────────────────────────────────────

export function createMeHandler(auth: PrimeAuth) {
  async function GET(request: NextRequest) {
    log('debug', '[next] /auth/me — verificando sessão do usuário.')

    const cookie = request.cookies.get(auth.cookieName)?.value
    if (!cookie) {
      log('debug', '[next] /auth/me — nenhum cookie de sessão encontrado. Retornando null.')
      return NextResponse.json(null)
    }

    const session = decodeSession(cookie, auth.clientSecret)
    if (!session) {
      log('warn', '[next] /auth/me — cookie de sessão presente mas inválido. Pode ter sido adulterado.')
      return NextResponse.json(null)
    }

    if (Date.now() >= session.expiresAt) {
      log('warn', '[next] /auth/me — sessão expirada.', { expiredAt: new Date(session.expiresAt).toISOString() })
      return NextResponse.json(null)
    }

    try {
      const user = await auth.getUserInfo(session.accessToken)
      log('debug', '[next] /auth/me — usuário retornado.', { sub: user.sub })
      return NextResponse.json(user)
    } catch (err) {
      log('error', '[next] /auth/me — falha ao buscar dados do usuário com o access token salvo.', { error: String(err) })
      return NextResponse.json(null)
    }
  }
  return { GET }
}
