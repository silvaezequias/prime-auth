import { createHash } from 'node:crypto'
import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import { PrimeAuth } from '../client.js'
import { AuthenticatedUser } from '../types.js'
import { encodeSession, decodeSession } from '../session.js'
import { resolveRequestUrl } from './request-url.js'
import { log } from '../logger.js'

/**
 * "Impressão digital" curta e não-reversível do client_secret em uso —
 * NUNCA o valor bruto. Serve só para comparar, olhando os logs, se a
 * instância resolvida aqui está usando o mesmo secret que o servidor tem
 * cadastrado para o client_id (ex.: depois de uma rotação de secret que não
 * chegou via webhook, o fingerprint muda e aparece nos logs — sem precisar
 * consultar os dois bancos manualmente pra descobrir).
 */
function secretFingerprint(secret: string): string {
  return createHash('sha256').update(secret).digest('hex').slice(0, 8)
}

function authDebugInfo(auth: PrimeAuth) {
  return {
    clientId: auth.clientId,
    tenant: auth.tenant,
    redirectUri: auth.redirectUri,
    serverUrl: auth.serverUrl,
    clientSecretFingerprint: secretFingerprint(auth.clientSecret),
  }
}

/**
 * Handlers Next.js para setups multi-tenant: cada empresa/tenant tem seu
 * próprio client_id/client_secret, resolvidos EM TEMPO DE REQUISIÇÃO (ex.:
 * consultando um banco local, populado via webhook do servidor de
 * autenticação) em vez de um único client_id/secret fixo no `.env`.
 *
 * Diferente de `createHandlers` (que aceita só uma instância `PrimeAuth`
 * fixa), aqui `resolve()` roda uma vez por requisição — em login, callback,
 * logout e /me — e decide qual `PrimeAuth` usar para ESSA requisição
 * específica. É o único lugar que precisa saber como identificar o tenant
 * (ex.: pelo header Host); o resto do fluxo OAuth2 (state, troca de code,
 * sessão) é implementado aqui de forma direta e sequencial, sem indireção
 * por cima de `createHandlers` — mais fácil de acompanhar e depurar.
 */
export interface MultiTenantOptions {
  /**
   * Resolve o `PrimeAuth` a usar nesta requisição. Retorne `null` quando
   * não for possível identificar um tenant, ou quando as credenciais dele
   * ainda não tiverem chegado — nesse caso `fallback` é usado.
   */
  resolve(request: NextRequest): PrimeAuth | null | Promise<PrimeAuth | null>
  /** Instância usada quando `resolve()` retorna `null`. */
  fallback: PrimeAuth
  /** Para onde redirecionar após login bem-sucedido. @default '/' */
  successRedirect?: string
  /** Para onde redirecionar em caso de erro (login, callback ou logout). @default '/auth/login' */
  errorRedirect?: string
  /**
   * Chamado após login bem-sucedido (server-side), já com o `PrimeAuth`
   * usado nesta requisição — evita o chamador ter que redescobrir o tenant
   * (ex.: decodificando claims do token) só para saber qual empresa
   * sincronizar. Retornar `false` impede o redirect padrão.
   */
  onSuccess?(user: AuthenticatedUser, auth: PrimeAuth): void | false | Promise<void | false>
}

async function resolveOrFallback(opts: MultiTenantOptions, request: NextRequest): Promise<PrimeAuth> {
  const resolved = await opts.resolve(request)
  if (resolved) return resolved
  log('debug', '[next:multi-tenant] resolve() não encontrou um tenant para esta requisição — usando fallback.', {
    pathname: request.nextUrl.pathname,
  })
  return opts.fallback
}

/** `secure` do cookie baseado no protocolo real da requisição — não em NODE_ENV (ver nota em next/handlers.ts). */
function isSecure(request: NextRequest): boolean {
  return request.nextUrl.protocol === 'https:'
}

export function createMultiTenantHandlers(opts: MultiTenantOptions) {
  const successRedirect = opts.successRedirect ?? '/'
  const errorRedirect   = opts.errorRedirect   ?? '/auth/login'

  async function login(request: NextRequest): Promise<Response> {
    const auth = await resolveOrFallback(opts, request)
    const secure = isSecure(request)
    const returnTo = request.nextUrl.searchParams.get('returnTo')

    log('info', '[next:multi-tenant] Iniciando fluxo de login.', {
      ...authDebugInfo(auth),
      returnTo: returnTo ?? undefined,
    })

    const { url, state } = auth.getAuthorizationUrl()
    const res = NextResponse.redirect(url)

    res.cookies.set('_pa_state', state, { httpOnly: true, sameSite: 'lax', maxAge: 600, secure, path: '/' })
    if (returnTo) {
      res.cookies.set('_pa_return', returnTo, { httpOnly: true, sameSite: 'lax', maxAge: 600, secure, path: '/' })
    }

    return res
  }

  async function callback(request: NextRequest): Promise<Response> {
    const auth = await resolveOrFallback(opts, request)
    const secure = isSecure(request)

    const { searchParams } = request.nextUrl
    const code      = searchParams.get('code')
    const state     = searchParams.get('state')
    const error     = searchParams.get('error')
    const errorDesc = searchParams.get('error_description')

    log('info', '[next:multi-tenant] Callback OAuth2 recebido.', {
      ...authDebugInfo(auth),
      hasCode: !!code,
      hasState: !!state,
      error: error ?? undefined,
    })

    if (error) {
      log('error', '[next:multi-tenant] Servidor de autenticação retornou erro no callback.', { error, description: errorDesc })
      return NextResponse.redirect(resolveRequestUrl(request, `${errorRedirect}?error=${encodeURIComponent(error)}`))
    }

    if (!code) {
      log('error', '[next:multi-tenant] Callback recebido sem o parâmetro "code".')
      return NextResponse.redirect(resolveRequestUrl(request, `${errorRedirect}?error=missing_code`))
    }

    const savedState = request.cookies.get('_pa_state')?.value
    const returnTo   = request.cookies.get('_pa_return')?.value

    if (savedState && state !== savedState) {
      log('warn', '[next:multi-tenant] State CSRF não confere.', { expected: savedState, received: state })
      return NextResponse.redirect(resolveRequestUrl(request, `${errorRedirect}?error=state_mismatch`))
    }
    if (!savedState) {
      log('warn', '[next:multi-tenant] Cookie de state não encontrado. Pode ter expirado (10 min) ou o navegador bloqueou cookies.')
    }

    try {
      log('info', '[next:multi-tenant] Trocando authorization code por tokens...', authDebugInfo(auth))
      const tokenSet = await auth.exchangeCode(code)
      log('info', '[next:multi-tenant] Code trocado com sucesso — token recebido.', {
        clientId: auth.clientId,
        tokenType: tokenSet.token_type,
        expiresIn: tokenSet.expires_in,
        hasRefreshToken: !!tokenSet.refresh_token,
        scope: tokenSet.scope,
      })

      const user = await auth.getUserInfo(tokenSet.access_token)

      const session = encodeSession({
        accessToken:  tokenSet.access_token,
        refreshToken: tokenSet.refresh_token,
        expiresAt:    tokenSet.expires_at,
      }, auth.sessionSecret)

      const redirectTo = returnTo ?? successRedirect
      const res = NextResponse.redirect(resolveRequestUrl(request, redirectTo))

      res.cookies.set(auth.cookieName, session, {
        httpOnly: true, sameSite: 'lax', maxAge: auth.cookieMaxAge, secure, path: '/',
      })
      res.cookies.delete('_pa_state')
      res.cookies.delete('_pa_return')

      log('info', '[next:multi-tenant] Login concluído com sucesso.', { user: user.sub, clientId: auth.clientId, redirectTo })

      if (opts.onSuccess) {
        const result = await opts.onSuccess(user, auth)
        if (result === false) return res
      }

      return res
    } catch (err) {
      log('error', '[next:multi-tenant] Falha ao trocar authorization code por tokens. Se o erro for invalid_client, o clientSecretFingerprint abaixo não bate com o que o servidor tem cadastrado para este clientId — geralmente porque o secret foi rotacionado no servidor (ex.: botão de sincronizar) e o webhook com o novo valor não chegou até aqui.', {
        error: String(err),
        ...authDebugInfo(auth),
      })
      return NextResponse.redirect(resolveRequestUrl(request, `${errorRedirect}?error=callback_failed`))
    }
  }

  async function logout(request: NextRequest): Promise<Response> {
    const auth = await resolveOrFallback(opts, request)
    log('info', '[next:multi-tenant] Usuário deslogado.', { clientId: auth.clientId })
    const res = NextResponse.redirect(resolveRequestUrl(request, errorRedirect))
    res.cookies.delete(auth.cookieName)
    return res
  }

  async function me(request: NextRequest): Promise<Response> {
    const auth = await resolveOrFallback(opts, request)
    const cookie = request.cookies.get(auth.cookieName)?.value
    if (!cookie) return NextResponse.json(null)

    const session = decodeSession(cookie, auth.sessionSecret)
    if (!session || Date.now() >= session.expiresAt) return NextResponse.json(null)

    try {
      const user = await auth.getUserInfo(session.accessToken)
      return NextResponse.json(user)
    } catch (err) {
      log('error', '[next:multi-tenant] /auth/me — falha ao buscar dados do usuário.', { error: String(err), clientId: auth.clientId })
      return NextResponse.json(null)
    }
  }

  async function GET(request: NextRequest): Promise<Response> {
    const action = request.nextUrl.pathname.split('/').at(-1)
    switch (action) {
      case 'login':    return login(request)
      case 'callback': return callback(request)
      case 'logout':   return logout(request)
      case 'me':       return me(request)
      default:
        log('warn', '[next:multi-tenant] Rota não reconhecida no catch-all.', { pathname: request.nextUrl.pathname })
        return NextResponse.json({ error: 'not_found' }, { status: 404 })
    }
  }

  return { GET }
}
