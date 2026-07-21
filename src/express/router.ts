import { Router, Request, Response } from 'express'
import { PrimeAuth } from '../client.js'
import { ExpressRouterOptions, AuthenticatedUser } from '../types.js'
import { encodeSession, decodeSession } from '../session.js'
import { extractTenantFromHost } from '../tenant.js'
import { log } from '../logger.js'

export function createRouter(auth: PrimeAuth, opts: ExpressRouterOptions = {}) {
  const successRedirect = opts.successRedirect ?? '/'
  const errorRedirect   = opts.errorRedirect   ?? '/auth/login'
  const loginPath       = opts.loginPath        ?? '/auth/login'
  const isProduction    = process.env['NODE_ENV'] === 'production'

  log('info', '[express] Router OAuth2 configurado.', { successRedirect, errorRedirect, loginPath })

  const router = Router()

  // GET /auth/login
  router.get('/auth/login', async (req: Request, res: Response) => {
    try {
      const returnTo = req.query['returnTo'] as string | undefined
      let tenant = (req.query['tenant'] as string | undefined)
        ?? (opts.tenantFromSubdomain ? extractTenantFromHost(req.hostname) : undefined)

      if (!tenant && opts.autoTenant) {
        try {
          tenant = (await auth.getAppInfo()).tenantSlug ?? undefined
        } catch (err) {
          log('warn', '[express] autoTenant: falha ao buscar o tenant via getAppInfo(). Prosseguindo sem tenant.', { error: String(err) })
        }
      }

      log('info', '[express] Iniciando fluxo de login.', { returnTo, tenant, ip: req.ip })

      const { url, state } = auth.getAuthorizationUrl(undefined, tenant)

      res.cookie('_pa_state', state, { httpOnly: true, sameSite: 'lax', maxAge: 10 * 60 * 1000, secure: isProduction })
      if (returnTo) {
        res.cookie('_pa_return', returnTo, { httpOnly: true, sameSite: 'lax', maxAge: 10 * 60 * 1000, secure: isProduction })
      }

      log('debug', '[express] Redirecionando para o servidor de autenticação.', { url })
      res.redirect(url)
    } catch (err) {
      log('error', '[express] Falha ao iniciar fluxo de login.', { error: String(err) })
      res.status(500).send('Erro ao iniciar login.')
    }
  })

  // GET /auth/callback
  router.get('/auth/callback', async (req: Request, res: Response) => {
    const { code, state, error, error_description } = req.query as Record<string, string>

    log('info', '[express] Callback OAuth2 recebido.', { hasCode: !!code, hasState: !!state, error: error ?? undefined })

    if (error) {
      log('error', '[express] Servidor de autenticação retornou erro no callback. Verifique as configurações da aplicação no painel.', {
        error,
        description: error_description,
      })
      return res.redirect(`${errorRedirect}?error=${encodeURIComponent(error)}`)
    }

    if (!code) {
      log('error', '[express] Callback recebido sem o parâmetro "code". O servidor deveria ter enviado o authorization code.')
      return res.redirect(`${errorRedirect}?error=missing_code`)
    }

    const savedState = req.cookies?.['_pa_state']
    const returnTo   = req.cookies?.['_pa_return']
    res.clearCookie('_pa_state')
    res.clearCookie('_pa_return')

    if (savedState && state !== savedState) {
      log('warn', '[express] State CSRF não confere. A requisição pode ter sido interceptada ou o cookie expirou.', {
        expected: savedState,
        received: state,
      })
      return res.redirect(`${errorRedirect}?error=state_mismatch`)
    }

    if (!savedState) {
      log('warn', '[express] Cookie de state não encontrado. Pode ter expirado (10 min) ou o navegador bloqueou cookies.')
    }

    let user: AuthenticatedUser
    try {
      log('info', '[express] Trocando authorization code por tokens...')
      const tokenSet = await auth.exchangeCode(code)

      log('info', '[express] Buscando dados do usuário...')
      user = await auth.getUserInfo(tokenSet.access_token)

      res.cookie(auth.cookieName, encodeSession({
        accessToken:  tokenSet.access_token,
        refreshToken: tokenSet.refresh_token,
        expiresAt:    tokenSet.expires_at,
      }, auth.sessionSecret), {
        httpOnly: true, sameSite: 'lax', maxAge: auth.cookieMaxAge * 1000, secure: isProduction,
      })

      log('info', '[express] Login concluído com sucesso. Redirecionando.', {
        sub: user.sub,
        username: user.username,
        redirectTo: returnTo ?? successRedirect,
      })

      if (opts.onSuccess) {
        log('debug', '[express] Executando callback onSuccess...')
        await opts.onSuccess(user, req, res)
      }

      res.redirect(returnTo ?? successRedirect)
    } catch (err) {
      log('error', '[express] Falha ao processar callback OAuth2. Verifique as credenciais e se o servidor está acessível.', {
        error: String(err),
        serverUrl: auth.serverUrl,
      })
      res.redirect(`${errorRedirect}?error=callback_failed`)
    }
  })

  // GET /auth/logout
  router.get('/auth/logout', (req: Request, res: Response) => {
    log('info', '[express] Usuário deslogado. Sessão encerrada.', { ip: req.ip })
    res.clearCookie(auth.cookieName)
    res.redirect(loginPath)
  })

  // GET /auth/me
  router.get('/auth/me', async (req: Request, res: Response) => {
    log('debug', '[express] /auth/me — verificando sessão do usuário.')

    const raw = req.cookies?.[auth.cookieName]
    if (!raw) {
      log('debug', '[express] /auth/me — nenhum cookie de sessão encontrado. Retornando null.')
      return res.json(null)
    }

    const session = decodeSession(raw, auth.sessionSecret)
    if (!session) {
      log('warn', '[express] /auth/me — cookie de sessão presente mas inválido. Pode ter sido adulterado.')
      return res.json(null)
    }

    if (Date.now() >= session.expiresAt) {
      log('warn', '[express] /auth/me — sessão expirada.', { expiredAt: new Date(session.expiresAt).toISOString() })
      return res.json(null)
    }

    try {
      const user = await auth.getUserInfo(session.accessToken)
      log('debug', '[express] /auth/me — usuário retornado.', { sub: user.sub })
      res.json(user)
    } catch (err) {
      log('error', '[express] /auth/me — falha ao buscar dados do usuário com o access token salvo.', { error: String(err) })
      res.json(null)
    }
  })

  return router
}
