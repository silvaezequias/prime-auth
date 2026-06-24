import { Router, Request, Response, NextFunction } from 'express'
import { PrimeAuth } from '../client.js'
import { ExpressRouterOptions, AuthenticatedUser } from '../types.js'
import { encodeSession, decodeSession } from '../session.js'

/**
 * Cria um Express Router com as rotas de login, callback, logout e /me
 * pré-configuradas. Monte com `app.use(createRouter(auth))`.
 *
 * Requer `cookie-parser` montado antes: `app.use(cookieParser())`
 *
 * Rotas criadas (defaults):
 *  GET /auth/login    → redireciona para o servidor de autenticação
 *  GET /auth/callback → troca o code por tokens e salva sessão em cookie
 *  GET /auth/logout   → apaga a sessão e redireciona para /auth/login
 *  GET /auth/me       → retorna o usuário atual em JSON
 *
 * @example
 * import express from 'express'
 * import cookieParser from 'cookie-parser'
 * import { createRouter } from 'prime-auth/express'
 * import { auth } from './lib/auth'
 *
 * const app = express()
 * app.use(cookieParser())
 * app.use(createRouter(auth, { successRedirect: '/dashboard' }))
 */
export function createRouter(auth: PrimeAuth, opts: ExpressRouterOptions = {}) {
  const successRedirect = opts.successRedirect ?? '/'
  const errorRedirect   = opts.errorRedirect   ?? '/auth/login'
  const loginPath       = opts.loginPath        ?? '/auth/login'
  const isProduction    = process.env['NODE_ENV'] === 'production'

  const router = Router()

  // GET /auth/login
  router.get('/auth/login', (req: Request, res: Response) => {
    const returnTo = req.query['returnTo'] as string | undefined
    const { url, state } = auth.getAuthorizationUrl()

    res.cookie('_pa_state', state, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 10 * 60 * 1000,
      secure: isProduction,
    })

    if (returnTo) {
      res.cookie('_pa_return', returnTo, {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 10 * 60 * 1000,
        secure: isProduction,
      })
    }

    res.redirect(url)
  })

  // GET /auth/callback
  router.get('/auth/callback', async (req: Request, res: Response) => {
    const { code, state, error, error_description } = req.query as Record<string, string>

    if (error) {
      console.error('[prime-auth] Servidor retornou erro:', error, error_description)
      return res.redirect(`${errorRedirect}?error=${encodeURIComponent(error)}`)
    }

    if (!code) return res.redirect(`${errorRedirect}?error=missing_code`)

    const savedState = req.cookies?.['_pa_state']
    const returnTo   = req.cookies?.['_pa_return']
    res.clearCookie('_pa_state')
    res.clearCookie('_pa_return')

    if (savedState && state !== savedState) {
      return res.redirect(`${errorRedirect}?error=state_mismatch`)
    }

    let user: AuthenticatedUser
    try {
      const tokenSet = await auth.exchangeCode(code)
      user = await auth.getUserInfo(tokenSet.access_token)

      res.cookie(auth.cookieName, encodeSession({
        accessToken:  tokenSet.access_token,
        refreshToken: tokenSet.refresh_token,
        expiresAt:    tokenSet.expires_at,
      }, auth.clientSecret), {
        httpOnly: true,
        sameSite: 'lax',
        maxAge:   auth.cookieMaxAge * 1000,
        secure:   isProduction,
      })

      if (opts.onSuccess) await opts.onSuccess(user, req, res)

      res.redirect(returnTo ?? successRedirect)
    } catch (err) {
      console.error('[prime-auth] Erro no callback:', err)
      res.redirect(`${errorRedirect}?error=callback_failed`)
    }
  })

  // GET /auth/logout
  router.get('/auth/logout', (req: Request, res: Response) => {
    res.clearCookie(auth.cookieName)
    res.redirect(loginPath)
  })

  // GET /auth/me
  router.get('/auth/me', async (req: Request, res: Response) => {
    const raw = req.cookies?.[auth.cookieName]
    if (!raw) return res.json(null)

    const session = decodeSession(raw, auth.clientSecret)
    if (!session || Date.now() >= session.expiresAt) return res.json(null)

    try {
      const user = await auth.getUserInfo(session.accessToken)
      res.json(user)
    } catch {
      res.json(null)
    }
  })

  return router
}
