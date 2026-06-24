import { Request, Response, NextFunction } from 'express'

// Augmenta o tipo Request do Express para incluir req.user
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: import('../types.js').AuthenticatedUser
    }
  }
}
import { PrimeAuth } from '../client.js'
import { ExpressRequireAuthOptions, AuthenticatedUser, SessionData } from '../types.js'
import { decodeSession, encodeSession } from '../session.js'
import { InsufficientScopeError } from '../errors.js'

/**
 * Middleware Express que protege rotas. Lê o cookie de sessão, verifica
 * (e renova se necessário) o access token e popula `req.user`.
 *
 * Requer `cookie-parser` montado antes: `app.use(cookieParser())`
 *
 * @example
 * import { requireAuth } from 'prime-auth/express'
 * import { auth } from './lib/auth'
 *
 * // Rota protegida — redireciona para /auth/login se não logado
 * app.get('/dashboard', requireAuth(auth), (req, res) => {
 *   res.json(req.user)
 * })
 *
 * // Modo API — retorna JSON 401 em vez de redirecionar
 * app.get('/api/me', requireAuth(auth, { json: true }), (req, res) => {
 *   res.json(req.user)
 * })
 *
 * // Exige escopos específicos
 * app.get('/api/profile', requireAuth(auth, { scopes: ['profile', 'email'] }), handler)
 */
export function requireAuth(auth: PrimeAuth, opts: ExpressRequireAuthOptions = {}) {
  const loginPath    = '/auth/login'
  const isProduction = process.env['NODE_ENV'] === 'production'

  return async function primeAuthGuard(req: Request, res: Response, next: NextFunction) {
    const raw = req.cookies?.[auth.cookieName] as string | undefined

    const fail = (code: string, message: string, status = 401) => {
      if (opts.json) return res.status(status).json({ error: code, error_description: message })
      const returnTo = encodeURIComponent(req.originalUrl ?? '/')
      res.redirect(`${loginPath}?returnTo=${returnTo}`)
    }

    if (!raw) return fail('unauthenticated', 'Sessão não encontrada.')

    let session = decodeSession(raw, auth.clientSecret)
    if (!session) return fail('invalid_session', 'Sessão inválida.')

    // Renova o access token automaticamente (margem de 60s)
    if (Date.now() >= session.expiresAt - 60_000) {
      if (!session.refreshToken) return fail('session_expired', 'Sessão expirada.')
      try {
        const tokenSet = await auth.refreshToken(session.refreshToken)
        session = {
          accessToken:  tokenSet.access_token,
          refreshToken: tokenSet.refresh_token ?? session.refreshToken,
          expiresAt:    tokenSet.expires_at,
        }
        res.cookie(auth.cookieName, encodeSession(session, auth.clientSecret), {
          httpOnly: true,
          sameSite: 'lax',
          maxAge:   auth.cookieMaxAge * 1000,
          secure:   isProduction,
        })
      } catch {
        res.clearCookie(auth.cookieName)
        return fail('session_expired', 'Sessão expirada.')
      }
    }

    let user: AuthenticatedUser
    try {
      user = await auth.getUserInfo(session.accessToken)
    } catch {
      res.clearCookie(auth.cookieName)
      return fail('invalid_token', 'Token inválido.')
    }

    if (opts.scopes?.length) {
      const granted = user.scope.split(' ')
      const missing = opts.scopes.filter(s => !granted.includes(s))
      if (missing.length) {
        const e = new InsufficientScopeError(missing)
        if (opts.json) return res.status(403).json({ error: e.code, error_description: e.message })
        return res.status(403).send(e.message)
      }
    }

    req.user = user
    next()
  }
}
