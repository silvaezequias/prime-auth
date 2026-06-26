import { Request, Response, NextFunction } from 'express'
import { PrimeAuth } from '../client.js'
import { ExpressRequireAuthOptions, AuthenticatedUser } from '../types.js'
import { decodeSession, encodeSession } from '../session.js'
import { InsufficientScopeError } from '../errors.js'
import { log } from '../logger.js'

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: import('../types.js').AuthenticatedUser
    }
  }
}

export function requireAuth(auth: PrimeAuth, opts: ExpressRequireAuthOptions = {}) {
  const loginPath    = '/auth/login'
  const isProduction = process.env['NODE_ENV'] === 'production'

  return async function primeAuthGuard(req: Request, res: Response, next: NextFunction) {
    const raw = req.cookies?.[auth.cookieName] as string | undefined

    const fail = (code: string, message: string, status = 401) => {
      if (opts.json) {
        log('warn', `[express:requireAuth] Acesso negado (${status}).`, { code, path: req.path })
        return res.status(status).json({ error: code, error_description: message })
      }
      const returnTo = encodeURIComponent(req.originalUrl ?? '/')
      log('warn', `[express:requireAuth] Acesso negado — redirecionando para login.`, { code, path: req.path, returnTo: req.originalUrl })
      res.redirect(`${loginPath}?returnTo=${returnTo}`)
    }

    if (!raw) {
      log('debug', `[express:requireAuth] Nenhum cookie de sessão encontrado.`, { path: req.path })
      return fail('unauthenticated', 'Sessão não encontrada.')
    }

    let session = decodeSession(raw, auth.clientSecret)
    if (!session) {
      log('warn', `[express:requireAuth] Cookie de sessão inválido ou adulterado.`, { path: req.path })
      return fail('invalid_session', 'Sessão inválida.')
    }

    // Renovação automática (margem de 60s)
    if (Date.now() >= session.expiresAt - 60_000) {
      if (!session.refreshToken) {
        log('warn', '[express:requireAuth] Sessão expirada e sem refresh token. Usuário precisará fazer login novamente.', {
          path: req.path,
          expiredAt: new Date(session.expiresAt).toISOString(),
        })
        res.clearCookie(auth.cookieName)
        return fail('session_expired', 'Sessão expirada.')
      }

      log('info', '[express:requireAuth] Access token prestes a expirar. Renovando automaticamente...')
      try {
        const tokenSet = await auth.refreshToken(session.refreshToken)
        session = {
          accessToken:  tokenSet.access_token,
          refreshToken: tokenSet.refresh_token ?? session.refreshToken,
          expiresAt:    tokenSet.expires_at,
        }
        res.cookie(auth.cookieName, encodeSession(session, auth.clientSecret), {
          httpOnly: true, sameSite: 'lax', maxAge: auth.cookieMaxAge * 1000, secure: isProduction,
        })
        log('info', '[express:requireAuth] Token renovado com sucesso.')
      } catch (err) {
        log('error', '[express:requireAuth] Falha ao renovar token. Encerrando sessão.', { error: String(err) })
        res.clearCookie(auth.cookieName)
        return fail('session_expired', 'Sessão expirada.')
      }
    }

    let user: AuthenticatedUser
    try {
      user = await auth.getUserInfo(session.accessToken)
    } catch (err) {
      log('error', '[express:requireAuth] Falha ao buscar dados do usuário. O access token pode ter sido revogado.', {
        path: req.path,
        error: String(err),
      })
      res.clearCookie(auth.cookieName)
      return fail('invalid_token', 'Token inválido.')
    }

    if (opts.scopes?.length) {
      const granted = user.scope.split(' ')
      const missing = opts.scopes.filter(s => !granted.includes(s))
      if (missing.length) {
        const e = new InsufficientScopeError(missing)
        log('warn', '[express:requireAuth] Escopos insuficientes.', {
          required: opts.scopes,
          granted,
          missing,
          path: req.path,
        })
        if (opts.json) return res.status(403).json({ error: e.code, error_description: e.message })
        return res.status(403).send(e.message)
      }
    }

    log('debug', '[express:requireAuth] Acesso permitido.', { sub: user.sub, path: req.path })
    req.user = user
    next()
  }
}
