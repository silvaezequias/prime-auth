import * as express_serve_static_core from 'express-serve-static-core';
import { P as PrimeAuth } from '../client-BkdewWL6.js';
import { E as ExpressRouterOptions, A as AuthenticatedUser, a as ExpressRequireAuthOptions } from '../types-CK3Pypy4.js';
export { P as PrimeAuthConfig, S as SessionData, T as TokenPayload, b as TokenSet, U as UserInfo } from '../types-CK3Pypy4.js';
import { Request, Response, NextFunction } from 'express';

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
declare function createRouter(auth: PrimeAuth, opts?: ExpressRouterOptions): express_serve_static_core.Router;

declare global {
    namespace Express {
        interface Request {
            user?: AuthenticatedUser;
        }
    }
}

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
declare function requireAuth(auth: PrimeAuth, opts?: ExpressRequireAuthOptions): (req: Request, res: Response, next: NextFunction) => Promise<Response<any, Record<string, any>> | undefined>;

export { AuthenticatedUser, ExpressRequireAuthOptions, ExpressRouterOptions, createRouter, requireAuth };
