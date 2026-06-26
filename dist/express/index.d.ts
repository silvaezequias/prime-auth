import * as express_serve_static_core from 'express-serve-static-core';
import { P as PrimeAuth } from '../client-BkdewWL6.js';
import { E as ExpressRouterOptions, A as AuthenticatedUser, a as ExpressRequireAuthOptions } from '../types-CK3Pypy4.js';
export { P as PrimeAuthConfig, S as SessionData, T as TokenPayload, b as TokenSet, U as UserInfo } from '../types-CK3Pypy4.js';
import { Request, Response, NextFunction } from 'express';

declare function createRouter(auth: PrimeAuth, opts?: ExpressRouterOptions): express_serve_static_core.Router;

declare global {
    namespace Express {
        interface Request {
            user?: AuthenticatedUser;
        }
    }
}
declare function requireAuth(auth: PrimeAuth, opts?: ExpressRequireAuthOptions): (req: Request, res: Response, next: NextFunction) => Promise<Response<any, Record<string, any>> | undefined>;

export { AuthenticatedUser, ExpressRequireAuthOptions, ExpressRouterOptions, createRouter, requireAuth };
