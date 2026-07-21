import { NextRequest, NextResponse } from 'next/server';
import { P as PrimeAuth } from '../client-DPad6k_c.js';
import { N as NextHandlersOptions, A as AuthenticatedUser, M as MiddlewareOptions } from '../types-BTzC6no2.js';
export { b as AppInfo, C as CompanyUser, P as PrimeAuthConfig, S as SessionData, T as TokenPayload, c as TokenSet, U as UserInfo } from '../types-BTzC6no2.js';

/**
 * Ou uma instância `PrimeAuth` fixa (modo tradicional, credenciais de um
 * único client_id/secret vindas do `.env`), ou uma função que resolve a
 * instância certa PARA CADA REQUISIÇÃO — usada em setups multi-tenant onde
 * cada empresa/tenant tem seu próprio client_id/secret guardado em banco.
 * A função recebe a `NextRequest` (para extrair o tenant do subdomínio, por
 * exemplo) e deve devolver o `PrimeAuth` com as credenciais certas para essa
 * requisição específica — inclusive para a troca do code por tokens no
 * callback, que é onde credenciais erradas quebram silenciosamente.
 */
type AuthSource = PrimeAuth | ((request: NextRequest) => PrimeAuth | Promise<PrimeAuth>);
declare function createHandlers(authSource: AuthSource, opts?: NextHandlersOptions): {
    GET: (request: NextRequest) => Promise<NextResponse<unknown>>;
};
declare function createLoginHandler(authSource: AuthSource, opts?: NextHandlersOptions): {
    GET: (request: NextRequest) => Promise<NextResponse<unknown>>;
};
declare function createCallbackHandler(authSource: AuthSource, opts?: NextHandlersOptions): {
    GET: (request: NextRequest) => Promise<NextResponse<unknown>>;
};
declare function createLogoutHandler(authSource: AuthSource, opts?: {
    redirectTo?: string;
}): {
    GET: (request: NextRequest) => Promise<NextResponse<unknown>>;
};
declare function createMeHandler(authSource: AuthSource): {
    GET: (request: NextRequest) => Promise<NextResponse<null> | NextResponse<AuthenticatedUser>>;
};

declare function createMiddleware(auth: PrimeAuth, opts?: MiddlewareOptions): (request: NextRequest) => NextResponse<unknown>;

declare function getUser(auth: PrimeAuth): Promise<AuthenticatedUser | null>;
declare function requireUser(auth: PrimeAuth, loginPath?: string): Promise<AuthenticatedUser>;

export { type AuthSource, AuthenticatedUser, MiddlewareOptions, NextHandlersOptions, createCallbackHandler, createHandlers, createLoginHandler, createLogoutHandler, createMeHandler, createMiddleware, getUser, requireUser };
