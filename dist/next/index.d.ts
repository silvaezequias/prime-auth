import { NextRequest, NextResponse } from 'next/server';
import { P as PrimeAuth } from '../client-DPad6k_c.js';
import { N as NextHandlersOptions, A as AuthenticatedUser, M as MiddlewareOptions } from '../types-BTzC6no2.js';
export { b as AppInfo, C as CompanyUser, P as PrimeAuthConfig, S as SessionData, T as TokenPayload, c as TokenSet, U as UserInfo } from '../types-BTzC6no2.js';

declare function createHandlers(auth: PrimeAuth, opts?: NextHandlersOptions): {
    GET: (request: NextRequest) => Promise<NextResponse<unknown>>;
};
declare function createLoginHandler(auth: PrimeAuth, opts?: NextHandlersOptions): {
    GET: (request: NextRequest) => Promise<NextResponse<unknown>>;
};
declare function createCallbackHandler(auth: PrimeAuth, opts?: NextHandlersOptions): {
    GET: (request: NextRequest) => Promise<NextResponse<unknown>>;
};
declare function createLogoutHandler(auth: PrimeAuth, opts?: {
    redirectTo?: string;
}): {
    GET: (request: NextRequest) => NextResponse<unknown>;
};
declare function createMeHandler(auth: PrimeAuth): {
    GET: (request: NextRequest) => Promise<NextResponse<null> | NextResponse<AuthenticatedUser>>;
};

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
interface MultiTenantOptions {
    /**
     * Resolve o `PrimeAuth` a usar nesta requisição. Retorne `null` quando
     * não for possível identificar um tenant, ou quando as credenciais dele
     * ainda não tiverem chegado — nesse caso `fallback` é usado.
     */
    resolve(request: NextRequest): PrimeAuth | null | Promise<PrimeAuth | null>;
    /** Instância usada quando `resolve()` retorna `null`. */
    fallback: PrimeAuth;
    /** Para onde redirecionar após login bem-sucedido. @default '/' */
    successRedirect?: string;
    /** Para onde redirecionar em caso de erro (login, callback ou logout). @default '/auth/login' */
    errorRedirect?: string;
    /**
     * Chamado após login bem-sucedido (server-side), já com o `PrimeAuth`
     * usado nesta requisição — evita o chamador ter que redescobrir o tenant
     * (ex.: decodificando claims do token) só para saber qual empresa
     * sincronizar. Retornar `false` impede o redirect padrão.
     */
    onSuccess?(user: AuthenticatedUser, auth: PrimeAuth): void | false | Promise<void | false>;
}
declare function createMultiTenantHandlers(opts: MultiTenantOptions): {
    GET: (request: NextRequest) => Promise<Response>;
};

declare function createMiddleware(auth: PrimeAuth, opts?: MiddlewareOptions): (request: NextRequest) => NextResponse<unknown>;

declare function getUser(auth: PrimeAuth): Promise<AuthenticatedUser | null>;
declare function requireUser(auth: PrimeAuth, loginPath?: string): Promise<AuthenticatedUser>;

export { AuthenticatedUser, MiddlewareOptions, type MultiTenantOptions, NextHandlersOptions, createCallbackHandler, createHandlers, createLoginHandler, createLogoutHandler, createMeHandler, createMiddleware, createMultiTenantHandlers, getUser, requireUser };
