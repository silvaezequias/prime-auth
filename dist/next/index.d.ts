import { NextRequest, NextResponse } from 'next/server';
import { P as PrimeAuth } from '../client-D88tXlAH.js';
import { N as NextHandlersOptions, A as AuthenticatedUser, M as MiddlewareOptions } from '../types-CGwq3iVS.js';
export { P as PrimeAuthConfig, S as SessionData, T as TokenPayload, a as TokenSet, U as UserInfo } from '../types-CGwq3iVS.js';

/**
 * Cria um único Route Handler que serve todas as rotas OAuth2.
 * Use em `app/auth/[...prime]/route.ts`.
 *
 * Rotas criadas automaticamente:
 *  GET /auth/login    → redireciona para o servidor de autenticação
 *  GET /auth/callback → troca o code por tokens e salva a sessão
 *  GET /auth/logout   → apaga a sessão
 *  GET /auth/me       → retorna o usuário atual em JSON
 */
declare function createHandlers(auth: PrimeAuth, opts?: NextHandlersOptions): {
    GET: (request: NextRequest) => Promise<NextResponse<unknown>>;
};
/**
 * Handler para a rota de login.
 * Redireciona o usuário para o servidor de autenticação.
 *
 * @example
 * // app/auth/login/route.ts
 * import { createLoginHandler } from 'prime-auth/next'
 * import { auth } from '@/lib/auth'
 * export const { GET } = createLoginHandler(auth)
 */
declare function createLoginHandler(auth: PrimeAuth): {
    GET: (request: NextRequest) => NextResponse<unknown>;
};
/**
 * Handler para a rota de callback OAuth2.
 *
 * Recebe o `code` enviado pelo servidor após o login, troca pelo par
 * access_token/refresh_token, busca os dados do usuário e salva a sessão
 * em um cookie httpOnly assinado.
 *
 * Parâmetros de query recebidos pelo servidor:
 *  - `code`  → authorization code (obrigatório)
 *  - `state` → valor anti-CSRF para validar (deve coincidir com o cookie `_pa_state`)
 *  - `error` + `error_description` → em caso de recusa/erro no servidor
 *
 * @example
 * // app/auth/callback/route.ts
 * import { createCallbackHandler } from 'prime-auth/next'
 * import { auth } from '@/lib/auth'
 *
 * export const { GET } = createCallbackHandler(auth, {
 *   successRedirect: '/dashboard',
 *   onSuccess: async (user) => {
 *     // Salve ou atualize o usuário no seu banco de dados
 *     await db.user.upsert({
 *       where: { sub: user.sub },
 *       update: { name: user.name, email: user.email, avatar: user.avatar },
 *       create: { sub: user.sub, name: user.name, email: user.email, avatar: user.avatar },
 *     })
 *   },
 * })
 */
declare function createCallbackHandler(auth: PrimeAuth, opts?: NextHandlersOptions): {
    GET: (request: NextRequest) => Promise<NextResponse<unknown>>;
};
/**
 * Handler para a rota de logout.
 * Apaga o cookie de sessão e redireciona para `/auth/login`.
 *
 * @example
 * // app/auth/logout/route.ts
 * import { createLogoutHandler } from 'prime-auth/next'
 * import { auth } from '@/lib/auth'
 * export const { GET } = createLogoutHandler(auth)
 */
declare function createLogoutHandler(auth: PrimeAuth, opts?: {
    redirectTo?: string;
}): {
    GET: (request: NextRequest) => NextResponse<unknown>;
};
/**
 * Handler para a rota `/auth/me`.
 * Retorna o usuário atual em JSON — usado pelo `UserFetchProvider` em Client Components.
 *
 * @example
 * // app/auth/me/route.ts
 * import { createMeHandler } from 'prime-auth/next'
 * import { auth } from '@/lib/auth'
 * export const { GET } = createMeHandler(auth)
 */
declare function createMeHandler(auth: PrimeAuth): {
    GET: (request: NextRequest) => Promise<NextResponse<null> | NextResponse<AuthenticatedUser>>;
};

/**
 * Cria o middleware do Next.js para proteger rotas automaticamente.
 *
 * Use em `middleware.ts` na raiz do projeto:
 *
 * @example
 * // middleware.ts
 * import { createMiddleware } from 'prime-auth/next'
 * import { auth } from './lib/auth'
 *
 * export const middleware = createMiddleware(auth, {
 *   protectedPaths: ['/dashboard', '/settings'],
 * })
 *
 * export const config = {
 *   matcher: ['/dashboard/:path*', '/settings/:path*'],
 * }
 */
declare function createMiddleware(auth: PrimeAuth, opts?: MiddlewareOptions): (request: NextRequest) => NextResponse<unknown>;

/**
 * Retorna o usuário autenticado atual em um Server Component ou Route Handler.
 * Retorna `null` se não houver sessão válida.
 *
 * Renova o access token automaticamente se estiver expirado.
 *
 * @example
 * // app/dashboard/page.tsx
 * import { getUser } from 'prime-auth/next'
 * import { auth } from '@/lib/auth'
 *
 * export default async function Page() {
 *   const user = await getUser(auth)
 *   if (!user) redirect('/auth/login')
 *   return <h1>Olá, {user.name}</h1>
 * }
 */
declare function getUser(auth: PrimeAuth): Promise<AuthenticatedUser | null>;
/**
 * Igual ao `getUser`, mas lança um redirect para `/auth/login` se não autenticado.
 * Use em páginas que exigem autenticação.
 *
 * @example
 * import { requireUser } from 'prime-auth/next'
 * import { auth } from '@/lib/auth'
 *
 * export default async function Page() {
 *   const user = await requireUser(auth) // redireciona se não logado
 *   return <h1>Olá, {user.name}</h1>
 * }
 */
declare function requireUser(auth: PrimeAuth, loginPath?: string): Promise<AuthenticatedUser>;

export { AuthenticatedUser, MiddlewareOptions, NextHandlersOptions, createCallbackHandler, createHandlers, createLoginHandler, createLogoutHandler, createMeHandler, createMiddleware, getUser, requireUser };
