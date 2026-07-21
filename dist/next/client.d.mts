import React, { ReactNode } from 'react';
import { A as AuthenticatedUser } from '../types-BTzC6no2.mjs';

interface UserContextValue {
    user: AuthenticatedUser | null;
    isLoading: boolean;
}
interface UserProviderProps {
    /**
     * Passe o usuário vindo de um Server Component (via `getUser(auth)` no layout).
     * Assim o cliente não precisa fazer nenhuma requisição extra.
     */
    user: AuthenticatedUser | null;
    children: ReactNode;
}
/**
 * Provider que disponibiliza o usuário para todos os Client Components.
 *
 * Adicione no `app/layout.tsx`:
 *
 * @example
 * // app/layout.tsx (Server Component)
 * import { UserProvider } from 'prime-auth/next/client'
 * import { getUser } from 'prime-auth/next'
 * import { auth } from '@/lib/auth'
 *
 * export default async function RootLayout({ children }) {
 *   const user = await getUser(auth)
 *   return (
 *     <html>
 *       <body>
 *         <UserProvider user={user}>
 *           {children}
 *         </UserProvider>
 *       </body>
 *     </html>
 *   )
 * }
 */
declare function UserProvider({ user, children }: UserProviderProps): React.JSX.Element;
/**
 * Hook para acessar o usuário autenticado em qualquer Client Component.
 *
 * @example
 * 'use client'
 * import { useUser } from 'prime-auth/next/client'
 *
 * export function Header() {
 *   const { user } = useUser()
 *   if (!user) return <a href="/auth/login">Entrar</a>
 *   return (
 *     <div>
 *       {user.avatar && <img src={user.avatar} alt={user.name} />}
 *       <span>{user.name}</span>
 *       <a href="/auth/logout">Sair</a>
 *     </div>
 *   )
 * }
 */
declare function useUser(): UserContextValue;
/**
 * Versão que busca o usuário via `/auth/me` no lado do cliente.
 * Use apenas quando não for possível passar o usuário via Server Component.
 *
 * @example
 * 'use client'
 * import { UserFetchProvider } from 'prime-auth/next/client'
 *
 * export function ClientLayout({ children }) {
 *   return <UserFetchProvider>{children}</UserFetchProvider>
 * }
 */
declare function UserFetchProvider({ children, mePath, }: {
    children: ReactNode;
    mePath?: string;
}): React.JSX.Element;

export { AuthenticatedUser, UserFetchProvider, UserProvider, useUser };
