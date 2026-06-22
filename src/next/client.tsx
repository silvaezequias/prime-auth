'use client'

import React, {
  createContext, useContext, useEffect, useState, ReactNode,
} from 'react'
import type { AuthenticatedUser } from '../types.js'

// Re-exporta para quem importa de 'prime-auth/next/client'
export type { AuthenticatedUser } from '../types.js'

interface UserContextValue {
  user: AuthenticatedUser | null
  isLoading: boolean
}

const UserContext = createContext<UserContextValue>({ user: null, isLoading: false })

interface UserProviderProps {
  /**
   * Passe o usuário vindo de um Server Component (via `getUser(auth)` no layout).
   * Assim o cliente não precisa fazer nenhuma requisição extra.
   */
  user: AuthenticatedUser | null
  children: ReactNode
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
export function UserProvider({ user, children }: UserProviderProps) {
  return (
    <UserContext.Provider value={{ user, isLoading: false }}>
      {children}
    </UserContext.Provider>
  )
}

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
export function useUser(): UserContextValue {
  return useContext(UserContext)
}

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
export function UserFetchProvider({
  children,
  mePath = '/auth/me',
}: { children: ReactNode; mePath?: string }) {
  const [user, setUser]       = useState<AuthenticatedUser | null>(null)
  const [isLoading, setLoading] = useState(true)

  useEffect(() => {
    fetch(mePath, { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then((data: unknown) => setUser(data as AuthenticatedUser | null))
      .catch(() => setUser(null))
      .finally(() => setLoading(false))
  }, [mePath])

  return (
    <UserContext.Provider value={{ user, isLoading }}>
      {children}
    </UserContext.Provider>
  )
}
