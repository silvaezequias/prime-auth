import { PrimeAuth } from '../client.js'
import { AuthenticatedUser, SessionData } from '../types.js'
import { decodeSession, encodeSession } from '../session.js'

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
export async function getUser(auth: PrimeAuth): Promise<AuthenticatedUser | null> {
  // cookies() é async no Next.js 15 e sync no 13/14
  const cookieStore = await getCookies()
  const raw = cookieStore.get(auth.cookieName)?.value
  if (!raw) return null

  const session = decodeSession(raw, auth.clientSecret)
  if (!session) return null

  // Tenta renovar se estiver prestes a expirar (margem de 60s)
  let activeSession: SessionData = session
  if (Date.now() >= session.expiresAt - 60_000) {
    if (!session.refreshToken) return null
    try {
      const tokenSet = await auth.refreshToken(session.refreshToken)
      activeSession = {
        accessToken:  tokenSet.access_token,
        refreshToken: tokenSet.refresh_token ?? session.refreshToken,
        expiresAt:    tokenSet.expires_at,
      }
      // Atualiza o cookie com o novo token
      const isProduction = process.env['NODE_ENV'] === 'production'
      cookieStore.set(auth.cookieName, encodeSession(activeSession, auth.clientSecret), {
        httpOnly: true,
        sameSite: 'lax',
        maxAge:   auth.cookieMaxAge,
        secure:   isProduction,
        path:     '/',
      })
    } catch {
      return null
    }
  }

  try {
    return await auth.getUserInfo(activeSession.accessToken)
  } catch {
    return null
  }
}

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
export async function requireUser(auth: PrimeAuth, loginPath = '/auth/login'): Promise<AuthenticatedUser> {
  const { redirect } = await import('next/navigation')
  const user = await getUser(auth)
  if (!user) redirect(loginPath)
  return user as AuthenticatedUser
}

// Compatibilidade com Next.js 13, 14 e 15 (cookies() virou async no 15)
async function getCookies() {
  const { cookies } = await import('next/headers')
  // No Next.js 15, cookies() retorna uma Promise
  const result = cookies()
  return result instanceof Promise ? await result : result
}
