import { PrimeAuth } from '../client.js'
import { AuthenticatedUser } from '../types.js'
import { decodeSession, encodeSession } from '../session.js'
import { log } from '../logger.js'

export async function getUser(auth: PrimeAuth): Promise<AuthenticatedUser | null> {
  log('debug', '[next:server] getUser() — lendo sessão do cookie.')

  const cookieStore = await getCookies()
  const raw = cookieStore.get(auth.cookieName)?.value

  if (!raw) {
    log('debug', '[next:server] getUser() — nenhum cookie de sessão encontrado.')
    return null
  }

  const session = decodeSession(raw, auth.sessionSecret)
  if (!session) {
    log('warn', '[next:server] getUser() — cookie de sessão inválido. Possível adulteração ou clientSecret diferente.')
    return null
  }

  // Renova se estiver dentro da margem de 60s
  if (Date.now() >= session.expiresAt - 60_000) {
    if (!session.refreshToken) {
      log('warn', '[next:server] getUser() — sessão expirada e sem refresh token. Usuário precisará fazer login novamente.', {
        expiredAt: new Date(session.expiresAt).toISOString(),
      })
      return null
    }

    log('info', '[next:server] getUser() — access token prestes a expirar. Renovando automaticamente...')
    try {
      const tokenSet = await auth.refreshToken(session.refreshToken)
      const newSession = {
        accessToken:  tokenSet.access_token,
        refreshToken: tokenSet.refresh_token ?? session.refreshToken,
        expiresAt:    tokenSet.expires_at,
      }

      cookieStore.set(auth.cookieName, encodeSession(newSession, auth.sessionSecret), {
        httpOnly: true, sameSite: 'lax', maxAge: auth.cookieMaxAge, secure: await isSecureRequest(), path: '/',
      })

      log('info', '[next:server] getUser() — token renovado com sucesso.')

      try {
        return await auth.getUserInfo(newSession.accessToken)
      } catch (err) {
        log('error', '[next:server] getUser() — token renovado mas falha ao buscar userinfo.', { error: String(err) })
        return null
      }
    } catch (err) {
      log('error', '[next:server] getUser() — falha ao renovar token. Usuário precisará fazer login novamente.', { error: String(err) })
      return null
    }
  }

  try {
    const user = await auth.getUserInfo(session.accessToken)
    log('debug', '[next:server] getUser() — usuário obtido com sucesso.', { sub: user.sub })
    return user
  } catch (err) {
    log('error', '[next:server] getUser() — falha ao buscar dados do usuário. O access token pode ter sido revogado.', { error: String(err) })
    return null
  }
}

export async function requireUser(auth: PrimeAuth, loginPath = '/auth/login'): Promise<AuthenticatedUser> {
  log('debug', '[next:server] requireUser() — verificando autenticação.')
  const { redirect } = await import('next/navigation')
  const user = await getUser(auth)
  if (!user) {
    log('warn', '[next:server] requireUser() — usuário não autenticado. Redirecionando para login.', { loginPath })
    redirect(loginPath)
  }
  log('debug', '[next:server] requireUser() — usuário autenticado.', { sub: (user as AuthenticatedUser).sub })
  return user as AuthenticatedUser
}

async function getCookies() {
  const { cookies } = await import('next/headers')
  const result = cookies()
  return result instanceof Promise ? await result : result
}

// Baseado no protocolo real (via x-forwarded-proto), não em NODE_ENV — ver
// nota equivalente em next/handlers.ts.
async function isSecureRequest(): Promise<boolean> {
  const { headers } = await import('next/headers')
  const h = await headers()
  return h.get('x-forwarded-proto') === 'https'
}
