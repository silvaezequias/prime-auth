import { createHmac, timingSafeEqual } from 'crypto'
import { SessionData } from './types.js'
import { log } from './logger.js'

const SEP = '.'

function sign(payload: string, secret: string): string {
  return createHmac('sha256', secret).update(payload).digest('base64url')
}

export function encodeSession(data: SessionData, secret: string): string {
  const payload = Buffer.from(JSON.stringify(data)).toString('base64url')
  const sig = sign(payload, secret)
  log('debug', 'Sessão codificada no cookie.', {
    expiresAt: new Date(data.expiresAt).toISOString(),
    hasRefreshToken: !!data.refreshToken,
  })
  return `${payload}${SEP}${sig}`
}

export function decodeSession(cookie: string, secret: string): SessionData | null {
  const dotIdx = cookie.lastIndexOf(SEP)
  if (dotIdx === -1) {
    log('warn', 'Cookie de sessão malformado (separador ausente). A sessão será ignorada.')
    return null
  }

  const payload = cookie.slice(0, dotIdx)
  const sig     = cookie.slice(dotIdx + 1)

  try {
    const expected    = Buffer.from(sign(payload, secret))
    const sigBuf      = Buffer.from(sig)
    if (expected.length !== sigBuf.length || !timingSafeEqual(expected, sigBuf)) {
      log('warn', 'Assinatura do cookie de sessão inválida. Possível adulteração ou clientSecret incorreto.')
      return null
    }
  } catch (err) {
    log('error', 'Erro ao verificar assinatura do cookie de sessão.', { error: String(err) })
    return null
  }

  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as SessionData
    log('debug', 'Sessão decodificada com sucesso.', {
      expiresAt: new Date(data.expiresAt).toISOString(),
      expired: Date.now() >= data.expiresAt,
    })
    return data
  } catch (err) {
    log('error', 'Erro ao desserializar dados da sessão.', { error: String(err) })
    return null
  }
}
