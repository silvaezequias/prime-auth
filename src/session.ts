import { createHmac, timingSafeEqual } from 'crypto'
import { SessionData } from './types.js'

const SEP = '.'

function sign(payload: string, secret: string): string {
  return createHmac('sha256', secret).update(payload).digest('base64url')
}

/** Serializa e assina os dados de sessão em uma string para cookie */
export function encodeSession(data: SessionData, secret: string): string {
  const payload = Buffer.from(JSON.stringify(data)).toString('base64url')
  const sig = sign(payload, secret)
  return `${payload}${SEP}${sig}`
}

/** Verifica e desserializa os dados de sessão do cookie. Retorna null se inválido */
export function decodeSession(cookie: string, secret: string): SessionData | null {
  const dotIdx = cookie.lastIndexOf(SEP)
  if (dotIdx === -1) return null

  const payload = cookie.slice(0, dotIdx)
  const sig = cookie.slice(dotIdx + 1)
  const expected = sign(payload, secret)

  try {
    const expectedBuf = Buffer.from(expected)
    const sigBuf = Buffer.from(sig)
    if (expectedBuf.length !== sigBuf.length) return null
    if (!timingSafeEqual(expectedBuf, sigBuf)) return null
  } catch {
    return null
  }

  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as SessionData
  } catch {
    return null
  }
}
