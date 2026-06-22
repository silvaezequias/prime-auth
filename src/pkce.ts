import { createHash, randomBytes } from 'crypto'

/** Gera um code_verifier aleatório para PKCE */
export function generateCodeVerifier(): string {
  return randomBytes(32).toString('base64url')
}

/** Gera o code_challenge S256 a partir do verifier */
export function generateCodeChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url')
}

/** Gera um state aleatório para proteção CSRF */
export function generateState(): string {
  return randomBytes(16).toString('hex')
}
