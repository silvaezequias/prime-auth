import type { NextRequest } from 'next/server'

/**
 * Monta uma URL relativa a esta requisição de forma confiável.
 *
 * `request.url` / `request.nextUrl` podem não refletir o host real da
 * requisição dentro de Route Handlers no Next.js 16 com Turbopack —
 * observado retornando o host base do servidor (ex.: "localhost:3000")
 * mesmo quando o cliente acessou um subdomínio de tenant (ex.:
 * "tenant.localhost:3000"). Usar `request.url` como base para
 * `new URL(path, base)` nesse caso produz redirects que "voltam" para o
 * host errado — exatamente o tipo de bug que fazia logout/login perderem
 * o tenant no meio do fluxo.
 *
 * O header Host bruto, em contrapartida, é confiável nesse contexto — é
 * ele que usamos aqui, com o protocolo de `nextUrl` (que por sua vez é
 * confiável).
 */
export function resolveRequestUrl(request: NextRequest, path: string): URL {
  const host = request.headers.get('host') ?? request.nextUrl.host
  const protocol = request.nextUrl.protocol
  return new URL(path, `${protocol}//${host}`)
}
