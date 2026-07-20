const IGNORED_SUBDOMAINS = new Set(['www'])

/**
 * Extrai o primeiro rótulo de um hostname como tenant, quando existe subdomínio.
 * Ex.: "acme.meuapp.com" → "acme". Retorna undefined para hosts sem subdomínio
 * (ex.: "meuapp.com", "localhost") ou para subdomínios comuns não relacionados
 * a tenant (ex.: "www").
 *
 * Heurística simples baseada em contagem de rótulos — não lida com domínios
 * multi-nível como "meuapp.co.uk" (trataria "meuapp" como tenant de "co.uk").
 */
export function extractTenantFromHost(hostname: string): string | undefined {
  const host = hostname.split(':')[0] ?? ''
  const labels = host.split('.').filter(Boolean)
  if (labels.length < 3) return undefined
  const candidate = labels[0]
  if (!candidate || IGNORED_SUBDOMAINS.has(candidate)) return undefined
  return candidate
}
