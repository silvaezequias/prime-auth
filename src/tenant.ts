const IGNORED_SUBDOMAINS = new Set(['www'])

/**
 * Extrai o primeiro rótulo de um hostname como tenant, quando existe subdomínio.
 * Ex.: "acme.meuapp.com" → "acme". Retorna undefined para hosts sem subdomínio
 * (ex.: "meuapp.com", "localhost") ou para subdomínios comuns não relacionados
 * a tenant (ex.: "www").
 *
 * Heurística simples baseada em contagem de rótulos — não lida com domínios
 * multi-nível como "meuapp.co.uk" (trataria "meuapp" como tenant de "co.uk").
 *
 * Caso especial: "tenant.localhost" (dev local, ex.: `teste.localhost:3000`)
 * só tem 2 rótulos, não 3+ como em produção — mas ainda é um host de tenant
 * válido, então é tratado à parte para que testes locais de multi-tenant
 * funcionem igual a produção.
 */
export function extractTenantFromHost(hostname: string): string | undefined {
  const host = hostname.split(':')[0] ?? ''
  const labels = host.split('.').filter(Boolean)
  const isLocalhostSubdomain = labels.length === 2 && labels[1] === 'localhost'
  if (labels.length < 3 && !isLocalhostSubdomain) return undefined
  const candidate = labels[0]
  if (!candidate || IGNORED_SUBDOMAINS.has(candidate)) return undefined
  return candidate
}
