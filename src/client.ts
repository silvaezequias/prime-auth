import { randomBytes } from 'crypto'
import { decodeJwt } from 'jose'
import {
  PrimeAuthConfig, TokenSet, TokenPayload, UserInfo, AuthenticatedUser, AppInfo, CompanyUser,
} from './types.js'
import {
  PrimeAuthError, InvalidTokenError, ServerError,
} from './errors.js'
import { log } from './logger.js'

const DEFAULT_SCOPES = ['openid', 'profile', 'email']
const APP_INFO_CACHE_MS = 5 * 60 * 1000

export class PrimeAuth {
  readonly cookieName: string
  readonly clientSecret: string
  readonly cookieMaxAge: number

  private readonly _serverUrl: string
  private readonly _clientId: string
  private readonly _redirectUri: string
  private readonly _scopes: string[]
  private readonly _timeoutMs: number
  private readonly _tenant: string | undefined
  private readonly _companyApiKey: string | undefined
  private _appInfoCache: { value: AppInfo; expiresAt: number } | null = null
  private _appInfoPromise: Promise<AppInfo> | null = null

  constructor(config: PrimeAuthConfig) {
    const serverUrl = config.serverUrl ?? process.env['PRIME_AUTH_SERVER_URL']

    if (!serverUrl) {
      log('error', 'serverUrl não configurado. Defina no construtor ou em PRIME_AUTH_SERVER_URL no .env.')
      throw new PrimeAuthError('serverUrl não configurado.', 'config_error')
    }
    if (!config.clientId) {
      log('error', 'clientId não informado. Verifique a configuração do PrimeAuth.')
      throw new PrimeAuthError('clientId é obrigatório.', 'config_error')
    }
    if (!config.clientSecret) {
      log('error', 'clientSecret não informado. Verifique a configuração do PrimeAuth.')
      throw new PrimeAuthError('clientSecret é obrigatório.', 'config_error')
    }
    if (!config.redirectUri) {
      log('error', 'redirectUri não informado. Defina a URI de redirecionamento registrada na aplicação.')
      throw new PrimeAuthError('redirectUri é obrigatório.', 'config_error')
    }

    // Normaliza a serverUrl removendo um "/api" final, se vier configurado
    // (algumas instalações incluem esse sufixo). Internamente, páginas
    // (/oauth/login, /oauth2/<tenant>) usam a URL "limpa", e chamadas de API
    // (/api/oauth/token, /api/oauth/userinfo, ...) adicionam o prefixo /api
    // explicitamente — assim funciona com ou sem o sufixo na env var.
    this._serverUrl    = serverUrl.replace(/\/$/, '').replace(/\/api$/i, '')
    this._clientId     = config.clientId
    this.clientSecret  = config.clientSecret
    this._redirectUri  = config.redirectUri
    this._scopes       = config.scopes ?? DEFAULT_SCOPES
    this._timeoutMs    = config.timeoutMs ?? 10_000
    this.cookieName    = config.cookieName ?? 'prime_auth_session'
    this.cookieMaxAge  = config.cookieMaxAge ?? 60 * 60 * 24 * 7
    this._tenant       = config.tenant
    this._companyApiKey = config.companyApiKey

    log('info', 'PrimeAuth inicializado.', {
      serverUrl: this._serverUrl,
      clientId:  this._clientId,
      redirectUri: this._redirectUri,
      scopes: this._scopes,
      tenant: this._tenant,
    })
  }

  // ─── Getters ──────────────────────────────────────────────────────────────

  get serverUrl(): string   { return this._serverUrl }
  get clientId(): string    { return this._clientId }
  get redirectUri(): string { return this._redirectUri }
  get scopes(): string[]    { return this._scopes }
  get tenant(): string | undefined { return this._tenant }

  // ─── Authorization URL ────────────────────────────────────────────────────

  /**
   * Monta a URL de autorização para redirecionar o usuário.
   *
   * Se um tenant estiver disponível (via `tenantOverride` ou `config.tenant`),
   * usa o atalho `GET /oauth2/<tenant>` do servidor, que resolve o client_id
   * e o redirect_uri automaticamente a partir do tenant cadastrado. Caso
   * contrário, monta a URL tradicional em `/oauth/login` com os parâmetros
   * OAuth2 explícitos.
   */
  getAuthorizationUrl(extra?: Record<string, string>, tenantOverride?: string): { url: string; state: string } {
    const state  = randomBytes(16).toString('hex')
    const tenant = tenantOverride ?? this._tenant

    if (tenant) {
      const query = new URLSearchParams({ state, ...extra })
      const url = `${this._serverUrl}/oauth2/${encodeURIComponent(tenant)}?${query}`
      log('debug', 'URL de autorização gerada via tenant.', { url, tenant })
      return { url, state }
    }

    const query = new URLSearchParams({
      response_type: 'code',
      client_id:     this._clientId,
      redirect_uri:  this._redirectUri,
      scope:         this._scopes.join(' '),
      state,
      ...extra,
    })
    const url = `${this._serverUrl}/oauth/login?${query}`
    log('debug', 'URL de autorização gerada.', { url, scopes: this._scopes.join(' ') })
    return { url, state }
  }

  /**
   * Busca informações públicas da aplicação (nome, empresa, logos e o
   * `tenantSlug` cadastrado, se houver) a partir do `clientId` configurado.
   * Não requer autenticação. O resultado é cacheado em memória por alguns
   * minutos para não bater na rede a cada chamada.
   */
  async getAppInfo(): Promise<AppInfo> {
    const now = Date.now()
    if (this._appInfoCache && this._appInfoCache.expiresAt > now) {
      return this._appInfoCache.value
    }
    if (this._appInfoPromise) return this._appInfoPromise

    this._appInfoPromise = (async () => {
      log('debug', 'Buscando informações da aplicação em /api/oauth/app-info...')
      try {
        const query = new URLSearchParams({ client_id: this._clientId })
        const info = await this._fetch(`${this._serverUrl}/api/oauth/app-info?${query}`) as AppInfo
        this._appInfoCache = { value: info, expiresAt: now + APP_INFO_CACHE_MS }
        log('debug', 'Informações da aplicação obtidas.', { appId: info.appId, tenantSlug: info.tenantSlug })
        return info
      } catch (err) {
        log('error', 'Falha ao buscar informações da aplicação.', { error: String(err) })
        throw err
      } finally {
        this._appInfoPromise = null
      }
    })()

    return this._appInfoPromise
  }

  // ─── Company API (leitura de usuários entre aplicações) ───────────────────

  /**
   * Lista usuários de todas as aplicações da empresa, usando a chave de API
   * da empresa (`config.companyApiKey`) — não o `clientSecret` da aplicação.
   * Útil quando a mesma empresa tem mais de um tenant/aplicação e você
   * precisa reconhecer usuários independente de qual deles foi usado no login.
   */
  async listCompanyUsers(opts?: { limit?: number; cursor?: string }): Promise<{ users: CompanyUser[]; nextCursor: string | null }> {
    this._requireCompanyApiKey()
    const query = new URLSearchParams()
    if (opts?.limit) query.set('limit', String(opts.limit))
    if (opts?.cursor) query.set('cursor', opts.cursor)
    const qs = query.toString()
    return this._fetch(`${this._serverUrl}/api/company/v1/users${qs ? `?${qs}` : ''}`, {
      headers: { Authorization: `Bearer ${this._companyApiKey}` },
    }) as Promise<{ users: CompanyUser[]; nextCursor: string | null }>
  }

  /** Busca um usuário específico (por `sub`) em qualquer aplicação da empresa. Retorna `null` se não encontrado. */
  async getCompanyUser(sub: string): Promise<CompanyUser | null> {
    this._requireCompanyApiKey()
    try {
      return await this._fetch(`${this._serverUrl}/api/company/v1/users/${encodeURIComponent(sub)}`, {
        headers: { Authorization: `Bearer ${this._companyApiKey}` },
      }) as CompanyUser
    } catch (err) {
      if (err instanceof ServerError && err.status === 404) return null
      throw err
    }
  }

  private _requireCompanyApiKey(): void {
    if (!this._companyApiKey) {
      log('error', 'companyApiKey não configurada. Defina em `new PrimeAuth({ companyApiKey: ... })`.')
      throw new PrimeAuthError('companyApiKey não configurada.', 'config_error')
    }
  }

  // ─── Token Exchange ───────────────────────────────────────────────────────

  async exchangeCode(code: string, codeVerifier?: string): Promise<TokenSet> {
    log('info', 'Trocando authorization code por tokens...', { hasPKCE: !!codeVerifier })
    const body: Record<string, string> = {
      grant_type:    'authorization_code',
      code,
      redirect_uri:  this._redirectUri,
      client_id:     this._clientId,
      client_secret: this.clientSecret,
    }
    if (codeVerifier) body['code_verifier'] = codeVerifier
    try {
      const tokenSet = await this._tokenRequest(body)
      log('info', 'Authorization code trocado com sucesso.', {
        tokenType: tokenSet.token_type,
        expiresIn: tokenSet.expires_in,
        hasRefreshToken: !!tokenSet.refresh_token,
        scope: tokenSet.scope,
      })
      return tokenSet
    } catch (err) {
      log('error', 'Falha ao trocar authorization code por tokens.', { error: String(err) })
      throw err
    }
  }

  async refreshToken(refreshToken: string): Promise<TokenSet> {
    log('info', 'Renovando access token via refresh token...')
    try {
      const tokenSet = await this._tokenRequest({
        grant_type:    'refresh_token',
        refresh_token: refreshToken,
        client_id:     this._clientId,
        client_secret: this.clientSecret,
      })
      log('info', 'Access token renovado com sucesso.', {
        expiresIn: tokenSet.expires_in,
        hasRefreshToken: !!tokenSet.refresh_token,
      })
      return tokenSet
    } catch (err) {
      log('error', 'Falha ao renovar access token. Verifique se o refresh token ainda é válido.', { error: String(err) })
      throw err
    }
  }

  async revokeToken(token: string, hint: 'access_token' | 'refresh_token' = 'access_token'): Promise<void> {
    log('info', `Revogando ${hint}...`)
    try {
      await this._fetch(`${this._serverUrl}/api/oauth/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token, token_type_hint: hint }).toString(),
      })
      log('info', `${hint} revogado com sucesso.`)
    } catch (err) {
      log('error', `Falha ao revogar ${hint}.`, { error: String(err) })
      throw err
    }
  }

  // ─── UserInfo ─────────────────────────────────────────────────────────────

  async getUserInfo(accessToken: string): Promise<AuthenticatedUser> {
    log('debug', 'Buscando informações do usuário em /oauth/userinfo...')
    try {
      const info = await this._fetch(`${this._serverUrl}/api/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      }) as UserInfo

      if (!info.sub) {
        log('warn', 'O servidor retornou userinfo sem o campo "sub". Verifique se o escopo "openid" foi concedido.')
      }

      const user: AuthenticatedUser = {
        sub:         String(info.sub),
        username:    info.username,
        name:        info.name,
        email:       info.email,
        avatar:      info.avatar ?? info.picture,
        scope:       String(info.scope ?? ''),
        accessToken,
      }

      log('debug', 'Dados do usuário obtidos com sucesso.', {
        sub:      user.sub,
        username: user.username,
        name:     user.name,
        email:    user.email,
        hasAvatar: !!user.avatar,
        scope:    user.scope,
      })

      return user
    } catch (err) {
      log('error', 'Falha ao buscar informações do usuário. Verifique se o access token é válido.', { error: String(err) })
      throw err
    }
  }

  // ─── Token helpers ────────────────────────────────────────────────────────

  decodeToken(accessToken: string): TokenPayload {
    try {
      const payload = decodeJwt(accessToken) as TokenPayload
      log('debug', 'Token JWT decodificado localmente.', {
        sub: payload.sub,
        exp: payload.exp ? new Date(payload.exp * 1000).toISOString() : undefined,
      })
      return payload
    } catch (err) {
      log('error', 'Não foi possível decodificar o JWT. O token pode estar malformado.', { error: String(err) })
      throw new InvalidTokenError('Não foi possível decodificar o token.')
    }
  }

  isTokenExpired(accessToken: string): boolean {
    try {
      const { exp } = this.decodeToken(accessToken)
      if (!exp) {
        log('warn', 'Token JWT não possui campo "exp". Assumindo que não está expirado.')
        return false
      }
      const expired = Date.now() >= exp * 1000
      if (expired) log('debug', 'Token JWT está expirado.', { expiredAt: new Date(exp * 1000).toISOString() })
      return expired
    } catch {
      return true
    }
  }

  // ─── Privados ─────────────────────────────────────────────────────────────

  private async _tokenRequest(body: Record<string, string>): Promise<TokenSet> {
    const data = await this._fetch(`${this._serverUrl}/api/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString(),
    }) as Record<string, unknown>

    return {
      access_token:  data['access_token'] as string,
      token_type:    (data['token_type'] as string) ?? 'Bearer',
      expires_in:    (data['expires_in'] as number) ?? 3600,
      refresh_token: data['refresh_token'] as string | undefined,
      scope:         data['scope'] as string | undefined,
      expires_at:    Date.now() + ((data['expires_in'] as number) ?? 3600) * 1000,
    }
  }

  private async _fetch(url: string, init: RequestInit = {}): Promise<unknown> {
    const method = (init.method ?? 'GET').toUpperCase()
    log('debug', `HTTP ${method} → ${url}`)

    const controller = new AbortController()
    const timer = setTimeout(() => {
      log('warn', `Requisição para ${url} excedeu o timeout de ${this._timeoutMs}ms.`)
      controller.abort()
    }, this._timeoutMs)

    let res: Response
    try {
      res = await fetch(url, { ...init, signal: controller.signal })
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      const isAbort = err instanceof Error && err.name === 'AbortError'
      if (isAbort) {
        log('error', `Timeout ao conectar em ${url}. Verifique se o servidor está acessível em: ${this._serverUrl}`)
      } else {
        log('error', `Falha de rede ao conectar em ${url}. Verifique a variável PRIME_AUTH_SERVER_URL e se o servidor está rodando.`, { error: msg })
      }
      throw new PrimeAuthError(`Falha de rede: ${msg}`, 'network_error')
    } finally {
      clearTimeout(timer)
    }

    log('debug', `HTTP ${method} ← ${url}`, { status: res.status, ok: res.ok })

    if (res.status === 204) return null

    const ct = res.headers.get('content-type') ?? ''
    let body: unknown
    try {
      body = ct.includes('application/json') ? await res.json() : await res.text()
    } catch {
      body = null
    }

    if (!res.ok) {
      const e = body as Record<string, unknown> | null
      const message = String(e?.['error_description'] ?? e?.['error'] ?? `Erro ${res.status}`)

      if (res.status === 401) {
        log('warn', `Servidor retornou 401 em ${url}. O token pode ser inválido ou expirado.`, { error: e?.['error'], description: e?.['error_description'] })
        throw new InvalidTokenError(message)
      }
      if (res.status === 400) {
        log('warn', `Servidor retornou 400 em ${url}. Verifique os parâmetros enviados.`, { error: e?.['error'], description: e?.['error_description'] })
      } else if (res.status >= 500) {
        log('error', `Servidor retornou ${res.status} em ${url}. O servidor de autenticação pode estar com problema.`, { body })
      } else {
        log('warn', `Servidor retornou ${res.status} em ${url}.`, { error: message })
      }
      throw new ServerError(message, res.status, body)
    }

    return body
  }
}
