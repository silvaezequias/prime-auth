import { randomBytes } from 'crypto'
import { decodeJwt } from 'jose'
import {
  PrimeAuthConfig, TokenSet, TokenPayload, UserInfo, AuthenticatedUser,
} from './types.js'
import {
  PrimeAuthError, InvalidTokenError, ServerError,
} from './errors.js'

const DEFAULT_SCOPES = ['openid', 'profile', 'email']

export class PrimeAuth {
  readonly cookieName: string
  readonly clientSecret: string
  readonly cookieMaxAge: number

  private readonly _serverUrl: string
  private readonly _clientId: string
  private readonly _redirectUri: string
  private readonly _scopes: string[]
  private readonly _timeoutMs: number

  constructor(config: PrimeAuthConfig) {
    const serverUrl = config.serverUrl ?? process.env['PRIME_AUTH_SERVER_URL']
    if (!serverUrl) throw new PrimeAuthError(
      'serverUrl não configurado. Defina no construtor ou em PRIME_AUTH_SERVER_URL.',
      'config_error',
    )
    if (!config.clientId)     throw new PrimeAuthError('clientId é obrigatório.', 'config_error')
    if (!config.clientSecret) throw new PrimeAuthError('clientSecret é obrigatório.', 'config_error')
    if (!config.redirectUri)  throw new PrimeAuthError('redirectUri é obrigatório.', 'config_error')

    this._serverUrl    = serverUrl.replace(/\/$/, '')
    this._clientId     = config.clientId
    this.clientSecret  = config.clientSecret
    this._redirectUri  = config.redirectUri
    this._scopes       = config.scopes ?? DEFAULT_SCOPES
    this._timeoutMs    = config.timeoutMs ?? 10_000
    this.cookieName    = config.cookieName ?? 'prime_auth_session'
    this.cookieMaxAge  = config.cookieMaxAge ?? 60 * 60 * 24 * 7 // 7 dias em segundos
  }

  // ─── Getters ──────────────────────────────────────────────────────────────

  get serverUrl(): string   { return this._serverUrl }
  get clientId(): string    { return this._clientId }
  get redirectUri(): string { return this._redirectUri }
  get scopes(): string[]    { return this._scopes }

  // ─── Authorization URL ────────────────────────────────────────────────────

  getAuthorizationUrl(extra?: Record<string, string>): { url: string; state: string } {
    const state = randomBytes(16).toString('hex')
    const query = new URLSearchParams({
      response_type: 'code',
      client_id:     this._clientId,
      redirect_uri:  this._redirectUri,
      scope:         this._scopes.join(' '),
      state,
      ...extra,
    })
    return { url: `${this._serverUrl}/oauth/authorize?${query}`, state }
  }

  // ─── Token Exchange ───────────────────────────────────────────────────────

  async exchangeCode(code: string, codeVerifier?: string): Promise<TokenSet> {
    const body: Record<string, string> = {
      grant_type:    'authorization_code',
      code,
      redirect_uri:  this._redirectUri,
      client_id:     this._clientId,
      client_secret: this.clientSecret,
    }
    if (codeVerifier) body['code_verifier'] = codeVerifier
    return this._tokenRequest(body)
  }

  async refreshToken(refreshToken: string): Promise<TokenSet> {
    return this._tokenRequest({
      grant_type:    'refresh_token',
      refresh_token: refreshToken,
      client_id:     this._clientId,
      client_secret: this.clientSecret,
    })
  }

  async revokeToken(token: string, hint: 'access_token' | 'refresh_token' = 'access_token'): Promise<void> {
    await this._fetch(`${this._serverUrl}/oauth/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token, token_type_hint: hint }).toString(),
    })
  }

  // ─── UserInfo ─────────────────────────────────────────────────────────────

  async getUserInfo(accessToken: string): Promise<AuthenticatedUser> {
    const info = await this._fetch(`${this._serverUrl}/oauth/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    }) as UserInfo

    return {
      sub:         String(info.sub),
      username:    info.username,
      name:        info.name,
      email:       info.email,
      avatar:      info.avatar ?? info.picture,
      scope:       String(info.scope ?? ''),
      accessToken,
    }
  }

  // ─── Token helpers ────────────────────────────────────────────────────────

  decodeToken(accessToken: string): TokenPayload {
    try {
      return decodeJwt(accessToken) as TokenPayload
    } catch {
      throw new InvalidTokenError('Não foi possível decodificar o token.')
    }
  }

  isTokenExpired(accessToken: string): boolean {
    try {
      const { exp } = this.decodeToken(accessToken)
      if (!exp) return false
      return Date.now() >= exp * 1000
    } catch {
      return true
    }
  }

  // ─── Privados ─────────────────────────────────────────────────────────────

  private async _tokenRequest(body: Record<string, string>): Promise<TokenSet> {
    const data = await this._fetch(`${this._serverUrl}/oauth/token`, {
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
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this._timeoutMs)

    let res: Response
    try {
      res = await fetch(url, { ...init, signal: controller.signal })
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      throw new PrimeAuthError(`Falha de rede: ${msg}`, 'network_error')
    } finally {
      clearTimeout(timer)
    }

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
      if (res.status === 401) throw new InvalidTokenError(message)
      throw new ServerError(message, res.status, body)
    }

    return body
  }
}
