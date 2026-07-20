export interface PrimeAuthConfig {
  /** client_id da aplicação cadastrada no painel */
  clientId: string
  /** client_secret da aplicação */
  clientSecret: string
  /**
   * URI de redirecionamento registrada na aplicação.
   * Exemplo: "http://localhost:3000/auth/callback"
   */
  redirectUri: string
  /**
   * Escopos solicitados.
   * @default ['openid', 'profile', 'email']
   */
  scopes?: string[]
  /**
   * URL base do servidor OAuth2.
   * Se omitido, lê de process.env.PRIME_AUTH_SERVER_URL
   */
  serverUrl?: string
  /** Timeout das requisições HTTP em ms. @default 10000 */
  timeoutMs?: number
  /** Nome do cookie de sessão. @default 'prime_auth_session' */
  cookieName?: string
  /** Duração da sessão em segundos. @default 604800 (7 dias) */
  cookieMaxAge?: number
  /**
   * Tenant padrão desta instância. Quando definido, o link de login passa a
   * usar o atalho `GET /oauth2/<tenant>` do servidor (que resolve client_id
   * e redirect_uri automaticamente) em vez de `/oauth/login?client_id=...`.
   *
   * Pode ser sobrescrito por requisição via `?tenant=` na rota de login, ou
   * (se `tenantFromSubdomain` estiver habilitado) detectado do subdomínio.
   *
   * Importante: o `redirectUri` configurado aqui precisa ser exatamente o
   * mesmo `defaultRedirectUri` cadastrado para o tenant no painel do
   * servidor — é ele que será usado na troca do code por tokens.
   */
  tenant?: string
}

export interface ExpressRouterOptions {
  /** Para onde redirecionar após login bem-sucedido. @default '/' */
  successRedirect?: string
  /** Para onde redirecionar em caso de erro. @default '/auth/login' */
  errorRedirect?: string
  /** Path da rota de login. @default '/auth/login' */
  loginPath?: string
  /** Callback chamado após login bem-sucedido (server-side). */
  onSuccess?: (user: AuthenticatedUser, req: unknown, res: unknown) => void | Promise<void>
  /**
   * Se `true`, quando nenhum tenant for informado via `?tenant=`, tenta
   * extrair o tenant do subdomínio do host da requisição
   * (ex.: `acme.meuapp.com` → `acme`). @default false
   */
  tenantFromSubdomain?: boolean
}

export interface ExpressRequireAuthOptions {
  /**
   * Se `true`, retorna JSON 401 em vez de redirecionar.
   * @default false
   */
  json?: boolean
  /** Escopos obrigatórios. Retorna 403 se o token não tiver todos. */
  scopes?: string[]
}

export interface NextHandlersOptions {
  /** Para onde redirecionar após login bem-sucedido. @default '/' */
  successRedirect?: string
  /** Para onde redirecionar em caso de erro. @default '/auth/login' */
  errorRedirect?: string
  /**
   * Callback chamado após login bem-sucedido (server-side).
   * Retornar `false` impede o redirect padrão.
   */
  onSuccess?: (user: AuthenticatedUser) => void | false | Promise<void | false>
  /**
   * Se `true`, quando nenhum tenant for informado via `?tenant=`, tenta
   * extrair o tenant do subdomínio do host da requisição
   * (ex.: `acme.meuapp.com` → `acme`). @default false
   */
  tenantFromSubdomain?: boolean
}

export interface MiddlewareOptions {
  /**
   * Padrões de paths protegidos (glob-like: '/dashboard', '/dashboard/:path*').
   * @default ['/dashboard']
   */
  protectedPaths?: string[]
  /** Path da rota de login para redirecionamento. @default '/auth/login' */
  loginPath?: string
}

export interface SessionData {
  accessToken: string
  refreshToken?: string
  expiresAt: number
}

export interface AuthenticatedUser {
  /** ID do usuário (sub do JWT) */
  sub: string
  /** Nome de usuário */
  username?: string
  /** Nome completo */
  name?: string
  /** E-mail */
  email?: string
  /** URL do avatar */
  avatar?: string
  /** Escopos concedidos */
  scope: string
  /** Access token bruto (para chamadas manuais à API) */
  accessToken: string
}

export interface TokenSet {
  access_token: string
  token_type: string
  expires_in: number
  refresh_token?: string
  scope?: string
  /** Timestamp (ms) de expiração calculado localmente */
  expires_at: number
}

export interface TokenPayload {
  sub: string
  username?: string
  name?: string
  email?: string
  scope?: string
  aud?: string | string[]
  iat?: number
  exp?: number
  jti?: string
  [key: string]: unknown
}

export interface UserInfo {
  sub: string
  username?: string
  name?: string
  email?: string
  avatar?: string
  picture?: string
  scope?: string
  [key: string]: unknown
}
