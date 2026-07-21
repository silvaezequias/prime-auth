import { P as PrimeAuthConfig, b as AppInfo, C as CompanyUser, c as TokenSet, A as AuthenticatedUser, T as TokenPayload } from './types-BTzC6no2.mjs';

declare class PrimeAuth {
    readonly cookieName: string;
    readonly clientSecret: string;
    readonly sessionSecret: string;
    readonly cookieMaxAge: number;
    private readonly _serverUrl;
    private readonly _clientId;
    private readonly _redirectUri;
    private readonly _scopes;
    private readonly _timeoutMs;
    private readonly _tenant;
    private readonly _companyApiKey;
    private _appInfoCache;
    private _appInfoPromise;
    constructor(config: PrimeAuthConfig);
    get serverUrl(): string;
    get clientId(): string;
    get redirectUri(): string;
    get scopes(): string[];
    get tenant(): string | undefined;
    /**
     * Monta a URL de autorização para redirecionar o usuário.
     *
     * Se um tenant estiver disponível (via `tenantOverride` ou `config.tenant`),
     * usa o atalho `GET /oauth2/<tenant>` do servidor, que resolve o client_id
     * e o redirect_uri automaticamente a partir do tenant cadastrado. Caso
     * contrário, monta a URL tradicional em `/oauth/login` com os parâmetros
     * OAuth2 explícitos.
     */
    getAuthorizationUrl(extra?: Record<string, string>, tenantOverride?: string): {
        url: string;
        state: string;
    };
    /**
     * Busca informações públicas da aplicação (nome, empresa, logos e o
     * `tenantSlug` cadastrado, se houver) a partir do `clientId` configurado.
     * Não requer autenticação. O resultado é cacheado em memória por alguns
     * minutos para não bater na rede a cada chamada.
     */
    getAppInfo(): Promise<AppInfo>;
    /**
     * Lista usuários de todas as aplicações da empresa, usando a chave de API
     * da empresa (`config.companyApiKey`) — não o `clientSecret` da aplicação.
     * Útil quando a mesma empresa tem mais de um tenant/aplicação e você
     * precisa reconhecer usuários independente de qual deles foi usado no login.
     */
    listCompanyUsers(opts?: {
        limit?: number;
        cursor?: string;
    }): Promise<{
        users: CompanyUser[];
        nextCursor: string | null;
    }>;
    /** Busca um usuário específico (por `sub`) em qualquer aplicação da empresa. Retorna `null` se não encontrado. */
    getCompanyUser(sub: string): Promise<CompanyUser | null>;
    private _requireCompanyApiKey;
    exchangeCode(code: string, codeVerifier?: string): Promise<TokenSet>;
    refreshToken(refreshToken: string): Promise<TokenSet>;
    revokeToken(token: string, hint?: 'access_token' | 'refresh_token'): Promise<void>;
    getUserInfo(accessToken: string): Promise<AuthenticatedUser>;
    decodeToken(accessToken: string): TokenPayload;
    isTokenExpired(accessToken: string): boolean;
    private _tokenRequest;
    private _fetch;
}

export { PrimeAuth as P };
