import { P as PrimeAuthConfig, b as TokenSet, A as AuthenticatedUser, T as TokenPayload } from './types-04ermxwR.js';

declare class PrimeAuth {
    readonly cookieName: string;
    readonly clientSecret: string;
    readonly cookieMaxAge: number;
    private readonly _serverUrl;
    private readonly _clientId;
    private readonly _redirectUri;
    private readonly _scopes;
    private readonly _timeoutMs;
    private readonly _tenant;
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
