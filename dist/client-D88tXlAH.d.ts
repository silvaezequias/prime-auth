import { P as PrimeAuthConfig, a as TokenSet, A as AuthenticatedUser, T as TokenPayload } from './types-CGwq3iVS.js';

declare class PrimeAuth {
    readonly cookieName: string;
    readonly clientSecret: string;
    readonly cookieMaxAge: number;
    private readonly _serverUrl;
    private readonly _clientId;
    private readonly _redirectUri;
    private readonly _scopes;
    private readonly _timeoutMs;
    constructor(config: PrimeAuthConfig);
    get serverUrl(): string;
    get clientId(): string;
    get redirectUri(): string;
    get scopes(): string[];
    getAuthorizationUrl(extra?: Record<string, string>): {
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
