export { P as PrimeAuth } from './client-BkdewWL6.js';
export { A as AuthenticatedUser, P as PrimeAuthConfig, S as SessionData, T as TokenPayload, b as TokenSet, U as UserInfo } from './types-CK3Pypy4.js';

/** Gera um code_verifier aleatório para PKCE */
declare function generateCodeVerifier(): string;
/** Gera o code_challenge S256 a partir do verifier */
declare function generateCodeChallenge(verifier: string): string;
/** Gera um state aleatório para proteção CSRF */
declare function generateState(): string;

declare class PrimeAuthError extends Error {
    readonly code: string;
    readonly status?: number | undefined;
    readonly detail?: unknown | undefined;
    constructor(message: string, code: string, status?: number | undefined, detail?: unknown | undefined);
}
declare class TokenExpiredError extends PrimeAuthError {
    constructor();
}
declare class InvalidTokenError extends PrimeAuthError {
    constructor(detail?: string);
}
declare class InsufficientScopeError extends PrimeAuthError {
    constructor(required: string[]);
}
declare class ServerError extends PrimeAuthError {
    constructor(message: string, status: number, detail?: unknown);
}

export { InsufficientScopeError, InvalidTokenError, PrimeAuthError, ServerError, TokenExpiredError, generateCodeChallenge, generateCodeVerifier, generateState };
