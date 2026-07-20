export { P as PrimeAuth } from './client-YpXX40Lg.mjs';
export { A as AuthenticatedUser, P as PrimeAuthConfig, S as SessionData, T as TokenPayload, b as TokenSet, U as UserInfo } from './types-04ermxwR.mjs';

type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent';
/**
 * Configura o comportamento de log da biblioteca.
 *
 * @example
 * import { configureLogger } from 'prime-auth'
 *
 * // Silenciar todos os logs
 * configureLogger({ level: 'silent' })
 *
 * // Mostrar logs de debug
 * configureLogger({ level: 'debug' })
 *
 * // Integrar com seu próprio logger (ex: Pino, Winston)
 * configureLogger({
 *   fn: (level, message, context) => myLogger[level]({ ...context }, message),
 * })
 */
declare function configureLogger(opts: {
    level?: LogLevel;
    fn?: (level: LogLevel, message: string, context?: Record<string, unknown>) => void;
}): void;

/** Gera um code_verifier aleatório para PKCE */
declare function generateCodeVerifier(): string;
/** Gera o code_challenge S256 a partir do verifier */
declare function generateCodeChallenge(verifier: string): string;
/** Gera um state aleatório para proteção CSRF */
declare function generateState(): string;

/**
 * Extrai o primeiro rótulo de um hostname como tenant, quando existe subdomínio.
 * Ex.: "acme.meuapp.com" → "acme". Retorna undefined para hosts sem subdomínio
 * (ex.: "meuapp.com", "localhost") ou para subdomínios comuns não relacionados
 * a tenant (ex.: "www").
 *
 * Heurística simples baseada em contagem de rótulos — não lida com domínios
 * multi-nível como "meuapp.co.uk" (trataria "meuapp" como tenant de "co.uk").
 */
declare function extractTenantFromHost(hostname: string): string | undefined;

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

export { InsufficientScopeError, InvalidTokenError, type LogLevel, PrimeAuthError, ServerError, TokenExpiredError, configureLogger, extractTenantFromHost, generateCodeChallenge, generateCodeVerifier, generateState };
