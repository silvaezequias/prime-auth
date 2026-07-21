export { P as PrimeAuth } from './client-CB-GK9C8.mjs';
export { b as AppInfo, A as AuthenticatedUser, C as CompanyUser, P as PrimeAuthConfig, S as SessionData, T as TokenPayload, c as TokenSet, U as UserInfo } from './types-BTzC6no2.mjs';

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
 *
 * Caso especial: "tenant.localhost" (dev local, ex.: `teste.localhost:3000`)
 * só tem 2 rótulos, não 3+ como em produção — mas ainda é um host de tenant
 * válido, então é tratado à parte para que testes locais de multi-tenant
 * funcionem igual a produção.
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
