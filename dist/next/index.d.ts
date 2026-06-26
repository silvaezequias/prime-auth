import { NextRequest, NextResponse } from 'next/server';
import { P as PrimeAuth } from '../client-BkdewWL6.js';
import { N as NextHandlersOptions, A as AuthenticatedUser, M as MiddlewareOptions } from '../types-CK3Pypy4.js';
export { P as PrimeAuthConfig, S as SessionData, T as TokenPayload, b as TokenSet, U as UserInfo } from '../types-CK3Pypy4.js';

declare function createHandlers(auth: PrimeAuth, opts?: NextHandlersOptions): {
    GET: (request: NextRequest) => Promise<NextResponse<unknown>>;
};
declare function createLoginHandler(auth: PrimeAuth): {
    GET: (request: NextRequest) => NextResponse<unknown>;
};
declare function createCallbackHandler(auth: PrimeAuth, opts?: NextHandlersOptions): {
    GET: (request: NextRequest) => Promise<NextResponse<unknown>>;
};
declare function createLogoutHandler(auth: PrimeAuth, opts?: {
    redirectTo?: string;
}): {
    GET: (request: NextRequest) => NextResponse<unknown>;
};
declare function createMeHandler(auth: PrimeAuth): {
    GET: (request: NextRequest) => Promise<NextResponse<null> | NextResponse<AuthenticatedUser>>;
};

declare function createMiddleware(auth: PrimeAuth, opts?: MiddlewareOptions): (request: NextRequest) => NextResponse<unknown>;

declare function getUser(auth: PrimeAuth): Promise<AuthenticatedUser | null>;
declare function requireUser(auth: PrimeAuth, loginPath?: string): Promise<AuthenticatedUser>;

export { AuthenticatedUser, MiddlewareOptions, NextHandlersOptions, createCallbackHandler, createHandlers, createLoginHandler, createLogoutHandler, createMeHandler, createMiddleware, getUser, requireUser };
