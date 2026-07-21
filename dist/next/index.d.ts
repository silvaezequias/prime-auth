import { NextRequest, NextResponse } from 'next/server';
import { P as PrimeAuth } from '../client-DPad6k_c.js';
import { N as NextHandlersOptions, A as AuthenticatedUser, M as MiddlewareOptions } from '../types-BTzC6no2.js';
export { b as AppInfo, C as CompanyUser, P as PrimeAuthConfig, S as SessionData, T as TokenPayload, c as TokenSet, U as UserInfo } from '../types-BTzC6no2.js';

declare function createHandlers(auth: PrimeAuth, opts?: NextHandlersOptions): {
    GET: (request: NextRequest) => Promise<NextResponse<unknown>>;
};
declare function createLoginHandler(auth: PrimeAuth, opts?: NextHandlersOptions): {
    GET: (request: NextRequest) => Promise<NextResponse<unknown>>;
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
