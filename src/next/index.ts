export {
  createHandlers,
  createLoginHandler,
  createCallbackHandler,
  createLogoutHandler,
  createMeHandler,
} from './handlers.js'
export { createMiddleware } from './middleware.js'
export { getUser, requireUser } from './server.js'
export type {
  // Opções dos helpers Next.js
  NextHandlersOptions,
  MiddlewareOptions,
  // Tipos de usuário e sessão — re-exportados para conveniência
  AuthenticatedUser,
  SessionData,
  TokenSet,
  TokenPayload,
  UserInfo,
  PrimeAuthConfig,
  AppInfo,
  CompanyUser,
} from '../types.js'
