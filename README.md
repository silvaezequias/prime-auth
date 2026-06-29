# prime-auth

Cliente OAuth2 para o servidor **Autenticação Prime**.

Suporta **Next.js** (App Router) e **Express**. Configure apenas as credenciais da aplicação — a biblioteca cuida de tudo: rotas de login/callback/logout, sessão em cookie httpOnly assinado, renovação automática de token e dados do usuário disponíveis onde você precisar.

---

## Instalação

```bash
npm install git@github.com:silvaezequias/prime-auth.git
```

---

## Configuração inicial (igual para os dois frameworks)

### 1. Variável de ambiente

```env
# .env  ou  .env.local
PRIME_AUTH_SERVER_URL=http://localhost:4000
```

### 2. Instância compartilhada

```ts
// lib/auth.ts
import { PrimeAuth } from 'prime-auth'

export const auth = new PrimeAuth({
  clientId:     process.env.PRIME_AUTH_CLIENT_ID!,
  clientSecret: process.env.PRIME_AUTH_CLIENT_SECRET!,
  redirectUri:  'http://localhost:3000/auth/callback',
  // scopes: ['openid', 'profile', 'email'] ← opcional, já é o padrão
})
```

---

## Next.js (App Router)

### Passo 1 — Rotas automáticas

Crie um único arquivo catch-all que registra todas as rotas OAuth2:

```ts
// app/auth/[...prime]/route.ts
import { createHandlers } from 'prime-auth/next'
import { auth } from '@/lib/auth'

export const { GET } = createHandlers(auth, {
  successRedirect: '/dashboard',
})
```

Rotas criadas automaticamente:

| Rota | O que faz |
|------|-----------|
| `GET /auth/login` | Redireciona para o servidor de login |
| `GET /auth/callback` | Troca o code por tokens e salva sessão |
| `GET /auth/logout` | Apaga a sessão |
| `GET /auth/me` | Retorna o usuário atual em JSON |

### Passo 2 — Middleware de proteção

```ts
// middleware.ts (raiz do projeto)
import { createMiddleware } from 'prime-auth/next'
import { auth } from './lib/auth'

export const middleware = createMiddleware(auth, {
  protectedPaths: ['/dashboard', '/settings'],
})

export const config = {
  matcher: ['/dashboard/:path*', '/settings/:path*'],
}
```

### Passo 3 — Usar o usuário

**Em Server Components:**

```tsx
// app/dashboard/page.tsx
import { requireUser } from 'prime-auth/next'
import { auth } from '@/lib/auth'

export default async function Dashboard() {
  const user = await requireUser(auth) // redireciona para /auth/login se não logado
  return <h1>Olá, {user.name}!</h1>
}
```

```tsx
// Verificar sem redirecionar:
import { getUser } from 'prime-auth/next'
const user = await getUser(auth) // retorna null se não logado
```

**Em Client Components (via hook):**

```tsx
// app/layout.tsx  (Server Component)
import { UserProvider } from 'prime-auth/next/client'
import { getUser } from 'prime-auth/next'
import { auth } from '@/lib/auth'

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const user = await getUser(auth)
  return (
    <html lang="pt-BR">
      <body>
        <UserProvider user={user}>{children}</UserProvider>
      </body>
    </html>
  )
}
```

```tsx
// components/Header.tsx  (Client Component)
'use client'
import { useUser } from 'prime-auth/next/client'

export function Header() {
  const { user } = useUser()
  if (!user) return <a href="/auth/login">Entrar</a>
  return (
    <header>
      {user.avatar && <img src={user.avatar} alt={user.name} width={32} />}
      <span>{user.name}</span>
      <a href="/auth/logout">Sair</a>
    </header>
  )
}
```

### Rotas separadas (alternativa ao catch-all)

```ts
// app/auth/login/route.ts
import { createLoginHandler } from 'prime-auth/next'
import { auth } from '@/lib/auth'
export const { GET } = createLoginHandler(auth)
```

```ts
// app/auth/callback/route.ts
import { createCallbackHandler } from 'prime-auth/next'
import { auth } from '@/lib/auth'

export const { GET } = createCallbackHandler(auth, {
  successRedirect: '/dashboard',
  onSuccess: async (user) => {
    // Salve ou atualize o usuário no seu banco de dados
    await db.user.upsert({
      where:  { sub: user.sub },
      update: { name: user.name, email: user.email, avatar: user.avatar },
      create: { sub: user.sub, name: user.name, email: user.email, avatar: user.avatar },
    })
  },
})
```

```ts
// app/auth/logout/route.ts
import { createLogoutHandler } from 'prime-auth/next'
import { auth } from '@/lib/auth'
export const { GET } = createLogoutHandler(auth)
```

```ts
// app/auth/me/route.ts
import { createMeHandler } from 'prime-auth/next'
import { auth } from '@/lib/auth'
export const { GET } = createMeHandler(auth)
```

---

## Express

### Passo 1 — Instalar dependências

```bash
npm install express cookie-parser
npm install -D @types/express @types/cookie-parser
```

### Passo 2 — Montar o router

```ts
// app.ts
import express from 'express'
import cookieParser from 'cookie-parser'
import { createRouter } from 'prime-auth/express'
import { auth } from './lib/auth'

const app = express()
app.use(cookieParser()) // obrigatório — lê os cookies de sessão

// Registra /auth/login, /auth/callback, /auth/logout, /auth/me
app.use(createRouter(auth, {
  successRedirect: '/dashboard',
}))

app.listen(3000)
```

### Passo 3 — Proteger rotas

```ts
import { requireAuth } from 'prime-auth/express'
import { auth } from './lib/auth'

// Redireciona para /auth/login se não estiver logado
app.get('/dashboard', requireAuth(auth), (req, res) => {
  const { username, name, email, avatar } = req.user!
  res.send(`Olá, ${name}!`)
})

// Modo API — retorna JSON 401 em vez de redirecionar
app.get('/api/me', requireAuth(auth, { json: true }), (req, res) => {
  res.json(req.user)
})

// Exige escopos específicos — retorna 403 se faltar
app.get('/api/profile', requireAuth(auth, { scopes: ['profile', 'email'] }), (req, res) => {
  res.json(req.user)
})
```

### Callback com `onSuccess` no Express

```ts
import { createRouter } from 'prime-auth/express'

app.use(createRouter(auth, {
  successRedirect: '/dashboard',
  onSuccess: async (user, req, res) => {
    // Salve o usuário no banco ao fazer login pela primeira vez
    await db.user.upsert({
      where:  { sub: user.sub },
      update: { name: user.name, email: user.email },
      create: { sub: user.sub, name: user.name, email: user.email, avatar: user.avatar },
    })
  },
}))
```

---

## O que está em `user` (igual nos dois frameworks)

```ts
{
  sub:         'abc123',                    // ID único do usuário
  username:    'joao.silva',               // Nome de usuário
  name:        'João Silva',               // Nome completo
  email:       'joao@exemplo.com',         // E-mail
  avatar:      'https://cdn.../foto.jpg',  // URL do avatar
  scope:       'openid profile email',     // Escopos concedidos
  accessToken: 'eyJ...',                  // JWT bruto (uso avançado)
}
```

---

## Como funciona o fluxo de callback

```
1. Usuário acessa /auth/login
        │
        ▼
2. Biblioteca redireciona para o servidor de autenticação
        │
        ▼
3. Usuário digita login e senha
        │
        ▼
4. Servidor redireciona para /auth/callback?code=ABC&state=XYZ
        │
        ▼
5. /auth/callback faz automaticamente:
   a) Valida o state (anti-CSRF)
   b) Troca o code pelo access_token + refresh_token
   c) Busca os dados do usuário (nome, e-mail, avatar)
   d) Chama onSuccess (se configurado)
   e) Salva tudo em cookie httpOnly assinado
   f) Redireciona para successRedirect
        │
        ▼
6. Usuário logado — req.user / getUser() / useUser() disponíveis
```

---

## Renovação automática de tokens

`getUser()` (Next.js) e `requireAuth()` (Express) renovam o access token automaticamente quando está prestes a expirar (margem de 60s), usando o refresh token salvo no cookie. O usuário não percebe nada.

---

## Opções do `new PrimeAuth(config)`

| Parâmetro | Tipo | Obrigatório | Descrição |
|-----------|------|-------------|-----------|
| `clientId` | `string` | ✅ | client_id da aplicação |
| `clientSecret` | `string` | ✅ | client_secret da aplicação |
| `redirectUri` | `string` | ✅ | URI de redirecionamento (`/auth/callback`) |
| `scopes` | `string[]` | — | Escopos (padrão: `['openid', 'profile', 'email']`) |
| `serverUrl` | `string` | — | URL do servidor (padrão: `PRIME_AUTH_SERVER_URL`) |
| `timeoutMs` | `number` | — | Timeout em ms (padrão: `10000`) |
| `cookieName` | `string` | — | Nome do cookie (padrão: `prime_auth_session`) |
| `cookieMaxAge` | `number` | — | Duração da sessão em segundos (padrão: `604800` = 7 dias) |

---

## Tipagens disponíveis

```ts
import type { AuthenticatedUser } from 'prime-auth'
import type { AuthenticatedUser } from 'prime-auth/next'
import type { AuthenticatedUser } from 'prime-auth/next/client'
import type { AuthenticatedUser } from 'prime-auth/express'
```

| Tipo | Descrição |
|------|-----------|
| `AuthenticatedUser` | Dados do usuário logado |
| `PrimeAuthConfig` | Configuração do construtor |
| `TokenSet` | Par de tokens retornado pelo servidor |
| `TokenPayload` | Payload decodificado do JWT |
| `UserInfo` | Resposta bruta do `/oauth/userinfo` |
| `SessionData` | Dados salvos no cookie de sessão |
| `NextHandlersOptions` | Opções do `createHandlers` / `createCallbackHandler` |
| `MiddlewareOptions` | Opções do `createMiddleware` (Next.js) |
| `ExpressRouterOptions` | Opções do `createRouter` (Express) |
| `ExpressRequireAuthOptions` | Opções do `requireAuth` (Express) |

---

## Build (para contribuidores)

```bash
npm run build      # gera dist/ com CJS + ESM + tipos
npm run dev        # watch mode
npm run typecheck
```

---

## Licença

MIT
