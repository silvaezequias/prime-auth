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

### Usar o usuário em uma página HTML pura (sem framework)

Para páginas HTML servidas pelo próprio Express (sem Next.js), use o cliente JS em [`src/auth-client.js`](src/auth-client.js), que consome o endpoint `GET /auth/me`. Como é um módulo sem build, copie-o para a pasta de arquivos estáticos do seu projeto (ex.: `public/auth-client.js`) — `node_modules` normalmente não fica acessível pelo navegador:

```bash
cp node_modules/prime-auth/src/auth-client.js public/auth-client.js
```

```html
<script type="module">
  import { getCurrentUser, redirectToLogin, logout } from '/auth-client.js'

  const user = await getCurrentUser()
  if (!user) {
    redirectToLogin() // manda para /auth/login preservando a URL atual
  } else {
    document.querySelector('#nome').textContent = user.name
  }
</script>
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

## Login por tenant

O servidor Autenticação Prime permite cadastrar um **tenant** (identificador único) para uma aplicação, junto com uma **URI de redirecionamento padrão**. Com isso, em vez de montar a URL de autorização manualmente (`client_id`, `redirect_uri`, `scope`...), basta indicar o tenant e a biblioteca usa o atalho `GET /oauth2/<tenant>` do servidor, que resolve tudo automaticamente.

> **Importante:** o `redirectUri` configurado no `new PrimeAuth({ ... })` precisa ser **exatamente igual** à "URI de redirecionamento padrão" cadastrada para esse tenant no painel do servidor — é ela que será usada na troca do `code` por tokens em `/auth/callback`.

### Tenant fixo (uma instância = um tenant)

```ts
export const auth = new PrimeAuth({
  clientId:     process.env.PRIME_AUTH_CLIENT_ID!,
  clientSecret: process.env.PRIME_AUTH_CLIENT_SECRET!,
  redirectUri:  'http://localhost:3000/auth/callback',
  tenant:       'minha-empresa', // usa /oauth2/minha-empresa em vez de /oauth/login
})
```

### Tenant dinâmico por link

Sem precisar fixar o tenant na instância, passe `?tenant=` na própria rota de login — útil quando o mesmo app serve mais de um tenant e o link muda por página/contexto:

```tsx
<a href="/auth/login?tenant=minha-empresa">Entrar</a>
```

### Tenant dinâmico por subdomínio

Habilite `tenantFromSubdomain` para que, na ausência de `?tenant=`, o tenant seja extraído automaticamente do subdomínio da requisição (ex.: `minha-empresa.meuapp.com` → `minha-empresa`; hosts sem subdomínio como `meuapp.com` ou `localhost` não geram tenant):

```ts
// Next.js
export const { GET } = createHandlers(auth, {
  successRedirect: '/dashboard',
  tenantFromSubdomain: true,
})
```

```ts
// Express
app.use(createRouter(auth, {
  successRedirect: '/dashboard',
  tenantFromSubdomain: true,
}))
```

### Tenant automático (descoberto do servidor)

Se o `clientId` da sua aplicação já tem um tenant cadastrado no painel do servidor, mas você não quer duplicar esse valor numa env var (e nem depende de subdomínio), habilite `autoTenant`: na ausência de `?tenant=`/subdomínio/config, a biblioteca busca o tenant automaticamente via `auth.getAppInfo()` (com cache de alguns minutos):

```ts
// Next.js
export const { GET } = createHandlers(auth, {
  successRedirect: '/dashboard',
  autoTenant: true,
})
```

```ts
// Express
app.use(createRouter(auth, {
  successRedirect: '/dashboard',
  autoTenant: true,
}))
```

Ordem de resolução completa: `?tenant=` na URL de login → subdomínio (`tenantFromSubdomain`) → `tenant` fixo no config → `autoTenant` (busca no servidor). Se nenhuma fonte resolver um tenant (ou se `getAppInfo()` falhar), a biblioteca volta ao fluxo tradicional (`/oauth/login?client_id=...`), sem quebrar quem não usa tenants.

Você também pode chamar `auth.getAppInfo()` diretamente quando precisar dos dados da aplicação (nome, empresa, logos, tenant):

```ts
const info = await auth.getAppInfo()
// { appId, appName, companyName, companyLogoUrl, appLogoUrl, tenantSlug }
```

---

## Chave de API da empresa (usuários entre tenants)

Cada tenant corresponde a uma aplicação diferente no servidor (client_id/secret próprios) — então, se a sua empresa tiver mais de um tenant, não dá para usar o `clientSecret` de uma aplicação para enxergar usuários de outra. Para isso existe a **chave de API da empresa**: um segredo à parte, gerado na página da empresa no painel do servidor, que dá acesso de leitura aos usuários de **todas** as aplicações daquela empresa — independente de qual tenant foi usado no login.

```ts
export const auth = new PrimeAuth({
  clientId:      process.env.PRIME_AUTH_CLIENT_ID!,
  clientSecret:  process.env.PRIME_AUTH_CLIENT_SECRET!,
  redirectUri:   'http://localhost:3000/auth/callback',
  companyApiKey: process.env.PRIME_AUTH_COMPANY_API_KEY, // opcional
})

const { users, nextCursor } = await auth.listCompanyUsers({ limit: 50 })
const user = await auth.getCompanyUser(someSub) // null se não encontrado
```

`companyApiKey` é opcional — só é exigida (erro de config) quando `listCompanyUsers`/`getCompanyUser` são chamados sem ela configurada. Não confunda com `clientSecret`: uma é por aplicação (login/token), a outra é por empresa (leitura entre aplicações).

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
| `tenant` | `string` | — | Tenant padrão — usa o atalho `/oauth2/<tenant>` para montar o link de login. Veja [Login por tenant](#login-por-tenant) |
| `companyApiKey` | `string` | — | Chave de API da empresa. Veja [Chave de API da empresa](#chave-de-api-da-empresa-usuários-entre-tenants) |

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
| `AppInfo` | Retorno de `getAppInfo()` |
| `CompanyUser` | Item retornado por `listCompanyUsers()` / `getCompanyUser()` |

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
