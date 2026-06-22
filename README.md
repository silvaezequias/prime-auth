# prime-auth

Cliente OAuth2 para **Next.js** + servidor **Autenticação Prime**.

Configure apenas as credenciais da sua aplicação — a biblioteca cuida de todo o resto: rotas de login/callback/logout, sessão em cookie, renovação automática de token e dados do usuário (nome, e-mail, avatar) disponíveis tanto em Server Components quanto em Client Components via hook React.

---

## Instalação

```bash
npm install prime-auth
```

---

## Setup rápido (catch-all — recomendado)

### 1. Variável de ambiente

```env
# .env.local
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

### 3. Um único arquivo cria todas as rotas

```ts
// app/auth/[...prime]/route.ts
import { createHandlers } from 'prime-auth/next'
import { auth } from '@/lib/auth'

export const { GET } = createHandlers(auth, {
  successRedirect: '/dashboard',
})
```

Esse arquivo cria automaticamente:

| Rota | O que faz |
|------|-----------|
| `GET /auth/login` | Redireciona o usuário para o servidor de login |
| `GET /auth/callback` | Recebe o code, troca por tokens, salva sessão |
| `GET /auth/logout` | Apaga a sessão e redireciona para `/auth/login` |
| `GET /auth/me` | Retorna o usuário atual em JSON |

### 4. Middleware de proteção

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

---

## Rotas separadas (alternativa ao catch-all)

Se preferir ter um arquivo por rota em vez do catch-all, use os handlers individuais:

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
export const { GET } = createCallbackHandler(auth, { successRedirect: '/dashboard' })
```

```ts
// app/auth/logout/route.ts
import { createLogoutHandler } from 'prime-auth/next'
import { auth } from '@/lib/auth'
export const { GET } = createLogoutHandler(auth)
```

```ts
// app/auth/me/route.ts  (necessário para o UserFetchProvider)
import { createMeHandler } from 'prime-auth/next'
import { auth } from '@/lib/auth'
export const { GET } = createMeHandler(auth)
```

---

## Como funciona o fluxo de callback

O callback é o passo mais importante do OAuth2. Veja o que acontece quando o usuário faz login:

```
1. Usuário acessa /auth/login
        │
        ▼
2. Biblioteca redireciona para o servidor de autenticação:
   https://auth.suaempresa.com/oauth/authorize
     ?response_type=code
     &client_id=xxx
     &redirect_uri=http://localhost:3000/auth/callback
     &scope=openid+profile+email
     &state=<valor aleatório salvo em cookie>
        │
        ▼
3. Usuário digita login e senha no servidor
        │
        ▼
4. Servidor redireciona de volta para sua aplicação:
   http://localhost:3000/auth/callback?code=ABC123&state=<mesmo valor>
        │
        ▼
5. /auth/callback (createCallbackHandler) faz automaticamente:
   a) Valida o state (anti-CSRF)
   b) Troca o code pelo access_token e refresh_token
   c) Busca os dados do usuário (nome, e-mail, avatar)
   d) Salva tudo em cookie httpOnly assinado
   e) Redireciona para /dashboard (ou successRedirect)
        │
        ▼
6. Usuário está logado — req.user e useUser() disponíveis
```

### Callback com hook `onSuccess`

Use `onSuccess` para executar lógica server-side logo após o login — por exemplo, criar ou atualizar o usuário no seu banco de dados:

```ts
// app/auth/callback/route.ts
import { createCallbackHandler } from 'prime-auth/next'
import { auth } from '@/lib/auth'
import { db } from '@/lib/db'

export const { GET } = createCallbackHandler(auth, {
  successRedirect: '/dashboard',

  onSuccess: async (user) => {
    // Cria o usuário no banco se for o primeiro acesso
    await db.user.upsert({
      where:  { sub: user.sub },
      update: { name: user.name, email: user.email, avatar: user.avatar },
      create: {
        sub:      user.sub,
        username: user.username,
        name:     user.name,
        email:    user.email,
        avatar:   user.avatar,
      },
    })
  },
})
```

### Callback com redirect manual

Retorne `false` em `onSuccess` para assumir o controle do redirect (por exemplo, para redirecionar para páginas diferentes dependendo do usuário):

```ts
import { createCallbackHandler } from 'prime-auth/next'
import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import { db } from '@/lib/db'

export const { GET } = createCallbackHandler(auth, {
  onSuccess: async (user) => {
    const dbUser = await db.user.findUnique({ where: { sub: user.sub } })

    // Retornar false impede o redirect automático
    // Mas como onSuccess não recebe req/res, use successRedirect dinâmico
    // ou implemente um handler manual (veja abaixo)
    return false
  },
})
```

Para redirect totalmente customizado, crie o handler manualmente:

```ts
// app/auth/callback/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import { db } from '@/lib/db'

export async function GET(request: NextRequest) {
  const code  = request.nextUrl.searchParams.get('code')
  const error = request.nextUrl.searchParams.get('error')

  if (error || !code) {
    return NextResponse.redirect(new URL('/auth/login?error=true', request.url))
  }

  try {
    // Troca o code pelos tokens
    const tokens = await auth.exchangeCode(code)

    // Busca os dados do usuário
    const user = await auth.getUserInfo(tokens.access_token)

    // Sua lógica de negócio aqui
    const dbUser = await db.user.upsert({
      where:  { sub: user.sub },
      update: { name: user.name },
      create: { sub: user.sub, name: user.name, email: user.email },
    })

    // Cria a resposta redirecionando para onde quiser
    const redirectTo = dbUser.isAdmin ? '/admin' : '/dashboard'
    const res = NextResponse.redirect(new URL(redirectTo, request.url))

    // Salva a sessão no cookie usando o helper da biblioteca
    const { encodeSession } = await import('prime-auth')
    // Ou manual:
    res.cookies.set(auth.cookieName, JSON.stringify({
      accessToken:  tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt:    tokens.expires_at,
    }), {
      httpOnly: true,
      sameSite: 'lax',
      maxAge:   auth.cookieMaxAge,
      path:     '/',
    })

    return res
  } catch (err) {
    console.error('Erro no callback:', err)
    return NextResponse.redirect(new URL('/auth/login?error=callback_failed', request.url))
  }
}
```

---

## Usando o usuário

### Em Server Components

```tsx
// app/dashboard/page.tsx
import { requireUser } from 'prime-auth/next'
import { auth } from '@/lib/auth'

export default async function Dashboard() {
  // Redireciona para /auth/login se não estiver logado
  const user = await requireUser(auth)

  return (
    <div>
      {user.avatar && <img src={user.avatar} alt={user.name} />}
      <h1>Olá, {user.name}!</h1>
      <p>{user.email}</p>
    </div>
  )
}
```

Verificar sem redirecionar:

```tsx
import { getUser } from 'prime-auth/next'

const user = await getUser(auth) // null se não logado
```

### Em Client Components (via `UserProvider`)

Passe o usuário do layout server-side — sem requisição extra do cliente.

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
        <UserProvider user={user}>
          {children}
        </UserProvider>
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
      {user.avatar && <img src={user.avatar} alt={user.name} width={32} height={32} />}
      <span>{user.name}</span>
      <a href="/auth/logout">Sair</a>
    </header>
  )
}
```

---

## O que está em `user`

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

## Renovação automática de tokens

`getUser()` e `requireUser()` renovam o access token automaticamente quando está prestes a expirar (margem de 60s), usando o refresh token salvo no cookie. O usuário não percebe nada.

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

## Build (para contribuidores)

```bash
npm run build      # gera dist/ com CJS + ESM + tipos
npm run dev        # watch mode
npm run typecheck
```

---

## Licença

MIT
