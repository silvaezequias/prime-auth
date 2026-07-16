/**
 * Cliente JS puro (sem build) para consumir o endpoint /auth/me exposto pelo
 * router Express do prime-auth (ver src/express/router.ts).
 *
 * Uso em um HTML:
 *
 * <script type="module">
 *   import { getCurrentUser, redirectToLogin, logout } from './auth-client.js'
 *
 *   const user = await getCurrentUser()
 *   if (!user) {
 *     redirectToLogin()
 *   } else {
 *     document.querySelector('#nome').textContent = user.name
 *   }
 * </script>
 */

/**
 * Busca o usuário autenticado na sessão atual.
 * Retorna `null` se não houver sessão válida.
 *
 * @param {string} mePath - rota do endpoint que retorna o usuário (padrão: /auth/me)
 * @returns {Promise<object|null>}
 */
export async function getCurrentUser(mePath = '/auth/me') {
  try {
    const res = await fetch(mePath, { credentials: 'same-origin' })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

/**
 * Redireciona o navegador para o fluxo de login.
 * Preserva a URL atual em `returnTo` para retornar após o login.
 *
 * @param {string} loginPath - rota de login (padrão: /auth/login)
 */
export function redirectToLogin(loginPath = '/auth/login') {
  const returnTo = encodeURIComponent(window.location.pathname + window.location.search)
  window.location.href = `${loginPath}?returnTo=${returnTo}`
}

/**
 * Redireciona o navegador para o fluxo de logout.
 *
 * @param {string} logoutPath - rota de logout (padrão: /auth/logout)
 */
export function logout(logoutPath = '/auth/logout') {
  window.location.href = logoutPath
}
