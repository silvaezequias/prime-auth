export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent'

const LEVELS: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3, silent: 4 }

const COLORS = {
  debug: '\x1b[36m', // ciano
  info:  '\x1b[32m', // verde
  warn:  '\x1b[33m', // amarelo
  error: '\x1b[31m', // vermelho
  reset: '\x1b[0m',
}

const PREFIX = '[prime-auth]'

// Nível padrão: 'info' em dev, 'warn' em produção
let currentLevel: LogLevel =
  process.env['NODE_ENV'] === 'production' ? 'warn' : 'info'

// Função de log customizável pelo usuário
let customFn: ((level: LogLevel, message: string, context?: Record<string, unknown>) => void) | null = null

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
export function configureLogger(opts: {
  level?: LogLevel
  fn?: (level: LogLevel, message: string, context?: Record<string, unknown>) => void
}) {
  if (opts.level !== undefined) currentLevel = opts.level
  if (opts.fn   !== undefined) customFn = opts.fn
}

export function log(
  level: Exclude<LogLevel, 'silent'>,
  message: string,
  context?: Record<string, unknown>,
) {
  if (LEVELS[level] < LEVELS[currentLevel]) return

  if (customFn) {
    customFn(level, message, context)
    return
  }

  const color  = COLORS[level]
  const reset  = COLORS.reset
  const label  = `${color}${PREFIX}[${level.toUpperCase()}]${reset}`
  const output = context ? `${message} ${JSON.stringify(context)}` : message

  if (level === 'error') console.error(label, output)
  else if (level === 'warn')  console.warn(label, output)
  else if (level === 'debug') console.debug(label, output)
  else                         console.info(label, output)
}
