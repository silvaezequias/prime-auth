// src/logger.ts
var LEVELS = { debug: 0, info: 1, warn: 2, error: 3, silent: 4 };
var COLORS = {
  debug: "\x1B[36m",
  // ciano
  info: "\x1B[32m",
  // verde
  warn: "\x1B[33m",
  // amarelo
  error: "\x1B[31m",
  // vermelho
  reset: "\x1B[0m"
};
var PREFIX = "[prime-auth]";
var currentLevel = process.env["NODE_ENV"] === "production" ? "warn" : "info";
var customFn = null;
function configureLogger(opts) {
  if (opts.level !== void 0) currentLevel = opts.level;
  if (opts.fn !== void 0) customFn = opts.fn;
}
function log(level, message, context) {
  if (LEVELS[level] < LEVELS[currentLevel]) return;
  if (customFn) {
    customFn(level, message, context);
    return;
  }
  const color = COLORS[level];
  const reset = COLORS.reset;
  const label = `${color}${PREFIX}[${level.toUpperCase()}]${reset}`;
  const output = context ? `${message} ${JSON.stringify(context)}` : message;
  if (level === "error") console.error(label, output);
  else if (level === "warn") console.warn(label, output);
  else if (level === "debug") console.debug(label, output);
  else console.info(label, output);
}

export {
  configureLogger,
  log
};
