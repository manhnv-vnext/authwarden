/**
 * Zero-dependency ANSI terminal color styling.
 * Respects NO_COLOR env variable and non-interactive TTY environments.
 */

const isColorSupported = !process.env.NO_COLOR && (process.stdout.isTTY || process.env.FORCE_COLOR);

const code = (open, close) => isColorSupported ? (str) => `\x1b[${open}m${str}\x1b[${close}m` : (str) => String(str);

export const colors = {
  reset: code(0, 0),
  bold: code(1, 22),
  dim: code(2, 22),
  italic: code(3, 23),
  underline: code(4, 24),
  inverse: code(7, 27),

  black: code(30, 39),
  red: code(31, 39),
  green: code(32, 39),
  yellow: code(33, 39),
  blue: code(34, 39),
  magenta: code(35, 39),
  cyan: code(36, 39),
  white: code(37, 39),
  gray: code(90, 39),

  bgRed: code(41, 49),
  bgGreen: code(42, 49),
  bgYellow: code(43, 49),
  bgBlue: code(44, 49),
  bgMagenta: code(45, 49),
  bgCyan: code(46, 49),
  bgWhite: code(47, 49)
};

export const badge = (text, bgFn, fgFn = colors.bold) => fgFn(bgFn(` ${text} `));
