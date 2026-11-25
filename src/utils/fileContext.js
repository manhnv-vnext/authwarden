import fs from 'fs';

/**
 * Shared per-file context: every engine reads a file through here so the
 * content is loaded and split once per scan instead of once per engine.
 */

const textCache = new WeakMap();
const linesCache = new WeakMap();
const maskedCache = new WeakMap();

/** Returns file content, or null when unreadable. Cached per file object. */
export function readText(file) {
  if (textCache.has(file)) return textCache.get(file);
  let content = null;
  try {
    content = fs.readFileSync(file.path, 'utf8');
  } catch {
    content = null;
  }
  textCache.set(file, content);
  return content;
}

export function getLines(file) {
  if (linesCache.has(file)) return linesCache.get(file);
  const content = readText(file);
  const lines = content === null ? [] : content.split('\n');
  linesCache.set(file, lines);
  return lines;
}

/** Lines with comments removed (string literals preserved). Cached per file object. */
export function getCodeLines(file) {
  if (maskedCache.has(file)) return maskedCache.get(file);
  const masked = maskComments(getLines(file), file.ext);
  maskedCache.set(file, masked);
  return masked;
}

const TEST_SEGMENT = /(?:^|\/)(?:[^/]*[._-])?(?:tests?|__tests__)\//i;

/** True when a path sits inside a test directory (segment match, not substring). */
export function isTestPath(relPath) {
  return TEST_SEGMENT.test((relPath || '').replace(/\\/g, '/'));
}

const HASH_COMMENT_EXTS = new Set(['.py', '.rb', '.sh', '.yml', '.yaml', '.tf', '.php']);
const SLASH_COMMENT_EXTS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.cs', '.java', '.go', '.php', '.dart', '.kt', '.swift', '.rs'
]);

/**
 * Removes line and block comments while leaving string literals intact, so a
 * URL such as "https://host" is never mistaken for a comment.
 */
export function maskComments(lines, ext = '.js') {
  const e = (ext || '').toLowerCase();
  const slash = SLASH_COMMENT_EXTS.has(e);
  const hash = HASH_COMMENT_EXTS.has(e);
  const out = [];
  let inBlock = false;
  let inTemplate = false; // backtick strings may span lines

  for (const line of lines) {
    let result = '';
    let quote = inTemplate ? '`' : null;
    let i = 0;

    while (i < line.length) {
      const ch = line[i];
      const next = line[i + 1];

      if (inBlock) {
        if (ch === '*' && next === '/') {
          inBlock = false;
          i += 2;
        } else {
          i++;
        }
        continue;
      }

      if (quote) {
        result += ch;
        if (ch === '\\' && next !== undefined) {
          result += next;
          i += 2;
          continue;
        }
        if (ch === quote) quote = null;
        i++;
        continue;
      }

      if (ch === '"' || ch === "'" || (ch === '`' && slash)) {
        quote = ch;
        result += ch;
        i++;
        continue;
      }

      if (slash && ch === '/' && next === '*') {
        inBlock = true;
        i += 2;
        continue;
      }

      if (slash && ch === '/' && next === '/') {
        const prev = line[i - 1];
        // "\/\/" is an escaped regex slash, "://" is a bare URL: neither starts a comment
        if (prev !== '\\' && prev !== ':') break;
      }

      if (hash && ch === '#') break;

      result += ch;
      i++;
    }

    inTemplate = quote === '`';
    out.push(result);
  }

  return out;
}
