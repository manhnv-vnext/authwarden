import fs from 'fs';

/**
 * Shared per-file context: every engine reads a file through here so the
 * content is loaded, split and masked once per scan instead of once per engine.
 *
 * Three aligned views of a file are available (same length, same line breaks):
 *   content  - the raw text
 *   code     - comments replaced by spaces
 *   skeleton - comments and the *contents* of string / template / regex literals
 *              replaced by spaces (quotes and structure kept)
 * Because offsets line up, a position found in one view can be read in another.
 */

const textCache = new WeakMap();
const linesCache = new WeakMap();
const maskCache = new WeakMap();
const codeLinesCache = new WeakMap();
const skeletonLinesCache = new WeakMap();

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

function getMasked(file) {
  if (maskCache.has(file)) return maskCache.get(file);
  const content = readText(file);
  const masked = content === null ? { code: '', skeleton: '' } : maskSource(content, file.ext);
  maskCache.set(file, masked);
  return masked;
}

/** Source with comments blanked. Same length as the raw content. */
export function getCode(file) {
  return getMasked(file).code;
}

/** Source with comments and literal contents blanked. Same length as the raw content. */
export function getSkeleton(file) {
  return getMasked(file).skeleton;
}

/** Lines with comments removed (string literals preserved). Cached per file object. */
export function getCodeLines(file) {
  if (!codeLinesCache.has(file)) codeLinesCache.set(file, getCode(file).split('\n'));
  return codeLinesCache.get(file);
}

/** Lines with comments and literal contents removed. Cached per file object. */
export function getSkeletonLines(file) {
  if (!skeletonLinesCache.has(file)) skeletonLinesCache.set(file, getSkeleton(file).split('\n'));
  return skeletonLinesCache.get(file);
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
const JS_EXTS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

// A "/" after one of these starts a regex literal rather than a division
const REGEX_PRECEDERS = new Set(['', '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '~', '^']);
const REGEX_KEYWORDS = new Set(['return', 'typeof', 'case', 'in', 'of', 'void', 'delete', 'throw', 'new', 'do', 'else', 'yield', 'await']);

/**
 * Produces the `code` and `skeleton` views of a source text.
 * Understands line / block comments, quoted strings, JS template literals
 * (including `${}` expressions), JS regex literals, Python triple-quoted
 * strings and C# verbatim strings. Unterminated single-line strings end at the
 * line break, so prose such as JSX text with an apostrophe cannot swallow the file.
 */
export function maskSource(content, ext = '.js') {
  const e = (ext || '').toLowerCase();
  const slash = SLASH_COMMENT_EXTS.has(e);
  const hash = HASH_COMMENT_EXTS.has(e);
  const jsLike = JS_EXTS.has(e);
  const python = e === '.py';
  const csharp = e === '.cs';

  const n = content.length;
  const code = content.split('');
  const skel = content.split('');
  const blank = (arr, from, to) => {
    for (let k = from; k < to && k < n; k++) if (arr[k] !== '\n' && arr[k] !== '\r') arr[k] = ' ';
  };

  // Context stack: 'code' frames track brace depth so a template's ${ } can be closed
  const stack = [{ type: 'code', depth: 0 }];
  let lastSig = '';
  let lastWord = '';
  let i = 0;

  while (i < n) {
    const ctx = stack[stack.length - 1];
    const ch = content[i];
    const next = content[i + 1];

    if (ctx.type === 'template') {
      if (ch === '\\') { blank(skel, i, i + 2); i += 2; continue; }
      if (ch === '`') { stack.pop(); lastSig = '`'; i++; continue; }
      if (ch === '$' && next === '{') { stack.push({ type: 'code', depth: 0 }); lastSig = '{'; i += 2; continue; }
      blank(skel, i, i + 1);
      i++;
      continue;
    }

    // ---- comments ----
    if (slash && ch === '/' && next === '/') {
      const prev = content[i - 1];
      const isUrl = prev === ':' && /[A-Za-z]/.test(content[i - 2] || '');
      if (!isUrl) {
        let end = content.indexOf('\n', i);
        if (end === -1) end = n;
        blank(code, i, end);
        blank(skel, i, end);
        i = end;
        continue;
      }
    }
    if (slash && ch === '/' && next === '*') {
      let end = content.indexOf('*/', i + 2);
      end = end === -1 ? n : end + 2;
      blank(code, i, end);
      blank(skel, i, end);
      i = end;
      continue;
    }
    if (hash && ch === '#' && !(e === '.php' && next === '[')) {
      let end = content.indexOf('\n', i);
      if (end === -1) end = n;
      blank(code, i, end);
      blank(skel, i, end);
      i = end;
      continue;
    }

    // ---- strings ----
    if (python && (ch === '"' || ch === "'") && next === ch && content[i + 2] === ch) {
      const close = content.indexOf(ch.repeat(3), i + 3);
      const end = close === -1 ? n : close;
      blank(skel, i + 3, end);
      i = close === -1 ? n : close + 3;
      lastSig = ch;
      continue;
    }
    if (csharp && ch === '"' && content[i - 1] === '@') {
      let j = i + 1;
      while (j < n) {
        if (content[j] === '"') {
          if (content[j + 1] === '"') { j += 2; continue; }
          break;
        }
        j++;
      }
      blank(skel, i + 1, j);
      i = j + 1;
      lastSig = '"';
      continue;
    }
    if (ch === '"' || ch === "'") {
      let j = i + 1;
      while (j < n && content[j] !== ch && content[j] !== '\n') {
        if (content[j] === '\\') j++;
        j++;
      }
      blank(skel, i + 1, Math.min(j, n));
      i = content[j] === ch ? j + 1 : j;
      lastSig = ch;
      continue;
    }
    if (jsLike && ch === '`') {
      stack.push({ type: 'template' });
      i++;
      continue;
    }

    // ---- JS regex literals ----
    if (jsLike && ch === '/' && (REGEX_PRECEDERS.has(lastSig) || REGEX_KEYWORDS.has(lastWord))) {
      let j = i + 1;
      let inClass = false;
      let closed = false;
      while (j < n && content[j] !== '\n') {
        const c = content[j];
        if (c === '\\') { j += 2; continue; }
        if (c === '[') inClass = true;
        else if (c === ']') inClass = false;
        else if (c === '/' && !inClass) { closed = true; break; }
        j++;
      }
      if (closed) {
        blank(skel, i + 1, j);
        i = j + 1;
        lastSig = '/';
        lastWord = '';
        continue;
      }
    }

    // ---- plain code ----
    if (ch === '{') ctx.depth++;
    else if (ch === '}') {
      if (ctx.depth === 0 && stack.length > 1) {
        stack.pop(); // end of a template ${ } expression
        i++;
        continue;
      }
      ctx.depth--;
    }

    if (/\s/.test(ch)) {
      // whitespace does not change what precedes a possible regex
    } else if (/[A-Za-z0-9_$]/.test(ch)) {
      const prev = content[i - 1];
      lastWord = /[A-Za-z0-9_$]/.test(prev || '') ? lastWord + ch : ch;
      lastSig = ch;
    } else {
      lastSig = ch;
      lastWord = '';
    }
    i++;
  }

  return { code: code.join(''), skeleton: skel.join('') };
}

/**
 * Line-array form of the `code` view, kept for callers that work on lines.
 */
export function maskComments(lines, ext = '.js') {
  return maskSource(lines.join('\n'), ext).code.split('\n');
}
