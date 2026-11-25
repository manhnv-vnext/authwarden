import path from 'path';
import { readText } from '../utils/fileContext.js';

/**
 * Project-wide authentication context.
 *
 * Route handlers are often protected one level up (a Next.js middleware, an
 * ASP.NET fallback policy, a Spring SecurityFilterChain) rather than in the
 * handler itself. This pass finds those upstream guards once per scan so the
 * per-file route checks do not report already-protected routes.
 */

// Stricter than the per-route auth signals: used for app.use()/router.use() guards, where
// generic words such as "session" (express-session) or "token" must not count as auth.
export const UPSTREAM_AUTH_MIDDLEWARE = /\b(?:require|ensure|verify|check|validate|is)_?(?:auth\w*|login|logged\w*|user|admin|token|jwt|session|role\w*|signed\w*)\b|\bauthenticate\w*\b|\bauth(?:Middleware|Guard|Required|orize\w*|enticated)?\b|\bprotect(?:ed)?\b|\bjwt(?:Check|Auth|Middleware)\b|\bexpressjwt\b|\bclerkMiddleware\b|\brequiresAuth\b|\bdeny(?:All|Access)\b|passport\.authenticate/i;

const JS_EXTS = new Set(['.js', '.ts', '.mjs', '.cjs']);

/**
 * Finds router modules that are mounted behind auth in another file:
 *   app.use(requireAuth); app.use(adminRouter);
 *   app.use('/admin', requireAuth, adminRouter);
 * Returns Map(relative path of the router module -> evidence string).
 */
function collectExpressMountGuards(files) {
  const guards = new Map();
  const known = new Set(files.map(f => f.relative.replace(/\\/g, '/')));
  const resolve = (fromRel, spec) => {
    const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromRel), spec));
    return [base, base + '.js', base + '.ts', base + '.mjs', base + '.cjs', base + '/index.js', base + '/index.ts'].find(c => known.has(c)) || null;
  };

  for (const file of files) {
    if (!JS_EXTS.has(file.ext)) continue;
    const content = readText(file);
    if (!content || !content.includes('.use(')) continue;
    const rel = file.relative.replace(/\\/g, '/');

    const imports = new Map();
    for (const m of content.matchAll(/\b(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['"](\.[^'"]+)['"]\s*\)/g)) imports.set(m[1], m[2]);
    for (const m of content.matchAll(/\bimport\s+(\w+)\s+from\s+['"](\.[^'"]+)['"]/g)) imports.set(m[1], m[2]);
    if (imports.size === 0) continue;

    let globalGuard = false;
    for (const m of content.matchAll(/\b(?:app|router|server)\.use\s*\(([^;\n]*)/g)) {
      const hasPrefix = /^\s*['"`]/.test(m[1]);
      const args = m[1].replace(/(['"`])(?:\\.|(?!\1).)*\1/g, ''); // drop string literals such as '/auth'
      const mounted = [...imports.keys()].filter(v => new RegExp('\\b' + v + '\\b').test(args));
      if (mounted.length === 0) {
        if (!hasPrefix && UPSTREAM_AUTH_MIDDLEWARE.test(args)) globalGuard = true;
        continue;
      }
      let rest = args;
      mounted.forEach(v => { rest = rest.replace(new RegExp('\\b' + v + '\\b', 'g'), ''); });
      const inline = UPSTREAM_AUTH_MIDDLEWARE.test(rest);
      if (!inline && !globalGuard) continue;
      for (const v of mounted) {
        const target = resolve(rel, imports.get(v));
        if (target) guards.set(target, inline ? `auth middleware where the router is mounted (${rel})` : `app.use(auth) before the router is mounted (${rel})`);
      }
    }
  }
  return guards;
}

const NEXT_MIDDLEWARE_FILE = /(?:^|\/)(?:src\/)?(?:middleware|proxy)\.(?:ts|js|mjs)$/;
const NEXT_MIDDLEWARE_AUTH = /\bauth\b|getToken|getServerSession|clerkMiddleware|withAuth|\bsession\b|\bjwt|verifyToken|updateSession/i;

export function buildProjectAuthContext(files = []) {
  const ctx = {
    nextMiddlewares: [],
    aspnetFallbackAuth: null,
    aspnetControllerAuth: null,
    springGlobalAuth: null,
    expressMountGuards: collectExpressMountGuards(files)
  };

  for (const file of files) {
    const rel = file.relative.replace(/\\/g, '/');

    if (NEXT_MIDDLEWARE_FILE.test(rel) && !rel.includes('app/api/')) {
      const content = readText(file);
      if (content && NEXT_MIDDLEWARE_AUTH.test(content)) {
        const dir = path.posix.dirname(rel).replace(/(?:^|\/)src$/, '');
        ctx.nextMiddlewares.push({
          file: rel,
          baseDir: dir === '.' ? '' : dir,
          matchers: parseNextMatchers(content)
        });
      }
    }

    if (file.ext === '.cs') {
      const content = readText(file);
      if (!content) continue;
      if (/FallbackPolicy\s*=[\s\S]{0,300}?RequireAuthenticatedUser/.test(content)) {
        ctx.aspnetFallbackAuth = rel;
      }
      if (/MapControllers\s*\(\s*\)\s*\.RequireAuthorization\s*\(|new\s+AuthorizeFilter\s*\(/.test(content)) {
        ctx.aspnetControllerAuth = rel;
      }
    }

    if (file.ext === '.java' || file.ext === '.kt') {
      const content = readText(file);
      if (content && /anyRequest\s*\(\s*\)\s*\.authenticated\s*\(/.test(content)) {
        ctx.springGlobalAuth = rel;
      }
    }
  }

  return ctx;
}

/** Extracts the string entries of `export const config = { matcher: ... }`. */
export function parseNextMatchers(content) {
  const m = content.match(/\bmatcher\s*:\s*(\[[\s\S]*?\]|['"`][^'"`]+['"`])/);
  if (!m) return null; // no matcher: middleware runs on every route
  const entries = [...m[1].matchAll(/['"`]([^'"`]+)['"`]/g)].map(x => x[1]);
  return entries.length ? entries : null;
}

/** True when a Next.js matcher pattern applies to the given URL path. */
export function nextMatcherCovers(matcher, routeUrl) {
  const negative = matcher.match(/^(.*?)\(\(\?!([^)]*)\)/);
  if (negative) {
    const prefix = negative[1];
    if (!routeUrl.startsWith(prefix)) return false;
    const rest = routeUrl.slice(prefix.length);
    return !negative[2].split('|').some(ex => ex && rest.startsWith(ex));
  }
  const prefix = matcher.split(/[:(*]/)[0].replace(/\/$/, '');
  if (prefix === '') return true;
  return routeUrl === prefix || routeUrl.startsWith(prefix + '/');
}

/** Returns the middleware file guarding a Next.js route, or null. */
export function findNextMiddlewareGuard(project, relPath, routeUrl) {
  for (const mw of project?.nextMiddlewares || []) {
    if (mw.baseDir && !relPath.startsWith(mw.baseDir + '/')) continue;
    if (!mw.matchers || mw.matchers.some(m => nextMatcherCovers(m, routeUrl))) {
      return mw.file;
    }
  }
  return null;
}
