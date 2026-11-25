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

const NEXT_MIDDLEWARE_FILE = /(?:^|\/)(?:src\/)?(?:middleware|proxy)\.(?:ts|js|mjs)$/;
const NEXT_MIDDLEWARE_AUTH = /\bauth\b|getToken|getServerSession|clerkMiddleware|withAuth|\bsession\b|\bjwt|verifyToken|updateSession/i;

export function buildProjectAuthContext(files = []) {
  const ctx = {
    nextMiddlewares: [],
    aspnetFallbackAuth: null,
    aspnetControllerAuth: null,
    springGlobalAuth: null
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
