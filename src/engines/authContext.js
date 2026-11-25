import path from 'path';
import { getCode, getSkeleton } from '../utils/fileContext.js';

/**
 * Project-wide authentication context.
 *
 * Route handlers are often protected one level up (a Next.js middleware, an
 * ASP.NET fallback policy, a Spring SecurityFilterChain, an Express mount)
 * rather than in the handler itself. This pass finds those upstream guards
 * once per scan so the per-file route checks do not report protected routes.
 *
 * Safety rule: a guard is only recognised from identifiers in real code. All
 * matching runs on the "skeleton" view (comments and literal contents removed)
 * so a word inside a string, a path or a comment can never make a route look
 * protected.
 */

/**
 * Identifier that names an authentication / authorisation guard.
 * Deliberately excludes generic words such as "session", "token", "csrf" or
 * "protection" on their own: express-session, csrfProtection and a variable
 * called `author` are not authentication.
 */
export const AUTH_IDENT = new RegExp([
  '\\b(?:require|ensure|verify|check|validate|is|has|must|needs?|with|only)_?(?:auth\\w*|login|logged\\w*|user|admin\\w*|token|jwt|session|role\\w*|signed\\w*|perm\\w*|scope\\w*|access\\w*|api_?key|member\\w*|owner\\w*|org\\w*|platform\\w*)\\b',
  '\\bauthenticat\\w*',
  '\\bauthoriz\\w*',
  '\\bauth(?:n|z)?(?:Middleware|Guard|Required|Check|Handler|Filter)?\\b',
  '\\b(?:jwt|token|bearer|basic|api_?key|session|admin|role|permission|access)_?(?:auth\\w*|guard|check|required|only|middleware)\\b',
  '\\bprotect(?:ed|Route)?\\b',
  '\\bguard\\b',
  '\\b\\w*AuthGuard\\b',
  '\\badminOnly\\b',
  '\\blogin_?required\\b',
  '\\bdeny(?:All|Access)\\b',
  '\\bexpressjwt\\b',
  '\\bclerkMiddleware\\b',
  '\\brequiresAuth\\b',
  '\\bcurrent_?user\\b',
  '\\bget_current\\w*',
  '\\bpassport\\.authenticate\\b'
].join('|'), 'i');

// Kept under its old name for callers written against earlier versions
export const UPSTREAM_AUTH_MIDDLEWARE = AUTH_IDENT;

const JS_EXTS = new Set(['.js', '.ts', '.mjs', '.cjs']);
const rel = (file) => file.relative.replace(/\\/g, '/');

/**
 * Router modules mounted behind auth in another file:
 *   app.use(requireAuth); app.use(adminRouter);
 *   app.use('/admin', requireAuth, adminRouter);
 * A module counts as guarded only when *every* mount of it is guarded.
 * Returns Map(relative path of the router module -> evidence string).
 */
function collectExpressMountGuards(files, isAuthName) {
  const mounts = new Map(); // target -> [{ guarded, evidence }]
  const known = new Set(files.map(rel));
  const resolve = (fromRel, spec) => {
    const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromRel), spec));
    return [base, base + '.js', base + '.ts', base + '.mjs', base + '.cjs', base + '/index.js', base + '/index.ts'].find(c => known.has(c)) || null;
  };

  for (const file of files) {
    if (!JS_EXTS.has(file.ext)) continue;
    const code = getCode(file);
    if (!code || !code.includes('.use(')) continue;
    const skeleton = getSkeleton(file);
    const fromRel = rel(file);

    const imports = new Map();
    for (const m of code.matchAll(/\b(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['"](\.[^'"]+)['"]\s*\)/g)) imports.set(m[1], m[2]);
    for (const m of code.matchAll(/\bimport\s+(\w+)\s+from\s+['"](\.[^'"]+)['"]/g)) imports.set(m[1], m[2]);
    if (imports.size === 0) continue;

    let globalGuard = false;
    for (const m of skeleton.matchAll(/\b(?:app|router|server)\.use\s*\(([^;\n]*)/g)) {
      const args = m[1];
      const hasPrefix = /^\s*['"`]/.test(args);
      const mounted = [...imports.keys()].filter(v => new RegExp('\\b' + v + '\\b').test(args));
      if (mounted.length === 0) {
        if (!hasPrefix && isAuthName(args)) globalGuard = true;
        continue;
      }
      let rest = args;
      mounted.forEach(v => { rest = rest.replace(new RegExp('\\b' + v + '\\b', 'g'), ''); });
      const inline = isAuthName(rest);
      for (const v of mounted) {
        const target = resolve(fromRel, imports.get(v));
        if (!target) continue;
        if (!mounts.has(target)) mounts.set(target, []);
        mounts.get(target).push({
          guarded: inline || globalGuard,
          evidence: inline ? `auth middleware where the router is mounted (${fromRel})` : `app.use(auth) before the router is mounted (${fromRel})`
        });
      }
    }
  }

  const guards = new Map();
  for (const [target, list] of mounts) {
    if (list.length > 0 && list.every(x => x.guarded)) guards.set(target, list[0].evidence);
  }
  return guards;
}

const NEXT_MIDDLEWARE_FILE = /(?:^|\/)(?:src\/)?(?:middleware|proxy)\.(?:ts|js|mjs)$/;
const NEXT_MIDDLEWARE_CALLS = /\bgetToken\b|\bgetServerSession\b|\bupdateSession\b|\bgetSession\b|\bgetUser\b|\bjwtVerify\b|\bjwt\.verify\b/;

function isAuthMiddleware(skeleton) {
  if (AUTH_IDENT.test(skeleton) || NEXT_MIDDLEWARE_CALLS.test(skeleton)) return true;
  // Hand-rolled: reads a cookie / header and redirects or rejects
  return /\.cookies\.get\s*\(|\.headers\.get\s*\(/.test(skeleton) && /\bredirect\b|\brewrite\b|status\s*:\s*40[13]/.test(skeleton);
}

/** Directory of the nearest .csproj above a file ('' when there is none). */
function projectDirOf(relPath, projectDirs) {
  let best = '';
  for (const dir of projectDirs) {
    if (dir === '' || relPath.startsWith(dir + '/')) {
      if (dir.length >= best.length) best = dir;
    }
  }
  return best;
}

const EMPTY_ASPNET = Object.freeze({ fallback: null, controllers: null, authorizedExtensions: new Set() });

function compileExtraAuth(names) {
  const clean = (Array.isArray(names) ? names : []).filter(n => typeof n === 'string' && /^[\w$.]+$/.test(n));
  if (clean.length === 0) return null;
  return new RegExp('(?:^|[^\\w$])(?:' + clean.map(n => n.replace(/[.$]/g, '\\$&')).join('|') + ')(?![\\w$])');
}

/**
 * @param options.authIdentifiers  extra middleware / dependency names the project uses for auth
 */
export function buildProjectAuthContext(files = [], options = {}) {
  const extraAuth = compileExtraAuth(options.authIdentifiers);
  const isAuthName = (text) => AUTH_IDENT.test(text) || Boolean(extraAuth && extraAuth.test(text));
  const ctx = {
    extraAuth,
    nextMiddlewares: [],
    aspnet: new Map(), // project dir -> { fallback, controllers, authorizedExtensions:Set }
    aspnetProjectDirs: [],
    spring: null, // { file, permitAll: [patterns] }
    expressMountGuards: collectExpressMountGuards(files, isAuthName)
  };

  ctx.aspnetProjectDirs = [...new Set(files.filter(f => f.ext === '.csproj').map(f => {
    const dir = path.posix.dirname(rel(f));
    return dir === '.' ? '' : dir;
  }))];
  const aspnetFor = (relPath) => {
    const dir = projectDirOf(relPath, ctx.aspnetProjectDirs);
    if (!ctx.aspnet.has(dir)) ctx.aspnet.set(dir, { fallback: null, controllers: null, authorizedExtensions: new Set() });
    return ctx.aspnet.get(dir);
  };

  for (const file of files) {
    const relPath = rel(file);

    if (NEXT_MIDDLEWARE_FILE.test(relPath) && !relPath.includes('app/api/')) {
      const skeleton = getSkeleton(file);
      if (skeleton && (isAuthMiddleware(skeleton) || Boolean(extraAuth && extraAuth.test(skeleton)))) {
        const dir = path.posix.dirname(relPath).replace(/(?:^|\/)src$/, '');
        ctx.nextMiddlewares.push({
          file: relPath,
          baseDir: dir === '.' ? '' : dir,
          matchers: parseNextMatchers(getCode(file))
        });
      }
    }

    if (file.ext === '.cs') {
      const skeleton = getSkeleton(file);
      if (!skeleton) continue;
      const info = aspnetFor(relPath);
      if (/FallbackPolicy\s*=[\s\S]{0,300}?RequireAuthenticatedUser/.test(skeleton)) info.fallback = relPath;
      if (/MapControllers\s*\(\s*\)\s*\.RequireAuthorization\s*\(|new\s+AuthorizeFilter\s*\(/.test(skeleton)) info.controllers = relPath;
      // orders.MapOrdersApiV1().RequireAuthorization(): every endpoint that method maps is protected
      for (const m of skeleton.matchAll(/\.(Map\w+)\s*\(\s*\)\s*(?:\.\w+\s*\([^()]*\)\s*)*\.RequireAuthorization\s*\(/g)) {
        info.authorizedExtensions.add(m[1]);
      }
    }

    if (file.ext === '.java' || file.ext === '.kt') {
      const skeleton = getSkeleton(file);
      if (skeleton && /anyRequest\s*\(\s*\)\s*\.authenticated\s*\(/.test(skeleton)) {
        const code = getCode(file);
        const permitAll = [];
        for (const m of code.matchAll(/(?:requestMatchers|antMatchers|mvcMatchers)\s*\(([^)]*)\)\s*\.permitAll\s*\(/g)) {
          for (const s of m[1].matchAll(/"([^"]+)"/g)) permitAll.push(s[1]);
        }
        ctx.spring = { file: relPath, permitAll };
      }
    }
  }

  return ctx;
}

/** Global ASP.NET Core authorization that applies to a file's project, if any. */
export function aspnetGuardsFor(project, relPath) {
  if (!project?.aspnet) return EMPTY_ASPNET;
  const dir = projectDirOf(relPath, project.aspnetProjectDirs || []);
  return project.aspnet.get(dir) || EMPTY_ASPNET;
}

/** Evidence string when Spring's global rule covers this route, otherwise null. */
export function springGuardFor(project, route) {
  const spring = project?.spring;
  if (!spring) return null;
  const open = spring.permitAll.some(pattern => {
    if (pattern.endsWith('*')) {
      const prefix = pattern.replace(/\/?\*+$/, '');
      return prefix === '' || route === prefix || route.startsWith(prefix + '/');
    }
    return route === pattern;
  });
  return open ? null : `SecurityFilterChain anyRequest().authenticated() (${spring.file})`;
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
