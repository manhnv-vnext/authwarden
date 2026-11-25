import { readText, getLines, getCode, getSkeleton, getCodeLines, isTestPath } from '../utils/fileContext.js';
import { findNextMiddlewareGuard, aspnetGuardsFor, springGuardFor, AUTH_IDENT } from './authContext.js';

/**
 * API & Authorization Scanner
 * Detects Shadow APIs, Missing Auth, BOLA / IDOR, Insecure Server Actions,
 * Unthrottled Auth Endpoints, and Sensitive Data Exposure, and records a
 * route inventory.
 *
 * Three aligned views of each file are used (see utils/fileContext.js):
 *   code     - comments removed: used to find routes and read their paths
 *   skeleton - comments and literal contents removed: used for every decision
 *              about whether auth is present, so a word in a string, a path or
 *              a comment can never make a route look protected
 */

const ADMIN_ROUTE_PATTERNS = [
  /\/admin\b/i,
  /\/dashboard\b/i,
  /\/internal\b/i,
  /\/manage\b/i,
  /\/billing\b/i,
  /\/export\b/i,
  /\/users\/delete\b/i,
  /\/settings\/security\b/i
];

const RATE_LIMIT_SIGNALS = [
  /ratelimit/i,
  /limiter/i,
  /throttle/i,
  /slowdown/i,
  /quota/i,
  /bottleneck/i
];

const JS_ROUTE_EXTS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

// An auth identifier that is actually called: auth(), requireUser(), verifyToken(req)
const AUTH_CALL = new RegExp('(?:' + AUTH_IDENT.source + ')[\\w.]*\\s*\\(', 'i');

// Explicit identity checks inside a handler body (skeleton view)
const BODY_IDENTITY = /\b(?:req|request|ctx|context)\.(?:user|auth|isAuthenticated)\b|\bsession\??\.user\b|\b(?:req|request)\.session\??\.(?:user\w*|uid)\b|\b(?:getServerSession|getToken|getSession|currentUser|getUser|getCurrentUser|jwtVerify)\s*\(|\bjwt\.verify\s*\(|\bsupabase\.auth\.|\bUser\.Identity\b|\bClaimsPrincipal\b|\bHttpContext\.User\b|\b(?:req|request)\.headers\.authorization\b/;

// Reading a credential header by name (needs the code view: the name is a string)
const HEADER_CREDENTIAL = /headers(?:\(\))?\.get\(\s*['"](?:authorization|x-api-key)['"]|headers\[\s*['"](?:authorization|x-api-key)['"]\s*\]/i;

// FastAPI: a security dependency in the decorator or the function signature
const PY_ROUTE_AUTH = /\bDepends\(\s*[\w.]*(?:auth|current_user|get_current|verify|token|jwt|require|permission|api_key|admin|oauth2?_scheme|security)\w*|\bSecurity\(|:\s*(?:Annotated\[[^\]]*)?(?:CurrentUser\w*|\w*(?:Auth|Token|Principal|SuperUser|AdminUser)\w*Dep\w*)\b|\bcurrent_user\b|\bHTTPBearer\b|\bOAuth2PasswordBearer\b|\bHTTPBasic\b|\bAPIKeyHeader\b/i;

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/** [start, end] of the bracket pair opening at openIdx, on a skeleton string. end is the closing bracket. */
function balancedRange(skeleton, openIdx, limit = 20000) {
  const open = skeleton[openIdx];
  const close = open === '(' ? ')' : open === '{' ? '}' : ']';
  let depth = 0;
  const max = Math.min(skeleton.length, openIdx + limit);
  for (let i = openIdx; i < max; i++) {
    if (skeleton[i] === open) depth++;
    else if (skeleton[i] === close && --depth === 0) return [openIdx, i];
  }
  return [openIdx, max - 1];
}

/** Top-level comma positions inside [from, to) of a skeleton string. */
function splitRanges(skeleton, from, to) {
  const ranges = [];
  let depth = 0;
  let start = from;
  for (let i = from; i < to; i++) {
    const ch = skeleton[i];
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if (ch === ',' && depth === 0) { ranges.push([start, i]); start = i + 1; }
  }
  if (skeleton.slice(start, to).trim()) ranges.push([start, to]);
  return ranges;
}

/** router.use(auth) / app.use('/prefix', auth) / fastify.addHook guards declared in a JS file. */
function collectExpressGuards(code, skeleton, isAuthName) {
  const guards = [];
  for (const h of code.matchAll(/\bfastify\.addHook\s*\(\s*['"](?:onRequest|preHandler|preValidation)['"]\s*,/g)) {
    const [, end] = balancedRange(skeleton, h.index + h[0].indexOf('('));
    if (isAuthName(skeleton.slice(h.index + h[0].length, end))) {
      guards.push({ receiver: 'fastify', prefix: null, index: h.index, line: lineOf(code, h.index), label: 'fastify.addHook(auth)' });
    }
  }
  for (const m of code.matchAll(/\b(router|app)\.use\s*\(\s*(?:(['"`])([^'"`]+)\2\s*,)?/g)) {
    const open = m.index + m[0].indexOf('(');
    const [, end] = balancedRange(skeleton, open);
    const args = skeleton.slice(m.index + m[0].length, end);
    if (/^\s*\w*(?:Router|Routes|router|routes)\b/.test(args)) continue; // sub-router mount
    if (!isAuthName(args)) continue;
    guards.push({ receiver: m[1], prefix: m[3] || null, index: m.index, line: lineOf(code, m.index) });
  }
  return guards;
}

/** name -> { prefix, guarded, line } for every APIRouter()/FastAPI() declared in a file. */
function collectFastApiRouters(code, skeleton, isAuthName) {
  const routers = new Map();
  for (const m of skeleton.matchAll(/\b(\w+)\s*=\s*(?:APIRouter|FastAPI)\s*\(/g)) {
    const [open, close] = balancedRange(skeleton, m.index + m[0].length - 1);
    const prefix = (code.slice(open, close).match(/\bprefix\s*=\s*['"]([^'"]*)['"]/) || [])[1] || '';
    const deps = (skeleton.slice(open, close).match(/\bdependencies\s*=\s*\[([\s\S]*?)\]\s*(?:,|$)/) || [])[1] || '';
    routers.set(m[1], { prefix, guarded: PY_ROUTE_AUTH.test(deps) || isAuthName(deps), line: lineOf(code, m.index) });
  }
  return routers;
}

/**
 * @param file  file descriptor from the walker
 * @param ctx   optional { project, routes }: project-wide auth context and an
 *              array that receives one inventory entry per discovered route
 */
export function scanApiAuth(file, ctx = {}) {
  const findings = [];
  const project = ctx.project || null;
  const relPath = file.relative.replace(/\\/g, '/');
  const recordRoute = (route) => {
    if (Array.isArray(ctx.routes)) ctx.routes.push({ ...route, file: relPath });
  };
  const content = readText(file);
  if (content === null) return findings;

  // Skip test files for auth heuristics
  if (isTestPath(file.relative)) {
    return findings;
  }

  const lines = getLines(file);
  const code = getCode(file);
  const skeleton = getSkeleton(file);

  // Project-declared auth middleware names (config: authIdentifiers) extend the built-in list
  const extraAuth = project?.extraAuth || null;
  const isAuthName = (text) => AUTH_IDENT.test(text) || Boolean(extraAuth && extraAuth.test(text));

  /** True when the body in [start, end] contains an explicit auth check. */
  const bodyHasAuth = (start, end) => {
    const skel = skeleton.slice(start, end + 1);
    return AUTH_CALL.test(skel) || BODY_IDENTITY.test(skel) || HEADER_CREDENTIAL.test(code.slice(start, end + 1)) ||
      Boolean(extraAuth && extraAuth.test(skel));
  };

  /** Range of the function body that follows a parameter list opening at parenIdx. */
  const bodyAfterParams = (parenIdx) => {
    const [, paramsEnd] = balancedRange(skeleton, parenIdx);
    const brace = skeleton.indexOf('{', paramsEnd);
    if (brace === -1 || brace - paramsEnd > 300) return null;
    return balancedRange(skeleton, brace);
  };

  // 1. Next.js App Router API Routes: app/api/**/route.(ts|js)
  if (relPath.includes('app/api/') && /route\.(ts|js|mjs)$/.test(relPath)) {
    const routeUrl = '/' + relPath.replace(/^.*app\//, '').replace(/\/route\.(ts|js|mjs)$/, '');
    const isAdmin = ADMIN_ROUTE_PATTERNS.some(p => p.test(routeUrl));

    // export [async] function GET(...) {}   |   export const GET = [wrapper(] async (...) => {}
    const handlerRegex = /\bexport\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)\s*\(|\bexport\s+const\s+(GET|POST|PUT|DELETE|PATCH)\s*=/g;
    let match;
    while ((match = handlerRegex.exec(skeleton)) !== null) {
      const method = match[1] || match[2];
      const lineNo = lineOf(code, match.index);
      let inHandler = false;

      if (match[1]) {
        const body = bodyAfterParams(match.index + match[0].length - 1);
        inHandler = body ? bodyHasAuth(body[0], body[1]) : false;
      } else {
        // Statement runs to the end of the initializer: wrapper name first, then the arrow body
        const after = match.index + match[0].length;
        const stmtEnd = Math.min(skeleton.length, after + 8000);
        const arrow = skeleton.indexOf('=>', after);
        const firstParen = skeleton.indexOf('(', after);
        const wrapper = firstParen === -1 ? skeleton.slice(after, Math.min(stmtEnd, after + 200)).split(/[;\n]/)[0] : skeleton.slice(after, firstParen);
        const wrapped = isAuthName(wrapper);
        let inBody = false;
        if (arrow !== -1 && arrow < stmtEnd) {
          const brace = skeleton.indexOf('{', arrow);
          if (brace !== -1 && brace - arrow < 20) {
            const [s, e] = balancedRange(skeleton, brace);
            inBody = bodyHasAuth(s, e);
          }
        }
        inHandler = wrapped || inBody;
      }

      const middlewareGuard = inHandler ? null : findNextMiddlewareGuard(project, relPath, routeUrl);
      const hasAuth = inHandler || Boolean(middlewareGuard);
      recordRoute({
        method, path: routeUrl, line: lineNo, framework: 'Next.js',
        auth: hasAuth ? 'protected' : 'unprotected',
        evidence: inHandler ? 'auth check in handler' : middlewareGuard ? `middleware (${middlewareGuard})` : 'no auth check found'
      });

      if (isAdmin && !hasAuth) {
        findings.push({
          ruleId: 'AUTH-001',
          severity: 'CRITICAL',
          title: `Shadow Admin Route Missing Authentication: ${method} ${routeUrl}`,
          file: relPath,
          line: lineNo,
          snippet: lines[lineNo - 1]?.trim(),
          description: `Route "${routeUrl}" contains administrative keywords but executes without authentication or role validation checks.`,
          remediation: `Add session or token validation at the beginning of the handler: const session = await auth(); if (!session?.user?.isAdmin) return new Response('Unauthorized', { status: 401 });`
        });
      } else if (!hasAuth && ['POST', 'PUT', 'DELETE'].includes(method)) {
        if (!/login|register|signup|forgot|webhook|callback|health/i.test(routeUrl)) {
          findings.push({
            ruleId: 'AUTH-002',
            severity: 'HIGH',
            title: `State-Modifying Route Without Auth: ${method} ${routeUrl}`,
            file: relPath,
            line: lineNo,
            snippet: lines[lineNo - 1]?.trim(),
            description: `State-altering endpoint "${method} ${routeUrl}" lacks obvious authentication or session verification logic.`,
            remediation: `Verify the requesting user's session before performing database mutations.`
          });
        }
      }
    }
  }

  // 2. Next.js Server Actions ('use server')
  if (JS_ROUTE_EXTS.has(file.ext) && /(?:^|[\n;{])\s*['"]use server['"]/.test(code)) {
    const actionRegex = /\bexport\s+async\s+function\s+([a-zA-Z0-9_]+)\s*\(/g;
    let actMatch;
    while ((actMatch = actionRegex.exec(skeleton)) !== null) {
      const fnName = actMatch[1];
      const lineNo = lineOf(code, actMatch.index);
      const body = bodyAfterParams(actMatch.index + actMatch[0].length - 1);
      const bodySkel = body ? skeleton.slice(body[0], body[1] + 1) : '';

      const hasMutation = /\bprisma\.|\bdb\.|\bquery\s*\(|delete|update|create|insert/i.test(bodySkel);
      const hasAuth = body ? bodyHasAuth(body[0], body[1]) : false;

      recordRoute({
        method: 'ACTION', path: fnName + '()', line: lineNo, framework: 'Next.js Server Action',
        auth: hasAuth ? 'protected' : 'unprotected',
        evidence: hasAuth ? 'auth check in action' : 'no auth check found'
      });

      if (hasMutation && !hasAuth && !/login|signin|register|signup/i.test(fnName)) {
        findings.push({
          ruleId: 'AUTH-004',
          severity: 'HIGH',
          title: `Server Action Performs Mutation Without Auth Check: ${fnName}()`,
          file: relPath,
          line: lineNo,
          snippet: lines[lineNo - 1]?.trim(),
          description: `Server Action "${fnName}" mutates data but does not verify caller session/authentication. Server Actions are publicly invokable RPCs.`,
          remediation: `Always verify identity: const user = await getCurrentUser(); if (!user) throw new Error('Unauthorized');`
        });
      }
    }
  }

  // 3. Express / Fastify routes: (router|app|fastify).(get|post|put|delete|patch)('/path', ...middleware, handler)
  if (JS_ROUTE_EXTS.has(file.ext) && /\b(router|app|fastify)\.(get|post|put|delete|patch)\s*\(/i.test(code)) {
    const expressGuards = collectExpressGuards(code, skeleton, isAuthName);
    const mountGuard = project?.expressMountGuards?.get(relPath) || null;
    const hasRateLimit = RATE_LIMIT_SIGNALS.some(s => s.test(skeleton));
    const expressRegex = /\b(router|app|fastify)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`\n]+)['"`]\s*,/g;
    let expMatch;
    while ((expMatch = expressRegex.exec(code)) !== null) {
      // The same text inside a string literal (docs, examples) is blank in the skeleton
      if (skeleton[expMatch.index] !== code[expMatch.index] || !/\w/.test(skeleton[expMatch.index])) continue;
      const receiver = expMatch[1];
      const method = expMatch[2].toUpperCase();
      const routePath = expMatch[3];
      const lineNo = lineOf(code, expMatch.index);
      const isAdmin = ADMIN_ROUTE_PATTERNS.some(p => p.test(routePath));

      // Arguments are (path, ...middleware, handler): only the middle ones can be auth middleware.
      // The handler counts only when it is a wrapper call such as requireAuth(handler).
      const [open, close] = balancedRange(skeleton, expMatch.index + expMatch[0].indexOf('('));
      const args = splitRanges(skeleton, open + 1, close).map(([s, e]) => ({ start: s, end: e, text: skeleton.slice(s, e) }));
      const middlewares = args.slice(1, -1);
      const handler = args.length > 1 ? args[args.length - 1] : null;
      const handlerIsInline = handler ? /=>|\bfunction\b/.test(handler.text) : false;
      const wrappedHandler = handler && !handlerIsInline && /^\s*[\w$.]+\s*\(/.test(handler.text) &&
        isAuthName(handler.text.slice(0, handler.text.indexOf('(')));
      const inChain = Boolean(wrappedHandler) || middlewares.some(arg => isAuthName(arg.text));

      const guard = inChain ? null : expressGuards.find(g =>
        g.receiver === receiver && g.index < expMatch.index &&
        (!g.prefix || routePath === g.prefix || routePath.startsWith(g.prefix.replace(/\/$/, '') + '/')));

      let inBody = false;
      if (!inChain && !guard && handlerIsInline) {
        const arrow = skeleton.slice(handler.start, handler.end).search(/=>|\bfunction\b/);
        const brace = skeleton.indexOf('{', handler.start + arrow);
        if (brace !== -1 && brace < handler.end) {
          const [s, e] = balancedRange(skeleton, brace);
          inBody = bodyHasAuth(s, e);
        }
      }

      const hasAuth = inChain || Boolean(guard) || inBody || Boolean(mountGuard);
      // Middleware is present but none of it is recognised as auth: say so instead of guessing
      const unknownMiddleware = hasAuth ? [] : middlewares.map(arg => arg.text.trim().replace(/\s+/g, ' ').slice(0, 40)).filter(Boolean);
      const isUnknown = unknownMiddleware.length > 0;
      recordRoute({
        method, path: routePath, line: lineNo, framework: receiver === 'fastify' ? 'Fastify' : 'Express',
        auth: hasAuth ? 'protected' : isUnknown ? 'unknown' : 'unprotected',
        evidence: inChain ? 'auth middleware in route chain'
          : guard ? `${guard.label || `${guard.receiver}.use(${guard.prefix ? `'${guard.prefix}', ` : ''}auth)`} at line ${guard.line}`
          : inBody ? 'auth check in handler body'
          : mountGuard ? mountGuard
          : isUnknown ? `middleware not recognised as auth: ${unknownMiddleware.join(', ')}`
          : 'no auth middleware found'
      });
      const isLoginOrAuth = /(?:^|\/)(?:auth\/)?(?:login|signin|token|authenticate|password\/reset)(?:\/|$)/i.test(routePath) && !/crawl|operator|live-login/i.test(routePath);

      if (isAdmin && !hasAuth) {
        findings.push({
          ruleId: 'AUTH-001',
          severity: 'CRITICAL',
          title: `Express Admin Endpoint Missing Auth Middleware: ${method} ${routePath}`,
          file: relPath,
          line: lineNo,
          snippet: lines[lineNo - 1]?.trim(),
          ...(isUnknown ? { confidence: 'LOW' } : {}),
          description: `Express endpoint "${routePath}" looks like an administrative API but lacks authentication middleware in its route definition chain.` +
            (isUnknown ? ` Its middleware (${unknownMiddleware.join(', ')}) is not recognised as authentication; if it is, list its name under "authIdentifiers" in .authwardenrc.json.` : ''),
          remediation: `Add your authentication middleware: router.${method.toLowerCase()}('${routePath}', requireAuth, requireRole('admin'), handler);`
        });
      }

      if (isLoginOrAuth && !hasRateLimit && method === 'POST') {
        findings.push({
          ruleId: 'AUTH-006',
          severity: 'HIGH',
          title: `Unthrottled Authentication Endpoint: ${method} ${routePath}`,
          file: relPath,
          line: lineNo,
          snippet: lines[lineNo - 1]?.trim(),
          description: `Authentication endpoint "${routePath}" does not apply rate limiting, leaving it vulnerable to automated brute-force and credential stuffing attacks.`,
          remediation: `Apply a rate limiter (e.g. express-rate-limit): router.post('${routePath}', authLimiter, handler);`
        });
      }
    }
  }

  // 4. FastAPI / Python Route Patterns
  if (file.ext === '.py') {
    const pyRouters = collectFastApiRouters(code, skeleton, isAuthName);
    const pyRouteRegex = /@(\w+)\.(get|post|put|delete|patch)\s*\(/g;
    let pyMatch;
    while ((pyMatch = pyRouteRegex.exec(skeleton)) !== null) {
      const routerName = pyMatch[1];
      const routerInfo = pyRouters.get(routerName);
      if (!routerInfo && routerName !== 'app' && routerName !== 'router') continue;
      const [decOpen, decClose] = balancedRange(skeleton, pyMatch.index + pyMatch[0].length - 1);
      const pathMatch = code.slice(decOpen, decClose).match(/^\(\s*(?:path\s*=\s*)?['"]([^'"]*)['"]/);
      if (!pathMatch) continue;
      const method = pyMatch[2].toUpperCase();
      const routePath = ((routerInfo?.prefix || '') + pathMatch[1]) || '/';
      const lineNo = lineOf(code, pyMatch.index);

      // Only the decorator arguments and the function parameters can declare a dependency
      const defMatch = /\bdef\s+\w+\s*\(/g;
      defMatch.lastIndex = decClose;
      const def = defMatch.exec(skeleton);
      let paramsSkel = '';
      if (def && def.index - decClose < 600) {
        const [pOpen, pClose] = balancedRange(skeleton, def.index + def[0].length - 1);
        paramsSkel = skeleton.slice(pOpen, pClose + 1);
      }
      const inSignature = PY_ROUTE_AUTH.test(skeleton.slice(decOpen, decClose + 1)) || PY_ROUTE_AUTH.test(paramsSkel) ||
        Boolean(extraAuth && (extraAuth.test(skeleton.slice(decOpen, decClose + 1)) || extraAuth.test(paramsSkel)));
      const routerGuarded = Boolean(routerInfo?.guarded);
      const hasAuth = inSignature || routerGuarded;
      const isAdmin = ADMIN_ROUTE_PATTERNS.some(p => p.test(routePath));
      recordRoute({
        method, path: routePath, line: lineNo, framework: 'FastAPI',
        auth: hasAuth ? 'protected' : 'unprotected',
        evidence: inSignature ? 'security dependency on route'
          : routerGuarded ? `router dependencies on ${routerName} (line ${routerInfo.line})`
          : 'no security dependency found'
      });

      if (isAdmin && !hasAuth) {
        findings.push({
          ruleId: 'AUTH-001',
          severity: 'CRITICAL',
          title: `FastAPI Admin Route Missing Security Dependency: ${method} ${routePath}`,
          file: relPath,
          line: lineNo,
          snippet: lines[lineNo - 1]?.trim(),
          description: `FastAPI endpoint "${routePath}" is defined without a Depends(verify_admin_token) or Security dependency.`,
          remediation: `Protect route: @router.${method.toLowerCase()}('${routePath}', dependencies=[Depends(require_admin)])`
        });
      }
    }
  }

  // Class declarations with their attribute / annotation header (C# and Java)
  const classInfos = [];
  if (file.ext === '.cs' || file.ext === '.java') {
    for (const m of skeleton.matchAll(/\bclass\s+(\w+)/g)) {
      const boundary = Math.max(skeleton.lastIndexOf('}', m.index), skeleton.lastIndexOf(';', m.index), skeleton.lastIndexOf('{', m.index));
      classInfos.push({ name: m[1], index: m.index, headerStart: boundary + 1 });
    }
  }
  const classAt = (index) => {
    let found = null;
    for (const c of classInfos) if (c.index < index) found = c;
    return found;
  };

  // 5. C# / ASP.NET Core Controllers & Minimal APIs
  if (file.ext === '.cs') {
    const aspnet = aspnetGuardsFor(project, relPath);
    const isController = /class\s+\w+Controller\b|:\s*(?:ControllerBase|Controller)\b|\[ApiController\]/.test(skeleton);
    if (isController) {
      const globalControllerAuth = aspnet.fallback || aspnet.controllers || null;

      const actionRegex = /\[(HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route)(?:\(\s*["']?([^"')\s]*)["']?\s*\))?\](?:\s*\[[^\]]+\])*\s*(?:public|protected)\s+(?:async\s+)?(?:Task<[A-Za-z0-9_<>,\s]+>|[A-Za-z0-9_<>]+)\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)/g;
      let actMatch;
      while ((actMatch = actionRegex.exec(code)) !== null) {
        const httpAttr = actMatch[1];
        const subRoute = actMatch[2] || '';
        const actionName = actMatch[3];
        const methodParams = actMatch[4] || '';
        const methodLineNo = lineOf(code, actMatch.index);
        const method = httpAttr === 'Route' ? 'ANY' : httpAttr.replace(/^Http/, '').toUpperCase();

        // Attributes of the class this action belongs to (a file may hold several controllers)
        const owner = classAt(actMatch.index);
        const classHeaderSkel = owner ? skeleton.slice(owner.headerStart, owner.index) : '';
        const classHeaderCode = owner ? code.slice(owner.headerStart, owner.index) : '';
        const classRoute = (classHeaderCode.match(/\[Route\(\s*["']([^"']+)["']\s*\)\]/i) || [])[1] || '';
        const classAttrAuthorize = /\[Authorize\b/.test(classHeaderSkel);
        const classAllowAnonymous = /\[AllowAnonymous\b/.test(classHeaderSkel);
        const classHasAuthorize = classAttrAuthorize || (Boolean(globalControllerAuth) && !classAllowAnonymous);

        const fullRoute = ('/' + classRoute + '/' + subRoute).replace(/\/+/g, '/').replace(/\/$/, '');
        const prevBoundary = Math.max(skeleton.lastIndexOf('}', actMatch.index), skeleton.lastIndexOf('{', actMatch.index), skeleton.lastIndexOf(';', actMatch.index));
        const methodAttributes = skeleton.slice(prevBoundary + 1, actMatch.index) + skeleton.slice(actMatch.index, actMatch.index + actMatch[0].length).split(/\b(?:public|protected)\b/)[0];
        const methodHasAuthorize = /\[Authorize\b/.test(methodAttributes);
        const methodHasAllowAnonymous = /\[AllowAnonymous\b/.test(methodAttributes);

        const isAuthorized = (classHasAuthorize || methodHasAuthorize) && !methodHasAllowAnonymous;
        const isAdmin = ADMIN_ROUTE_PATTERNS.some(p => p.test(fullRoute)) || /admin/i.test(actionName);
        recordRoute({
          method, path: fullRoute || actionName, line: methodLineNo, framework: 'ASP.NET Core',
          auth: isAuthorized ? 'protected' : 'unprotected',
          evidence: methodHasAllowAnonymous ? '[AllowAnonymous]'
            : methodHasAuthorize ? '[Authorize] on action'
            : classAttrAuthorize ? '[Authorize] on controller'
            : isAuthorized ? `global authorization policy (${globalControllerAuth})`
            : 'no [Authorize] attribute'
        });

        if (isAdmin && !isAuthorized) {
          findings.push({
            ruleId: 'AUTH-001',
            severity: 'CRITICAL',
            title: `ASP.NET Core Admin Endpoint Missing [Authorize]: ${method} ${fullRoute || actionName}`,
            file: relPath,
            line: methodLineNo,
            snippet: lines[methodLineNo - 1]?.trim(),
            description: `Action "${actionName}" at route "${fullRoute}" contains administrative keywords but lacks the [Authorize] attribute, allowing unauthenticated caller access.`,
            remediation: `Add [Authorize] or [Authorize(Roles = "Admin")] attribute to the action method or controller class.`
          });
        }

        const hasFileUpload = /\b(?:IFormFile|IFormFileCollection|IEnumerable<IFormFile>|List<IFormFile>)\b/i.test(methodParams) ||
          /\b(?:Request\.Form\.Files|InitiateMultipartUpload|UploadPart|CompleteMultipartUpload|GetPreSignedURL)/i.test(lines.slice(methodLineNo - 1, methodLineNo + 25).join('\n'));

        if (hasFileUpload && !isAuthorized) {
          findings.push({
            ruleId: 'AUTH-008',
            severity: 'HIGH',
            title: `Unauthenticated File Upload Endpoint: ${method} ${fullRoute || actionName}`,
            file: relPath,
            line: methodLineNo,
            snippet: lines[methodLineNo - 1]?.trim(),
            description: `Endpoint "${method} ${fullRoute || actionName}" accepts file uploads or initiates multipart upload without authentication ([Authorize]). Anonymous upload endpoints enable storage exhaustion, malware hosting, and denial of service.`,
            remediation: `Add [Authorize] attribute to the upload action method or require caller authentication before processing uploads.`
          });
        } else if (!isAuthorized && ['POST', 'PUT', 'DELETE'].includes(method)) {
          if (!/login|register|signup|forgot|webhook|callback|health|auth/i.test(fullRoute + actionName)) {
            findings.push({
              ruleId: 'AUTH-002',
              severity: 'HIGH',
              title: `State-Modifying ASP.NET Core Route Without [Authorize]: ${method} ${fullRoute || actionName}`,
              file: relPath,
              line: methodLineNo,
              snippet: lines[methodLineNo - 1]?.trim(),
              description: `State-altering endpoint "${method} ${fullRoute || actionName}" lacks [Authorize] attribute. Attackers can execute mutations anonymously.`,
              remediation: `Decorate the endpoint with [Authorize].`
            });
          }
        }

        if (/\[FromBody\]\s*(?:User|Account|Order|Payment|Role|Permission)\b|\b(?:User|Account|Order|Payment|Role|Permission)\s+[a-z]\w*(?:\s*,|\s*\))/i.test(methodParams) &&
            !/DTO|Request|Model|Input|Vm/i.test(methodParams)) {
          findings.push({
            ruleId: 'AUTH-005',
            severity: 'MEDIUM',
            title: `Mass Assignment Risk in ASP.NET Core Controller: ${actionName}()`,
            file: relPath,
            line: methodLineNo,
            snippet: lines[methodLineNo - 1]?.trim(),
            description: `Action binds request body directly to a core database entity type. Attackers can tamper with sensitive model properties (e.g. IsAdmin, Role, Balance).`,
            remediation: `Use dedicated Input/DTO classes instead of direct entity binding, or specify [Bind("AllowedProp1,AllowedProp2")].`
          });
        }
      }
    }

    // 5b. C# / ASP.NET Core Minimal APIs
    const minimalApiRegex = /\b([a-zA-Z0-9_]+)\.(MapGet|MapPost|MapPut|MapDelete|MapPatch)\s*\(\s*["']([^"']+)["']/g;
    let minMatch;
    while ((minMatch = minimalApiRegex.exec(code)) !== null) {
      if (!/\w/.test(skeleton[minMatch.index])) continue; // inside a string literal
      const caller = minMatch[1];
      const httpVerb = minMatch[2].replace(/^Map/, '').toUpperCase();
      const routePath = minMatch[3];
      const lineNo = lineOf(code, minMatch.index);

      // The endpoint's own arguments, then every chained call (.RequireAuthorization(), .AllowAnonymous(), ...)
      const [argsOpen, argsClose] = balancedRange(skeleton, minMatch.index + minMatch[0].indexOf('('));
      let pos = argsClose + 1;
      for (;;) {
        const rest = skeleton.slice(pos).match(/^\s*\.\s*\w+\s*(?:<[^>()]*>)?\s*\(/);
        if (!rest) break;
        const [, callClose] = balancedRange(skeleton, pos + rest[0].length - 1);
        pos = callClose + 1;
      }
      const argsSkel = skeleton.slice(argsOpen, argsClose + 1);
      const chainSkel = skeleton.slice(argsClose + 1, pos);

      const hasAuth = /\.\s*RequireAuthorization\s*\(/.test(chainSkel) || /\[Authorize\b/.test(argsSkel);
      const hasAllowAnonymous = /\.\s*AllowAnonymous\s*\(/.test(chainSkel) || /\[AllowAnonymous\b/.test(argsSkel);
      const isGroupAuthorized = new RegExp(`\\b${caller}\\s*=[^;]*\\.RequireAuthorization\\s*\\(`).test(skeleton);

      // Endpoints mapped inside an extension method that callers chain with .RequireAuthorization()
      let extensionGuard = null;
      if (aspnet.authorizedExtensions.size > 0) {
        let enclosing = null;
        for (const m of skeleton.matchAll(/\bstatic\s+[\w<>\[\],.?\s]+?\s+(\w+)\s*\(\s*this\s/g)) {
          if (m.index < minMatch.index) enclosing = m[1];
        }
        if (enclosing && aspnet.authorizedExtensions.has(enclosing)) extensionGuard = enclosing;
      }

      const fallbackAuth = aspnet.fallback || null;
      const isAuthorized = (hasAuth || isGroupAuthorized || Boolean(extensionGuard) || Boolean(fallbackAuth)) && !hasAllowAnonymous;
      const isAdmin = ADMIN_ROUTE_PATTERNS.some(p => p.test(routePath)) || /admin/i.test(routePath);
      recordRoute({
        method: httpVerb, path: routePath, line: lineNo, framework: 'ASP.NET Core Minimal API',
        auth: isAuthorized ? 'protected' : 'unprotected',
        evidence: hasAllowAnonymous ? '.AllowAnonymous()'
          : hasAuth ? '.RequireAuthorization() on endpoint'
          : isGroupAuthorized ? `.RequireAuthorization() on group ${caller}`
          : extensionGuard ? `${extensionGuard}().RequireAuthorization() where the endpoints are mapped`
          : fallbackAuth ? `fallback authorization policy (${fallbackAuth})`
          : 'no .RequireAuthorization()'
      });
      const hasFileUpload = /\b(?:IFormFile|IFormFileCollection|IEnumerable<IFormFile>|List<IFormFile>)\b/i.test(argsSkel) ||
        /\b(?:Request\.Form\.Files|InitiateMultipartUpload|UploadPart|CompleteMultipartUpload|GetPreSignedURL)/i.test(argsSkel);

      if (isAdmin && !isAuthorized) {
        findings.push({
          ruleId: 'AUTH-001',
          severity: 'CRITICAL',
          title: `ASP.NET Core Minimal API Admin Route Missing RequireAuthorization: ${httpVerb} ${routePath}`,
          file: relPath,
          line: lineNo,
          snippet: lines[lineNo - 1]?.trim(),
          description: `Minimal API endpoint "${httpVerb} ${routePath}" contains administrative keywords but lacks .RequireAuthorization(), allowing unauthenticated access.`,
          remediation: `Chain .RequireAuthorization() to the endpoint mapping: app.${minMatch[2]}('${routePath}', ...).RequireAuthorization();`
        });
      } else if (hasFileUpload && !isAuthorized) {
        findings.push({
          ruleId: 'AUTH-008',
          severity: 'HIGH',
          title: `Unauthenticated File Upload Minimal API: ${httpVerb} ${routePath}`,
          file: relPath,
          line: lineNo,
          snippet: lines[lineNo - 1]?.trim(),
          description: `Minimal API endpoint "${httpVerb} ${routePath}" accepts file uploads without requiring authentication.`,
          remediation: `Chain .RequireAuthorization() to the upload endpoint.`
        });
      } else if (!isAuthorized && ['POST', 'PUT', 'DELETE'].includes(httpVerb)) {
        if (!/login|register|signup|forgot|webhook|callback|health|auth/i.test(routePath)) {
          findings.push({
            ruleId: 'AUTH-002',
            severity: 'HIGH',
            title: `State-Modifying ASP.NET Core Minimal API Without Authorization: ${httpVerb} ${routePath}`,
            file: relPath,
            line: lineNo,
            snippet: lines[lineNo - 1]?.trim(),
            description: `State-altering Minimal API "${httpVerb} ${routePath}" lacks .RequireAuthorization(). Anonymous users can invoke mutations.`,
            remediation: `Chain .RequireAuthorization() to the endpoint.`
          });
        }
      }
    }

    // 5c. Check for Unconditional Swagger UI in Production (SPEC-005)
    const swaggerMatch = skeleton.match(/\b(?:app|builder)\.UseSwaggerUI\s*\(/);
    if (swaggerMatch) {
      const prevCode = code.slice(Math.max(0, swaggerMatch.index - 350), swaggerMatch.index);
      const hasDevCheck = /IsDevelopment\s*\(\s*\)/i.test(prevCode) || /IsEnvironment\s*\(\s*["']Development["']\s*\)/i.test(prevCode);
      if (!hasDevCheck) {
        const lineNo = lineOf(code, swaggerMatch.index);
        findings.push({
          ruleId: 'SPEC-005',
          severity: 'MEDIUM',
          title: 'Unconditional Swagger UI Registration in Production',
          file: relPath,
          line: lineNo,
          snippet: lines[lineNo - 1]?.trim(),
          description: 'Swagger UI is registered without verifying whether the application is running in Development mode. In production, this publicly exposes internal API routes, data structures, and schemas to unauthenticated attackers.',
          remediation: 'Wrap Swagger in an environment check: if (app.Environment.IsDevelopment()) { app.UseSwagger(); app.UseSwaggerUI(); }'
        });
      }
    }
  }

  // 6. Java Spring Boot Controllers
  if (file.ext === '.java' && /@RestController\b|@Controller\b/.test(skeleton)) {
    const SECURITY_ANNOTATION = /@PreAuthorize\b|@Secured\b|@RolesAllowed\b/;
    const mappingRegex = /@(Get|Post|Put|Delete|Patch|Request)Mapping\b/g;
    let jMatch;
    while ((jMatch = mappingRegex.exec(skeleton)) !== null) {
      // Annotation arguments, then any further annotations, then the declaration
      let pos = jMatch.index + jMatch[0].length;
      let argsCode = '';
      const argOpen = skeleton.slice(pos).match(/^\s*\(/);
      if (argOpen) {
        const [o, c] = balancedRange(skeleton, pos + argOpen[0].length - 1);
        argsCode = code.slice(o + 1, c);
        pos = c + 1;
      }
      const annotationsStart = pos;
      for (;;) {
        const more = skeleton.slice(pos).match(/^\s*@\w+(?:\.\w+)*/);
        if (!more) break;
        pos += more[0].length;
        const paren = skeleton.slice(pos).match(/^\s*\(/);
        if (paren) pos = balancedRange(skeleton, pos + paren[0].length - 1)[1] + 1;
      }
      const decl = skeleton.slice(pos, pos + 400);
      if (/^\s*(?:(?:public|protected|private|abstract|final|static|sealed)\s+)*(?:class|interface|enum|record)\b/.test(decl)) continue; // class-level mapping
      const nameMatch = decl.match(/^[^({;=]*?\b(\w+)\s*\(/);
      if (!nameMatch) continue;
      const methodName = nameMatch[1];
      const methodLineNo = lineOf(code, jMatch.index);
      const method = jMatch[1] === 'Request' ? 'ANY' : jMatch[1].toUpperCase();
      const subRoute = (argsCode.match(/["']([^"']*)["']/) || [])[1] || '';

      const owner = classAt(jMatch.index);
      const classHeaderSkel = owner ? skeleton.slice(owner.headerStart, owner.index) : '';
      const classHeaderCode = owner ? code.slice(owner.headerStart, owner.index) : '';
      const classRoute = (classHeaderCode.match(/@RequestMapping\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']+)["']/) || [])[1] || '';
      const classHasAuth = SECURITY_ANNOTATION.test(classHeaderSkel);

      const fullRoute = ('/' + classRoute + '/' + subRoute).replace(/\/+/g, '/').replace(/\/$/, '');
      const prevBoundary = Math.max(skeleton.lastIndexOf('}', jMatch.index), skeleton.lastIndexOf('{', jMatch.index), skeleton.lastIndexOf(';', jMatch.index));
      const methodHasAuth = SECURITY_ANNOTATION.test(skeleton.slice(prevBoundary + 1, jMatch.index)) || SECURITY_ANNOTATION.test(skeleton.slice(annotationsStart, pos));

      const springGlobal = classHasAuth || methodHasAuth ? null : springGuardFor(project, fullRoute);
      const isAuthorized = classHasAuth || methodHasAuth || Boolean(springGlobal);
      const isAdmin = ADMIN_ROUTE_PATTERNS.some(p => p.test(fullRoute)) || /admin/i.test(methodName);
      recordRoute({
        method, path: fullRoute || methodName, line: methodLineNo, framework: 'Spring',
        auth: isAuthorized ? 'protected' : 'unprotected',
        evidence: methodHasAuth ? 'security annotation on method'
          : classHasAuth ? 'security annotation on class'
          : springGlobal ? springGlobal
          : 'no security annotation'
      });

      if (isAdmin && !isAuthorized) {
        findings.push({
          ruleId: 'AUTH-001',
          severity: 'CRITICAL',
          title: `Spring Boot Admin Endpoint Missing Security Annotation: ${method} ${fullRoute || methodName}`,
          file: relPath,
          line: methodLineNo,
          snippet: lines[methodLineNo - 1]?.trim(),
          description: `Spring Boot endpoint "${methodName}" at route "${fullRoute}" contains administrative keywords but lacks @PreAuthorize or @Secured annotation.`,
          remediation: `Add @PreAuthorize("hasRole('ADMIN')") to the method or class.`
        });
      }
    }
  }

  // 7. Insecure CORS Configuration: Wildcard / Dynamic Origin with Credentials (AUTH-009)
  if (file.ext === '.cs') {
    const csharpCorsRegex = /(?:AllowAnyOrigin\s*\([^)]*\)[\s\S]{0,150}\.AllowCredentials\s*\(|\.SetIsOriginAllowed\s*\(\s*[^)]*=>\s*true\s*\)[\s\S]{0,150}\.AllowCredentials\s*\(|\.AllowCredentials\s*\(\)[\s\S]{0,150}\.SetIsOriginAllowed\s*\(\s*[^)]*=>\s*true\s*\))/i;
    const corsMatch = code.match(csharpCorsRegex);
    if (corsMatch) {
      const lineNo = lineOf(code, corsMatch.index);
      findings.push({
        ruleId: 'AUTH-009',
        severity: 'HIGH',
        title: 'Insecure CORS Policy: Arbitrary Origin with Credentials Allowed',
        file: relPath,
        line: lineNo,
        snippet: lines[lineNo - 1]?.trim(),
        description: 'CORS policy enables .AllowCredentials() together with .AllowAnyOrigin() or .SetIsOriginAllowed(_ => true). Attackers can host malicious sites that make authenticated cross-origin requests to your API.',
        remediation: 'Specify explicit trusted origins via .WithOrigins("https://yourdomain.com") when using .AllowCredentials().'
      });
    }
  } else if (['.js', '.ts'].includes(file.ext)) {
    const nodeCorsRegex = /cors\s*\(\s*\{[\s\S]{0,100}(?:origin\s*:\s*(?:true|['"]\*['"])[\s\S]{0,100}credentials\s*:\s*true|credentials\s*:\s*true[\s\S]{0,100}origin\s*:\s*(?:true|['"]\*['"]))/i;
    const match = code.match(nodeCorsRegex);
    if (match) {
      const lineNo = lineOf(code, match.index);
      findings.push({
        ruleId: 'AUTH-009',
        severity: 'HIGH',
        title: 'Insecure CORS Policy: Wildcard / Dynamic Origin with Credentials Allowed',
        file: relPath,
        line: lineNo,
        snippet: lines[lineNo - 1]?.trim(),
        description: 'Express CORS middleware allows credentials with origin: true or origin: "*". Any third-party website visited by an authenticated user can access private API responses.',
        remediation: 'Set origin to an explicit domain allowlist array: cors({ origin: ["https://app.example.com"], credentials: true }).'
      });
    }
  }

  // 8. BOLA / IDOR Pattern & Sensitive Data Exposure
  const codeLines = getCodeLines(file);
  for (let i = 0; i < lines.length; i++) {
    const line = codeLines[i] || '';
    const rawLine = lines[i];
    if (!line.trim()) continue;

    // Pattern: findById(req.params.id) / EF Core FindAsync(id) / Spring Data findById without owner check
    if (/\.(?:findById|findByPk)\s*\([^)]*?(?:id|req\.params|\$id)|\.find(?:Unique|First)(?:OrThrow)?\s*\(\s*\{\s*where\s*:\s*\{\s*id\b|\.FindAsync\s*\(\s*(?:id|orderId|userId|accountId|itemId)\b|\.FirstOrDefault(?:Async)?\s*\(\s*[a-zA-Z0-9_]+\s*=>\s*[a-zA-Z0-9_]+\.Id\s*==\s*id\b|filter_by\(id=|\.filter\([a-zA-Z_]+\.id\s*==\s*id/i.test(line)) {
      const contextBlock = codeLines.slice(Math.max(0, i - 10), Math.min(codeLines.length, i + 15)).join('\n');
      // Lookup keyed by the caller's own identity is not an object reference from the client
      const keyedByCaller = /\(\s*(?:req\.user|request\.user|loggedInUser|currentUser|authenticatedUser|authUser|session\.user)\b[\w.?]*\s*\)/.test(line);
      const hasOwnerCheck = keyedByCaller || /user_id|userId|tenant_id|tenantId|owner_id|ownerId|org_id|accountId|req\.user|current_user|User\.FindFirst|ClaimsPrincipal|User\.Identity/i.test(contextBlock);

      if (!hasOwnerCheck &&
          !/^\s*['"`]/.test(line) &&
          !/(?:vulnerableCode|content|example|sample|snippet|pattern|description|hypothesis|title|lineNumber|isTarget)\s*[:=]/i.test(line)) {
        findings.push({
          ruleId: 'AUTH-003',
          severity: 'HIGH',
          title: 'Potential BOLA / IDOR: Object Query without Ownership Scope',
          file: relPath,
          line: i + 1,
          snippet: rawLine.trim(),
          description: 'Database query queries an object directly by identifier without validating ownership against the authenticated user/tenant session.',
          remediation: 'Scope the query to the authenticated user: db.item.findFirst({ where: { id, userId: req.user.id } })'
        });
      }
    }

    // Pattern: Mass Assignment
    if (!/^\s*(?:description|hypothesis|message|summary|detail|doc|comment|prompt|title)\w*\s*[:=]/i.test(line) &&
        !/^\s*['"`]/.test(line) &&
        !line.trim().startsWith('//') && !line.trim().startsWith('*') &&
        /(?:\.create|\.update|\.insert)\s*\(\s*(?:req\.body|request\.body|params)\s*\)/i.test(line)) {
      findings.push({
        ruleId: 'AUTH-005',
        severity: 'MEDIUM',
        title: 'Mass Assignment: Unfiltered Request Body Assigned to Model',
        file: relPath,
        line: i + 1,
        snippet: line.trim(),
        description: 'Entire request body is passed directly to database mutation. Attackers can inject privileged fields (e.g. role, isAdmin, balance).',
        remediation: 'Use a strict DTO or pick only allowed fields: const { name, bio } = req.body; await db.user.update({ data: { name, bio } });'
      });
    }

    // Pattern: Sensitive Data Exposure in API response
    if (!line.includes('.test(') && /(?:res\.json|Response\.json)\s*\(?.*?(?:password_hash|passwordHash|hashed_password|salt|secret_key)\b/i.test(line)) {
      findings.push({
        ruleId: 'AUTH-007',
        severity: 'HIGH',
        title: 'Sensitive Data Exposure: Password Hash or Secret in Response',
        file: relPath,
        line: i + 1,
        snippet: line.trim(),
        description: 'Response payload appears to serialize sensitive user attributes such as password_hash or salt.',
        remediation: 'Exclude password hashes and internal credentials before returning user models: delete user.password_hash or use a sanitized DTO.'
      });
    }
  }

  return findings;
}
