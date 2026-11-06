import fs from 'fs';
import path from 'path';

/**
 * API & Authorization Scanner
 * Detects Shadow APIs, Missing Auth, BOLA / IDOR, Insecure Server Actions,
 * Unthrottled Auth Endpoints, and Sensitive Data Exposure.
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

const AUTH_MIDDLEWARE_SIGNALS = [
  /auth/i,
  /session/i,
  /jwt/i,
  /bearer/i,
  /token/i,
  /passport/i,
  /guard/i,
  /verify/i,
  /protect/i,
  /checkrole/i,
  /requirelogin/i,
  /current_user/i,
  /get_current_user/i,
  /depends\(.*auth/i,
  /security/i
];

const RATE_LIMIT_SIGNALS = [
  /ratelimit/i,
  /limiter/i,
  /throttle/i,
  /slowdown/i,
  /quota/i,
  /bottleneck/i
];

export function scanApiAuth(file) {
  const findings = [];
  let content;
  try {
    content = fs.readFileSync(file.path, 'utf8');
  } catch {
    return findings;
  }

  // Skip test files for auth heuristics
  if (file.relative.includes('test/') || file.relative.includes('tests/')) {
    return findings;
  }

  const lines = content.split('\n');
  const relPath = file.relative.replace(/\\/g, '/');

  // 1. Next.js App Router API Routes: app/api/**/route.(ts|js)
  if (relPath.includes('app/api/') && /route\.(ts|js|mjs)$/.test(relPath)) {
    const routeUrl = '/' + relPath.replace(/^.*app\//, '').replace(/\/route\.(ts|js|mjs)$/, '');
    const isAdmin = ADMIN_ROUTE_PATTERNS.some(p => p.test(routeUrl));
    
    // Check if handlers exist (GET, POST, PUT, DELETE, PATCH)
    const handlerRegex = /export\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)\s*\(/g;
    let match;
    while ((match = handlerRegex.exec(content)) !== null) {
      const method = match[1];
      const matchIndex = match.index;
      const lineNo = content.slice(0, matchIndex).split('\n').length;
      
      const handlerBody = lines.slice(lineNo - 1, lineNo + 40).join('\n');
      const hasAuth = AUTH_MIDDLEWARE_SIGNALS.some(s => s.test(handlerBody));

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
  if (content.includes("'use server'") || content.includes('"use server"')) {
    const actionRegex = /export\s+async\s+function\s+([a-zA-Z0-9_]+)\s*\(/g;
    let actMatch;
    while ((actMatch = actionRegex.exec(content)) !== null) {
      const fnName = actMatch[1];
      const lineNo = content.slice(0, actMatch.index).split('\n').length;
      const fnBody = lines.slice(lineNo - 1, lineNo + 35).join('\n');
      
      const hasMutation = /prisma\.|db\.|query\(|delete|update|create|insert/i.test(fnBody);
      const hasAuth = AUTH_MIDDLEWARE_SIGNALS.some(s => s.test(fnBody));

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

  // 3. Express Route Patterns: (router|app).(get|post|put|delete)('/path', ...)
  if (/\b(router|app)\.(get|post|put|delete|patch)\s*\(/i.test(content)) {
    const expressRegex = /\b(router|app)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*([^)]+)\)/g;
    let expMatch;
    while ((expMatch = expressRegex.exec(content)) !== null) {
      const method = expMatch[2].toUpperCase();
      const routePath = expMatch[3];
      const middlewareChain = expMatch[4];
      const lineNo = content.slice(0, expMatch.index).split('\n').length;

      const isAdmin = ADMIN_ROUTE_PATTERNS.some(p => p.test(routePath));
      const hasAuth = AUTH_MIDDLEWARE_SIGNALS.some(s => s.test(middlewareChain));
      const isLoginOrAuth = /login|signin|auth\/token|password\/reset/i.test(routePath);
      const hasRateLimit = RATE_LIMIT_SIGNALS.some(s => s.test(middlewareChain) || s.test(content));

      if (isAdmin && !hasAuth) {
        findings.push({
          ruleId: 'AUTH-001',
          severity: 'CRITICAL',
          title: `Express Admin Endpoint Missing Auth Middleware: ${method} ${routePath}`,
          file: relPath,
          line: lineNo,
          snippet: lines[lineNo - 1]?.trim(),
          description: `Express endpoint "${routePath}" looks like an administrative API but lacks authentication middleware in its route definition chain.`,
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
    const pyRouteRegex = /@(app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]/g;
    let pyMatch;
    while ((pyMatch = pyRouteRegex.exec(content)) !== null) {
      const method = pyMatch[2].toUpperCase();
      const routePath = pyMatch[3];
      const lineNo = content.slice(0, pyMatch.index).split('\n').length;
      const fnSignature = lines.slice(lineNo - 1, lineNo + 10).join('\n');

      const isAdmin = ADMIN_ROUTE_PATTERNS.some(p => p.test(routePath));
      const hasAuth = AUTH_MIDDLEWARE_SIGNALS.some(s => s.test(fnSignature));

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

  // 5. BOLA / IDOR Pattern & Sensitive Data Exposure
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    // Pattern: findById(req.params.id) without owner check
    if (/(?:findById|findByPk|filter_by\(id=|\.filter\([a-zA-Z_]+\.id\s*==\s*id)\s*\(/i.test(line)) {
      const contextBlock = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 15)).join('\n');
      const hasOwnerCheck = /user_id|userId|tenant_id|tenantId|owner_id|ownerId|org_id|accountId|req\.user|current_user/i.test(contextBlock);

      if (!hasOwnerCheck && !line.includes('//') && !line.includes('#')) {
        findings.push({
          ruleId: 'AUTH-003',
          severity: 'HIGH',
          title: 'Potential BOLA / IDOR: Object Query without Ownership Scope',
          file: relPath,
          line: i + 1,
          snippet: line.trim(),
          description: 'Database query queries an object directly by identifier without validating ownership against the authenticated user/tenant session.',
          remediation: 'Scope the query to the authenticated user: db.item.findFirst({ where: { id, userId: req.user.id } })'
        });
        break;
      }
    }

    // Pattern: Mass Assignment
    if (/(?:\.create|\.update|\.insert)\s*\(\s*(?:req\.body|request\.body|params)\s*\)/i.test(line)) {
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
      break;
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
      break;
    }
  }

  return findings;
}
