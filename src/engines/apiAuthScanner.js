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
  /security/i,
  /(?:require|ensure|is|check)(?:org|user|admin|role|perm|platform|member|auth|access)/i
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
      const isLoginOrAuth = /(?:^|\/)(?:auth\/)?(?:login|signin|token|authenticate|password\/reset)(?:\/|$)/i.test(routePath) && !/crawl|operator|live-login/i.test(routePath);
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

  // 5. C# / ASP.NET Core Controllers & Minimal APIs
  if (file.ext === '.cs') {
    const isController = /class\s+\w+Controller\b|:\s*(?:ControllerBase|Controller)\b|\[ApiController\]/.test(content);
    if (isController) {
      const classRouteMatch = content.match(/\[Route\(\s*["']([^"']+)["']\s*\)\]/i);
      const classRoute = classRouteMatch ? classRouteMatch[1] : '';
      const classHeader = content.slice(0, content.indexOf('class ')).replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
      const classHasAuthorize = /\[Authorize(?:\([^)]*\))?\]/i.test(classHeader);

      const actionRegex = /\[(HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route)(?:\(\s*["']?([^"')\s]*)["']?\s*\))?\](?:\s*\[[^\]]+\])*\s*(?:public|protected)\s+(?:async\s+)?(?:Task<[A-Za-z0-9_<>,\s]+>|[A-Za-z0-9_<>]+)\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)/g;
      let actMatch;
      while ((actMatch = actionRegex.exec(content)) !== null) {
        const httpAttr = actMatch[1];
        const subRoute = actMatch[2] || '';
        const actionName = actMatch[3];
        const methodParams = actMatch[4] || '';
        const methodLineNo = content.slice(0, actMatch.index).split('\n').length;
        const method = httpAttr === 'Route' ? 'ANY' : httpAttr.replace(/^Http/, '').toUpperCase();

        const fullRoute = ('/' + classRoute + '/' + subRoute).replace(/\/+/g, '/').replace(/\/$/, '');
        const prevBrace = content.lastIndexOf('}', actMatch.index);
        const headerStartIndex = prevBrace === -1 ? Math.max(0, actMatch.index - 300) : prevBrace + 1;
        const rawMethodAttributes = content.slice(headerStartIndex, actMatch.index);
        const cleanMethodAttributes = rawMethodAttributes.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
        const methodHasAuthorize = /\[Authorize(?:\([^)]*\))?\]/i.test(cleanMethodAttributes);
        const methodHasAllowAnonymous = /\[AllowAnonymous\]/i.test(cleanMethodAttributes);

        const isAuthorized = (classHasAuthorize || methodHasAuthorize) && !methodHasAllowAnonymous;
        const isAdmin = ADMIN_ROUTE_PATTERNS.some(p => p.test(fullRoute)) || /admin/i.test(actionName);

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
    while ((minMatch = minimalApiRegex.exec(content)) !== null) {
      const caller = minMatch[1];
      const httpVerb = minMatch[2].replace(/^Map/, '').toUpperCase();
      const routePath = minMatch[3];
      const lineNo = content.slice(0, minMatch.index).split('\n').length;

      // Extract statement chain up to semicolon or next 600 chars
      const chainSlice = content.slice(minMatch.index, Math.min(content.length, minMatch.index + 600));
      const statementChain = chainSlice.split(';')[0];

      const hasAuth = /\.RequireAuthorization\s*\(/i.test(statementChain) || /\[Authorize(?:\([^)]*\))?\]/i.test(statementChain);
      const hasAllowAnonymous = /\.AllowAnonymous\s*\(/i.test(statementChain) || /\[AllowAnonymous\]/i.test(statementChain);
      const isGroupAuthorized = new RegExp(`\\b${caller}\\s*=[^;]*\\.RequireAuthorization\\s*\\(`, 'i').test(content);

      const isAuthorized = (hasAuth || isGroupAuthorized) && !hasAllowAnonymous;
      const isAdmin = ADMIN_ROUTE_PATTERNS.some(p => p.test(routePath)) || /admin/i.test(routePath);
      const hasFileUpload = /\b(?:IFormFile|IFormFileCollection|IEnumerable<IFormFile>|List<IFormFile>)\b/i.test(statementChain) ||
        /\b(?:Request\.Form\.Files|InitiateMultipartUpload|UploadPart|CompleteMultipartUpload|GetPreSignedURL)/i.test(statementChain);

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
    if (/\b(?:app|builder)\.UseSwaggerUI\s*\(/i.test(content)) {
      const swaggerMatch = content.match(/\b(?:app|builder)\.UseSwaggerUI\s*\(/);
      if (swaggerMatch) {
        const prevCode = content.slice(Math.max(0, swaggerMatch.index - 350), swaggerMatch.index);
        const hasDevCheck = /IsDevelopment\s*\(\s*\)/i.test(prevCode) || /IsEnvironment\s*\(\s*["']Development["']\s*\)/i.test(prevCode);
        if (!hasDevCheck) {
          const lineNo = content.slice(0, swaggerMatch.index).split('\n').length;
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
  }

  // 6. Java Spring Boot Controllers
  if (file.ext === '.java') {
    const isSpringController = /@RestController|@Controller/.test(content);
    if (isSpringController) {
      const classMappingMatch = content.match(/@RequestMapping\(\s*(?:value\s*=\s*)?["']([^"']+)["']/i);
      const classRoute = classMappingMatch ? classMappingMatch[1] : '';
      const classHeader = content.slice(0, content.indexOf('class ')).replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
      const classHasAuth = /@PreAuthorize|@Secured|@RolesAllowed/.test(classHeader);

      const methodRegex = /@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)(?:\(\s*(?:value\s*=\s*)?["']([^"']+)["']\s*\))?(?:\s*@[A-Za-z0-9_]+(?:\([^)]*\))?)*\s*(?:public|protected)\s+(?:ResponseEntity<[A-Za-z0-9_<>,\s]+>|[A-Za-z0-9_<>]+)\s+([A-Za-z0-9_]+)/g;
      let jMatch;
      while ((jMatch = methodRegex.exec(content)) !== null) {
        const ann = jMatch[1];
        const subRoute = jMatch[2] || '';
        const methodName = jMatch[3];
        const methodLineNo = content.slice(0, jMatch.index).split('\n').length;
        const method = ann === 'RequestMapping' ? 'ANY' : ann.replace(/Mapping$/, '').toUpperCase();

        const fullRoute = ('/' + classRoute + '/' + subRoute).replace(/\/+/g, '/').replace(/\/$/, '');
        const prevBrace = content.lastIndexOf('}', jMatch.index);
        const headerStartIndex = prevBrace === -1 ? Math.max(0, jMatch.index - 250) : prevBrace + 1;
        const rawMethodAttributes = content.slice(headerStartIndex, jMatch.index);
        const cleanMethodAttributes = rawMethodAttributes.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
        const methodHasAuth = /@PreAuthorize|@Secured|@RolesAllowed/.test(cleanMethodAttributes);

        const isAuthorized = classHasAuth || methodHasAuth;
        const isAdmin = ADMIN_ROUTE_PATTERNS.some(p => p.test(fullRoute)) || /admin/i.test(methodName);

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
  }

  // 7. Insecure CORS Configuration: Wildcard / Dynamic Origin with Credentials (AUTH-009)
  if (file.ext === '.cs') {
    const csharpCorsRegex = /(?:AllowAnyOrigin\s*\([^)]*\)[\s\S]{0,150}\.AllowCredentials\s*\(|\.SetIsOriginAllowed\s*\(\s*[^)]*=>\s*true\s*\)[\s\S]{0,150}\.AllowCredentials\s*\(|\.AllowCredentials\s*\(\)[\s\S]{0,150}\.SetIsOriginAllowed\s*\(\s*[^)]*=>\s*true\s*\))/i;
    const corsMatch = content.match(csharpCorsRegex);
    if (corsMatch) {
      const lineNo = content.slice(0, corsMatch.index).split('\n').length;
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
    const match = content.match(nodeCorsRegex);
    if (match) {
      const lineNo = content.slice(0, match.index).split('\n').length;
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
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    // Pattern: findById(req.params.id) / EF Core FindAsync(id) / Spring Data findById without owner check
    if (/(?:findById|findByPk)\s*\([^)]*?(?:id|req\.params|\$id)|\.FindAsync\s*\(\s*(?:id|orderId|userId|accountId|itemId)\b|\.FirstOrDefault(?:Async)?\s*\(\s*[a-zA-Z0-9_]+\s*=>\s*[a-zA-Z0-9_]+\.Id\s*==\s*id\b|filter_by\(id=|\.filter\([a-zA-Z_]+\.id\s*==\s*id/i.test(line)) {
      const contextBlock = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 15)).join('\n');
      const hasOwnerCheck = /user_id|userId|tenant_id|tenantId|owner_id|ownerId|org_id|accountId|req\.user|current_user|User\.FindFirst|ClaimsPrincipal|User\.Identity/i.test(contextBlock);

      if (!hasOwnerCheck && !line.includes('//') && !line.includes('#') &&
          !/^\s*['"`]/.test(line) &&
          !/(?:vulnerableCode|content|example|sample|snippet|pattern|description|hypothesis|title|lineNumber|isTarget)\s*[:=]/i.test(line)) {
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
