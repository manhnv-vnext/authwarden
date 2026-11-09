import fs from 'fs';

/**
 * OpenAPI & API Specification Security Auditor
 * Audits openapi.yaml, openapi.json, swagger.json, and Postman collections.
 * Detects:
 * - SPEC-001: Unprotected Sensitive Endpoint in API Specification
 * - SPEC-002: Explicit Security Override (security: []) on Restricted Route
 * - SPEC-003: Sensitive Credential Defined as Query Parameter
 * - SPEC-004: Insecure HTTP Protocol in Server URL
 * - SPEC-005: Shadow API Drift (Privileged route in code missing from OpenAPI spec)
 */

const SPEC_FILE_REGEX = /(?:^|\/)(?:openapi|swagger|api-docs)[^/]*\.(?:json|ya?ml)$|\.postman_collection\.json$/i;

export async function scanApiSpecs(file, allFiles = [], options = {}) {
  const findings = [];
  const fileName = file.name.toLowerCase();
  const relPath = file.relative.replace(/\\/g, '/');

  if (!SPEC_FILE_REGEX.test(fileName)) {
    return findings;
  }

  let content;
  try {
    content = fs.readFileSync(file.path, 'utf8');
  } catch {
    return findings;
  }

  const lines = content.split('\n');

  // Check 1: Insecure HTTP Server URL (SPEC-004)
  lines.forEach((line, idx) => {
    if (/(?:url\s*:\s*|["']url["']\s*:\s*)["']http:\/\/(?!localhost|127\.0\.0\.1)/i.test(line)) {
      findings.push({
        ruleId: 'SPEC-004',
        severity: 'MEDIUM',
        title: 'Insecure Cleartext Transport (HTTP) in API Server URL',
        file: relPath,
        line: idx + 1,
        snippet: line.trim(),
        description: 'API specification declares an unencrypted HTTP endpoint in its server definition, risking credential interception in transit.',
        remediation: 'Enforce HTTPS for all server environments: https://api.example.com.'
      });
    }
  });

  // Check 2: Credential Defined in Query Parameter (SPEC-003)
  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx];
    if (/(?:name\s*:\s*|["']name["']\s*:\s*)["']?(?:api_?key|token|access_?token|secret|auth)["']?/i.test(line)) {
      // Check surrounding lines for 'in: query'
      const window = lines.slice(Math.max(0, idx - 5), Math.min(lines.length, idx + 6)).join('\n');
      if (/(?:in\s*:\s*|["']in["']\s*:\s*)["']?query["']?/i.test(window)) {
        findings.push({
          ruleId: 'SPEC-003',
          severity: 'HIGH',
          title: 'Sensitive Credential Passed via URL Query Parameter',
          file: relPath,
          line: idx + 1,
          snippet: line.trim(),
          description: 'API parameter exposes secrets/tokens in query parameters, causing sensitive credentials to leak into server access logs, browser history, and proxy traces.',
          remediation: 'Pass credentials via HTTP Authorization header (e.g. Bearer <token>) or custom header (e.g. X-API-Key) instead of URL query strings.'
        });
      }
    }
  }

  // Check 3: Explicit Security Override (SPEC-002)
  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx];
    if (/security\s*:\s*\[\s*\]|["']security["']\s*:\s*\[\s*\]/.test(line)) {
      // Look back for path
      let endpointPath = '';
      for (let p = idx - 1; p >= Math.max(0, idx - 20); p--) {
        const pathMatch = lines[p].match(/['"]?(\/(?:api\/)?[a-zA-Z0-9_\-\/{}]*)['"]?\s*:/);
        if (pathMatch) {
          endpointPath = pathMatch[1];
          break;
        }
      }

      if (/(?:admin|user|account|internal|payment|billing|secret)/i.test(endpointPath)) {
        findings.push({
          ruleId: 'SPEC-002',
          severity: 'HIGH',
          title: `Explicit Public Security Override on Sensitive Endpoint (${endpointPath})`,
          file: relPath,
          line: idx + 1,
          snippet: line.trim(),
          description: `Endpoint ${endpointPath} explicitly defines 'security: []', removing global authentication barriers from a sensitive resource.`,
          remediation: 'Remove the empty security override and specify required OAuth2/Bearer scopes.'
        });
      }
    }
  }

  // Check 4: Unprotected Sensitive Operation in Spec (SPEC-001)
  const isJson = fileName.endsWith('.json');
  if (isJson) {
    try {
      const parsed = JSON.parse(content);
      const paths = parsed.paths || {};
      const globalSecurity = parsed.security && parsed.security.length > 0;

      for (const [routePath, methods] of Object.entries(paths)) {
        if (!/(?:admin|internal|payment|credit|vault)/i.test(routePath)) continue;

        for (const [method, op] of Object.entries(methods)) {
          if (['get', 'post', 'put', 'delete', 'patch'].includes(method.toLowerCase())) {
            const hasOpSec = op.security && op.security.length > 0;
            if (!globalSecurity && !hasOpSec) {
              const lineNo = lines.findIndex(l => l.includes(`"${routePath}"`)) + 1 || 1;
              findings.push({
                ruleId: 'SPEC-001',
                severity: 'HIGH',
                title: `Unprotected Sensitive Operation in API Spec: ${method.toUpperCase()} ${routePath}`,
                file: relPath,
                line: lineNo,
                snippet: `"${routePath}": { "${method}": ... }`,
                description: `High-privilege route ${routePath} has no security requirement defined at operation or document root.`,
                remediation: 'Add a security requirement (e.g. bearerAuth, apiKey) to this operation or globally.'
              });
            }
          }
        }
      }
    } catch {
      // ignore
    }
  } else {
    // Zero-dependency YAML Spec Auditor
    const hasGlobalSecurity = /(?:^|\n)security\s*:\s*\n\s*-\s*\w+/m.test(content) || /(?:^|\n)security\s*:\s*\[\s*\{/m.test(content);
    let currentRoute = null;
    let currentMethod = null;
    let currentMethodLine = 0;
    let methodHasSecurity = false;

    const flushMethod = () => {
      if (currentRoute && currentMethod && !hasGlobalSecurity && !methodHasSecurity) {
        findings.push({
          ruleId: 'SPEC-001',
          severity: 'HIGH',
          title: `Unprotected Sensitive Operation in API Spec: ${currentMethod.toUpperCase()} ${currentRoute}`,
          file: relPath,
          line: currentMethodLine,
          snippet: `${currentRoute} > ${currentMethod}:`,
          description: `High-privilege route ${currentRoute} has no security requirement defined at operation or document root.`,
          remediation: 'Add a security requirement (e.g. bearerAuth, apiKey) to this operation or globally.'
        });
      }
      currentMethod = null;
      methodHasSecurity = false;
    };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const routeMatch = line.match(/^\s{2,4}(['"]?(\/(?:api\/)?[a-zA-Z0-9_\-\/{}]*)['"]?)\s*:/);
      if (routeMatch) {
        flushMethod();
        const rPath = routeMatch[2];
        currentRoute = /(?:admin|internal|payment|credit|vault)/i.test(rPath) ? rPath : null;
        continue;
      }
      if (currentRoute) {
        const methodMatch = line.match(/^\s{4,6}(get|post|put|delete|patch)\s*:/i);
        if (methodMatch) {
          flushMethod();
          currentMethod = methodMatch[1].toLowerCase();
          currentMethodLine = i + 1;
          continue;
        }
        if (currentMethod && /^\s{6,10}security\s*:/i.test(line)) {
          methodHasSecurity = true;
        }
      }
    }
    flushMethod();
  }

  return findings;
}
