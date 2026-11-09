import fs from 'fs';

/**
 * Business Logic & Authorization Integrity Scanner
 * Detects deep semantic flaws:
 * - LOGIC-001: Workflow / Payment State Evasion via Client Payload
 * - LOGIC-002: TOCTOU & Non-Atomic Race Conditions in Balances/Coupons
 * - LOGIC-003: Negative Quantity or Price Manipulation
 * - LOGIC-004: Insecure JWT Verification (Missing Algorithm Whitelist)
 * - LOGIC-005: Client-Only Logout / Missing Server Session Revocation
 */

const LOGIC_RULES = [
  {
    id: 'LOGIC-001',
    severity: 'HIGH',
    title: 'Multi-Step Workflow / Payment Status Evasion via Client Payload',
    description: 'Endpoint trusts client-supplied state flags (e.g. is_paid, payment_status, approved, step) to verify business transactions instead of server-verified state.',
    remediation: 'Enforce a server-side state machine. Never allow client payloads to set payment or approval status directly.',
    test: (line, content) => {
      if (line.includes('//') || line.includes('test(') || line.includes('ruleId')) return false;
      return /(?:req\.body\.(?:is_?paid|payment_?status|approved|is_?verified)|order\.(?:isPaid|status)\s*=\s*req\.body)/i.test(line);
    }
  },
  {
    id: 'LOGIC-002',
    severity: 'HIGH',
    title: 'Potential TOCTOU Race Condition on Balance / Coupon State',
    description: 'Non-atomic check-then-act operation detected on financial balance or one-time coupon. Concurrent requests can cause double-spending.',
    remediation: 'Use database transactions with row-level locks (e.g. SELECT FOR UPDATE) or atomic conditional updates (e.g. UPDATE coupons SET used=true WHERE id=? AND used=false).',
    test: (line, content, lines, idx) => {
      if (line.includes('//') || line.includes('test(') || line.includes('ruleId')) return false;
      const window = lines.slice(idx, Math.min(lines.length, idx + 10)).join('\n');
      return /(?:if\s*\([^)]*balance\s*>=?[^)]*\)[\s\S]{0,120}balance\s*-=|coupon\.isUsed\s*===\s*false[\s\S]{0,120}coupon\.isUsed\s*=\s*true)/i.test(window);
    }
  },
  {
    id: 'LOGIC-003',
    severity: 'HIGH',
    title: 'Unchecked Numeric Input: Potential Negative Price / Quantity Tampering',
    description: 'Calculation multiplies or assigns item quantity or price directly from request input without validating that it is a positive integer.',
    remediation: 'Validate that all quantities and prices are positive numbers greater than zero before performing calculations.',
    test: (line, content) => {
      if (line.includes('//') || line.includes('test(') || line.includes('ruleId')) return false;
      return /(?:total\s*\+?=\s*[^;]*\*\s*req\.body\.quantity|price\s*:\s*req\.body\.price)/i.test(line);
    }
  },
  {
    id: 'LOGIC-004',
    severity: 'HIGH',
    title: 'Insecure JWT Verification: Missing Algorithm Whitelist',
    description: 'jwt.verify() is called without explicitly specifying allowed algorithms, making the application vulnerable to algorithm confusion attacks or "none" algorithm bypass.',
    remediation: 'Pass an explicit algorithm whitelist: jwt.verify(token, secret, { algorithms: ["HS256"] }).',
    test: (line, content) => {
      if (line.includes('//') || line.includes('test(') || line.includes('ruleId') || line.includes('algorithms')) return false;
      return /jwt\.verify\s*\(\s*[\w$]+\s*,\s*[\w$]+\s*\)/.test(line);
    }
  },
  {
    id: 'LOGIC-005',
    severity: 'MEDIUM',
    title: 'Client-Only Logout: Missing Server-Side Session Revocation',
    description: 'Logout route merely clears client cookies without invalidating the session token in the server-side store or JWT revocation blocklist.',
    remediation: 'Invalidate the server-side session or record the JWT identifier (jti) in a token revocation blacklist on logout.',
    test: (line, content) => {
      if (line.includes('//') || line.includes('test(') || line.includes('ruleId')) return false;
      return /(?:router|app)\.(?:post|get)\s*\(\s*['"]\/(?:api\/)?(?:auth\/)?(?:log(?:out|off|in-out)|sign(?:out|-out))/i.test(line) &&
        !content.includes('revoke') && !content.includes('blacklist') && !content.includes('destroy') && !content.includes('deleteSession');
    }
  }
];

export async function scanBusinessLogic(file, allFiles = [], options = {}) {
  const findings = [];
  const ext = file.ext.toLowerCase();

  // Only scan application logic files
  if (!['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.py', '.php', '.go'].includes(ext)) {
    return findings;
  }

  // Skip vendor / test files
  const relPath = file.relative.replace(/\\/g, '/');
  if (relPath.includes('node_modules') || relPath.includes('test/') || relPath.includes('tests/')) {
    return findings;
  }

  let content;
  try {
    content = fs.readFileSync(file.path, 'utf8');
  } catch {
    return findings;
  }

  const lines = content.split('\n');

  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx];

    for (const rule of LOGIC_RULES) {
      if (rule.test(line, content, lines, idx)) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          title: rule.title,
          file: relPath,
          line: idx + 1,
          snippet: line.trim(),
          description: rule.description,
          remediation: rule.remediation
        });
      }
    }
  }

  return findings;
}
