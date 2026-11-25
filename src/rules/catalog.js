/**
 * Rule catalog: the single description of every built-in rule.
 *
 * Engines own detection; this file owns metadata (category, default severity,
 * CWE, confidence). The `rules` command, SARIF rule metadata and finding
 * enrichment are all generated from here, and a test keeps it in sync with
 * the engines and the README.
 *
 * confidence: how often a match is a real issue without human review.
 *   HIGH   - exact pattern or configuration value
 *   MEDIUM - single-line code pattern with some context
 *   LOW    - heuristic over naming or nearby lines; expect to triage
 */

const CATEGORIES = [
  ['API & Authorization', [
    ['AUTH-001', 'CRITICAL', 'MEDIUM', 'CWE-306', 'Shadow Admin Route Missing Auth Middleware'],
    ['AUTH-002', 'HIGH', 'MEDIUM', 'CWE-306', 'State-Modifying Route Without Authentication'],
    ['AUTH-003', 'HIGH', 'LOW', 'CWE-639', 'Potential BOLA / IDOR Unscoped Object Query'],
    ['AUTH-004', 'HIGH', 'MEDIUM', 'CWE-862', 'Server Action Missing Identity Check'],
    ['AUTH-005', 'MEDIUM', 'MEDIUM', 'CWE-915', 'Mass Assignment in Request Body Handling'],
    ['AUTH-006', 'HIGH', 'LOW', 'CWE-307', 'Unthrottled Authentication Endpoint (Brute-Force Risk)'],
    ['AUTH-007', 'HIGH', 'MEDIUM', 'CWE-200', 'Sensitive Data Exposure (Password Hash in Response)'],
    ['AUTH-008', 'HIGH', 'MEDIUM', 'CWE-306', 'Unauthenticated File Upload Endpoint'],
    ['AUTH-009', 'HIGH', 'HIGH', 'CWE-942', 'Insecure CORS Policy (Arbitrary Origin with Credentials)']
  ]],
  ['Business Logic & Workflows', [
    ['LOGIC-001', 'HIGH', 'MEDIUM', 'CWE-841', 'Multi-Step Workflow / Payment Status Evasion via Client Payload'],
    ['LOGIC-002', 'HIGH', 'LOW', 'CWE-367', 'Potential TOCTOU Race Condition on Balance / Coupon State'],
    ['LOGIC-003', 'HIGH', 'MEDIUM', 'CWE-20', 'Unchecked Numeric Input: Negative Price / Quantity Tampering'],
    ['LOGIC-004', 'HIGH', 'MEDIUM', 'CWE-347', 'Insecure JWT Verification: Missing Algorithm Whitelist'],
    ['LOGIC-005', 'MEDIUM', 'LOW', 'CWE-613', 'Client-Only Logout: Missing Server-Side Session Revocation'],
    ['LOGIC-006', 'CRITICAL', 'HIGH', 'CWE-347', 'Disabled JWT Signature or Expiration Validation']
  ]],
  ['OpenAPI & API Spec Contracts', [
    ['SPEC-001', 'HIGH', 'MEDIUM', 'CWE-306', 'Unprotected Sensitive Operation in API Spec'],
    ['SPEC-002', 'HIGH', 'MEDIUM', 'CWE-306', 'Explicit Public Security Override (security: []) on Restricted Route'],
    ['SPEC-003', 'HIGH', 'MEDIUM', 'CWE-598', 'Sensitive Credential Passed via URL Query Parameter'],
    ['SPEC-004', 'MEDIUM', 'HIGH', 'CWE-319', 'Insecure Cleartext Transport (HTTP) in Server URL'],
    ['SPEC-005', 'MEDIUM', 'MEDIUM', 'CWE-200', 'Unconditional Swagger UI Registration in Production']
  ]],
  ['SAST & Intra-file Taint', [
    ['SAST-001', 'CRITICAL', 'MEDIUM', 'CWE-89', 'SQL Injection: Dynamic Query Construction with User Input'],
    ['SAST-002', 'CRITICAL', 'MEDIUM', 'CWE-78', 'Command Injection: Untrusted Input in System Shell Call'],
    ['SAST-003', 'CRITICAL', 'MEDIUM', 'CWE-95', 'Dangerous Code Execution via eval() / new Function()'],
    ['SAST-004', 'HIGH', 'LOW', 'CWE-918', 'Server-Side Request Forgery (SSRF)'],
    ['SAST-005', 'HIGH', 'MEDIUM', 'CWE-22', 'Path Traversal: Arbitrary File Read / Include'],
    ['SAST-006', 'HIGH', 'MEDIUM', 'CWE-79', 'Cross-Site Scripting (XSS): dangerouslySetInnerHTML / DOM write'],
    ['SAST-007', 'CRITICAL', 'MEDIUM', 'CWE-502', 'Insecure Deserialization (pickle / unsafe yaml)'],
    ['SAST-008', 'HIGH', 'HIGH', 'CWE-295', 'Disabled TLS Certificate Verification'],
    ['SAST-009', 'MEDIUM', 'MEDIUM', 'CWE-328', 'Weak Cryptographic Hash (MD5 / SHA-1)'],
    ['SAST-011', 'MEDIUM', 'MEDIUM', 'CWE-601', 'Open Redirect: Unvalidated URL in Redirect Call'],
    ['SAST-012', 'HIGH', 'MEDIUM', 'CWE-434', 'Arbitrary File Upload: Unsanitized File Name in Path'],
    ['TAINT-001', 'CRITICAL', 'MEDIUM', 'CWE-78', 'Taint Flow: Request Input Reaches Command Execution (RCE)'],
    ['TAINT-002', 'CRITICAL', 'MEDIUM', 'CWE-89', 'Taint Flow: Request Input Reaches Raw SQL Query'],
    ['TAINT-003', 'HIGH', 'MEDIUM', 'CWE-22', 'Taint Flow: Request Input Reaches File System Read'],
    ['TAINT-004', 'HIGH', 'MEDIUM', 'CWE-918', 'Taint Flow: Request Input Reaches Outbound HTTP Call (SSRF)']
  ]],
  ['Secrets & Tokens', [
    ['SEC-001', 'CRITICAL', 'HIGH', 'CWE-798', 'AWS Access Key ID Exposure'],
    ['SEC-002', 'CRITICAL', 'HIGH', 'CWE-798', 'GitHub Personal Access Token Exposure'],
    ['SEC-003', 'CRITICAL', 'MEDIUM', 'CWE-798', 'OpenAI API Secret Key Exposure'],
    ['SEC-004', 'CRITICAL', 'HIGH', 'CWE-798', 'Stripe Live Secret Key Exposure'],
    ['SEC-005', 'HIGH', 'HIGH', 'CWE-798', 'Slack Bot / Webhook Token Exposure'],
    ['SEC-006', 'HIGH', 'HIGH', 'CWE-798', 'Google Cloud API Key Exposure'],
    ['SEC-007', 'CRITICAL', 'MEDIUM', 'CWE-798', 'Database Connection String with Credentials'],
    ['SEC-008', 'CRITICAL', 'HIGH', 'CWE-321', 'Private Cryptographic Key in Source'],
    ['SEC-009', 'CRITICAL', 'HIGH', 'CWE-798', 'Anthropic API Key Exposure'],
    ['SEC-010', 'HIGH', 'LOW', 'CWE-798', 'Generic High-Entropy Secret / Token Exposure']
  ]],
  ['Container & Cloud IaC', [
    ['IAC-001', 'MEDIUM', 'HIGH', 'CWE-250', 'Container Default Execution as Root'],
    ['IAC-002', 'HIGH', 'HIGH', 'CWE-494', 'Insecure Remote Script Pipe (curl | sh)'],
    ['IAC-003', 'HIGH', 'MEDIUM', 'CWE-668', 'Exposed Database Port in Container Manifest'],
    ['IAC-004', 'CRITICAL', 'HIGH', 'CWE-250', 'Docker Daemon Socket Mounted into Container'],
    ['IAC-005', 'HIGH', 'HIGH', 'CWE-250', 'Privileged Container Mode in Docker Compose'],
    ['IAC-006', 'CRITICAL', 'HIGH', 'CWE-732', 'Public S3 Bucket in Terraform'],
    ['IAC-007', 'CRITICAL', 'MEDIUM', 'CWE-284', 'Sensitive Port Open to 0.0.0.0/0 in Security Group'],
    ['IAC-008', 'HIGH', 'HIGH', 'CWE-250', 'Kubernetes Pod with Host Network or Host PID'],
    ['IAC-009', 'HIGH', 'HIGH', 'CWE-269', 'Kubernetes Container Allows Privilege Escalation'],
    ['IAC-010', 'CRITICAL', 'MEDIUM', 'CWE-798', 'Secret Baked into Dockerfile ENV Instruction'],
    ['IAC-011', 'MEDIUM', 'HIGH', 'CWE-311', 'Unencrypted Storage Volume / Database in Terraform']
  ]],
  ['App Configuration Security', [
    ['CONF-001', 'HIGH', 'HIGH', 'CWE-295', 'Disabled Database TLS Certificate Validation (TrustServerCertificate=True)'],
    ['CONF-002', 'MEDIUM', 'HIGH', 'CWE-209', 'DetailedErrors Enabled in Application Configuration'],
    ['CONF-003', 'MEDIUM', 'HIGH', 'CWE-209', 'CustomErrors Mode Set to Off in Web.config']
  ]],
  ['Mobile Application Security', [
    ['MOBILE-001', 'HIGH', 'HIGH', 'CWE-319', 'Insecure Cleartext Traffic Allowed (Android / iOS ATS)'],
    ['MOBILE-002', 'MEDIUM', 'HIGH', 'CWE-276', 'Broad External Storage Permission Requested in AndroidManifest']
  ]],
  ['AI Agent & MCP Tools', [
    ['MCP-001', 'CRITICAL', 'MEDIUM', 'CWE-78', 'Unsandboxed Shell Execution Tool in MCP Config'],
    ['MCP-002', 'HIGH', 'MEDIUM', 'CWE-732', 'Unrestricted Root Filesystem Path in MCP Server'],
    ['MCP-003', 'CRITICAL', 'MEDIUM', 'CWE-798', 'Hardcoded Secret in MCP Server Config'],
    ['MCP-004', 'MEDIUM', 'LOW', 'CWE-77', 'Prompt Injection Concatenation in System Instructions'],
    ['MCP-005', 'HIGH', 'MEDIUM', 'CWE-1427', 'Hidden Instruction in MCP Tool Description (Tool Poisoning)']
  ]],
  ['Supply Chain', [
    ['SUPPLY-001', 'CRITICAL', 'MEDIUM', 'CWE-506', 'Lifecycle Script Exfiltration Risk in package.json'],
    ['SUPPLY-002', 'HIGH', 'HIGH', 'CWE-829', 'Unpinned Git Repository Dependency']
  ]]
];

export const RULE_CATALOG = CATEGORIES.flatMap(([category, rows]) =>
  rows.map(([id, severity, confidence, cwe, title]) => ({ id, category, severity, confidence, cwe, title }))
);

const BY_ID = new Map(RULE_CATALOG.map(r => [r.id, r]));

/** Catalog entry for a rule id; CVE-* / GHSA-* ids map to a shared SCA entry. */
export function getRule(ruleId) {
  if (BY_ID.has(ruleId)) return BY_ID.get(ruleId);
  if (/^(?:CVE|GHSA|PYSEC|GO|RUSTSEC|OSV)-/i.test(ruleId || '')) {
    return { id: ruleId, category: 'SCA & Known Vulnerabilities', confidence: 'HIGH', cwe: 'CWE-1395', title: 'Known Vulnerable Dependency' };
  }
  return null;
}

export function getCategories() {
  return CATEGORIES.map(([category]) => ({
    category,
    rules: RULE_CATALOG.filter(r => r.category === category)
  }));
}

/** Adds catalog metadata to a finding without overriding what the engine set. */
export function enrichFinding(finding) {
  const rule = getRule(finding.ruleId);
  if (!rule) {
    if (!finding.confidence) finding.confidence = 'MEDIUM';
    return finding;
  }
  if (!finding.cwe && rule.cwe) finding.cwe = rule.cwe;
  if (!finding.confidence) finding.confidence = rule.confidence;
  if (!finding.category) finding.category = rule.category;
  return finding;
}
