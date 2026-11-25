import { readText, getLines, isTestPath } from '../utils/fileContext.js';

/**
 * Secret Scanner with Precision Regexes and Automatic Redaction.
 */

export const SECRET_RULES = [
  {
    id: 'SEC-001',
    name: 'AWS Access Key ID',
    severity: 'CRITICAL',
    type: 'aws_key',
    regex: /\b(AKIA|ASIA|AROA|AIPA)[A-Z0-9]{16}\b/g
  },
  {
    id: 'SEC-002',
    name: 'GitHub Personal Access Token',
    severity: 'CRITICAL',
    type: 'github_pat',
    regex: /\b(ghp_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82})\b/g
  },
  {
    id: 'SEC-003',
    name: 'OpenAI API Secret Key',
    severity: 'CRITICAL',
    type: 'openai_key',
    regex: /\bsk-(?:proj-|live-)?[a-zA-Z0-9_-]{32,80}\b/g
  },
  {
    id: 'SEC-004',
    name: 'Stripe Live Secret Key',
    severity: 'CRITICAL',
    type: 'stripe_key',
    regex: /\b(sk_live_[0-9a-zA-Z]{24,34}|rk_live_[0-9a-zA-Z]{24,34})\b/g
  },
  {
    id: 'SEC-005',
    name: 'Slack Bot / Webhook Token',
    severity: 'HIGH',
    type: 'slack_token',
    regex: /\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}|https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+)\b/g
  },
  {
    id: 'SEC-006',
    name: 'Google Cloud API Key',
    severity: 'HIGH',
    type: 'gcp_key',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g
  },
  {
    id: 'SEC-007',
    name: 'Database Connection String with Credentials',
    severity: 'CRITICAL',
    type: 'db_uri',
    regex: /\b(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis):\/\/[a-zA-Z0-9_]+:[^@\s/:]+@[a-zA-Z0-9.-]+(?::[0-9]+)?(?:\/[a-zA-Z0-9_.-]*)?|(?:Server|Data Source)\s*=[^\"'\r\n]+?;[^\"'\r\n]*?(?:User\s*Id|Uid|User)\s*=[^\"'\r\n]+?;[^\"'\r\n]*?(?:Password|Pwd)\s*=[^;\"'\r\n]+/gi
  },
  {
    id: 'SEC-008',
    name: 'Private Cryptographic Key',
    severity: 'CRITICAL',
    type: 'private_key',
    regex: /-----BEGIN\s+(?:RSA|OPENSSH|EC|PGP|DSA)?\s*PRIVATE\s+KEY-----/g
  },
  {
    id: 'SEC-009',
    name: 'Anthropic API Key',
    severity: 'CRITICAL',
    type: 'anthropic_key',
    regex: /\bsk-ant-api[0-9]{2}-[a-zA-Z0-9_\-]{80,100}\b/g
  },
  {
    id: 'SEC-010',
    name: 'Generic High-Entropy Secret / Token',
    severity: 'HIGH',
    type: 'high_entropy_secret',
    entropyThreshold: 3.8,
    regex: /(?:api[_-]?secret|api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key)\s*[:=]\s*['"]([a-zA-Z0-9_\-+/]{24,80})['"]/gi
  }
];

export function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const frequencies = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(frequencies)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function redactSecret(secret) {
  if (!secret || secret.length < 8) return '********';
  const prefix = secret.slice(0, 4);
  const suffix = secret.slice(-3);
  return `${prefix}${'*'.repeat(Math.max(6, secret.length - 7))}${suffix}`;
}

function compileAllowlist(patterns) {
  if (!Array.isArray(patterns)) return [];
  const compiled = [];
  for (const p of patterns) {
    try {
      compiled.push(new RegExp(p));
    } catch {
      // ignore invalid allowlist pattern
    }
  }
  return compiled;
}

/**
 * @param options.allowSecrets  regex strings; a match against the secret value or its
 *                              source line suppresses the finding (known test keys, etc.)
 */
export function scanSecrets(file, options = {}) {
  const findings = [];
  const allowlist = compileAllowlist(options.allowSecrets);
  const content = readText(file);
  if (content === null) return findings;

  // Skip files that usually have placeholders or tests
  if (isTestPath(file.relative) || file.relative.includes('.example')) {
    // If it's a test file, only report if it's not a generic dummy value
    if (content.includes('dummy') || content.includes('placeholder') || content.includes('fake')) {
      return findings;
    }
  }

  const lines = getLines(file);

  for (const rule of SECRET_RULES) {
    let match;
    const regex = new RegExp(rule.regex);
    while ((match = regex.exec(content)) !== null) {
      let secretValue = match[0];
      
      if (rule.entropyThreshold) {
        const token = match[1] || match[0];
        if (calculateShannonEntropy(token) < rule.entropyThreshold) {
          continue;
        }
        secretValue = token;
      }

      // Filter out obvious documentation or dummy examples
      if (/example|dummy|placeholder|your_key|my_secret|12345678/i.test(secretValue) || /X{6,}/.test(secretValue)) {
        continue;
      }

      const matchIndex = match.index;
      const lineNo = content.slice(0, matchIndex).split('\n').length;
      const lineText = lines[lineNo - 1] || '';

      if (allowlist.some(rx => rx.test(secretValue) || rx.test(lineText))) {
        continue;
      }

      const redactedSnippet = lineText.replace(secretValue, redactSecret(secretValue)).trim();

      const finding = {
        ruleId: rule.id,
        severity: rule.severity,
        title: `${rule.name} Exposed in Source`,
        file: file.relative.replace(/\\/g, '/'),
        line: lineNo,
        secretType: rule.type,
        snippet: redactedSnippet,
        description: `Found raw ${rule.name}. Hardcoded credentials can be exploited for unauthorized access or automated scraping.`,
        remediation: `Immediately revoke this credential, rotate it, and store it in environment variables or a Secret Manager (e.g. AWS Secrets Manager, Doppler).`
      };
      // Non-enumerable: available in memory for optional live verification, but never
      // serialized into JSON / SARIF / baseline output.
      Object.defineProperty(finding, 'rawSecret', { value: secretValue, enumerable: false });
      findings.push(finding);
    }
  }

  return findings;
}
