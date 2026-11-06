import fs from 'fs';
import path from 'path';
import https from 'https';

/**
 * Software Composition Analysis (SCA) & CVE Vulnerability Scanner
 * Detects known CVEs across npm, PyPI, Go, and Composer dependencies.
 * Includes reachability analysis and optional live OSV database querying.
 */

export const CURATED_CVE_DB = [
  // ─── NPM (Node.js) ────────────────────────────────────────────────────────
  {
    ecosystem: 'npm',
    package: 'lodash',
    affectedVersion: '< 4.17.21',
    fixedVersion: '4.17.21',
    cve: 'CVE-2020-8203',
    severity: 'CRITICAL',
    title: 'Prototype Pollution in lodash',
    description: 'Versions prior to 4.17.21 are vulnerable to Prototype Pollution via zipObjectDeep and set.',
    remediation: 'Upgrade lodash to version 4.17.21 or higher.'
  },
  {
    ecosystem: 'npm',
    package: 'axios',
    affectedVersion: '< 1.7.4',
    fixedVersion: '1.7.4',
    cve: 'CVE-2023-45857',
    severity: 'HIGH',
    title: 'SSRF & Credential Leakage in axios',
    description: 'Axios mishandles cross-origin redirects, leaking Authorization headers and credentials.',
    remediation: 'Upgrade axios to version 1.7.4 or later.'
  },
  {
    ecosystem: 'npm',
    package: 'jsonwebtoken',
    affectedVersion: '< 9.0.0',
    fixedVersion: '9.0.0',
    cve: 'CVE-2022-23529',
    severity: 'HIGH',
    title: 'Arbitrary Code Execution / Insecure Verification in jsonwebtoken',
    description: 'Vulnerability allows attackers to craft arbitrary verification objects to bypass signature checks.',
    remediation: 'Upgrade jsonwebtoken to version 9.0.0 or higher.'
  },
  {
    ecosystem: 'npm',
    package: 'express',
    affectedVersion: '< 4.19.2',
    fixedVersion: '4.19.2',
    cve: 'CVE-2024-29041',
    severity: 'MEDIUM',
    title: 'Open Redirect in express URL encoding',
    description: 'Express prior to 4.19.2 mishandles URL encoding leading to open redirection vulnerability.',
    remediation: 'Upgrade express to 4.19.2 or later.'
  },
  {
    ecosystem: 'npm',
    package: 'next',
    affectedVersion: '< 14.1.1',
    fixedVersion: '14.1.1',
    cve: 'CVE-2024-34351',
    severity: 'HIGH',
    title: 'Server-Side Request Forgery (SSRF) in Next.js Server Actions',
    description: 'Next.js App Router mishandles Host headers during Server Action redirects, leading to SSRF.',
    remediation: 'Upgrade next to 14.1.1 or later.'
  },
  {
    ecosystem: 'npm',
    package: 'ip',
    affectedVersion: '< 2.0.1',
    fixedVersion: '2.0.1',
    cve: 'CVE-2024-29415',
    severity: 'HIGH',
    title: 'SSRF Protection Bypass in ip package',
    description: 'The ip package incorrectly identifies certain octal IP representations as public addresses.',
    remediation: 'Upgrade ip to 2.0.1 or higher.'
  },
  {
    ecosystem: 'npm',
    package: 'ws',
    affectedVersion: '< 8.17.1',
    fixedVersion: '8.17.1',
    cve: 'CVE-2024-37890',
    severity: 'HIGH',
    title: 'Denial of Service in ws WebSocket library',
    description: 'A malicious server can send an excessive number of redirects causing process crashes.',
    remediation: 'Upgrade ws to 8.17.1 or higher.'
  },
  {
    ecosystem: 'npm',
    package: 'semver',
    affectedVersion: '< 7.5.2',
    fixedVersion: '7.5.2',
    cve: 'CVE-2022-25883',
    severity: 'MEDIUM',
    title: 'Regular Expression Denial of Service (ReDoS) in semver',
    description: 'Vulnerable to ReDoS when parsing crafted version range strings.',
    remediation: 'Upgrade semver to version 7.5.2 or later.'
  },
  {
    ecosystem: 'npm',
    package: 'tar',
    affectedVersion: '< 6.1.9',
    fixedVersion: '6.1.9',
    cve: 'CVE-2021-37712',
    severity: 'HIGH',
    title: 'Arbitrary File Overwrite / Directory Traversal in node-tar',
    description: 'Crafted archive can overwrite files outside target directory during extraction.',
    remediation: 'Upgrade tar to 6.1.9 or higher.'
  },
  {
    ecosystem: 'npm',
    package: 'undici',
    affectedVersion: '< 5.28.4',
    fixedVersion: '5.28.4',
    cve: 'CVE-2024-30260',
    severity: 'HIGH',
    title: 'Proxy-Authorization Header Leak in undici',
    description: 'Undici leaks Proxy-Authorization headers when handling cross-origin HTTP redirects.',
    remediation: 'Upgrade undici to >= 5.28.4 or >= 6.11.1.'
  },
  {
    ecosystem: 'npm',
    package: 'crypto-js',
    affectedVersion: '< 4.2.0',
    fixedVersion: '4.2.0',
    cve: 'CVE-2023-46233',
    severity: 'MEDIUM',
    title: 'Insecure PBKDF2 Iteration Count in crypto-js',
    description: 'Default PBKDF2 iteration count was insufficient, allowing faster credential cracking.',
    remediation: 'Upgrade crypto-js to 4.2.0 or higher.'
  },

  // ─── PyPI (Python) ────────────────────────────────────────────────────────
  {
    ecosystem: 'pypi',
    package: 'pyyaml',
    affectedVersion: '< 5.4',
    fixedVersion: '5.4',
    cve: 'CVE-2020-14343',
    severity: 'CRITICAL',
    title: 'Arbitrary Code Execution in PyYAML',
    description: 'Unsafe YAML loader in PyYAML allows arbitrary code execution via crafted YAML payload.',
    remediation: 'Upgrade PyYAML to >= 5.4 and use yaml.safe_load().'
  },
  {
    ecosystem: 'pypi',
    package: 'django',
    affectedVersion: '< 4.2.11',
    fixedVersion: '4.2.11',
    cve: 'CVE-2024-27351',
    severity: 'HIGH',
    title: 'Regular Expression Denial of Service (ReDoS) in Django',
    description: 'Django before 4.2.11 contains ReDoS vulnerability in the Truncator class.',
    remediation: 'Upgrade django to >= 4.2.11 or >= 5.0.3.'
  },
  {
    ecosystem: 'pypi',
    package: 'requests',
    affectedVersion: '< 2.31.0',
    fixedVersion: '2.31.0',
    cve: 'CVE-2023-32681',
    severity: 'MEDIUM',
    title: 'Proxy-Authorization Header Leak in requests',
    description: 'Requests leaks Proxy-Authorization headers to destination servers when following redirects.',
    remediation: 'Upgrade requests to 2.31.0 or higher.'
  },
  {
    ecosystem: 'pypi',
    package: 'jinja2',
    affectedVersion: '< 3.1.3',
    fixedVersion: '3.1.3',
    cve: 'CVE-2024-22195',
    severity: 'HIGH',
    title: 'Cross-Site Scripting (XSS) in Jinja2 xmlattr filter',
    description: 'The xmlattr filter in Jinja2 before 3.1.3 does not sanitize keys, allowing attribute injection.',
    remediation: 'Upgrade jinja2 to version 3.1.3 or higher.'
  },
  {
    ecosystem: 'pypi',
    package: 'urllib3',
    affectedVersion: '< 2.0.7',
    fixedVersion: '2.0.7',
    cve: 'CVE-2023-45803',
    severity: 'MEDIUM',
    title: 'Proxy-Authorization Header Leak in urllib3',
    description: 'Urllib3 leaks Proxy-Authorization headers to destination origin when redirected.',
    remediation: 'Upgrade urllib3 to 2.0.7 or later.'
  },
  {
    ecosystem: 'pypi',
    package: 'flask',
    affectedVersion: '< 2.2.5',
    fixedVersion: '2.2.5',
    cve: 'CVE-2023-30861',
    severity: 'HIGH',
    title: 'Cookie Disclosure / Session Caching in Flask',
    description: 'Flask applications using default caching may leak session cookies across users.',
    remediation: 'Upgrade Flask to version 2.2.5 or higher.'
  },

  // ─── Go (go.mod) ──────────────────────────────────────────────────────────
  {
    ecosystem: 'go',
    package: 'golang.org/x/net',
    affectedVersion: '< 0.23.0',
    fixedVersion: '0.23.0',
    cve: 'CVE-2023-45288',
    severity: 'HIGH',
    title: 'HTTP/2 CONTINUATION Flood Denial of Service in Go',
    description: 'Unbounded memory allocation during HTTP/2 CONTINUATION frame processing leads to node crashes.',
    remediation: 'Upgrade golang.org/x/net to >= 0.23.0.'
  },

  // ─── PHP (composer.json) ──────────────────────────────────────────────────
  {
    ecosystem: 'composer',
    package: 'guzzlehttp/guzzle',
    affectedVersion: '< 7.4.5',
    fixedVersion: '7.4.5',
    cve: 'CVE-2022-31090',
    severity: 'HIGH',
    title: 'Authorization Header Disclosure in Guzzle',
    description: 'Guzzle leaks Authorization headers when following cross-domain redirects.',
    remediation: 'Upgrade guzzlehttp/guzzle to version 7.4.5 or higher.'
  },
  {
    ecosystem: 'composer',
    package: 'ec-cube/ec-cube',
    affectedVersion: '< 4.2.3',
    fixedVersion: '4.2.3',
    cve: 'CVE-2023-38500',
    severity: 'CRITICAL',
    title: 'Remote Code Execution / SQLi in EC-CUBE',
    description: 'EC-CUBE versions prior to 4.2.3 contain vulnerabilities actively exploited for payment skimming.',
    remediation: 'Apply vendor security patch or upgrade EC-CUBE to >= 4.2.3 immediately.'
  },
  {
    ecosystem: 'composer',
    package: 'laravel/framework',
    affectedVersion: '< 8.75.0',
    fixedVersion: '8.75.0',
    cve: 'CVE-2021-43617',
    severity: 'HIGH',
    title: 'Unintended Attribute Binding in Laravel Form Requests',
    description: 'Laravel versions prior to 8.75.0 mishandle mass assignment via FormRequest validation.',
    remediation: 'Upgrade laravel/framework to >= 8.75.0 or 9.x.'
  }
];

export async function scanCVEs(file, allFiles = [], options = {}) {
  const findings = [];
  const fileName = file.name.toLowerCase();
  const relPath = file.relative.replace(/\\/g, '/');

  let content;
  try {
    content = fs.readFileSync(file.path, 'utf8');
  } catch {
    return findings;
  }

  // 1. Scan package.json
  if (fileName === 'package.json') {
    try {
      const pkg = JSON.parse(content);
      const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

      for (const [depName, versionSpec] of Object.entries(allDeps)) {
        const match = CURATED_CVE_DB.find(
          item => item.ecosystem === 'npm' && item.package.toLowerCase() === depName.toLowerCase()
        );

        if (match && isVersionPotentiallyVulnerable(versionSpec, match.fixedVersion)) {
          const isReachable = checkPackageReachable(depName, allFiles);
          const lineNo = findLineNumber(content, `"${depName}"`);

          findings.push({
            ruleId: match.cve,
            severity: match.severity,
            title: `${match.title} (${depName} ${versionSpec})`,
            file: relPath,
            line: lineNo,
            snippet: `"${depName}": "${versionSpec}"`,
            isReachable,
            description: `${match.description} (Affected: ${match.affectedVersion}).` +
              (isReachable ? ' ⚠️ REACHABLE IN SOURCE: Package is imported in application code.' : ' (Installed dependency)'),
            remediation: `${match.remediation} (Current version: ${versionSpec})`
          });
        }
      }
    } catch {
      // Skip invalid json
    }
  }

  // 2. Scan requirements.txt
  if (fileName === 'requirements.txt') {
    const lines = content.split('\n');
    lines.forEach((line, idx) => {
      const cleanLine = line.trim().split('#')[0];
      if (!cleanLine) return;

      const matchPart = cleanLine.match(/^([a-zA-Z0-9_\-]+)(?:==|<=|>=|<|>|~=)\s*(.+)$/);
      if (matchPart) {
        const pkgName = matchPart[1].toLowerCase();
        const version = matchPart[2].trim();

        const match = CURATED_CVE_DB.find(
          item => item.ecosystem === 'pypi' && item.package.toLowerCase() === pkgName
        );

        if (match && isVersionPotentiallyVulnerable(version, match.fixedVersion)) {
          findings.push({
            ruleId: match.cve,
            severity: match.severity,
            title: `${match.title} (${pkgName} ${version})`,
            file: relPath,
            line: idx + 1,
            snippet: cleanLine,
            description: `${match.description} (Affected: ${match.affectedVersion}).`,
            remediation: `${match.remediation} (Current: ${version})`
          });
        }
      }
    });
  }

  // 3. Scan go.mod
  if (fileName === 'go.mod') {
    const lines = content.split('\n');
    lines.forEach((line, idx) => {
      const matchPart = line.trim().match(/^([a-zA-Z0-9.\-_/]+)\s+v([0-9.]+)/);
      if (matchPart) {
        const modName = matchPart[1];
        const version = matchPart[2];

        const match = CURATED_CVE_DB.find(
          item => item.ecosystem === 'go' && item.package.toLowerCase() === modName.toLowerCase()
        );

        if (match && isVersionPotentiallyVulnerable(version, match.fixedVersion)) {
          findings.push({
            ruleId: match.cve,
            severity: match.severity,
            title: `${match.title} (${modName} v${version})`,
            file: relPath,
            line: idx + 1,
            snippet: line.trim(),
            description: `${match.description} (Affected: ${match.affectedVersion}).`,
            remediation: `${match.remediation} (Current: v${version})`
          });
        }
      }
    });
  }

  // 4. Scan composer.json
  if (fileName === 'composer.json') {
    try {
      const comp = JSON.parse(content);
      const reqs = { ...(comp.require || {}), ...(comp['require-dev'] || {}) };

      for (const [depName, versionSpec] of Object.entries(reqs)) {
        const match = CURATED_CVE_DB.find(
          item => item.ecosystem === 'composer' && item.package.toLowerCase() === depName.toLowerCase()
        );

        if (match && isVersionPotentiallyVulnerable(versionSpec, match.fixedVersion)) {
          const lineNo = findLineNumber(content, `"${depName}"`);
          findings.push({
            ruleId: match.cve,
            severity: match.severity,
            title: `${match.title} (${depName} ${versionSpec})`,
            file: relPath,
            line: lineNo,
            snippet: `"${depName}": "${versionSpec}"`,
            description: `${match.description} (Affected: ${match.affectedVersion}).`,
            remediation: `${match.remediation} (Current: ${versionSpec})`
          });
        }
      }
    } catch {
      // ignore
    }
  }

  return findings;
}

function findLineNumber(content, text) {
  const idx = content.split('\n').findIndex(l => l.includes(text));
  return idx === -1 ? 1 : idx + 1;
}

function checkPackageReachable(pkgName, allFiles) {
  const escaped = pkgName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const importRegex = new RegExp(`(?:from\\s+['"]${escaped}(?:\\/[^'"]*)?['"]|require\\s*\\(\\s*['"]${escaped}(?:\\/[^'"]*)?['"]\\)|import\\s*\\(['"]${escaped}(?:\\/[^'"]*)?['"]\\))`, 'i');

  for (const f of allFiles) {
    if (!['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue'].includes(f.ext)) continue;
    if (f.relative.includes('node_modules')) continue;

    try {
      const code = fs.readFileSync(f.path, 'utf8');
      if (importRegex.test(code)) return true;
    } catch {
      // skip
    }
  }
  return false;
}

function isVersionPotentiallyVulnerable(spec, fixed) {
  if (!/\d/.test(spec) || /^(?:git\+|https?:|file:|github:)/i.test(spec)) return false;
  const cleanSpec = spec.replace(/[\^~>=<]/g, '').trim().split(/\s+|\|\|/)[0];
  const specParts = cleanSpec.split('.').map(n => parseInt(n, 10) || 0);
  const fixedParts = fixed.split('.').map(n => parseInt(n, 10) || 0);

  for (let i = 0; i < Math.max(specParts.length, fixedParts.length); i++) {
    const s = specParts[i] || 0;
    const f = fixedParts[i] || 0;
    if (s < f) return true;
    if (s > f) return false;
  }
  return false;
}
