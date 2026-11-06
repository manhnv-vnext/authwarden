import fs from 'fs';

/**
 * Supply Chain Security Scanner
 */

export function scanSupplyChain(file) {
  const findings = [];
  const fileName = file.name.toLowerCase();
  const relPath = file.relative.replace(/\\/g, '/');

  if (fileName !== 'package.json') return findings;

  let pkg;
  try {
    const raw = fs.readFileSync(file.path, 'utf8');
    pkg = JSON.parse(raw);
  } catch {
    return findings;
  }

  // 1. Check lifecycle scripts (postinstall, preinstall)
  if (pkg.scripts) {
    const dangerousHooks = ['preinstall', 'install', 'postinstall', 'prepublish'];
    for (const hook of dangerousHooks) {
      const script = pkg.scripts[hook];
      if (typeof script === 'string') {
        // Detect suspicious outbound network calls or code execution
        if (/\b(curl|wget|fetch|nc|ncat|bash\s+-i|sh\s+-i)\b/i.test(script) || /eval\s*\(/i.test(script) || /base64/i.test(script)) {
          findings.push({
            ruleId: 'SUPPLY-001',
            severity: 'CRITICAL',
            title: `Suspicious Lifecycle Script Detected in "${hook}"`,
            file: relPath,
            line: 1,
            snippet: `"${hook}": "${script}"`,
            description: `Package lifecycle script "${hook}" executes network or evaluation commands that can be used for supply chain exfiltration.`,
            remediation: 'Inspect the script closely. If unintended, remove the lifecycle hook or run npm install with --ignore-scripts in CI/CD.'
          });
        }
      }
    }
  }

  // 2. Check git dependencies without immutable SHA
  const depSections = ['dependencies', 'devDependencies', 'peerDependencies'];
  for (const section of depSections) {
    const deps = pkg[section];
    if (deps && typeof deps === 'object') {
      for (const [depName, version] of Object.entries(deps)) {
        if (typeof version === 'string' && (version.startsWith('git+') || version.startsWith('github:') || version.startsWith('http'))) {
          // If not pinned to a 40-char SHA
          if (!/#[0-9a-f]{40}$/i.test(version)) {
            findings.push({
              ruleId: 'SUPPLY-002',
              severity: 'HIGH',
              title: `Unpinned Git Dependency: ${depName}`,
              file: relPath,
              line: 1,
              snippet: `"${depName}": "${version}"`,
              description: `Dependency "${depName}" is fetched from a remote git branch/tag without an immutable 40-character commit hash pin. Upstream changes can break builds or inject malicious code.`,
              remediation: `Pin the dependency to a specific commit SHA: "${depName}": "git+https://github.com/org/repo.git#<full-commit-sha>"`
            });
          }
        }
      }
    }
  }

  return findings;
}
