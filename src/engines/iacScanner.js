import fs from 'fs';

/**
 * Infrastructure as Code (IaC) & Container Security Scanner
 */

export function scanIaC(file) {
  const findings = [];
  const fileName = file.name.toLowerCase();
  const relPath = file.relative.replace(/\\/g, '/');

  let content;
  try {
    content = fs.readFileSync(file.path, 'utf8');
  } catch {
    return findings;
  }
  const lines = content.split('\n');

  // 1. Dockerfile Analysis
  if (fileName === 'dockerfile' || fileName.startsWith('dockerfile.')) {
    let hasUser = false;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line.startsWith('#')) continue;

      if (/^USER\s+/i.test(line)) {
        hasUser = true;
      }

      // Curl pipe to bash
      if (/curl\s+[^|]+\|\s*(?:ba)?sh/i.test(line) || /wget\s+[^|]+\|\s*(?:ba)?sh/i.test(line)) {
        findings.push({
          ruleId: 'IAC-002',
          severity: 'HIGH',
          title: 'Insecure Remote Script Execution (curl | bash)',
          file: relPath,
          line: i + 1,
          snippet: line,
          description: 'Executing unverified remote scripts via curl/wget piped directly to bash exposes the container build to man-in-the-middle attacks.',
          remediation: 'Download the script first, verify its SHA256 checksum, then execute it.'
        });
      }

      // Expose database ports
      const exposeMatch = /^EXPOSE\s+([0-9\s]+)/i.exec(line);
      if (exposeMatch) {
        const ports = exposeMatch[1].split(/\s+/).map(Number);
        const dangerousPorts = [3306, 5432, 27017, 6379, 9200];
        const exposedDb = ports.find(p => dangerousPorts.includes(p));
        if (exposedDb) {
          findings.push({
            ruleId: 'IAC-003',
            severity: 'HIGH',
            title: `Exposed Database Port in Dockerfile (${exposedDb})`,
            file: relPath,
            line: i + 1,
            snippet: line,
            description: `Exposing database port ${exposedDb} inside the container can result in inadvertent external access if container ports are mapped directly.`,
            remediation: 'Do not expose database ports publicly; connect via internal docker network.'
          });
        }
      }
    }

    if (!hasUser) {
      findings.push({
        ruleId: 'IAC-001',
        severity: 'MEDIUM',
        title: 'Container Default Execution as Root',
        file: relPath,
        line: 1,
        snippet: lines[0] || 'FROM ...',
        description: 'Dockerfile does not specify a non-root USER directive. If the application is compromised, the attacker has root privileges.',
        remediation: 'Add a non-privileged user: RUN addgroup -S app && adduser -S app -G app \\n USER app'
      });
    }
  }

  // 2. Docker Compose Analysis
  if (fileName.includes('docker-compose') && (file.ext === '.yml' || file.ext === '.yaml')) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Docker socket mount
      if (line.includes('/var/run/docker.sock')) {
        findings.push({
          ruleId: 'IAC-004',
          severity: 'CRITICAL',
          title: 'Docker Daemon Socket Mounted into Container',
          file: relPath,
          line: i + 1,
          snippet: line.trim(),
          description: 'Mounting /var/run/docker.sock allows root escape from the container to the host machine.',
          remediation: 'Avoid mounting the Docker socket unless running a dedicated orchestrator proxy.'
        });
      }

      // Privileged container
      if (/privileged:\s*true/i.test(line)) {
        findings.push({
          ruleId: 'IAC-005',
          severity: 'HIGH',
          title: 'Privileged Mode Enabled in Docker Compose',
          file: relPath,
          line: i + 1,
          snippet: line.trim(),
          description: 'Privileged containers disable all Linux security capabilities and seccomp filters.',
          remediation: 'Remove privileged: true and only grant specific Linux capabilities (e.g. cap_add).'
        });
      }
    }
  }

  // 3. Terraform Analysis (*.tf)
  if (file.ext === '.tf') {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/acl\s*=\s*["']public-read["']/i.test(line)) {
        findings.push({
          ruleId: 'IAC-006',
          severity: 'CRITICAL',
          title: 'Public S3 Bucket Configuration in Terraform',
          file: relPath,
          line: i + 1,
          snippet: line.trim(),
          description: 'S3 bucket is configured with public-read ACL, exposing stored files to the public internet.',
          remediation: 'Use acl = "private" and enable aws_s3_bucket_public_access_block.'
        });
      }
      if (/cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']\s*\]/i.test(line) && lines.slice(Math.max(0, i-5), i+5).some(l => /3306|5432|22|3389/i.test(l))) {
        findings.push({
          ruleId: 'IAC-007',
          severity: 'CRITICAL',
          title: 'Sensitive Port Open to the World (0.0.0.0/0) in Security Group',
          file: relPath,
          line: i + 1,
          snippet: line.trim(),
          description: 'Security group rule allows ingress from 0.0.0.0/0 on sensitive ports (SSH/RDP/DB), inviting automated brute-force attacks.',
          remediation: 'Restrict ingress cidr_blocks to specific internal VPC or corporate VPN CIDR blocks.'
        });
      }
    }
  }

  return findings;
}
