import path from 'path';
import fs from 'fs';
import { walkDirectory } from './utils/fileWalker.js';
import { scanApiAuth } from './engines/apiAuthScanner.js';
import { scanSecrets } from './engines/secretScanner.js';
import { scanIaC } from './engines/iacScanner.js';
import { scanSupplyChain } from './engines/supplyChainScanner.js';
import { scanMcpAgent } from './engines/mcpAgentScanner.js';
import { scanSAST } from './engines/sastScanner.js';
import { scanCVEs } from './engines/cveScanner.js';
import { scanBusinessLogic } from './engines/businessLogicScanner.js';
import { scanApiSpecs } from './engines/apiSpecScanner.js';
import { verifySecret } from './verifier/secretVerifier.js';

export async function runScan(targetPath = '.', options = {}) {
  const startTime = Date.now();
  const rootDir = path.resolve(targetPath);
  
  const files = walkDirectory(rootDir, options);

  // Framework & ecosystem detection
  const frameworks = new Set();
  for (const f of files) {
    if (f.relative.includes('app/api') || f.name === 'next.config.js' || f.name === 'next.config.mjs') {
      frameworks.add('Next.js');
    }
    if (f.ext === '.py' && (f.name === 'main.py' || f.name === 'app.py')) {
      frameworks.add('FastAPI/Python');
    }
    if (f.name === 'docker-compose.yml' || f.name.toLowerCase() === 'dockerfile') {
      frameworks.add('Docker');
    }
    if (f.ext === '.tf') {
      frameworks.add('Terraform');
    }
    if (f.name.includes('mcp') || f.name.includes('claude')) {
      frameworks.add('AI Agent / MCP');
    }
    if (f.name === 'k8s.yaml' || f.name === 'deployment.yaml' || f.relative.includes('k8s/')) {
      frameworks.add('Kubernetes');
    }
    if (f.name === 'package.json') {
      frameworks.add('npm/Node.js');
    }
    if (f.name === 'requirements.txt') {
      frameworks.add('Python/pip');
    }
    if (f.name === 'go.mod') {
      frameworks.add('Go Modules');
    }
    if (f.name === 'composer.json') {
      frameworks.add('Composer/PHP');
    }
    if (/(?:openapi|swagger|api-docs)[^/]*\.(?:json|ya?ml)$/i.test(f.name)) {
      frameworks.add('OpenAPI / Swagger');
    }
  }

  const allFindings = [];

  for (const file of files) {
    // 1. API & Auth Scanner
    if (['.js', '.ts', '.jsx', '.tsx', '.mjs', '.py'].includes(file.ext)) {
      const apiFindings = scanApiAuth(file);
      allFindings.push(...apiFindings);
    }

    // 2. Secret Scanner (all text files)
    const secretFindings = scanSecrets(file);
    allFindings.push(...secretFindings);

    // 3. SAST & Intra-file Taint-Lite Scanner
    if (['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.php', '.go', '.java'].includes(file.ext)) {
      const sastFindings = scanSAST(file);
      allFindings.push(...sastFindings);
    }

    // 4. IaC Scanner
    const iacFindings = scanIaC(file);
    allFindings.push(...iacFindings);

    // 5. Supply Chain Scanner
    const supplyFindings = scanSupplyChain(file);
    allFindings.push(...supplyFindings);

    // 6. MCP & AI Agent Scanner
    const mcpFindings = scanMcpAgent(file);
    allFindings.push(...mcpFindings);

    // 7. CVE & Software Composition Analysis (SCA) Scanner
    if (['package.json', 'requirements.txt', 'go.mod', 'composer.json'].includes(file.name.toLowerCase())) {
      const cveFindings = await scanCVEs(file, files, options);
      allFindings.push(...cveFindings);
    }

    // 8. Business Logic & Authorization Integrity Scanner
    const logicFindings = await scanBusinessLogic(file, files, options);
    allFindings.push(...logicFindings);

    // 9. OpenAPI & API Specification Auditor
    const specFindings = await scanApiSpecs(file, files, options);
    allFindings.push(...specFindings);
  }

  // Active Verification (if enabled)
  const verifiedMap = {};
  if (options.verify) {
    for (const f of allFindings) {
      if (f.rawSecret && !verifiedMap[f.rawSecret]) {
        const v = await verifySecret(f);
        if (v) verifiedMap[f.rawSecret] = v;
      }
    }
  }

  // Sort findings by severity
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  allFindings.sort((a, b) => (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99));

  const durationMs = Date.now() - startTime;

  return {
    targetDir: rootDir,
    findings: allFindings,
    verifiedMap,
    stats: {
      filesScanned: files.length,
      frameworks: Array.from(frameworks),
      durationMs
    }
  };
}
