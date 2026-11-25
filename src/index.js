import path from 'path';
import fs from 'fs';
import { walkDirectory, matchesPathPattern } from './utils/fileWalker.js';
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
    if (f.name === 'pubspec.yaml' || f.name === 'pubspec.lock' || f.ext === '.dart') {
      frameworks.add('Flutter / Dart');
    }
    if (f.name === 'AndroidManifest.xml' || f.name.endsWith('.gradle')) {
      frameworks.add('Android');
    }
    if (f.name === 'Info.plist' || f.name === 'Podfile' || f.name.endsWith('.pbxproj')) {
      frameworks.add('iOS');
    }
    if (f.ext === '.csproj' || f.name.endsWith('.sln') || f.ext === '.cs') {
      let netAdded = false;
      if (f.ext === '.csproj') {
        try {
          const csprojContent = fs.readFileSync(f.path, 'utf8');
          const tfMatch = csprojContent.match(/<TargetFramework>(net[\d.]+)<\/TargetFramework>/i);
          if (tfMatch) {
            frameworks.add(`ASP.NET Core (.NET ${tfMatch[1].replace(/^net/i, '')})`);
            netAdded = true;
          }
          if (/Microsoft\.AspNetCore\.Authentication\.JwtBearer/i.test(csprojContent)) {
            frameworks.add('JwtBearer (Auth)');
          }
          if (/AWSSDK\.S3/i.test(csprojContent)) {
            frameworks.add('AWS S3 (Storage)');
          }
          if (/Microsoft\.EntityFrameworkCore/i.test(csprojContent)) {
            frameworks.add('Entity Framework Core');
          }
        } catch {
          // ignore
        }
      }
      if (!netAdded && !Array.from(frameworks).some(fr => fr.includes('ASP.NET') || fr.includes('.NET'))) {
        frameworks.add('.NET (C#)');
      }
      if (f.ext === '.cs') {
        try {
          const csContent = fs.readFileSync(f.path, 'utf8');
          if (/\b(?:app|endpoints|routes)\.Map(?:Get|Post|Put|Delete)\b|\bWebApplication\.CreateBuilder\b/i.test(csContent)) {
            frameworks.add('ASP.NET Core Minimal APIs');
          }
          if (/IFormFile|AmazonS3Client|InitiateMultipartUpload|TransferUtility/i.test(csContent)) {
            frameworks.add('File Upload / Multipart (S3/IFormFile)');
          }
        } catch {
          // ignore
        }
      }
      if (f.name === 'packages.lock.json' || f.name.toLowerCase() === 'directory.packages.props') {
        frameworks.add('NuGet (.NET Packages)');
      }
    }
    if (f.name === 'pom.xml' || f.name === 'build.gradle' || f.name === 'build.gradle.kts') {
      frameworks.add('Java (Spring/Maven/Gradle)');
    }
    if (f.name === 'Cargo.toml') {
      frameworks.add('Rust (Cargo)');
    }
    if (f.name === 'Gemfile') {
      frameworks.add('Ruby (Bundler)');
    }
  }

  const allFindings = [];

  for (const file of files) {
    // 1. API & Auth Scanner
    if (['.js', '.ts', '.jsx', '.tsx', '.mjs', '.py', '.cs', '.java'].includes(file.ext)) {
      const apiFindings = scanApiAuth(file);
      allFindings.push(...apiFindings);
    }

    // 2. Secret Scanner (all text files)
    const secretFindings = scanSecrets(file);
    allFindings.push(...secretFindings);

    // 3. SAST & Intra-file Taint-Lite Scanner
    if (['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.php', '.go', '.java', '.cs', '.dart'].includes(file.ext)) {
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
    if (
      ['package.json', 'package-lock.json', 'requirements.txt', 'go.mod', 'composer.json', 'packages.lock.json', 'directory.packages.props', 'pom.xml'].includes(file.name.toLowerCase()) ||
      file.ext === '.csproj'
    ) {
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

  // 10. Custom Organization Rules Loader (from rules/*.json or options.rulesDir)
  const rulesDir = path.resolve(rootDir, options.rulesDir || 'rules');
  if (fs.existsSync(rulesDir)) {
    try {
      const ruleFiles = fs.readdirSync(rulesDir).filter(f => f.endsWith('.json'));
      for (const rf of ruleFiles) {
        const raw = fs.readFileSync(path.join(rulesDir, rf), 'utf8');
        const customRules = JSON.parse(raw);
        if (Array.isArray(customRules)) {
          for (const cr of customRules) {
            if (!cr.pattern || !cr.id) continue;
            const rx = new RegExp(cr.pattern, 'i');
            for (const file of files) {
              if (cr.languages && !cr.languages.includes(file.ext)) continue;
              try {
                const fContent = fs.readFileSync(file.path, 'utf8');
                const fLines = fContent.split('\n');
                fLines.forEach((l, idx) => {
                  if (rx.test(l)) {
                    allFindings.push({
                      ruleId: cr.id,
                      severity: cr.severity || 'HIGH',
                      title: cr.name || cr.id,
                      file: file.relative.replace(/\\/g, '/'),
                      line: idx + 1,
                      snippet: l.trim(),
                      description: cr.description || 'Matched custom organization security rule.',
                      remediation: cr.remediation || 'Inspect code according to internal security guidelines.'
                    });
                  }
                });
              } catch {
                // skip
              }
            }
          }
        }
      }
    } catch {
      // skip invalid custom rules
    }
  }

  // 11. Filter out findings by ignoreRules, ignorePaths, or inline comments
  const ignoredRules = options.ignoreRules && Array.isArray(options.ignoreRules) ? new Set(options.ignoreRules) : null;
  const ignoredPaths = options.ignorePaths && Array.isArray(options.ignorePaths) ? options.ignorePaths.map(p => p.replace(/\\/g, '/')) : null;

  const fileLinesCache = new Map();
  const activeFindings = allFindings.filter(f => {
    if (ignoredRules && ignoredRules.has(f.ruleId)) {
      return false;
    }
    if (ignoredPaths && ignoredPaths.some(p => matchesPathPattern(f.file, p))) {
      return false;
    }

    try {
      const fullPath = path.resolve(rootDir, f.file);
      if (!fs.existsSync(fullPath)) return true;
      let lines = fileLinesCache.get(fullPath);
      if (!lines) {
        lines = fs.readFileSync(fullPath, 'utf8').split('\n');
        fileLinesCache.set(fullPath, lines);
      }
      const lineIdx = (f.line || 1) - 1;
      const currentLine = lines[lineIdx] || '';
      const prevLine = lineIdx > 0 ? (lines[lineIdx - 1] || '') : '';

      if (currentLine.includes('authwarden-disable-line') || currentLine.includes('authwarden-ignore')) {
        return false;
      }
      if (prevLine.includes('authwarden-disable-next-line')) {
        return false;
      }
    } catch {
      // keep finding on read error
    }
    return true;
  });

  // Active Verification (if enabled)
  const verifiedMap = {};
  if (options.verify) {
    for (const f of activeFindings) {
      if (f.rawSecret && !verifiedMap[f.rawSecret]) {
        const v = await verifySecret(f);
        if (v) verifiedMap[f.rawSecret] = v;
      }
    }
  }

  // Sort findings by severity
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  activeFindings.sort((a, b) => (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99));

  // Coverage Transparency Scorecard
  const detectedExts = new Set(files.map(f => f.ext.toLowerCase()).filter(Boolean));
  const coverageScorecard = [];
  coverageScorecard.push({
    target: 'Secrets & Credentials',
    status: 'ACTIVE',
    detail: '100% (All text & config files)'
  });
  if (files.some(f => f.name.toLowerCase() === 'dockerfile' || f.name === 'docker-compose.yml' || f.ext === '.tf' || f.relative.includes('k8s/') || (f.name.toLowerCase().startsWith('appsettings') && f.ext === '.json') || f.name.toLowerCase() === 'web.config')) {
    coverageScorecard.push({
      target: 'IaC & Config Security',
      status: 'ACTIVE',
      detail: 'Docker, Terraform, K8s, appsettings'
    });
  }
  if (detectedExts.has('.cs') || files.some(f => f.ext === '.csproj')) {
    coverageScorecard.push({
      target: 'C# (.NET / ASP.NET Core)',
      status: 'ACTIVE',
      detail: 'Auth, BOLA, File Upload, SAST & NuGet SCA'
    });
  }
  if (detectedExts.has('.java') || files.some(f => f.name.toLowerCase() === 'pom.xml')) {
    coverageScorecard.push({
      target: 'Java (Spring Boot)',
      status: 'ACTIVE',
      detail: 'Auth, SAST & Maven SCA'
    });
  }
  if (detectedExts.has('.js') || detectedExts.has('.ts') || detectedExts.has('.jsx') || detectedExts.has('.tsx')) {
    coverageScorecard.push({
      target: 'JavaScript / TypeScript',
      status: 'ACTIVE',
      detail: 'Auth, SAST & Taint flow'
    });
  }
  if (detectedExts.has('.py')) {
    coverageScorecard.push({
      target: 'Python (FastAPI / Django)',
      status: 'ACTIVE',
      detail: 'Auth & SAST rules'
    });
  }
  if (detectedExts.has('.go')) {
    coverageScorecard.push({
      target: 'Go',
      status: 'ACTIVE',
      detail: 'SAST rules'
    });
  }
  if (detectedExts.has('.php')) {
    coverageScorecard.push({
      target: 'PHP',
      status: 'ACTIVE',
      detail: 'SAST rules'
    });
  }
  if (detectedExts.has('.dart') || files.some(f => f.name === 'pubspec.yaml')) {
    coverageScorecard.push({
      target: 'Flutter / Dart',
      status: 'ACTIVE',
      detail: 'Mobile ATS, Cleartext & SAST'
    });
  }
  if (detectedExts.has('.rs') || files.some(f => f.name === 'Cargo.toml')) {
    coverageScorecard.push({
      target: 'Rust',
      status: 'LIMITED',
      detail: 'Secrets & IaC only (SAST in roadmap)'
    });
  }
  if (detectedExts.has('.rb') || files.some(f => f.name === 'Gemfile')) {
    coverageScorecard.push({
      target: 'Ruby',
      status: 'LIMITED',
      detail: 'Secrets & IaC only (SAST in roadmap)'
    });
  }

  const durationMs = Date.now() - startTime;

  return {
    targetDir: rootDir,
    findings: activeFindings,
    verifiedMap,
    stats: {
      filesScanned: files.length,
      frameworks: Array.from(frameworks),
      coverageScorecard,
      durationMs
    }
  };
}
