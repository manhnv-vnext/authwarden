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
import { enrichFinding } from './rules/catalog.js';
import { loadCustomRules, runCustomRules } from './utils/customRules.js';
import { getLines, getCodeLines } from './utils/fileContext.js';
import { buildProjectAuthContext } from './engines/authContext.js';
import { scanOsv } from './engines/osvScanner.js';
import { DEPENDENCY_FILES } from './engines/dependencies.js';

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

  // Upstream auth (Next.js middleware, ASP.NET fallback policy, Spring filter chain) + route inventory
  const authCtx = { project: buildProjectAuthContext(files, options), routes: [] };

  for (const file of files) {
    // 1. API & Auth Scanner
    if (['.js', '.ts', '.jsx', '.tsx', '.mjs', '.py', '.cs', '.java'].includes(file.ext)) {
      const apiFindings = scanApiAuth(file, authCtx);
      allFindings.push(...apiFindings);
    }

    // 2. Secret Scanner (all text files)
    const secretFindings = scanSecrets(file, options);
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
      DEPENDENCY_FILES.has(file.name.toLowerCase()) ||
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

  // 9b. Online SCA via OSV.dev (opt-in: sends package names and versions only)
  let osvStatus;
  if (options.online) {
    const osv = await scanOsv(files, options);
    osvStatus = osv.status;
    const known = new Set(allFindings.map(f => `${f.ruleId}|${f.file}`));
    for (const f of osv.findings) {
      const key = `${f.ruleId}|${f.file}`;
      if (known.has(key)) continue; // already reported by the offline database
      known.add(key);
      allFindings.push(f);
    }
  }

  // 10. Custom organisation rules (rules/*.json or options.rulesDir).
  // They live in the scanned repository, so they are validated, run in a worker with a
  // time limit, and skipped entirely in untrusted mode unless a rules directory was given.
  const warnings = [];
  if (!options.untrusted || options.rulesDir) {
    const rulesDir = path.resolve(rootDir, options.rulesDir || 'rules');
    const loaded = loadCustomRules(rulesDir);
    warnings.push(...loaded.warnings);
    const custom = await runCustomRules(loaded.rules, files, options.customRuleTimeoutMs);
    warnings.push(...custom.warnings);
    allFindings.push(...custom.findings);
  }

  // 11. Filter out findings by ignoreRules, ignorePaths, or inline comments
  const ignoredRules = options.ignoreRules && Array.isArray(options.ignoreRules) ? new Set(options.ignoreRules) : null;
  const ignoredPaths = options.ignorePaths && Array.isArray(options.ignorePaths) ? options.ignorePaths.map(p => p.replace(/\\/g, '/')) : null;
  const suppressed = { config: 0, inline: 0 };
  const filesByRel = new Map(files.map(f => [f.relative.replace(/\\/g, '/'), f]));

  // A marker only counts inside a comment: it must disappear from the comment-stripped view.
  // File types without comment masking fall back to "after a comment opener on the line".
  const markerInComment = (file, lineIdx, marker) => {
    const raw = getLines(file)[lineIdx] || '';
    if (!raw.includes(marker)) return false;
    const code = getCodeLines(file)[lineIdx] || '';
    if (code !== raw) return !code.includes(marker);
    return new RegExp('(?:#|//|<!--|--)[^\\n]*' + marker).test(raw);
  };

  const activeFindings = allFindings.filter(f => {
    if (ignoredRules && ignoredRules.has(f.ruleId)) {
      suppressed.config++;
      return false;
    }
    if (ignoredPaths && ignoredPaths.some(p => matchesPathPattern(f.file, p))) {
      suppressed.config++;
      return false;
    }
    if (options.untrusted) return true; // inline markers are written by the code under review

    const file = filesByRel.get(f.file);
    if (!file) return true;
    const lineIdx = (f.line || 1) - 1;
    if (markerInComment(file, lineIdx, 'authwarden-disable-line') || markerInComment(file, lineIdx, 'authwarden-ignore') ||
        (lineIdx > 0 && markerInComment(file, lineIdx - 1, 'authwarden-disable-next-line'))) {
      suppressed.inline++;
      return false;
    }
    return true;
  });

  // Active Verification (if enabled)
  if (options.verify) {
    const verifyCache = new Map(); // raw secret -> result, kept in memory only
    for (const f of activeFindings) {
      if (!f.rawSecret) continue;
      if (!verifyCache.has(f.rawSecret)) {
        verifyCache.set(f.rawSecret, await verifySecret(f));
      }
      const v = verifyCache.get(f.rawSecret);
      if (v) f.verification = v;
    }
  }

  // Attach catalog metadata (CWE, confidence, category)
  activeFindings.forEach(enrichFinding);

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

  const routes = authCtx.routes;
  const protectedRoutes = routes.filter(r => r.auth === 'protected').length;
  const unknownRoutes = routes.filter(r => r.auth === 'unknown').length;

  const durationMs = Date.now() - startTime;

  return {
    targetDir: rootDir,
    findings: activeFindings,
    routes,
    stats: {
      filesScanned: files.length,
      frameworks: Array.from(frameworks),
      coverageScorecard,
      suppressed,
      warnings,
      routes: { total: routes.length, protected: protectedRoutes, unprotected: routes.length - protectedRoutes - unknownRoutes, unknown: unknownRoutes },
      ...(osvStatus ? { osv: osvStatus } : {}),
      durationMs
    }
  };
}
