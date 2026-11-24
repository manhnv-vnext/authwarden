import fs from 'fs';
import path from 'path';
import os from 'os';
import { execFileSync } from 'child_process';
import { runScan } from './index.js';
import { printTerminalReport } from './reporters/terminalReporter.js';
import { generateSarif, generateMarkdown, generateJson } from './reporters/sarifReporter.js';
import { generateHtml } from './reporters/htmlReporter.js';
import { colors } from './utils/colors.js';
import { getGitChangedFiles } from './utils/git.js';
import { loadConfig } from './utils/config.js';
import { saveBaseline, applyBaseline } from './utils/baseline.js';

export async function cli(args = []) {
  if (args.includes('--help') || args.includes('-h') || args[0] === 'help') {
    printHelp();
    return 0;
  }

  if (args.includes('--version') || args.includes('-v') || args[0] === 'version') {
    console.log('authwarden v1.4.0');
    return 0;
  }

  const command = args[0];

  if (command === 'init-hook') {
    return installPreCommitHook();
  }

  if (command === 'rules') {
    return listRules();
  }

  // Parse options and positional target argument
  const valFlags = new Set(['--format', '--output', '--fail-on', '--baseline', '--save-baseline', '--config']);
  const positionals = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === 'scan' && i === 0) continue;
    if (valFlags.has(arg)) {
      i++; // skip next arg (its value)
      continue;
    }
    if (arg.startsWith('--') || arg.startsWith('-')) {
      continue; // boolean flag or flag=value
    }
    positionals.push(arg);
  }

  let targetDir = positionals[0] || process.env.INPUT_PATH || '.';
  let tempZipDir = null;

  if (targetDir.toLowerCase().endsWith('.zip') && fs.existsSync(targetDir)) {
    try {
      tempZipDir = fs.mkdtempSync(path.join(os.tmpdir(), 'authwarden-unzip-'));
      execFileSync('unzip', ['-q', path.resolve(targetDir), '-d', tempZipDir]);
      targetDir = tempZipDir;
    } catch (err) {
      console.error(colors.red(`Failed to extract zip archive: ${err.message}`));
      return 2;
    }
  }

  const customConfigPath = getArgValue(args, '--config');
  const { config } = loadConfig(customConfigPath || targetDir);

  const isStaged = args.includes('--staged') || process.env.INPUT_STAGED === 'true';
  const isWatch = args.includes('--watch') || config.watch === true;

  const options = {
    verify: args.includes('--verify') || process.env.INPUT_VERIFY === 'true' || config.verify === true,
    staged: isStaged,
    watch: isWatch,
    format: getArgValue(args, '--format') || process.env.INPUT_FORMAT || config.format || 'terminal',
    output: getArgValue(args, '--output') || process.env.INPUT_OUTPUT || config.output || null,
    failOn: getArgValue(args, '--fail-on') || process.env['INPUT_FAIL-ON'] || process.env.INPUT_FAIL_ON || config.failOn || 'high',
    baseline: getArgValue(args, '--baseline') || config.baseline || null,
    saveBaseline: getArgValue(args, '--save-baseline') || null,
    ignoreRules: config.ignoreRules || [],
    ignorePaths: config.ignorePaths || [],
    rulesDir: config.rulesDir || null
  };

  if (options.watch) {
    return startWatchMode(targetDir, options);
  }

  if (isStaged) {
    const stagedFiles = getGitChangedFiles(targetDir, { stagedOnly: true });
    if (stagedFiles) {
      if (stagedFiles.length === 0) {
        console.log(colors.green('✔ No staged git files to scan. Pre-commit check passed.'));
        return 0;
      }
      options.onlyFiles = stagedFiles;
    }
  }

  try {
    const scanResult = await runScan(targetDir, options);

    // Save baseline mode
    if (options.saveBaseline) {
      const savedPath = saveBaseline(options.saveBaseline, scanResult.findings, scanResult.stats);
      console.log(colors.green(`✔ Saved ${scanResult.findings.length} finding(s) to baseline: ${savedPath}`));
      return 0;
    }

    // Apply existing baseline (suppress historical findings)
    if (options.baseline) {
      const { newFindings, suppressedCount } = applyBaseline(scanResult.findings, options.baseline);
      scanResult.findings = newFindings;
      scanResult.suppressedBaselineCount = suppressedCount;
    }

    // Output formatting
    let outputText = '';
    if (options.format === 'sarif') {
      outputText = generateSarif(scanResult);
    } else if (options.format === 'markdown' || options.format === 'md') {
      outputText = generateMarkdown(scanResult);
    } else if (options.format === 'json') {
      outputText = generateJson(scanResult);
    } else if (options.format === 'html') {
      outputText = generateHtml(scanResult);
    } else {
      printTerminalReport(scanResult);
    }

    if (options.output && outputText) {
      fs.writeFileSync(path.resolve(options.output), outputText, 'utf8');
      console.log(colors.green(`Report saved to ${options.output}`));
    } else if (options.format !== 'terminal' && outputText) {
      console.log(outputText);
    }

    // Automatic GitHub Step Summary in GitHub Actions
    if (process.env.GITHUB_STEP_SUMMARY) {
      try {
        const summaryText = generateMarkdown(scanResult);
        fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `\n\n${summaryText}\n`, 'utf8');
      } catch {
        // ignore if not writable
      }
    }

    // Exit code evaluation
    const severityLevels = { critical: 4, high: 3, medium: 2, low: 1 };
    const threshold = severityLevels[options.failOn.toLowerCase()] || 3;

    const hasBlockingFinding = scanResult.findings.some(f => {
      const level = severityLevels[f.severity.toLowerCase()] || 0;
      return level >= threshold;
    });

    return hasBlockingFinding ? 1 : 0;
  } catch (err) {
    console.error(colors.red(`Error during scan: ${err.message}`));
    return 2;
  } finally {
    if (tempZipDir && fs.existsSync(tempZipDir)) {
      try {
        fs.rmSync(tempZipDir, { recursive: true, force: true });
      } catch {
        // ignore cleanup error
      }
    }
  }
}

async function startWatchMode(targetDir, options) {
  console.log(colors.cyan(colors.bold(`\n👁️  AuthWarden Watch Mode Active`)));
  console.log(colors.gray(`Watching ${path.resolve(targetDir)} ... (Press Ctrl+C to stop)\n`));

  let isScanning = false;
  let debounceTimer = null;

  async function triggerScan() {
    if (isScanning) return;
    isScanning = true;
    try {
      console.clear();
      console.log(colors.gray(`[${new Date().toLocaleTimeString()}] File change detected, re-scanning...`));
      const res = await runScan(targetDir, options);
      if (options.baseline) {
        const { newFindings, suppressedCount } = applyBaseline(res.findings, options.baseline);
        res.findings = newFindings;
        res.suppressedBaselineCount = suppressedCount;
      }
      printTerminalReport(res);
    } catch (e) {
      console.error(colors.red(`Scan error: ${e.message}`));
    } finally {
      isScanning = false;
    }
  }

  // Initial scan
  await triggerScan();

  try {
    const watcher = fs.watch(path.resolve(targetDir), { recursive: true }, (eventType, filename) => {
      if (!filename) return;
      if (filename.includes('node_modules') || filename.includes('.git') || filename.endsWith('.sarif') || filename.endsWith('.json') || filename.endsWith('.html')) {
        return;
      }
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(triggerScan, 150);
    });

    return new Promise(() => {
      process.on('SIGINT', () => {
        watcher.close();
        process.exit(0);
      });
    });
  } catch (err) {
    console.error(colors.red(`Watch mode error: ${err.message}`));
    return 1;
  }
}

function getArgValue(args, flag) {
  const idx = args.indexOf(flag);
  if (idx !== -1 && args[idx + 1] && !args[idx + 1].startsWith('-')) {
    return args[idx + 1];
  }
  const eqArg = args.find(a => a.startsWith(flag + '='));
  if (eqArg) return eqArg.split('=')[1];
  return null;
}

function printHelp() {
  console.log(`
${colors.bold(colors.cyan('AuthWarden'))} - Lightning-fast Static API & Authorization Vulnerability Scanner

${colors.bold('USAGE:')}
  authwarden scan [path] [options]
  authwarden init-hook
  authwarden rules

${colors.bold('OPTIONS:')}
  --watch             Continuous watch mode: re-scans instantly upon file save
  --format <type>     Output format: terminal (default), html, sarif, markdown, json
  --output <file>     Write report output to specified file
  --fail-on <level>   Threshold to exit with status 1: critical, high (default), medium, low
  --baseline <file>   Filter out historical findings from baseline file
  --save-baseline <f> Save current scan findings to baseline snapshot file
  --config <file>     Path to custom configuration file (.authwardenrc.json)
  --staged            Scan only staged git changes (fast for pre-commit hooks)
  --verify            Safely verify detected secrets against live APIs (Stripe, GitHub, OpenAI, Anthropic, Slack)
  -v, --version       Show version number
  -h, --help          Show this help message

${colors.bold('EXAMPLES:')}
  $ npx authwarden scan .
  $ npx authwarden scan . --watch
  $ npx authwarden scan . --format html --output report.html
  $ npx authwarden scan . --save-baseline .authwarden-baseline.json
  $ npx authwarden scan . --baseline .authwarden-baseline.json
  $ npx authwarden scan . --verify
  $ npx authwarden scan --staged
  $ npx authwarden init-hook
`);
}

function installPreCommitHook() {
  const hookDir = path.resolve('.git', 'hooks');
  if (!fs.existsSync(hookDir)) {
    console.error(colors.red('Error: .git directory not found. Please run this inside a git repository root.'));
    return 1;
  }

  const hookFile = path.join(hookDir, 'pre-commit');
  const hookScript = `#!/usr/bin/env sh
# AuthWarden Pre-commit Security Gate
echo "🛡️  Running AuthWarden pre-commit security check..."
npx authwarden scan . --staged --fail-on high
`;

  try {
    fs.writeFileSync(hookFile, hookScript, { mode: 0o755 });
    console.log(colors.green('✔ Successfully installed AuthWarden pre-commit hook in .git/hooks/pre-commit!'));
    return 0;
  } catch (err) {
    console.error(colors.red(`Failed to write pre-commit hook: ${err.message}`));
    return 1;
  }
}

function listRules() {
  console.log(`
${colors.bold('AuthWarden Core Rule Catalog:')}
────────────────────────────────────────────────────────────────────────
${colors.bold('API & AUTHORIZATION:')}
  • ${colors.red('AUTH-001')}  Shadow Admin Route Missing Auth Middleware
  • ${colors.yellow('AUTH-002')}  State-Modifying Route Without Auth
  • ${colors.yellow('AUTH-003')}  Potential BOLA / IDOR Unscoped Object Query
  • ${colors.yellow('AUTH-004')}  Server Action Missing Identity Check
  • ${colors.blue('AUTH-005')}  Mass Assignment in Body Handling
  • ${colors.yellow('AUTH-006')}  Unthrottled Authentication Endpoint (Brute-Force Risk)
  • ${colors.yellow('AUTH-007')}  Sensitive Data Exposure (Password Hash in Response)
  • ${colors.yellow('AUTH-008')}  Unauthenticated File Upload Endpoint

${colors.bold('SAST & INTRA-FILE TAINT-LITE:')}
  • ${colors.red('SAST-001')}  SQL Injection: Dynamic Query Construction with User Input
  • ${colors.red('SAST-002')}  Command Injection: Untrusted Input in System Shell Call
  • ${colors.red('SAST-003')}  Dangerous Code Execution via eval() / new Function()
  • ${colors.yellow('SAST-004')}  Server-Side Request Forgery (SSRF)
  • ${colors.yellow('SAST-005')}  Path Traversal: Arbitrary File Read / Include
  • ${colors.yellow('SAST-006')}  Cross-Site Scripting (XSS): dangerouslySetInnerHTML / DOM write
  • ${colors.red('SAST-007')}  Insecure Deserialization (pickle / unsafe yaml)
  • ${colors.yellow('SAST-008')}  Disabled TLS Certificate Verification
  • ${colors.blue('SAST-009')}  Weak Cryptographic Hash (MD5 / SHA-1)
  • ${colors.blue('SAST-011')}  Open Redirect: Unvalidated URL in Redirect Call
  • ${colors.yellow('SAST-012')}  Arbitrary File Upload: Unsanitized File Name in Path
  • ${colors.red('TAINT-001')} Taint Flow: Request Input Reaches Command Execution (RCE)
  • ${colors.red('TAINT-002')} Taint Flow: Request Input Reaches Raw SQL Query
  • ${colors.yellow('TAINT-003')} Taint Flow: Request Input Reaches File System Read
  • ${colors.yellow('TAINT-004')} Taint Flow: Request Input Reaches Outbound HTTP Call (SSRF)

${colors.bold('SECRETS & TOKENS:')}
  • ${colors.red('SEC-001')}   AWS Access Key ID Exposure
  • ${colors.red('SEC-002')}   GitHub Personal Access Token Exposure
  • ${colors.red('SEC-003')}   OpenAI API Secret Key Exposure
  • ${colors.red('SEC-004')}   Stripe Live Secret Key Exposure
  • ${colors.yellow('SEC-005')}   Slack Bot / Webhook Token Exposure
  • ${colors.yellow('SEC-006')}   Google Cloud API Key Exposure
  • ${colors.red('SEC-007')}   Database Connection String with Credentials
  • ${colors.red('SEC-008')}   Private Cryptographic Key in Source
  • ${colors.red('SEC-009')}   Anthropic API Key Exposure
  • ${colors.yellow('SEC-010')} Generic High-Entropy Secret / Token Exposure

${colors.bold('CONTAINER & CLOUD IAC:')}
  • ${colors.blue('IAC-001')}   Container Default Execution as Root
  • ${colors.yellow('IAC-002')}   Insecure Remote Script Pipe (curl | sh)
  • ${colors.yellow('IAC-003')}   Exposed Database Port in Dockerfile
  • ${colors.red('IAC-004')}   Docker Daemon Socket Mounted into Container
  • ${colors.yellow('IAC-005')}   Privileged Container Mode in Docker Compose
  • ${colors.red('IAC-006')}   Public S3 Bucket in Terraform
  • ${colors.red('IAC-007')}   Sensitive Port Open to 0.0.0.0/0 in Security Group
  • ${colors.yellow('IAC-008')}   Kubernetes Pod with Host Network or Host PID
  • ${colors.yellow('IAC-009')}   Kubernetes Container Allows Privilege Escalation
  • ${colors.red('IAC-010')}   Secret Baked into Dockerfile ENV Instruction
  • ${colors.blue('IAC-011')}   Unencrypted Storage Volume / Database in Terraform

${colors.bold('BUSINESS LOGIC & WORKFLOWS:')}
  • ${colors.yellow('LOGIC-001')} Multi-Step Workflow / Payment Status Evasion via Client Payload
  • ${colors.yellow('LOGIC-002')} Potential TOCTOU Race Condition on Balance / Coupon State
  • ${colors.yellow('LOGIC-003')} Unchecked Numeric Input: Negative Price / Quantity Tampering
  • ${colors.yellow('LOGIC-004')} Insecure JWT Verification: Missing Algorithm Whitelist
  • ${colors.blue('LOGIC-005')}   Client-Only Logout: Missing Server-Side Session Revocation

${colors.bold('OPENAPI & API SPEC CONTRACTS:')}
  • ${colors.yellow('SPEC-001')}  Unprotected Sensitive Operation in API Spec
  • ${colors.yellow('SPEC-002')}  Explicit Public Security Override (security: []) on Restricted Route
  • ${colors.yellow('SPEC-003')}  Sensitive Credential Passed via URL Query Parameter
  • ${colors.blue('SPEC-004')}    Insecure Cleartext Transport (HTTP) in Server URL

${colors.bold('AI AGENT & MCP TOOLS:')}
  • ${colors.red('MCP-001')}   Unsandboxed Shell Execution Tool in MCP Config
  • ${colors.yellow('MCP-002')}   Unrestricted Root Filesystem Path in MCP Server
  • ${colors.red('MCP-003')}   Hardcoded Secret in MCP Server Config
  • ${colors.blue('MCP-004')}   Prompt Injection Concatenation in System Instructions

${colors.bold('SCA & KNOWN CVE VULNERABILITIES:')}
  • ${colors.red('CVE-xxxx')}  Known High/Critical Vulnerabilities in Dependencies (npm, PyPI, Go, Composer, NuGet)
  • ${colors.bold('Reachability')} AST-guided Reachability Analysis (Flags Imported vs Dormant Vulnerabilities)
  • ${colors.yellow('SUPPLY-001')} Lifecycle Script Exfiltration Risk in package.json
  • ${colors.blue('SUPPLY-002')} Unpinned Git Repository Dependency

${colors.bold('MOBILE APPLICATION SECURITY:')}
  • ${colors.yellow('MOBILE-001')} Insecure Cleartext Traffic Allowed (Android Network Security Config / iOS ATS)
  • ${colors.blue('MOBILE-002')} Broad External Storage Permission Requested in AndroidManifest
`);
  return 0;
}
