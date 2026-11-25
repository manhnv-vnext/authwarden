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
import { VERSION } from './utils/version.js';
import { getCategories } from './rules/catalog.js';

export async function cli(args = []) {
  if (args.includes('--help') || args.includes('-h') || args[0] === 'help') {
    printHelp();
    return 0;
  }

  if (args.includes('--version') || args.includes('-v') || args[0] === 'version') {
    console.log(`authwarden v${VERSION}`);
    return 0;
  }

  const command = args[0];

  if (command === 'init-hook') {
    return installPreCommitHook();
  }

  if (command === 'rules') {
    return listRules();
  }

  const routesOnly = command === 'routes';

  // Parse options and positional target argument
  const valFlags = new Set(['--format', '--output', '--fail-on', '--baseline', '--save-baseline', '--config']);
  const positionals = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if ((arg === 'scan' || arg === 'routes') && i === 0) continue;
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
    online: args.includes('--online') || process.env.INPUT_ONLINE === 'true' || config.online === true,
    verify: args.includes('--verify') || process.env.INPUT_VERIFY === 'true' || config.verify === true,
    staged: isStaged,
    watch: isWatch,
    format: getArgValue(args, '--format') || process.env.INPUT_FORMAT || config.format || 'terminal',
    output: getArgValue(args, '--output') || process.env.INPUT_OUTPUT || config.output || null,
    failOn: getArgValue(args, '--fail-on') || process.env['INPUT_FAIL-ON'] || process.env.INPUT_FAIL_ON || config.failOn || 'high',
    baseline: getArgValue(args, '--baseline') || config.baseline || null,
    saveBaseline: getArgValue(args, '--save-baseline') || null,
    allowSecrets: config.allowSecrets || [],
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

    // Route inventory mode: list every discovered endpoint and how it is protected
    if (routesOnly) {
      return printRoutes(scanResult, options);
    }

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

function printRoutes(scanResult, options) {
  const routes = scanResult.routes || [];
  const summary = scanResult.stats.routes || { total: 0, protected: 0, unprotected: 0 };

  if (options.format === 'json') {
    const text = JSON.stringify({ summary, routes }, null, 2);
    if (options.output) {
      fs.writeFileSync(path.resolve(options.output), text, 'utf8');
      console.log(colors.green(`Route inventory saved to ${options.output}`));
    } else {
      console.log(text);
    }
    return 0;
  }

  console.log('');
  console.log(colors.bold(`Route inventory: ${summary.total} route(s), ${summary.protected} protected, ${summary.unprotected} without detected auth`));
  console.log(colors.gray('─'.repeat(72)));
  if (routes.length === 0) {
    console.log(colors.gray('  No routes discovered (supported: Next.js, Express, FastAPI, ASP.NET Core, Spring).'));
  }
  const sorted = [...routes].sort((a, b) => (a.auth === b.auth ? a.path.localeCompare(b.path) : a.auth === 'unprotected' ? -1 : 1));
  for (const r of sorted) {
    const status = r.auth === 'protected' ? colors.green('PROTECTED  ') : colors.yellow('UNPROTECTED');
    console.log(`  ${status} ${colors.bold(r.method.padEnd(7))}${r.path}`);
    console.log(colors.gray(`              ${r.file}:${r.line} · ${r.framework} · ${r.evidence}`));
  }
  console.log('');
  console.log(colors.gray('  "Unprotected" means no auth was detected statically; public endpoints such as login or health checks are expected here.'));
  console.log('');
  return 0;
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
  authwarden routes [path] [--format json]
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
  --online            Look up dependency versions on OSV.dev (sends package names and versions only)
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
  $ npx authwarden scan . --online
  $ npx authwarden scan --staged
  $ npx authwarden routes . --format json --output routes.json
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
  const sevColor = { CRITICAL: colors.red, HIGH: colors.yellow, MEDIUM: colors.blue, LOW: colors.gray };
  console.log('');
  console.log(colors.bold('AuthWarden Core Rule Catalog:'));
  console.log('─'.repeat(72));
  for (const { category, rules } of getCategories()) {
    console.log(colors.bold(category.toUpperCase() + ':'));
    for (const r of rules) {
      const paint = sevColor[r.severity] || colors.gray;
      const meta = colors.gray(`[${r.severity} · confidence ${r.confidence} · ${r.cwe}]`);
      console.log(`  • ${paint(r.id.padEnd(11))}${r.title} ${meta}`);
    }
    console.log('');
  }
  console.log(colors.bold('SCA & KNOWN VULNERABILITIES:'));
  console.log(`  • ${colors.red('CVE-xxxx'.padEnd(11))}Known vulnerable dependency (npm, PyPI, Go, Composer, NuGet, Maven)`);
  console.log(`  • ${'Reachability'.padEnd(11)} Import-level check: is the vulnerable package imported in source?`);
  console.log('');
  return 0;
}
