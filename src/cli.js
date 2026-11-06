import fs from 'fs';
import path from 'path';
import { runScan } from './index.js';
import { printTerminalReport } from './reporters/terminalReporter.js';
import { generateSarif, generateMarkdown, generateJson } from './reporters/sarifReporter.js';
import { colors } from './utils/colors.js';

export async function cli(args) {
  const command = args[0] || 'scan';

  if (command === '--help' || command === '-h' || command === 'help') {
    printHelp();
    return 0;
  }

  if (command === '--version' || command === '-v' || command === 'version') {
    console.log('authwarden v1.0.0');
    return 0;
  }

  if (command === 'init-hook') {
    return installPreCommitHook();
  }

  if (command === 'rules') {
    return listRules();
  }

  if (command === 'scan' || !command.startsWith('-')) {
    const targetDir = (command === 'scan' ? args[1] : command) || '.';
    const options = {
      verify: args.includes('--verify'),
      format: getArgValue(args, '--format') || 'terminal',
      output: getArgValue(args, '--output'),
      failOn: getArgValue(args, '--fail-on') || 'high'
    };

    try {
      const scanResult = await runScan(targetDir, options);

      // Output formatting
      let outputText = '';
      if (options.format === 'sarif') {
        outputText = generateSarif(scanResult);
      } else if (options.format === 'markdown' || options.format === 'md') {
        outputText = generateMarkdown(scanResult);
      } else if (options.format === 'json') {
        outputText = generateJson(scanResult);
      } else {
        printTerminalReport(scanResult);
      }

      if (options.output && outputText) {
        fs.writeFileSync(path.resolve(options.output), outputText, 'utf8');
        console.log(colors.green(`Report saved to ${options.output}`));
      } else if (options.format !== 'terminal' && outputText) {
        console.log(outputText);
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
    }
  }

  printHelp();
  return 1;
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
  --verify            Safely verify detected secrets against live APIs (e.g. Stripe, GitHub)
  --format <type>     Output format: terminal (default), sarif, markdown, json
  --output <file>     Write report output to specified file
  --fail-on <level>   Threshold to exit with status 1: critical, high (default), medium, low
  -v, --version       Show version number
  -h, --help          Show this help message

${colors.bold('EXAMPLES:')}
  $ npx authwarden scan .
  $ npx authwarden scan . --verify
  $ npx authwarden scan . --format sarif --output results.sarif
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
npx authwarden scan . --fail-on high
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

${colors.bold('AI AGENT & MCP TOOLS:')}
  • ${colors.red('MCP-001')}   Unsandboxed Shell Execution Tool in MCP Config
  • ${colors.yellow('MCP-002')}   Unrestricted Root Filesystem Path in MCP Server
  • ${colors.blue('MCP-004')}   Prompt Injection Concatenation in System Instructions
`);
  return 0;
}
