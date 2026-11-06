import { colors, badge } from '../utils/colors.js';

export function printTerminalReport(scanResult) {
  const { findings, stats, targetDir, verifiedMap = {} } = scanResult;

  // Print Banner
  console.log('');
  console.log(colors.cyan(colors.bold('   ___         __  __    _      __              __          ')));
  console.log(colors.blue(colors.bold('  / _ | __ __ / /_/ /_  | | /| / /__ _____ ___ / /__ ___    ')));
  console.log(colors.magenta(colors.bold(' / __ |/ // // __/ _ \\  | |/ |/ / _ `/ __// _  / -_) _ \\   ')));
  console.log(colors.red(colors.bold('/_/ |_|\\_,_/ \\__/_//_/  |__/|__/\\_,_/_/   \\_,_/\\__/_//_/ ') + colors.gray('v1.0.0')));
  console.log(colors.gray(' ──────────────────────────────────────────────────────────────────────────'));
  
  // Target & Environment Info
  console.log(` ${colors.green('✔')} Target: ${colors.bold(targetDir)}`);
  if (stats.frameworks?.length) {
    console.log(` ${colors.green('✔')} Frameworks: ${stats.frameworks.map(f => colors.cyan(f)).join(', ')}`);
  }
  console.log(` ${colors.green('✔')} Scanned ${colors.bold(stats.filesScanned)} files in ${colors.cyan(stats.durationMs + 'ms')}`);
  console.log(colors.gray(' ──────────────────────────────────────────────────────────────────────────'));
  console.log('');

  if (findings.length === 0) {
    console.log(` ${colors.bgGreen(colors.black(colors.bold(' PASS ')))} ${colors.green(colors.bold('No authorization flaws or security vulnerabilities detected!'))}`);
    console.log('');
    return;
  }

  // Print Findings
  findings.forEach((finding, idx) => {
    let sevBadge;
    if (finding.severity === 'CRITICAL') {
      sevBadge = badge('CRITICAL', colors.bgRed, colors.bold);
    } else if (finding.severity === 'HIGH') {
      sevBadge = badge('HIGH', colors.bgYellow, colors.black);
    } else if (finding.severity === 'MEDIUM') {
      sevBadge = badge('MEDIUM', colors.bgBlue, colors.white);
    } else {
      sevBadge = badge('LOW', colors.bgCyan, colors.black);
    }

    const verification = verifiedMap[finding.rawSecret];
    let verifyBadge = '';
    if (verification) {
      verifyBadge = verification.verified 
        ? ` ${colors.bgGreen(colors.black(' LIVE VERIFIED '))}` 
        : ` ${colors.gray('(Revoked / Inactive)')}`;
    }

    console.log(` ${sevBadge} ${colors.bold(finding.ruleId)}: ${colors.bold(finding.title)}${verifyBadge}`);
    console.log(`   ${colors.gray('Location:')} ${colors.cyan(finding.file + ':' + finding.line)}`);

    if (finding.snippet) {
      console.log(`   ${colors.gray('Snippet:')}  ${colors.red(finding.snippet)}`);
    }
    if (finding.description) {
      console.log(`   ${colors.gray('Detail:')}   ${finding.description}`);
    }
    if (finding.remediation) {
      console.log(`   ${colors.green('Fix:')}      ${finding.remediation}`);
    }
    console.log('');
  });

  // Summary Metrics
  const criticals = findings.filter(f => f.severity === 'CRITICAL').length;
  const highs = findings.filter(f => f.severity === 'HIGH').length;
  const mediums = findings.filter(f => f.severity === 'MEDIUM').length;
  const lows = findings.filter(f => f.severity === 'LOW').length;

  console.log(colors.gray(' ──────────────────────────────────────────────────────────────────────────'));
  console.log(` ${colors.bold('Summary:')} ` +
    (criticals > 0 ? colors.red(colors.bold(`${criticals} Critical `)) : '') +
    (highs > 0 ? colors.yellow(colors.bold(`${highs} High `)) : '') +
    (mediums > 0 ? colors.blue(`${mediums} Medium `) : '') +
    (lows > 0 ? colors.gray(`${lows} Low `) : '') +
    `• ${findings.length} total finding(s)`);
  console.log(colors.gray(' ──────────────────────────────────────────────────────────────────────────'));
  console.log('');
}
