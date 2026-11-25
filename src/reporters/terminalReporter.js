import { colors, badge } from '../utils/colors.js';
import { VERSION } from '../utils/version.js';

export function printTerminalReport(scanResult) {
  const { findings, stats, targetDir } = scanResult;

  // Print Banner
  console.log('');
  console.log(colors.cyan(colors.bold('   ___         __  __    _      __              __          ')));
  console.log(colors.blue(colors.bold('  / _ | __ __ / /_/ /_  | | /| / /__ _____ ___ / /__ ___    ')));
  console.log(colors.magenta(colors.bold(' / __ |/ // // __/ _ \\  | |/ |/ / _ `/ __// _  / -_) _ \\   ')));
  console.log(colors.red(colors.bold('/_/ |_|\\_,_/ \\__/_//_/  |__/|__/\\_,_/_/   \\_,_/\\__/_//_/ ') + colors.gray('v' + VERSION)));
  console.log(colors.gray(' ──────────────────────────────────────────────────────────────────────────'));
  
  // Target & Environment Info
  console.log(` ${colors.green('✔')} Target: ${colors.bold(targetDir)}`);
  if (stats.frameworks?.length) {
    console.log(` ${colors.green('✔')} Frameworks: ${stats.frameworks.map(f => colors.cyan(f)).join(', ')}`);
  }
  console.log(` ${colors.green('✔')} Scanned ${colors.bold(stats.filesScanned)} files in ${colors.cyan(stats.durationMs + 'ms')}`);
  if (scanResult.suppressedBaselineCount) {
    console.log(` ${colors.cyan('ℹ')} Baseline: ${colors.bold(scanResult.suppressedBaselineCount)} historical finding(s) suppressed.`);
  }

  if (stats.osv) {
    console.log(stats.osv.state === 'ok'
      ? ` ${colors.green('✔')} OSV.dev: ${colors.bold(stats.osv.packagesQueried)} package version(s) checked, ${colors.bold(stats.osv.vulnerablePackages)} with known advisories`
      : ` ${colors.yellow('▲')} OSV.dev lookup failed (${stats.osv.message}); results below use the offline database only`);
  }
  if (stats.routes?.total) {
    console.log(` ${colors.green('✔')} Routes: ${colors.bold(stats.routes.total)} discovered, ${colors.bold(stats.routes.unprotected)} without detected auth ${colors.gray('(run "authwarden routes" for the inventory)')}`);
  }

  // Coverage Transparency Scorecard
  if (stats.coverageScorecard && stats.coverageScorecard.length > 1) {
    console.log(colors.gray(' ──────────────────────────────────────────────────────────────────────────'));
    console.log(` ${colors.bold('Coverage Transparency:')}`);
    for (const item of stats.coverageScorecard) {
      const statusIcon = item.status === 'ACTIVE' ? colors.green('✔ ACTIVE') : colors.yellow('▲ LIMITED');
      console.log(`   ${statusIcon}  ${colors.bold(item.target.padEnd(25))} ${colors.gray(item.detail)}`);
    }
  }
  console.log(colors.gray(' ──────────────────────────────────────────────────────────────────────────'));
  console.log('');

  if (findings.length === 0) {
    const msg = scanResult.suppressedBaselineCount
      ? `No new vulnerabilities detected! (${scanResult.suppressedBaselineCount} historical finding(s) suppressed via baseline)`
      : 'No authorization flaws or security vulnerabilities detected!';
    console.log(` ${colors.bgGreen(colors.black(colors.bold(' PASS ')))} ${colors.green(colors.bold(msg))}`);
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

    const verification = finding.verification;
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
    if (finding.dataFlow) {
      console.log(`   ${colors.yellow('Data Flow:')} Line ${finding.dataFlow.sourceLine} [${colors.gray(finding.dataFlow.sourceCode)}] ${colors.cyan('➔')} Line ${finding.dataFlow.sinkLine} [${colors.red(finding.dataFlow.sinkCode)}]`);
    }
    if (finding.confidence) {
      console.log(`   ${colors.gray('Confidence:')} ${finding.confidence}${finding.cwe ? colors.gray(' · ' + finding.cwe) : ''}`);
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
