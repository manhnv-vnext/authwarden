/**
 * SARIF 2.1.0 Exporter for GitHub Code Scanning
 */
import crypto from 'crypto';
import { VERSION } from '../utils/version.js';
import { getRule } from '../rules/catalog.js';
import { generateFingerprint } from '../utils/baseline.js';

const HELP_URI = 'https://github.com/manhnv-vnext/authwarden#-rule-catalog';

// GitHub maps security-severity to critical (>=9), high (>=7), medium (>=4), low
const SECURITY_SEVERITY = { CRITICAL: '9.5', HIGH: '8.0', MEDIUM: '5.5', LOW: '3.0' };
const PRECISION = { HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

function sarifLevel(severity) {
  return severity === 'CRITICAL' || severity === 'HIGH' ? 'error' : 'warning';
}

export function generateSarif(scanResult) {
  const { findings } = scanResult;

  const sarifRules = [];
  const ruleSet = new Set();

  findings.forEach(f => {
    if (ruleSet.has(f.ruleId)) return;
    ruleSet.add(f.ruleId);
    const meta = getRule(f.ruleId);
    const cwe = f.cwe || meta?.cwe;
    const tags = ['security'];
    if (cwe) tags.push('external/cwe/' + cwe.toLowerCase());
    sarifRules.push({
      id: f.ruleId,
      name: meta?.title || f.title,
      shortDescription: { text: meta?.title || f.title },
      fullDescription: { text: f.description || f.title },
      defaultConfiguration: { level: sarifLevel(f.severity) },
      help: { text: f.remediation || 'Remediate according to security guidelines.' },
      helpUri: HELP_URI,
      properties: {
        tags,
        precision: PRECISION[f.confidence || meta?.confidence] || 'medium',
        'security-severity': SECURITY_SEVERITY[f.severity] || '5.5'
      }
    });
  });

  const sarifResults = findings.map(f => ({
    ruleId: f.ruleId,
    level: sarifLevel(f.severity),
    message: { text: `${f.title}: ${f.description || ''}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file },
          region: {
            startLine: Math.max(1, f.line || 1)
          }
        }
      }
    ],
    // Line-independent so alerts stay matched when code above them moves
    partialFingerprints: {
      'authwarden/v1': crypto.createHash('sha256').update(generateFingerprint(f)).digest('hex')
    }
  }));

  return JSON.stringify({
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'AuthWarden',
            semanticVersion: VERSION,
            informationUri: 'https://github.com/manhnv-vnext/authwarden',
            rules: sarifRules
          }
        },
        results: sarifResults
      }
    ]
  }, null, 2);
}

// Report text comes from scanned files, so nothing may break out of its Markdown context
const mdText = (v) => String(v ?? '').replace(/[\r\n]+/g, ' ').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/([\\`*_\[\]()|!#])/g, '\\$1');
const mdCode = (v) => '`' + String(v ?? '').replace(/[\r\n]+/g, ' ').replace(/`/g, "'").replace(/\|/g, '\\|').replace(/</g, '‹').replace(/>/g, '›').slice(0, 300) + '`';

export function generateMarkdown(scanResult) {
  const { findings, stats } = scanResult;

  const formatScorecard = () => {
    if (!stats.coverageScorecard || stats.coverageScorecard.length === 0) return '';
    let section = `\n#### 📊 Coverage Transparency\n`;
    if (stats.frameworks?.length) {
      section += `**Detected Stack:** ${stats.frameworks.map(f => mdCode(f)).join(', ')}\n\n`;
    }
    section += `| Target / Language | Status | Scope |\n|:---|:---:|:---|\n`;
    for (const item of stats.coverageScorecard) {
      const badge = item.status === 'ACTIVE' ? '🟢 ACTIVE' : '🟡 LIMITED';
      section += `| ${item.target} | ${badge} | ${item.detail} |\n`;
    }
    return section;
  };

  const formatNotes = () => {
    const notes = [];
    const sup = stats.suppressed;
    if (sup && (sup.config || sup.inline)) {
      notes.push(`${sup.config || 0} finding(s) suppressed by configuration and ${sup.inline || 0} by inline comments.`);
    }
    for (const w of stats.warnings || []) notes.push(mdText(w));
    return notes.length ? `\n> ℹ️ ${notes.join(' ')}\n` : '';
  };

  if (findings.length === 0) {
    return `### 🛡️ AuthWarden Security Scan: PASSED ✅\n\nNo authorization flaws, exposed secrets, or configuration risks detected across **${stats.filesScanned}** files.\n${formatNotes()}${formatScorecard()}`;
  }

  let md = `### 🛡️ AuthWarden Security Scan: ${findings.length} Finding(s) Detected ⚠️\n\n`;
  md += `| Severity | Rule ID | Title | File | Line |\n`;
  md += `|:---:|:---:|:---|:---|:---:|\n`;

  findings.forEach(f => {
    const icon = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : '🟡';
    md += `| ${icon} **${mdText(f.severity)}** | ${mdCode(f.ruleId)} | ${mdText(f.title)} | ${mdCode(f.file)} | ${Number(f.line) || 1} |\n`;
  });

  md += formatNotes();
  md += formatScorecard();

  md += `\n<details><summary><b>Detailed Remediation Advice</b></summary>\n\n`;
  findings.forEach(f => {
    md += `#### [${mdText(f.ruleId)}] ${mdText(f.title)}\n`;
    md += `- **Location:** ${mdCode(f.file + ':' + (Number(f.line) || 1))}\n`;
    if (f.snippet) md += `- **Snippet:** ${mdCode(f.snippet)}\n`;
    if (f.description) md += `- **Description:** ${mdText(f.description)}\n`;
    if (f.remediation) md += `- **Recommended Fix:** ${mdText(f.remediation)}\n\n`;
  });
  md += `</details>\n`;

  return md;
}

export function generateJson(scanResult) {
  return JSON.stringify(scanResult, null, 2);
}
