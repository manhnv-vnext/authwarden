/**
 * SARIF 2.1.0 Exporter for GitHub Code Scanning
 */

export function generateSarif(scanResult) {
  const { findings } = scanResult;

  const sarifRules = [];
  const ruleSet = new Set();

  findings.forEach(f => {
    if (!ruleSet.has(f.ruleId)) {
      ruleSet.add(f.ruleId);
      sarifRules.push({
        id: f.ruleId,
        name: f.title,
        shortDescription: { text: f.title },
        fullDescription: { text: f.description || f.title },
        defaultConfiguration: {
          level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : 'warning'
        },
        help: { text: f.remediation || 'Remediate according to security guidelines.' }
      });
    }
  });

  const sarifResults = findings.map(f => ({
    ruleId: f.ruleId,
    level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : 'warning',
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
    ]
  }));

  return JSON.stringify({
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'AuthWarden',
            semanticVersion: '1.1.1',
            informationUri: 'https://github.com/manhnv-vnext/authwarden',
            rules: sarifRules
          }
        },
        results: sarifResults
      }
    ]
  }, null, 2);
}

export function generateMarkdown(scanResult) {
  const { findings, stats } = scanResult;

  if (findings.length === 0) {
    return `### 🛡️ AuthWarden Security Scan: PASSED ✅\n\nNo authorization flaws, exposed secrets, or configuration risks detected across **${stats.filesScanned}** files.`;
  }

  let md = `### 🛡️ AuthWarden Security Scan: ${findings.length} Finding(s) Detected ⚠️\n\n`;
  md += `| Severity | Rule ID | Title | File | Line |\n`;
  md += `|:---:|:---:|:---|:---|:---:|\n`;

  findings.forEach(f => {
    const icon = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : '🟡';
    md += `| ${icon} **${f.severity}** | \`${f.ruleId}\` | ${f.title} | \`${f.file}\` | ${f.line} |\n`;
  });

  md += `\n<details><summary><b>Detailed Remediation Advice</b></summary>\n\n`;
  findings.forEach(f => {
    md += `#### [${f.ruleId}] ${f.title}\n`;
    md += `- **Location:** \`${f.file}:${f.line}\`\n`;
    if (f.snippet) md += `- **Snippet:** \`${f.snippet}\`\n`;
    if (f.description) md += `- **Description:** ${f.description}\n`;
    if (f.remediation) md += `- **Recommended Fix:** ${f.remediation}\n\n`;
  });
  md += `</details>\n`;

  return md;
}

export function generateJson(scanResult) {
  return JSON.stringify(scanResult, null, 2);
}
