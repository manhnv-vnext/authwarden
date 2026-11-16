import fs from 'fs';
import path from 'path';

/**
 * Enterprise Baseline Engine
 * Enables suppressing known historical issues so CI only fails on newly introduced vulnerabilities.
 */

export function generateFingerprint(finding) {
  const normFile = (finding.file || '').replace(/\\/g, '/');
  const snippet = (finding.snippet || '').trim().replace(/\s+/g, ' ');
  return `${finding.ruleId}:${normFile}:${snippet}`;
}

export function saveBaseline(filePath, findings, stats = {}) {
  const fullPath = path.resolve(filePath);
  const baselineData = {
    version: '1.2.0',
    createdAt: new Date().toISOString(),
    stats: {
      totalHistoricalFindings: findings.length,
      filesScanned: stats.filesScanned || 0
    },
    findings: findings.map(f => ({
      ruleId: f.ruleId,
      severity: f.severity,
      title: f.title,
      file: f.file,
      line: f.line,
      snippet: f.snippet,
      fingerprint: generateFingerprint(f)
    }))
  };

  fs.writeFileSync(fullPath, JSON.stringify(baselineData, null, 2), 'utf8');
  return fullPath;
}

export function loadBaseline(filePath) {
  const fullPath = path.resolve(filePath);
  if (!fs.existsSync(fullPath)) {
    throw new Error(`Baseline file not found: ${filePath}`);
  }

  const raw = fs.readFileSync(fullPath, 'utf8');
  const data = JSON.parse(raw);
  const fingerprints = new Set();

  if (Array.isArray(data.findings)) {
    for (const f of data.findings) {
      if (f.fingerprint) {
        fingerprints.add(f.fingerprint);
      } else {
        fingerprints.add(generateFingerprint(f));
      }
    }
  }

  return {
    fingerprints,
    metadata: data
  };
}

export function applyBaseline(findings, baselinePath) {
  const { fingerprints, metadata } = loadBaseline(baselinePath);

  const newFindings = [];
  let suppressedCount = 0;

  for (const finding of findings) {
    const fp = generateFingerprint(finding);
    if (fingerprints.has(fp)) {
      suppressedCount++;
    } else {
      newFindings.push(finding);
    }
  }

  return {
    newFindings,
    suppressedCount,
    baselineMetadata: metadata
  };
}
