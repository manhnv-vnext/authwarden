import fs from 'fs';
import { parentPort, workerData } from 'worker_threads';

/**
 * Runs custom regex rules in a worker thread so that a catastrophic pattern
 * (ReDoS) can be terminated by the parent instead of hanging the scan.
 */

const MAX_LINE_LENGTH = 5000;
const findings = [];

for (const file of workerData.files) {
  let lines;
  try {
    lines = fs.readFileSync(file.path, 'utf8').split('\n');
  } catch {
    continue;
  }
  for (const rule of workerData.rules) {
    if (rule.languages && !rule.languages.includes(file.ext)) continue;
    const rx = new RegExp(rule.pattern, 'i');
    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx];
      if (line.length > MAX_LINE_LENGTH) continue;
      if (rx.test(line)) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          title: rule.name,
          file: file.relative,
          line: idx + 1,
          snippet: line.trim().slice(0, 300),
          description: rule.description,
          remediation: rule.remediation
        });
      }
    }
  }
}

parentPort.postMessage(findings);
