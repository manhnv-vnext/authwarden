import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { runScan } from '../src/index.js';

test('honors inline comments to suppress findings', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-suppress-'));
  const testFile = path.join(tmpDir, 'service.js');

  const code = `
const { exec } = require('child_process');

function run(req) {
  // Line suppressed with authwarden-disable-line
  exec(req.query.cmd); // authwarden-disable-line

  // Next line suppressed with authwarden-disable-next-line
  // authwarden-disable-next-line
  exec(req.query.cmd2);

  // Unsuppressed finding
  exec(req.query.cmd3);
}
`;
  fs.writeFileSync(testFile, code);

  const scanResult = await runScan(tmpDir);
  const cmdFindings = scanResult.findings.filter(f => f.ruleId === 'SAST-002');
  
  // Only cmd3 should be reported
  assert.equal(cmdFindings.length, 1);
  assert.ok(cmdFindings[0].snippet.includes('cmd3'));

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('loads and executes custom rules from rules/*.json', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-custom-rules-'));
  const rulesDir = path.join(tmpDir, 'rules');
  fs.mkdirSync(rulesDir);

  const customRule = [
    {
      id: 'CORP-001',
      name: 'Forbidden Console Log',
      severity: 'HIGH',
      languages: ['.js'],
      pattern: 'console\\.warn\\(',
      description: 'console.warn is disallowed by company policy.',
      remediation: 'Use logger.warn() instead.'
    }
  ];
  fs.writeFileSync(path.join(rulesDir, 'corp.json'), JSON.stringify(customRule, null, 2));

  const codeFile = path.join(tmpDir, 'index.js');
  fs.writeFileSync(codeFile, 'console.warn("warning message");\n');

  const scanResult = await runScan(tmpDir);
  const customFinding = scanResult.findings.find(f => f.ruleId === 'CORP-001');
  assert.ok(customFinding, 'Expected custom rule CORP-001 finding');
  assert.equal(customFinding.title, 'Forbidden Console Log');
  assert.equal(customFinding.severity, 'HIGH');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
