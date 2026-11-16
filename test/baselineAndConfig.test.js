import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { loadConfig } from '../src/utils/config.js';
import { generateFingerprint, saveBaseline, loadBaseline, applyBaseline } from '../src/utils/baseline.js';
import { generateHtml } from '../src/reporters/htmlReporter.js';
import { runScan } from '../src/index.js';

test('loadConfig discovers .authwardenrc.json and reads direct config file', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-config-test-'));
  const configPath = path.join(tmpDir, '.authwardenrc.json');
  fs.writeFileSync(configPath, JSON.stringify({
    failOn: 'critical',
    ignoreRules: ['SAST-001'],
    ignorePaths: ['legacy/**']
  }));

  // Auto-discovery from target directory
  const discovered = loadConfig(tmpDir);
  assert.equal(discovered.config.failOn, 'critical');
  assert.deepEqual(discovered.config.ignoreRules, ['SAST-001']);
  assert.deepEqual(discovered.config.ignorePaths, ['legacy/**']);
  assert.equal(discovered.configPath, configPath);

  // Direct file path loading
  const direct = loadConfig(configPath);
  assert.equal(direct.config.failOn, 'critical');
  assert.equal(direct.configPath, configPath);

  // Non-existent directory returns empty config
  const empty = loadConfig('/tmp/non-existent-dir-' + Date.now());
  assert.deepEqual(empty.config, {});
  assert.equal(empty.configPath, null);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('runScan respects ignoreRules and ignorePaths configured via options', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-scan-ignore-'));
  const activeFile = path.join(tmpDir, 'vuln.js');
  const ignoredFolder = path.join(tmpDir, 'legacy');
  fs.mkdirSync(ignoredFolder);
  const ignoredFile = path.join(ignoredFolder, 'old.js');

  const vulnCode = `
const { exec } = require('child_process');
exec(req.query.cmd);
`;
  fs.writeFileSync(activeFile, vulnCode);
  fs.writeFileSync(ignoredFile, vulnCode);

  // Scan without ignores: should find 2 SAST-002 vulnerabilities
  const res1 = await runScan(tmpDir);
  assert.equal(res1.findings.filter(f => f.ruleId === 'SAST-002').length, 2);

  // Scan with ignorePaths: 'legacy'
  const res2 = await runScan(tmpDir, { ignorePaths: ['legacy'] });
  assert.equal(res2.findings.filter(f => f.ruleId === 'SAST-002').length, 1);
  assert.equal(res2.findings[0].file, 'vuln.js');

  // Scan with ignoreRules: ['SAST-002']
  const res3 = await runScan(tmpDir, { ignoreRules: ['SAST-002'] });
  assert.equal(res3.findings.filter(f => f.ruleId === 'SAST-002').length, 0);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('baseline engine: saveBaseline, loadBaseline, and applyBaseline filter historical findings', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-baseline-test-'));
  const baselineFile = path.join(tmpDir, 'baseline.json');

  const finding1 = {
    ruleId: 'SAST-001',
    severity: 'HIGH',
    title: 'SQL Injection',
    file: 'src/db.js',
    line: 12,
    snippet: 'db.query("SELECT * FROM users WHERE id = " + req.query.id)'
  };

  const finding2 = {
    ruleId: 'AUTH-001',
    severity: 'CRITICAL',
    title: 'Missing Auth',
    file: 'src/admin.js',
    line: 5,
    snippet: 'app.get("/admin", handler)'
  };

  const newFinding = {
    ruleId: 'SEC-001',
    severity: 'CRITICAL',
    title: 'AWS Key',
    file: 'src/config.js',
    line: 1,
    snippet: 'AKIAIOSFODNN7EXAMPLE12'
  };

  // 1. Generate Fingerprint
  const fp1 = generateFingerprint(finding1);
  assert.ok(fp1.includes('SAST-001'));
  assert.ok(fp1.includes('src/db.js'));

  // 2. Save baseline
  saveBaseline(baselineFile, [finding1, finding2], { filesScanned: 25 });
  assert.ok(fs.existsSync(baselineFile));

  // 3. Load baseline
  const loaded = loadBaseline(baselineFile);
  assert.equal(loaded.fingerprints.size, 2);
  assert.ok(loaded.fingerprints.has(fp1));
  assert.equal(loaded.metadata.stats.filesScanned, 25);

  // 4. Apply baseline: finding1 and finding2 are suppressed, newFinding remains
  const currentFindings = [
    { ...finding1, line: 15 }, // line shifted down, but snippet is the same
    finding2,
    newFinding
  ];

  const result = applyBaseline(currentFindings, baselineFile);
  assert.equal(result.suppressedCount, 2);
  assert.equal(result.newFindings.length, 1);
  assert.equal(result.newFindings[0].ruleId, 'SEC-001');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('generateHtml creates self-contained interactive dashboard with escaping', () => {
  const scanResult = {
    targetDir: '/projects/my-api',
    stats: { filesScanned: 42, durationMs: 128 },
    findings: [
      {
        ruleId: 'SAST-001',
        title: 'SQL Injection <script>alert(1)</script>',
        severity: 'CRITICAL',
        file: 'api/users.js',
        line: 14,
        snippet: 'SELECT * FROM users WHERE name = \'' + ' + req.body.name',
        description: 'Vulnerable query construction & unsanitized input',
        remediation: 'Use parameterized queries: db.query("SELECT * FROM users WHERE name = ?", [name]);'
      },
      {
        ruleId: 'AUTH-006',
        title: 'Unthrottled Endpoint',
        severity: 'MEDIUM',
        file: 'api/login.js',
        line: 22,
        snippet: 'app.post("/login", doLogin);',
        description: 'Missing rate limit middleware'
      }
    ],
    verifiedMap: {}
  };

  const html = generateHtml(scanResult);

  // Basic HTML validity checks
  assert.ok(html.includes('<!DOCTYPE html>'));
  assert.ok(html.includes('<title>AuthWarden Security Report - /projects/my-api</title>'));
  assert.ok(html.includes('Total Findings'));
  assert.ok(html.includes('42')); // filesScanned
  assert.ok(html.includes('128ms'));

  // Ensure HTML escaping is applied to protect against script tag breakout injection
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(html.includes('\\u003cscript\\u003ealert(1)\\u003c/script\\u003e'));

  // Verify interactive controls exist
  assert.ok(html.includes('id="searchInput"'));
  assert.ok(html.includes('class="filter-btn"'));
  assert.ok(html.includes('copyFix('));
  assert.ok(html.includes('const findings ='));
});
