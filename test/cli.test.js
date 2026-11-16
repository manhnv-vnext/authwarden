import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { cli } from '../src/cli.js';

test('cli handles --version and --help', async () => {
  const codeV = await cli(['--version']);
  assert.equal(codeV, 0);

  const codeH = await cli(['--help']);
  assert.equal(codeH, 0);

  const codeR = await cli(['rules']);
  assert.equal(codeR, 0);
});

test('cli parses flags before target path correctly', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-cli-order-'));
  const testFile = path.join(tmpDir, 'safe.js');
  fs.writeFileSync(testFile, 'console.log("clean");');

  // Flags placed before positional path argument
  const exitCode = await cli(['scan', '--format', 'json', tmpDir]);
  assert.equal(exitCode, 0);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('cli returns exit code 2 on non-existent path', async () => {
  const exitCode = await cli(['scan', '/tmp/path-that-does-not-exist-authwarden-test']);
  assert.equal(exitCode, 2);
});

test('cli falls back to GitHub Actions INPUT_* environment variables', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-cli-gha-'));
  const testFile = path.join(tmpDir, 'index.js');
  fs.writeFileSync(testFile, 'console.log(1);');

  process.env.INPUT_PATH = tmpDir;
  process.env.INPUT_FORMAT = 'json';

  const exitCode = await cli([]);
  assert.equal(exitCode, 0);

  delete process.env.INPUT_PATH;
  delete process.env.INPUT_FORMAT;
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('cli generates HTML report to output file and appends GITHUB_STEP_SUMMARY', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-cli-html-'));
  const testFile = path.join(tmpDir, 'vuln.js');
  fs.writeFileSync(testFile, 'eval(req.query.code);');

  const reportFile = path.join(tmpDir, 'report.html');
  const summaryFile = path.join(tmpDir, 'step_summary.md');
  process.env.GITHUB_STEP_SUMMARY = summaryFile;

  const exitCode = await cli(['scan', tmpDir, '--format', 'html', '--output', reportFile, '--fail-on', 'critical']);
  assert.equal(exitCode, 1); // eval is CRITICAL

  assert.ok(fs.existsSync(reportFile));
  const htmlContent = fs.readFileSync(reportFile, 'utf8');
  assert.ok(htmlContent.includes('<!DOCTYPE html>'));
  assert.ok(htmlContent.includes('AuthWarden Security Report'));

  assert.ok(fs.existsSync(summaryFile));
  const summaryContent = fs.readFileSync(summaryFile, 'utf8');
  assert.ok(summaryContent.includes('AuthWarden Security Scan'));

  delete process.env.GITHUB_STEP_SUMMARY;
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('cli handles --save-baseline and --baseline in workflow', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-cli-base-'));
  const testFile = path.join(tmpDir, 'vuln.js');
  fs.writeFileSync(testFile, 'eval(req.query.code);');

  const baselineFile = path.join(tmpDir, 'baseline.json');

  // 1. Save baseline: exitCode should be 0 because we are only taking a snapshot
  const codeSave = await cli(['scan', tmpDir, '--save-baseline', baselineFile]);
  assert.equal(codeSave, 0);
  assert.ok(fs.existsSync(baselineFile));

  // 2. Scan with baseline applied: known finding is suppressed, exitCode should be 0
  const codeWithBaseline = await cli(['scan', tmpDir, '--baseline', baselineFile]);
  assert.equal(codeWithBaseline, 0);

  // 3. Add a new vulnerability
  const newFile = path.join(tmpDir, 'new.js');
  fs.writeFileSync(newFile, 'eval(req.query.other);');

  // 4. Scan with baseline applied again: new vulnerability triggers failure (code 1)
  const codeNewVuln = await cli(['scan', tmpDir, '--baseline', baselineFile, '--fail-on', 'critical']);
  assert.equal(codeNewVuln, 1);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

