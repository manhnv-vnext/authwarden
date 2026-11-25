import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { runScan } from '../src/index.js';
import { generateJson, generateSarif } from '../src/reporters/sarifReporter.js';
import { generateHtml } from '../src/reporters/htmlReporter.js';
import { scanBusinessLogic } from '../src/engines/businessLogicScanner.js';
import { scanSAST } from '../src/engines/sastScanner.js';
import { isTestPath, maskComments } from '../src/utils/fileContext.js';
import { VERSION } from '../src/utils/version.js';

const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

function tmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-hard-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

function fileObj(dir, rel) {
  return { path: path.join(dir, rel), relative: rel, name: path.basename(rel), ext: path.extname(rel) };
}

// Built dynamically so the scanner never flags this fixture in its own repo
const FAKE_TOKEN = 'gh' + 'p_' + 'aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jK5';

test('JSON and HTML reports never contain the raw secret value', async () => {
  const dir = tmpProject({ 'src/config.js': `export const token = "${FAKE_TOKEN}";\n` });
  const result = await runScan(dir, {});
  fs.rmSync(dir, { recursive: true, force: true });

  const secretFinding = result.findings.find(f => f.ruleId === 'SEC-002');
  assert.ok(secretFinding, 'expected SEC-002 finding');
  assert.equal(generateJson(result).includes(FAKE_TOKEN), false, 'raw secret leaked into JSON report');
  assert.equal(generateHtml(result).includes(FAKE_TOKEN), false, 'raw secret leaked into HTML report');
  assert.equal(generateSarif(result).includes(FAKE_TOKEN), false, 'raw secret leaked into SARIF report');
});

test('maskComments strips comments but keeps URLs inside strings', () => {
  const masked = maskComments([
    'const u = "https://api.example.com/v1"; // trailing note',
    '/* block start',
    '   still comment */ const live = 1;',
    'const re = /^https?:\\/\\//;'
  ], '.js');
  assert.equal(masked[0].includes('https://api.example.com/v1'), true);
  assert.equal(masked[0].includes('trailing note'), false);
  assert.equal(masked[1].trim(), '');
  assert.equal(masked[2].includes('still comment'), false);
  assert.equal(masked[2].includes('const live = 1;'), true);
  assert.equal(masked[3].includes('const re'), true);
});

test('maskComments treats # as a comment only for Python', () => {
  assert.equal(maskComments(['x = 1  # note'], '.py')[0].includes('note'), false);
  assert.equal(maskComments(['this.#secret = 1;'], '.js')[0].includes('#secret'), true);
});

test('LOGIC-001 still fires when the vulnerable line carries a trailing comment', async () => {
  const dir = tmpProject({
    'src/checkout.js': [
      'async function handleCheckout(req, res) {',
      '  if (req.body.is_paid) { // see https://docs.example.com/pay',
      '    await markOrderComplete(req.body.orderId);',
      '  }',
      '}'
    ].join('\n')
  });
  const findings = await scanBusinessLogic(fileObj(dir, 'src/checkout.js'), []);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.ok(findings.find(f => f.ruleId === 'LOGIC-001'));
});

test('LOGIC-001 ignores code that only appears inside a comment', async () => {
  const dir = tmpProject({
    'src/checkout.js': 'const a = 1; // legacy: if (req.body.is_paid) fulfil()\n'
  });
  const findings = await scanBusinessLogic(fileObj(dir, 'src/checkout.js'), []);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(findings.length, 0);
});

test('isTestPath matches test directory segments, not substrings', () => {
  assert.equal(isTestPath('test/a.js'), true);
  assert.equal(isTestPath('src/tests/a.js'), true);
  assert.equal(isTestPath('packages/api/__tests__/a.ts'), true);
  assert.equal(isTestPath('Shop.Api.Tests/OrderTests.cs'), true);
  assert.equal(isTestPath('src/latest/handler.js'), false);
  assert.equal(isTestPath('src/contest/handler.js'), false);
  assert.equal(isTestPath('src/attest/handler.js'), false);
});

test('SAST scans source under directories that merely end in "test"', () => {
  const dir = tmpProject({
    'src/latest/run.js': 'const out = eval(req.query.code);\n'
  });
  const findings = scanSAST(fileObj(dir, 'src/latest/run.js'));
  fs.rmSync(dir, { recursive: true, force: true });
  assert.ok(findings.find(f => f.ruleId === 'SAST-003'));
});

test('version is sourced from package.json everywhere', () => {
  assert.equal(VERSION, pkg.version);
  const sarif = JSON.parse(generateSarif({ findings: [], stats: {} }));
  assert.equal(sarif.runs[0].tool.driver.semanticVersion, pkg.version);
});
