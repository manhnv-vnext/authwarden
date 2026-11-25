import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { RULE_CATALOG, getRule } from '../src/rules/catalog.js';
import { runScan } from '../src/index.js';
import { cli } from '../src/cli.js';
import { generateSarif } from '../src/reporters/sarifReporter.js';

const root = new URL('../', import.meta.url);
const enginesDir = new URL('src/engines/', root);

function engineRuleIds() {
  const ids = new Set();
  for (const f of fs.readdirSync(enginesDir)) {
    const src = fs.readFileSync(new URL(f, enginesDir), 'utf8');
    for (const m of src.matchAll(/\b(?:ruleId|id):\s*'([A-Z]+-\d{3})'/g)) ids.add(m[1]);
  }
  return ids;
}

test('every rule emitted by an engine is described in the catalog, and vice versa', () => {
  const emitted = engineRuleIds();
  const catalog = new Set(RULE_CATALOG.map(r => r.id));
  assert.deepEqual([...emitted].filter(id => !catalog.has(id)), [], 'engine rules missing from catalog');
  assert.deepEqual([...catalog].filter(id => !emitted.has(id)), [], 'catalog rules no engine emits');
});

test('catalog entries are complete and unique', () => {
  const seen = new Set();
  for (const r of RULE_CATALOG) {
    assert.equal(seen.has(r.id), false, `duplicate ${r.id}`);
    seen.add(r.id);
    assert.ok(r.title && r.category, `${r.id} needs title and category`);
    assert.ok(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(r.severity), `${r.id} severity`);
    assert.ok(['HIGH', 'MEDIUM', 'LOW'].includes(r.confidence), `${r.id} confidence`);
  }
});

test('README rule table lists every catalog rule', () => {
  const readme = fs.readFileSync(new URL('README.md', root), 'utf8');
  const missing = RULE_CATALOG.filter(r => !readme.includes('`' + r.id + '`')).map(r => r.id);
  assert.deepEqual(missing, []);
});

test('rules command prints every catalog rule', async () => {
  const lines = [];
  const orig = console.log;
  console.log = (...a) => lines.push(a.join(' '));
  try {
    await cli(['rules']);
  } finally {
    console.log = orig;
  }
  const out = lines.join('\n');
  const missing = RULE_CATALOG.filter(r => !out.includes(r.id)).map(r => r.id);
  assert.deepEqual(missing, []);
});

function project(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-cat-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

test('findings are enriched with confidence and CWE from the catalog', async () => {
  const dir = project({ 'src/run.js': 'const out = eval(req.query.code);\n' });
  const result = await runScan(dir, {});
  fs.rmSync(dir, { recursive: true, force: true });
  const f = result.findings.find(x => x.ruleId === 'SAST-003');
  assert.ok(f);
  assert.equal(f.cwe, getRule('SAST-003').cwe);
  assert.equal(f.confidence, getRule('SAST-003').confidence);
});

test('SARIF carries CWE tags, security-severity, help link and stable fingerprints', async () => {
  const code = 'const out = eval(req.query.code);\n';
  const dirA = project({ 'src/run.js': code });
  const dirB = project({ 'src/run.js': '\n\n\n' + code });
  const a = JSON.parse(generateSarif(await runScan(dirA, {})));
  const b = JSON.parse(generateSarif(await runScan(dirB, {})));
  fs.rmSync(dirA, { recursive: true, force: true });
  fs.rmSync(dirB, { recursive: true, force: true });

  const rule = a.runs[0].tool.driver.rules.find(r => r.id === 'SAST-003');
  assert.ok(rule.properties.tags.includes('security'));
  assert.ok(rule.properties.tags.includes('external/cwe/cwe-95'));
  assert.equal(typeof rule.properties['security-severity'], 'string');
  assert.ok(Number(rule.properties['security-severity']) >= 9);
  assert.match(rule.helpUri, /^https:\/\//);

  const ra = a.runs[0].results.find(r => r.ruleId === 'SAST-003');
  const rb = b.runs[0].results.find(r => r.ruleId === 'SAST-003');
  const fa = Object.values(ra.partialFingerprints)[0];
  assert.match(fa, /^[0-9a-f]{64}$/);
  assert.equal(fa, Object.values(rb.partialFingerprints)[0], 'fingerprint must survive line shifts');
  assert.notEqual(ra.locations[0].physicalLocation.region.startLine, rb.locations[0].physicalLocation.region.startLine);
});
