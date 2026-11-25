import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { spawnSync } from 'child_process';
import { runScan } from '../src/index.js';
import { generateHtml } from '../src/reporters/htmlReporter.js';
import { generateMarkdown } from '../src/reporters/sarifReporter.js';

// The scanned repository is input, not configuration: it must not be able to
// switch the scanner off, hang it, write outside itself or inject into reports.

const BIN = path.resolve('bin/authwarden.js');
const L = (...l) => l.join('\n') + '\n';
const VULN = "app.delete('/admin/users/:id', (req, res) => { db.del(req.params.id); res.end(); });\n";

function project(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-trust-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}
const run = (args, opts = {}) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', timeout: 20000, ...opts });
const count = (r, id) => r.findings.filter(f => f.ruleId === id).length;

test('repo config cannot enable watch mode, redirect output or turn on network features', () => {
  const outside = path.join(os.tmpdir(), `aw-outside-${process.pid}.txt`);
  const dir = project({
    'src/app.js': VULN,
    '.authwardenrc.json': JSON.stringify({ watch: true, verify: true, online: true, format: 'markdown', output: outside })
  });
  const res = run(['scan', dir]);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.notEqual(res.signal, 'SIGTERM', 'scan must not enter watch mode');
  assert.equal(res.status, 1);
  assert.equal(fs.existsSync(outside), false, 'output path from repo config must be ignored');
  assert.match(res.stderr, /ignor/i);
});

test('repo config that suppresses findings is honoured but reported', () => {
  const dir = project({ 'src/app.js': VULN, '.authwardenrc.json': JSON.stringify({ ignoreRules: ['AUTH-001'] }) });
  const res = run(['scan', dir, '--format', 'json']);
  fs.rmSync(dir, { recursive: true, force: true });
  const out = JSON.parse(res.stdout);
  assert.equal(out.findings.filter(f => f.ruleId === 'AUTH-001').length, 0);
  assert.equal(out.stats.suppressed.config, 1);
});

test('--untrusted ignores repo config, repo rules, inline suppressions and .gitignore', () => {
  const dir = project({
    'src/app.js': VULN,
    'src/b.js': "app.delete('/admin/b', h); // authwarden-ignore\n",
    'gen/c.js': "app.delete('/admin/c', h);\n",
    '.gitignore': 'gen/\n',
    '.authwardenrc.json': JSON.stringify({ ignorePaths: ['src/app.js'], failOn: 'critical' }),
    'rules/x.json': JSON.stringify([{ id: 'X-1', pattern: 'app' }])
  });
  const res = run(['scan', dir, '--format', 'json', '--untrusted']);
  fs.rmSync(dir, { recursive: true, force: true });
  const out = JSON.parse(res.stdout);
  assert.equal(out.findings.filter(f => f.ruleId === 'AUTH-001').length, 3);
  assert.equal(out.findings.filter(f => f.ruleId === 'X-1').length, 0);
  assert.equal(res.status, 1);
});

test('a catastrophic custom rule regex times out instead of hanging the scan', async () => {
  const dir = project({
    'rules/x.json': JSON.stringify([{ id: 'X-1', pattern: '^(a+)+$' }]),
    'data.txt': 'a'.repeat(40) + '!\n',
    'src/app.js': VULN
  });
  const started = Date.now();
  const r = await runScan(dir, { customRuleTimeoutMs: 800 });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.ok(Date.now() - started < 10000);
  assert.equal(count(r, 'AUTH-001'), 1, 'built-in findings survive');
  assert.ok(r.stats.warnings.some(w => /custom rule/i.test(w)));
});

test('an invalid custom rule does not drop the valid ones, and severity is restricted', async () => {
  const dir = project({
    'rules/a.json': JSON.stringify([{ id: 'BAD-1', pattern: '(' }, { id: 'OK-1', pattern: 'hello', severity: '<img src=x onerror=alert(1)>' }]),
    'rules/b.json': JSON.stringify([{ id: 'OK-2', pattern: 'hello', severity: 'low' }]),
    'a.txt': 'hello\n'
  });
  const r = await runScan(dir, {});
  fs.rmSync(dir, { recursive: true, force: true });
  const inData = (id) => r.findings.filter(f => f.ruleId === id && f.file === 'a.txt').length;
  assert.equal(inData('OK-1'), 1);
  assert.equal(inData('OK-2'), 1);
  assert.equal(count(r, 'BAD-1'), 0);
  assert.ok(r.stats.warnings.some(w => /BAD-1/.test(w)));
  assert.equal(r.findings.find(f => f.ruleId === 'OK-1').severity, 'HIGH');
  assert.equal(r.findings.find(f => f.ruleId === 'OK-2').severity, 'LOW');
  const html = generateHtml(r);
  assert.equal(html.includes('<img src=x'), false);
});

test('HTML report never places an unknown severity into markup', () => {
  const html = generateHtml({
    targetDir: '/x', stats: { filesScanned: 1, durationMs: 1 },
    findings: [{ ruleId: 'X', severity: '"><script>alert(1)</script>', title: 't', file: 'f', line: 1 }]
  });
  assert.equal(html.includes('alert(1)'), false);
});

test('symlinks are not followed', async () => {
  const outside = project({ 'creds.txt': 'aws_key = ' + 'AKIA' + 'IOSFODNN7QWERTYZ' + '\n' });
  const dir = project({ 'readme.txt': 'hi\n' });
  fs.symlinkSync(path.join(outside, 'creds.txt'), path.join(dir, 'link.txt'));
  const r = await runScan(dir, {});
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(outside, { recursive: true, force: true });
  assert.equal(r.findings.length, 0);
  assert.equal(r.stats.filesScanned, 1);
});

test('a .gitignore wildcard line does not disable the scan', async () => {
  const dir = project({ '.gitignore': '*\n!.gitignore\n', 'src/app.js': VULN });
  const r = await runScan(dir, {});
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(count(r, 'AUTH-001'), 1);
});

test('inline suppression works only from a comment and is counted', async () => {
  const dir = project({
    'src/a.js': "app.delete('/admin/a', (req, res) => { res.end('authwarden-ignore'); });\n",
    'src/b.js': "app.delete('/admin/b', h); // authwarden-ignore reviewed 2026-01\n",
    'src/c.js': L('// authwarden-disable-next-line', "app.delete('/admin/c', h);")
  });
  const r = await runScan(dir, {});
  fs.rmSync(dir, { recursive: true, force: true });
  const flagged = r.findings.filter(f => f.ruleId === 'AUTH-001').map(f => f.file);
  assert.deepEqual(flagged, ['src/a.js']);
  assert.equal(r.stats.suppressed.inline, 2);
});

test('a real-looking secret in a test directory is still reported when the file merely contains the word "fake"', async () => {
  const key = 'AKIA' + 'IOSFODNN7QWERTYZ';
  const dir = project({ 'tests/helpers.js': L('// fake user factory', `const k = '${key}';`, "const placeholder = 'AKIA' + 'XXXXXXXXXXXXXXXX'; // dummy") });
  const r = await runScan(dir, {});
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(count(r, 'SEC-001'), 1);
});

test('Markdown report cannot be broken out of by file content', () => {
  const md = generateMarkdown({
    stats: { filesScanned: 1 },
    findings: [{
      ruleId: 'SEC-001', severity: 'HIGH', title: 'T | <b>x</b>', file: 'a`b|c.js', line: 1,
      snippet: 'k // ` </details> <h1>SCAN PASSED</h1> [Approve](https://evil.example) ![t](https://evil.example/p.png) `',
      description: 'd', remediation: 'r'
    }]
  });
  assert.equal(md.includes('<h1>'), false);
  assert.equal(md.includes('</details> <h1>'), false);
  // The link text survives only as inert characters inside a single code span
  assert.match(md, /`[^`\n]*\]\(https:\/\/evil\.example[^`\n]*`/);
  assert.equal(md.split('\n').filter(l => l.includes('evil.example')).every(l => (l.match(/`/g) || []).length === 2), true);
  assert.equal((md.match(/<\/details>/g) || []).length, 1);
});

test('CLI rejects unknown --fail-on and --format values and survives a null config', () => {
  const dir = project({ 'src/app.js': VULN });
  const badFail = run(['scan', dir, '--fail-on', 'bogus']);
  const badFormat = run(['scan', dir, '--format', 'xml']);
  fs.writeFileSync(path.join(dir, '.authwardenrc.json'), 'null');
  const nullConfig = run(['scan', dir, '--format', 'json']);
  const missingConfig = run(['scan', dir, '--config', path.join(dir, 'nope.json')]);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(badFail.status, 2);
  assert.match(badFail.stderr, /fail-on/);
  assert.equal(badFormat.status, 2);
  assert.match(badFormat.stderr, /format/);
  assert.equal(nullConfig.status, 1);
  assert.equal(JSON.parse(nullConfig.stdout).findings.length > 0, true);
  assert.equal(missingConfig.status, 2);
});
