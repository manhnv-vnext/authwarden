import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { spawnSync, execFileSync } from 'child_process';
import { runScan } from '../src/index.js';
import { generateJson, generateMarkdown } from '../src/reporters/sarifReporter.js';
import { saveBaseline } from '../src/utils/baseline.js';

const BIN = path.resolve('bin/authwarden.js');

// Secret-shaped values are assembled at runtime so none is stored in the repository
const AWS_A = 'AKIA' + 'IOSFODNN7QWERTYA';
const AWS_B = 'AKIA' + 'IOSFODNN7QWERTYB';
const STRIPE = 'sk_' + 'live_' + '4eC39HqLyjWDarjtT1zdp7dcAbCd';
const KEY_BODY = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7' + 'VJTUt9Us8cKj';
const DB_PASS = 'S3cr3t' + 'Passw0rd';
const PEM = (kind) => '-----' + kind + ' PRIV' + 'ATE KEY-----';
const ADO = 'Server=db1;User Id=sa;Pass' + 'word=abc';

async function scanText(rel, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-red-'));
  fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), content);
  try {
    const result = await runScan(dir, {});
    const baselinePath = path.join(dir, 'baseline.json');
    saveBaseline(baselinePath, result.findings, result.stats);
    const all = generateJson(result) + generateMarkdown(result) + fs.readFileSync(baselinePath, 'utf8');
    return { result, all };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('every secret on a line is redacted in every finding for that line', async () => {
  const { result, all } = await scanText('src/c.js', `const a = '${AWS_A}', b = '${AWS_B}', s = '${STRIPE}';\n`);
  assert.ok(result.findings.length >= 3);
  for (const secret of [AWS_A, AWS_B, STRIPE]) assert.equal(all.includes(secret), false, `leaked ${secret.slice(0, 8)}…`);
});

test('a one-line private key never prints its body', async () => {
  const { result, all } = await scanText('src/key.json', `{ "private_key": "${PEM('BEGIN')}\\n${KEY_BODY}\\n${PEM('END')}" }\n`);
  assert.ok(result.findings.find(f => f.ruleId === 'SEC-008'));
  assert.equal(all.includes(KEY_BODY), false);
  assert.equal(all.includes(KEY_BODY.slice(0, 20)), false);
});

test('connection strings keep the host but never the password, however short', async () => {
  const { result, all } = await scanText('src/db.js', [
    `const a = "postgres://app:${DB_PASS}@db.internal:5432/shop";`,
    `const b = "${ADO}";`,
    ''
  ].join('\n'));
  const snippets = result.findings.filter(f => f.ruleId === 'SEC-007').map(f => f.snippet);
  assert.equal(snippets.length, 2);
  assert.equal(all.includes(DB_PASS), false);
  assert.equal(snippets.some(s => /Password=abc/.test(s)), false);
  assert.ok(snippets.some(s => s.includes('db.internal')));
  assert.ok(snippets.some(s => /Password=\*+/.test(s)));
});

// ───────── --staged ─────────

function gitRepo(files) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'aw-git-')));
  execFileSync('git', ['init', '-q'], { cwd: dir });
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}
const git = (dir, ...args) => execFileSync('git', args, { cwd: dir, stdio: ['ignore', 'pipe', 'ignore'] });
const run = (cwd, args) => spawnSync(process.execPath, [BIN, ...args], { cwd, encoding: 'utf8', timeout: 30000 });
const VULN = "app.delete('/admin/users/:id', (req, res) => { db.del(req.params.id); res.end(); });\n";
const ids = (res) => JSON.parse(res.stdout).findings.map(f => `${f.ruleId} ${f.file}`);

test('--staged finds staged files when the target is a subdirectory', () => {
  const dir = gitRepo({ 'services/api/src/app.js': VULN, 'services/web/x.js': VULN });
  git(dir, 'add', 'services/api/src/app.js');
  const fromRoot = run(dir, ['scan', 'services/api', '--staged', '--format', 'json']);
  const fromSub = run(path.join(dir, 'services/api'), ['scan', '.', '--staged', '--format', 'json']);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.deepEqual(ids(fromRoot), ['AUTH-001 src/app.js']);
  assert.deepEqual(ids(fromSub), ['AUTH-001 src/app.js']);
  assert.equal(fromRoot.status, 1);
});

test('--staged scans the staged content, not the working tree, and skips unstaged files', () => {
  const dir = gitRepo({ 'src/app.js': VULN, 'src/unstaged.js': VULN });
  git(dir, 'add', 'src/app.js');
  fs.writeFileSync(path.join(dir, 'src/app.js'), '// cleaned up after staging\n');
  const res = run(dir, ['scan', '.', '--staged', '--format', 'json']);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.deepEqual(ids(res), ['AUTH-001 src/app.js']);
});

test('--staged handles non-ASCII file names', () => {
  const dir = gitRepo({ 'src/ключ.js': VULN });
  git(dir, 'add', '.');
  const res = run(dir, ['scan', '.', '--staged', '--format', 'json']);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.deepEqual(ids(res), ['AUTH-001 src/ключ.js']);
});

test('--staged with nothing staged passes without scanning', () => {
  const dir = gitRepo({ 'src/app.js': VULN });
  const res = run(dir, ['scan', '.', '--staged']);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(res.status, 0);
  assert.match(res.stdout, /No staged/);
});
