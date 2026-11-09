import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { scanSAST } from '../src/engines/sastScanner.js';

test('detects direct SQL injection template literal', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-sast-'));
  const file = path.join(tmpDir, 'service.ts');

  const code = `
export async function findUser(req, res) {
  const query = \`SELECT * FROM users WHERE email = '\${req.query.email}'\`;
  return db.execute(query);
}
`;
  fs.writeFileSync(file, code);

  const mockFile = {
    path: file,
    relative: 'src/services/service.ts',
    name: 'service.ts',
    ext: '.ts'
  };

  const findings = scanSAST(mockFile);
  assert.equal(findings.length > 0, true);
  const sqli = findings.find(f => f.ruleId === 'SAST-001');
  assert.ok(sqli);
  assert.equal(sqli.severity, 'CRITICAL');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('tracks intra-file taint flow from req.body to command execution (RCE)', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-sast-'));
  const file = path.join(tmpDir, 'deploy.js');

  const code = `
const { exec } = require('child_process');

function handleDeploy(req, res) {
  const branchName = req.body.branch;
  // Some other operations
  const command = 'git checkout ' + branchName;
  exec(command);
}
`;
  fs.writeFileSync(file, code);

  const mockFile = {
    path: file,
    relative: 'src/deploy.js',
    name: 'deploy.js',
    ext: '.js'
  };

  const findings = scanSAST(mockFile);
  assert.equal(findings.length > 0, true);
  const taintFinding = findings.find(f => f.ruleId === 'TAINT-001');
  assert.ok(taintFinding);
  assert.equal(taintFinding.severity, 'CRITICAL');
  assert.equal(taintFinding.dataFlow.variable, 'command');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('detects path traversal via untrusted file read', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-sast-'));
  const file = path.join(tmpDir, 'download.js');

  const code = `
const fs = require('fs');

function download(req, res) {
  const content = fs.readFileSync(req.query.path, 'utf8');
  res.send(content);
}
`;
  fs.writeFileSync(file, code);

  const mockFile = {
    path: file,
    relative: 'src/download.js',
    name: 'download.js',
    ext: '.js'
  };

  const findings = scanSAST(mockFile);
  const pt = findings.find(f => f.ruleId === 'SAST-005');
  assert.ok(pt);
  assert.equal(pt.severity, 'HIGH');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('does not flag benign constant template literal in exec as SAST-002', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-sast-fp-'));
  const file = path.join(tmpDir, 'safe.js');

  const code = `
const { exec } = require('child_process');
const id = 123;
exec(\`echo safe-\${id}\`);
`;
  fs.writeFileSync(file, code);

  const findings = scanSAST({
    path: file,
    relative: 'src/safe.js',
    name: 'safe.js',
    ext: '.js'
  });

  const cmdInj = findings.find(f => f.ruleId === 'SAST-002');
  assert.equal(cmdInj, undefined, 'Constant template literal should not trigger SAST-002');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('tracks taint flow through template literal concatenation to sink (TAINT-001)', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-sast-tmpl-'));
  const file = path.join(tmpDir, 'tmplTaint.js');

  const code = `
const { exec } = require('child_process');
function run(req, res) {
  const branch = req.body.branch;
  exec(\`git checkout \${branch}\`);
}
`;
  fs.writeFileSync(file, code);

  const findings = scanSAST({
    path: file,
    relative: 'src/tmplTaint.js',
    name: 'tmplTaint.js',
    ext: '.js'
  });

  const taintFinding = findings.find(f => f.ruleId === 'TAINT-001');
  assert.ok(taintFinding, 'Expected TAINT-001 for template literal sink');
  assert.equal(taintFinding.severity, 'CRITICAL');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
