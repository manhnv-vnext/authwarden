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
