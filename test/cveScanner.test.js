import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { scanCVEs } from '../src/engines/cveScanner.js';

test('detects CVE in package.json and checks reachability', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-cve-'));
  const pkgFile = path.join(tmpDir, 'package.json');
  const codeFile = path.join(tmpDir, 'app.js');

  const pkgJson = {
    dependencies: {
      "lodash": "^4.17.15",
      "express": "^4.18.1"
    }
  };
  fs.writeFileSync(pkgFile, JSON.stringify(pkgJson, null, 2));

  // app.js actively imports lodash
  fs.writeFileSync(codeFile, "const _ = require('lodash');\nconsole.log(_.get({a:1}, 'a'));\n");

  const allFiles = [
    { path: pkgFile, relative: 'package.json', name: 'package.json', ext: '.json' },
    { path: codeFile, relative: 'app.js', name: 'app.js', ext: '.js' }
  ];

  const findings = await scanCVEs(allFiles[0], allFiles);
  assert.equal(findings.length > 0, true);

  const lodashVuln = findings.find(f => f.ruleId === 'CVE-2020-8203');
  assert.ok(lodashVuln);
  assert.equal(lodashVuln.severity, 'CRITICAL');
  assert.equal(lodashVuln.isReachable, true);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('detects vulnerable Python package in requirements.txt', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-cve-'));
  const reqFile = path.join(tmpDir, 'requirements.txt');

  fs.writeFileSync(reqFile, "pyyaml==5.3.1\nrequests==2.31.0\n");

  const file = {
    path: reqFile,
    relative: 'requirements.txt',
    name: 'requirements.txt',
    ext: '.txt'
  };

  const findings = await scanCVEs(file, [file]);
  assert.equal(findings.length > 0, true);

  const pyyamlVuln = findings.find(f => f.ruleId === 'CVE-2020-14343');
  assert.ok(pyyamlVuln);
  assert.equal(pyyamlVuln.severity, 'CRITICAL');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
