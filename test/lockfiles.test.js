import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { extractDependencies } from '../src/engines/dependencies.js';
import { runScan } from '../src/index.js';
import { walkDirectory } from '../src/utils/fileWalker.js';

function project(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-lock-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

function deps(files) {
  const dir = project(files);
  const all = walkDirectory(dir);
  const out = all.flatMap(f => extractDependencies(f, all)).map(d => `${d.ecosystem}:${d.name}@${d.version}`).sort();
  fs.rmSync(dir, { recursive: true, force: true });
  return out;
}

const YARN_V1 = [
  '# yarn lockfile v1',
  '',
  '"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.8.3":',
  '  version "7.12.11"',
  '  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.11.tgz"',
  '',
  'lodash@^4.17.15:',
  '  version "4.17.15"',
  '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.15.tgz"',
  ''
].join('\n');

const YARN_BERRY = [
  '__metadata:',
  '  version: 8',
  '',
  '"lodash@npm:^4.17.15":',
  '  version: 4.17.15',
  '  resolution: "lodash@npm:4.17.15"',
  '',
  '"demo@workspace:.":',
  '  version: 0.0.0-use.local',
  ''
].join('\n');

const PNPM_V9 = [
  "lockfileVersion: '9.0'",
  '',
  'importers:',
  '  .:',
  '    dependencies:',
  '      lodash:',
  '        specifier: ^4.17.15',
  '        version: 4.17.15',
  '',
  'packages:',
  '',
  '  lodash@4.17.15:',
  '    resolution: {integrity: sha512-x}',
  '',
  "  '@scope/pkg@2.0.0':",
  '    resolution: {integrity: sha512-y}',
  '',
  'snapshots:',
  '',
  '  lodash@4.17.15: {}',
  ''
].join('\n');

const PNPM_V6 = [
  "lockfileVersion: '6.0'",
  '',
  'packages:',
  '',
  '  /lodash@4.17.15:',
  '    resolution: {integrity: sha512-x}',
  '',
  '  /@scope/pkg@2.0.0(react@18.2.0):',
  '    resolution: {integrity: sha512-y}',
  ''
].join('\n');

const POETRY = [
  '[[package]]',
  'name = "django"',
  'version = "3.2.1"',
  'description = "A high-level Python web framework"',
  '',
  '[[package]]',
  'name = "requests"',
  'version = "2.31.0"',
  '',
  '[metadata]',
  'lock-version = "2.0"',
  ''
].join('\n');

test('yarn.lock v1 entries are parsed, including scoped and multi-spec headers', () => {
  assert.deepEqual(deps({ 'yarn.lock': YARN_V1 }), ['npm:@babel/code-frame@7.12.11', 'npm:lodash@4.17.15']);
});

test('yarn berry lockfile is parsed and workspace entries are skipped', () => {
  assert.deepEqual(deps({ 'yarn.lock': YARN_BERRY }), ['npm:lodash@4.17.15']);
});

test('pnpm-lock.yaml v9 and v6 package keys are parsed without duplicates', () => {
  assert.deepEqual(deps({ 'pnpm-lock.yaml': PNPM_V9 }), ['npm:@scope/pkg@2.0.0', 'npm:lodash@4.17.15']);
  assert.deepEqual(deps({ 'pnpm-lock.yaml': PNPM_V6 }), ['npm:@scope/pkg@2.0.0', 'npm:lodash@4.17.15']);
});

test('poetry.lock packages are parsed', () => {
  assert.deepEqual(deps({ 'poetry.lock': POETRY }), ['PyPI:django@3.2.1', 'PyPI:requests@2.31.0']);
});

test('package.json is not used as a fallback when a yarn or pnpm lockfile sits next to it', () => {
  const pkg = JSON.stringify({ dependencies: { lodash: '^4.17.15' } });
  assert.deepEqual(deps({ 'package.json': pkg, 'yarn.lock': YARN_V1 }), ['npm:@babel/code-frame@7.12.11', 'npm:lodash@4.17.15']);
});

for (const [name, content] of [['yarn.lock', YARN_V1], ['pnpm-lock.yaml', PNPM_V9]]) {
  test(`offline scan reports a known CVE from ${name}`, async () => {
    const dir = project({ [name]: content, 'src/app.js': "import _ from 'lodash';\n" });
    const result = await runScan(dir, {});
    fs.rmSync(dir, { recursive: true, force: true });
    const hit = result.findings.find(f => f.ruleId === 'CVE-2020-8203');
    assert.ok(hit, `expected CVE-2020-8203 from ${name}`);
    assert.equal(hit.file, name);
    assert.equal(hit.isReachable, true);
    assert.ok(hit.line > 1);
  });
}

test('offline scan reports a known CVE from poetry.lock', async () => {
  const dir = project({ 'poetry.lock': POETRY });
  const result = await runScan(dir, {});
  fs.rmSync(dir, { recursive: true, force: true });
  const django = result.findings.filter(f => f.file === 'poetry.lock' && /django/i.test(f.title));
  assert.ok(django.length >= 1);
  assert.equal(result.findings.some(f => f.file === 'poetry.lock' && /requests 2\.31\.0/.test(f.title) && f.ruleId === 'CVE-2023-32681'), false);
});
