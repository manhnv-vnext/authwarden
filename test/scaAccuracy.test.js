import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { runScan } from '../src/index.js';
import { compareVersions, findVulns } from '../src/engines/cveScanner.js';

async function sca(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-sca-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), content);
    }
    const r = await runScan(dir, {});
    return r.findings.filter(f => /^(CVE|GHSA|PYSEC|GO)-/.test(f.ruleId));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const L = (...l) => l.join('\n') + '\n';

test('go.mod: single-line require is read', async () => {
  const f = await sca({ 'go.mod': L('module example.com/app', '', 'go 1.21', '', 'require golang.org/x/net v0.1.0') });
  assert.ok(f.length > 0);
});

test('go.mod: a recent pseudo-version is not reported for long-fixed advisories', async () => {
  const f = await sca({ 'go.mod': L('module example.com/app', '', 'require (', '\tgolang.org/x/net v0.0.0-20991231000000-abcdef123456', ')') });
  assert.equal(f.some(x => x.ruleId === 'CVE-2018-17142' || x.ruleId === 'CVE-2019-9512'), false);
});

test('requirements.txt: extras and spaces around == are read', async () => {
  const a = await sca({ 'requirements.txt': 'requests[security]==2.19.0\n' });
  const b = await sca({ 'requirements.txt': 'requests == 2.19.0\n' });
  assert.ok(a.length > 0);
  assert.equal(a.length, b.length);
});

test('pom.xml: versions declared through properties are resolved', async () => {
  const f = await sca({ 'pom.xml': L('<project>', '<properties><log4j2.version>2.14.1</log4j2.version></properties>', '<dependencies><dependency>', '<groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>', '<version>${log4j2.version}</version>', '</dependency></dependencies>', '</project>') });
  assert.ok(f.some(x => x.ruleId === 'CVE-2021-44228'));
});

test('csproj: Version on a following line and as a child element are read', async () => {
  const f = await sca({ 'App.csproj': L('<Project><ItemGroup>', '<PackageReference Include="Newtonsoft.Json"', '                  Version="12.0.1" />', '<PackageReference Include="RestSharp">', '  <Version>106.11.7</Version>', '</PackageReference>', '</ItemGroup></Project>') });
  assert.ok(f.some(x => /Newtonsoft/i.test(x.title)));
  assert.ok(f.some(x => /RestSharp/i.test(x.title)));
});

test('pnpm v5 keys with a peer suffix are read', async () => {
  const f = await sca({ 'pnpm-lock.yaml': L('lockfileVersion: 5.4', '', 'packages:', '', '  /axios/0.21.0_debug@4.3.4:', '    resolution: {integrity: sha512-x}') });
  assert.ok(f.some(x => x.ruleId === 'CVE-2023-45857'));
});

test('yarn alias entries resolve to the real package', async () => {
  const f = await sca({ 'yarn.lock': L('"my-lodash@npm:lodash@4.17.15":', '  version "4.17.15"') });
  assert.ok(f.some(x => x.ruleId === 'CVE-2020-8203'));
});

test('composer.lock is matched offline', async () => {
  const f = await sca({ 'composer.lock': JSON.stringify({ packages: [{ name: 'guzzlehttp/guzzle', version: '7.4.0' }] }) });
  assert.ok(f.length > 0);
});

test('package.json ranges are not reported when a lockfile resolves a fixed version', async () => {
  const f = await sca({
    'package.json': JSON.stringify({ dependencies: { lodash: '^4.17.15' } }),
    'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/lodash': { version: '99.0.0' } } })
  });
  assert.deepEqual(f, []);
});

test('version comparison handles rc numbers and post-releases', () => {
  assert.ok(compareVersions('1.0.0-rc10', '1.0.0-rc9') > 0);
  assert.ok(compareVersions('1.0.0-rc1', '1.0.0') < 0);
  assert.ok(compareVersions('2.0.post1', '2.0') > 0);
  assert.ok(compareVersions('4.17.20', '4.17.21') < 0);
});

test('an upper-bound-only range is not evaluated as if it were a version', () => {
  assert.deepEqual(findVulns('npm', 'lodash', '<4.17.21'), []);
  assert.ok(findVulns('npm', 'lodash', '>=4.17.15 <4.18.0').length > 0);
});
