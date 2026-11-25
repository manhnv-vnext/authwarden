import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { extractDependencies, scanOsv } from '../src/engines/osvScanner.js';
import { runScan } from '../src/index.js';
import { walkDirectory } from '../src/utils/fileWalker.js';

function project(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-osv-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

const LOCK = JSON.stringify({
  name: 'demo',
  lockfileVersion: 3,
  packages: {
    '': { name: 'demo', version: '1.0.0' },
    'node_modules/lodash': { version: '4.17.20' },
    'node_modules/a/node_modules/@scope/pkg': { version: '2.0.0' }
  }
}, null, 2);

/** Fake OSV API: lodash@4.17.20 has one advisory, everything else is clean. */
function fakeOsv(calls = []) {
  return async (url, init = {}) => {
    calls.push({ url, body: init.body ? JSON.parse(init.body) : null });
    if (url.endsWith('/v1/querybatch')) {
      const body = JSON.parse(init.body);
      return {
        ok: true,
        json: async () => ({
          results: body.queries.map(q =>
            q.package.name === 'lodash' ? { vulns: [{ id: 'GHSA-35jh-r3h4-6jhm' }] } : {})
        })
      };
    }
    if (url.endsWith('/v1/vulns/GHSA-35jh-r3h4-6jhm')) {
      return {
        ok: true,
        json: async () => ({
          id: 'GHSA-35jh-r3h4-6jhm',
          aliases: ['CVE-2021-23337'],
          summary: 'Command Injection in lodash',
          database_specific: { severity: 'HIGH', cwe_ids: ['CWE-77'] },
          affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }]
        })
      };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
}

test('extractDependencies reads resolved versions from package-lock.json', () => {
  const dir = project({ 'package-lock.json': LOCK });
  const files = walkDirectory(dir);
  const deps = files.flatMap(f => extractDependencies(f, files));
  fs.rmSync(dir, { recursive: true, force: true });
  assert.deepEqual(
    deps.map(d => `${d.ecosystem}:${d.name}@${d.version}`).sort(),
    ['npm:@scope/pkg@2.0.0', 'npm:lodash@4.17.20']
  );
});

test('extractDependencies covers PyPI, Go, Maven and NuGet manifests with pinned versions', () => {
  const dir = project({
    'requirements.txt': 'Django==3.2.1\nrequests>=2.0\n# comment\n',
    'go.mod': 'module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.7.0\n)\n',
    'pom.xml': '<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency><dependency><groupId>g</groupId><artifactId>a</artifactId><version>${a.version}</version></dependency></dependencies></project>',
    'App.csproj': '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>'
  });
  const files = walkDirectory(dir);
  const deps = files.flatMap(f => extractDependencies(f, files)).map(d => `${d.ecosystem}:${d.name}@${d.version}`).sort();
  fs.rmSync(dir, { recursive: true, force: true });
  assert.deepEqual(deps, [
    'Go:github.com/gin-gonic/gin@1.7.0',
    'Maven:org.apache.logging.log4j:log4j-core@2.14.1',
    'NuGet:Newtonsoft.Json@12.0.1',
    'PyPI:Django@3.2.1'
  ]);
});

test('package.json is only used when no lockfile sits next to it', () => {
  const pkg = JSON.stringify({ dependencies: { lodash: '^4.17.20', local: 'file:../x' } });
  const withLock = project({ 'package.json': pkg, 'package-lock.json': LOCK });
  const without = project({ 'package.json': pkg });
  const a = walkDirectory(withLock);
  const b = walkDirectory(without);
  const fromManifestA = a.filter(f => f.name === 'package.json').flatMap(f => extractDependencies(f, a));
  const fromManifestB = b.filter(f => f.name === 'package.json').flatMap(f => extractDependencies(f, b));
  fs.rmSync(withLock, { recursive: true, force: true });
  fs.rmSync(without, { recursive: true, force: true });
  assert.equal(fromManifestA.length, 0);
  assert.deepEqual(fromManifestB.map(d => `${d.name}@${d.version}`), ['lodash@4.17.20']);
});

test('scanOsv turns OSV advisories into findings and sends only package coordinates', async () => {
  const dir = project({ 'package-lock.json': LOCK, 'src/app.js': "import _ from 'lodash';\n" });
  const files = walkDirectory(dir);
  const calls = [];
  const { findings, status } = await scanOsv(files, { fetchImpl: fakeOsv(calls) });
  fs.rmSync(dir, { recursive: true, force: true });

  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.ruleId, 'CVE-2021-23337');
  assert.equal(f.severity, 'HIGH');
  assert.equal(f.file, 'package-lock.json');
  assert.equal(f.isReachable, true);
  assert.match(f.title, /lodash 4\.17\.20/);
  assert.match(f.remediation, /4\.17\.21/);
  assert.equal(status.state, 'ok');
  assert.equal(status.packagesQueried, 2);

  const batch = calls.find(c => c.url.endsWith('/v1/querybatch'));
  for (const q of batch.body.queries) {
    assert.deepEqual(Object.keys(q).sort(), ['package', 'version']);
    assert.deepEqual(Object.keys(q.package).sort(), ['ecosystem', 'name']);
  }
  assert.equal(JSON.stringify(calls).includes(dir), false, 'local paths must never be sent');
});

test('scanOsv reports a network failure instead of throwing', async () => {
  const dir = project({ 'package-lock.json': LOCK });
  const files = walkDirectory(dir);
  const { findings, status } = await scanOsv(files, { fetchImpl: async () => { throw new Error('offline'); } });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(findings.length, 0);
  assert.equal(status.state, 'error');
  assert.match(status.message, /offline/);
});

test('runScan never touches the network unless online mode is requested', async () => {
  const dir = project({ 'package-lock.json': LOCK });
  let called = 0;
  const fetchImpl = async (...a) => { called++; return fakeOsv()(...a); };
  const offline = await runScan(dir, { fetchImpl });
  assert.equal(called, 0);
  assert.equal(offline.stats.osv, undefined);

  const online = await runScan(dir, { online: true, fetchImpl });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.ok(called > 0);
  assert.equal(online.stats.osv.state, 'ok');
  assert.equal(online.findings.filter(f => f.ruleId === 'CVE-2021-23337').length, 1);
});

test('online results do not duplicate a CVE the offline database already reported', async () => {
  // axios 0.21.0 / CVE-2023-45857 is in the curated offline database
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/axios': { version: '0.21.0' } } });
  const dir = project({ 'package-lock.json': lock });
  const fetchImpl = async (url, init = {}) => {
    if (url.endsWith('/v1/querybatch')) return { ok: true, json: async () => ({ results: [{ vulns: [{ id: 'GHSA-wf5p-g6vw-rhxx' }] }] }) };
    return { ok: true, json: async () => ({ id: 'GHSA-wf5p-g6vw-rhxx', aliases: ['CVE-2023-45857'], summary: 'Axios CSRF', database_specific: { severity: 'MODERATE' }, affected: [] }) };
  };
  const result = await runScan(dir, { online: true, fetchImpl });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(result.findings.filter(f => f.ruleId === 'CVE-2023-45857').length, 1);
});
