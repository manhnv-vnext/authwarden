import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compareVersions, isVersionAffected, findVulns, CURATED_CVE_DB, CVE_DB_META } from '../src/engines/cveScanner.js';

test('compareVersions orders numeric, prerelease and qualifier versions', () => {
  assert.equal(compareVersions('4.17.20', '4.17.21') < 0, true);
  assert.equal(compareVersions('4.17.21', '4.17.21'), 0);
  assert.equal(compareVersions('1.10.0', '1.9.9') > 0, true);
  assert.equal(compareVersions('2.0', '2.0.0'), 0);
  assert.equal(compareVersions('5.0.0-beta.2', '5.0.0') < 0, true);
  assert.equal(compareVersions('5.0.0-beta.2', '5.0.0-beta.3') < 0, true);
  assert.equal(compareVersions('5.2.20.RELEASE', '5.2.20'), 0);
  assert.equal(compareVersions('3.7.0.25', '3.7.0.3') > 0, true);
  assert.equal(compareVersions('v1.7.0', '1.7.0'), 0);
});

test('isVersionAffected honours introduced, fixed and last_affected bounds', () => {
  const ranges = [{ introduced: '1.0.0', fixed: '1.6.0' }, { introduced: '0.8.1', fixed: '0.28.0' }];
  assert.equal(isVersionAffected('0.21.0', ranges), true);
  assert.equal(isVersionAffected('1.5.0', ranges), true);
  assert.equal(isVersionAffected('1.6.0', ranges), false);
  assert.equal(isVersionAffected('0.28.0', ranges), false);
  assert.equal(isVersionAffected('0.5.0', ranges), false);
  assert.equal(isVersionAffected('2.0.1', [{ introduced: '0', lastAffected: '2.0.1' }]), true);
  assert.equal(isVersionAffected('2.0.2', [{ introduced: '0', lastAffected: '2.0.1' }]), false);
});

const cves = (eco, name, version) => findVulns(eco, name, version).map(v => v.cve);

test('offline database uses real affected ranges, not a single cut-off', () => {
  // CVE-2020-8203 was fixed in lodash 4.17.19
  assert.equal(cves('npm', 'lodash', '4.17.15').includes('CVE-2020-8203'), true);
  assert.equal(cves('npm', 'lodash', '4.17.20').includes('CVE-2020-8203'), false);
  // CVE-2023-45857 was fixed in axios 1.6.0 and backported to 0.28.0
  assert.equal(cves('npm', 'axios', '0.21.0').includes('CVE-2023-45857'), true);
  assert.equal(cves('npm', 'axios', '1.6.5').includes('CVE-2023-45857'), false);
  // Log4Shell: 2.14.1 affected, 2.17.1 not
  assert.equal(cves('maven', 'log4j-core', '2.14.1').includes('CVE-2021-44228'), true);
  assert.equal(cves('maven', 'log4j-core', '2.17.1').includes('CVE-2021-44228'), false);
});

test('a package version can carry several advisories', () => {
  assert.ok(cves('npm', 'lodash', '4.17.15').length >= 2);
});

test('range specifiers are reduced to their lowest admissible version', () => {
  assert.equal(cves('npm', 'lodash', '^4.17.15').includes('CVE-2020-8203'), true);
  assert.equal(cves('npm', 'lodash', 'github:lodash/lodash').length, 0);
});

test('database entries are well formed and carry a snapshot date', () => {
  assert.match(CVE_DB_META.generatedAt, /^\d{4}-\d{2}-\d{2}/);
  assert.equal(CVE_DB_META.source, 'https://osv.dev');
  assert.ok(CURATED_CVE_DB.length > 30);
  for (const e of CURATED_CVE_DB) {
    assert.ok(e.ecosystem && e.package && e.cve && e.title, JSON.stringify(e).slice(0, 80));
    assert.ok(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(e.severity), e.cve);
    assert.ok(Array.isArray(e.ranges) && e.ranges.length > 0, e.cve);
  }
});
