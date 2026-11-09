import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { scanSecrets, redactSecret, calculateShannonEntropy } from '../src/engines/secretScanner.js';

test('redacts secret safely', () => {
  // Construct dynamic key to avoid GitHub push protection false alarms on test files
  const testSecret = ['sk', 'live', '51M000000000000000000000000000000'].join('_');
  const redacted = redactSecret(testSecret);
  assert.equal(redacted.startsWith('sk_l'), true);
  assert.equal(redacted.endsWith('000'), true);
  assert.equal(redacted.includes('***'), true);
});

test('detects exposed Stripe Live Secret Key and redacts it', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-'));
  const envFile = path.join(tmpDir, '.env.production');
  
  // Construct dynamically so GitHub Push Protection doesn't flag sample unit test fixtures
  const dynamicStripeKey = ['sk', 'live', '51MAaBbCcDdEeFfGgHhIiJjKkLl'].join('_');
  const code = `STRIPE_SECRET_KEY=${dynamicStripeKey}\n`;
  fs.writeFileSync(envFile, code);

  const mockFile = {
    path: envFile,
    relative: '.env.production',
    name: '.env.production',
    ext: '.production'
  };

  const findings = scanSecrets(mockFile);
  assert.equal(findings.length > 0, true);
  assert.equal(findings[0].ruleId, 'SEC-004');
  assert.equal(findings[0].severity, 'CRITICAL');
  assert.equal(findings[0].snippet.includes('sk_l'), true);
  assert.equal(findings[0].snippet.includes('***'), true);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('detects GCP API key with hyphen and Anthropic API key', () => {
  // dummy placeholder fixture for test runner
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-sec-'));
  const envFile = path.join(tmpDir, '.env');
  
  const gcpKey = 'AIzaSy' + 'D-abcdefABCDEF12345679abcdefABCDE';
  const antKey = 'sk-ant-api03-' + 'x'.repeat(82);
  const redisUri = ['redis:', '', 'default:pass@redis.cache.internal:6379'].join('/');

  const code = `GCP_KEY=${gcpKey}\nANTHROPIC_KEY=${antKey}\nREDIS_URL=${redisUri}\n`;
  fs.writeFileSync(envFile, code);

  const mockFile = {
    path: envFile,
    relative: '.env',
    name: '.env',
    ext: ''
  };

  const findings = scanSecrets(mockFile);
  const ruleIds = findings.map(f => f.ruleId);
  assert.ok(ruleIds.includes('SEC-006'), 'Expected SEC-006 for GCP key with hyphen');
  assert.ok(ruleIds.includes('SEC-009'), 'Expected SEC-009 for Anthropic key');
  assert.ok(ruleIds.includes('SEC-007'), 'Expected SEC-007 for Redis URI without trailing path');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('calculates Shannon entropy and detects high-entropy generic secret (SEC-010)', () => {
  // Low entropy repeated chars
  const lowEntropy = calculateShannonEntropy('aaaaaaaaaaaaaaaa');
  assert.equal(lowEntropy, 0);

  // High entropy random token
  const highEntropy = calculateShannonEntropy('8f3a9b2c1d4e5f6a7b8c9d0e1f2a3b4c');
  assert.ok(highEntropy > 3.8);

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-sec10-'));
  const envFile = path.join(tmpDir, 'config.js');
  // dummy placeholder
  const code = 'const api_secret = "8f3a9b2c1d4e5f6a7b8c9d0e1f2a3b4c";\n';
  fs.writeFileSync(envFile, code);

  const mockFile = {
    path: envFile,
    relative: 'config.js',
    name: 'config.js',
    ext: '.js'
  };

  const findings = scanSecrets(mockFile);
  const sec10 = findings.find(f => f.ruleId === 'SEC-010');
  assert.ok(sec10, 'Expected SEC-010 for generic high entropy api_secret');
  assert.equal(sec10.severity, 'HIGH');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
