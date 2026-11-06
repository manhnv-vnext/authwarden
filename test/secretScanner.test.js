import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { scanSecrets, redactSecret } from '../src/engines/secretScanner.js';

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
