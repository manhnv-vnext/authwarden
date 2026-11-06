import { test } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { scanBusinessLogic } from '../src/engines/businessLogicScanner.js';

test('detects client-manipulable payment status in business logic (LOGIC-001)', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'authwarden-logic-'));
  const testFile = path.join(tmpDir, 'checkout.js');
  
  // Vulnerable checkout handler accepting client is_paid flag
  const code = [
    'async function handleCheckout(req, res) {',
    '  if (req.body.is_paid) {',
    '    await markOrderComplete(req.body.orderId);',
    '  }',
    '}'
  ].join('\n');

  fs.writeFileSync(testFile, code);

  const findings = await scanBusinessLogic({
    path: testFile,
    relative: 'src/checkout.js',
    ext: '.js',
    name: 'checkout.js'
  }, []);

  fs.rmSync(tmpDir, { recursive: true, force: true });

  const paymentFlaw = findings.find(f => f.ruleId === 'LOGIC-001');
  assert.ok(paymentFlaw, 'Expected LOGIC-001 finding');
  assert.strictEqual(paymentFlaw.severity, 'HIGH');
});

test('detects insecure JWT verification without algorithm whitelist (LOGIC-004)', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'authwarden-jwt-'));
  const testFile = path.join(tmpDir, 'authService.js');
  
  const code = [
    'import jwt from "jsonwebtoken";',
    'function authenticate(token, secret) {',
    '  return jwt.verify(token, secret);',
    '}'
  ].join('\n');

  fs.writeFileSync(testFile, code);

  const findings = await scanBusinessLogic({
    path: testFile,
    relative: 'src/authService.js',
    ext: '.js',
    name: 'authService.js'
  }, []);

  fs.rmSync(tmpDir, { recursive: true, force: true });

  const jwtFlaw = findings.find(f => f.ruleId === 'LOGIC-004');
  assert.ok(jwtFlaw, 'Expected LOGIC-004 finding');
});
