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

test('detects multi-line TOCTOU race condition in financial operation (LOGIC-002)', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'authwarden-toctou-'));
  const testFile = path.join(tmpDir, 'wallet.js');
  
  const code = [
    'async function withdraw(user, amount) {',
    '  if (user.balance >= amount) {',
    '    await logTransaction(user.id);',
    '    user.balance -= amount;',
    '    await user.save();',
    '  }',
    '}'
  ].join('\n');

  fs.writeFileSync(testFile, code);

  const findings = await scanBusinessLogic({
    path: testFile,
    relative: 'src/wallet.js',
    ext: '.js',
    name: 'wallet.js'
  }, []);

  fs.rmSync(tmpDir, { recursive: true, force: true });

  const toctou = findings.find(f => f.ruleId === 'LOGIC-002');
  assert.ok(toctou, 'Expected LOGIC-002 for multi-line balance mutation');
  assert.strictEqual(toctou.severity, 'HIGH');
});

test('detects client-only logout missing server revocation (LOGIC-005)', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'authwarden-logout-'));
  const testFile = path.join(tmpDir, 'authRoute.js');
  
  const code = [
    'app.post("/api/auth/logout", (req, res) => {',
    '  res.clearCookie("session_token");',
    '  return res.json({ success: true });',
    '});'
  ].join('\n');

  fs.writeFileSync(testFile, code);

  const findings = await scanBusinessLogic({
    path: testFile,
    relative: 'src/authRoute.js',
    ext: '.js',
    name: 'authRoute.js'
  }, []);

  fs.rmSync(tmpDir, { recursive: true, force: true });

  const logoutFlaw = findings.find(f => f.ruleId === 'LOGIC-005');
  assert.ok(logoutFlaw, 'Expected LOGIC-005 for client-only logout');
});
