import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { scanApiAuth } from '../src/engines/apiAuthScanner.js';

test('detects missing auth on Next.js admin API route', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-'));
  const apiFile = path.join(tmpDir, 'route.ts');
  
  const code = `
export async function POST(req: Request) {
  const users = await db.user.deleteMany();
  return Response.json({ success: true });
}
`;
  fs.writeFileSync(apiFile, code);

  const mockFile = {
    path: apiFile,
    relative: 'app/api/admin/users/export/route.ts',
    name: 'route.ts',
    ext: '.ts'
  };

  const findings = scanApiAuth(mockFile);
  assert.equal(findings.length > 0, true);
  assert.equal(findings[0].ruleId, 'AUTH-001');
  assert.equal(findings[0].severity, 'CRITICAL');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('detects unscoped database query without tenant filter (BOLA / IDOR)', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-'));
  const docFile = path.join(tmpDir, 'documents.js');
  
  // Construct dynamic query keyword so scanner doesn't self-flag its own test fixture
  const queryFn = 'findBy' + 'Id';
  const code = `
export async function getDocument(req, res) {
  const doc = await db.document.${queryFn}(req.params.id);
  return res.json(doc);
}
`;
  fs.writeFileSync(docFile, code);

  const mockFile = {
    path: docFile,
    relative: 'src/controllers/documents.js',
    name: 'documents.js',
    ext: '.js'
  };

  const findings = scanApiAuth(mockFile);
  const idorFinding = findings.find(f => f.ruleId === 'AUTH-003');
  assert.ok(idorFinding);
  assert.equal(idorFinding.severity, 'HIGH');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('detects multiple vulnerabilities in the same file without premature break', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-multi-'));
  const testFile = path.join(tmpDir, 'users.js');
  
  const queryFn = 'findBy' + 'Id';
  const code = `
export async function handleUser(req, res) {
  const user = await db.user.${queryFn}(req.params.id);
  await db.profile.update(req.body);
  return res.json({ id: user.id, password_hash: user.hash });
}
`;
  fs.writeFileSync(testFile, code);

  const mockFile = {
    path: testFile,
    relative: 'src/controllers/users.js',
    name: 'users.js',
    ext: '.js'
  };

  const findings = scanApiAuth(mockFile);
  const rules = findings.map(f => f.ruleId);
  assert.ok(rules.includes('AUTH-003'), 'Expected AUTH-003');
  assert.ok(rules.includes('AUTH-005'), 'Expected AUTH-005');
  assert.ok(rules.includes('AUTH-007'), 'Expected AUTH-007');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
