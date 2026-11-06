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
  
  const code = `
export async function getDocument(req, res) {
  const doc = await db.document.findById(req.params.id);
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
