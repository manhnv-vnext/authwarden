import { test } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { scanApiSpecs } from '../src/engines/apiSpecScanner.js';

test('detects cleartext HTTP server and sensitive query parameters in OpenAPI spec', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'authwarden-spec-'));
  const testFile = path.join(tmpDir, 'openapi.yaml');
  
  const yamlContent = [
    'openapi: 3.0.0',
    'info:',
    '  title: Test API',
    '  version: 1.0.0',
    'servers:',
    '  - url: "http://api.production-domain.com/v1"',
    'paths:',
    '  /auth/session:',
    '    get:',
    '      parameters:',
    '        - name: "token"',
    '          in: query'
  ].join('\n');

  fs.writeFileSync(testFile, yamlContent);

  const findings = await scanApiSpecs({
    path: testFile,
    relative: 'openapi.yaml',
    ext: '.yaml',
    name: 'openapi.yaml'
  }, []);

  fs.rmSync(tmpDir, { recursive: true, force: true });

  const httpFinding = findings.find(f => f.ruleId === 'SPEC-004');
  assert.ok(httpFinding, 'Expected SPEC-004 for http server URL');

  const querySecretFinding = findings.find(f => f.ruleId === 'SPEC-003');
  assert.ok(querySecretFinding, 'Expected SPEC-003 for token in query parameter');
});

test('detects unprotected sensitive endpoint in OpenAPI JSON', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'authwarden-specjson-'));
  const testFile = path.join(tmpDir, 'swagger.json');
  
  const jsonContent = JSON.stringify({
    openapi: '3.0.0',
    paths: {
      '/api/admin/users': {
        delete: {
          summary: 'Delete user'
        }
      }
    }
  }, null, 2);

  fs.writeFileSync(testFile, jsonContent);

  const findings = await scanApiSpecs({
    path: testFile,
    relative: 'swagger.json',
    ext: '.json',
    name: 'swagger.json'
  }, []);

  fs.rmSync(tmpDir, { recursive: true, force: true });

  const unprotectedFinding = findings.find(f => f.ruleId === 'SPEC-001');
  assert.ok(unprotectedFinding, 'Expected SPEC-001 for unprotected admin delete');
});

test('detects unprotected sensitive endpoint in OpenAPI YAML (SPEC-001)', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'authwarden-specyaml-'));
  const testFile = path.join(tmpDir, 'openapi.yaml');
  
  const yamlContent = [
    'openapi: 3.0.0',
    'paths:',
    '  /api/admin/system/restart:',
    '    post:',
    '      summary: Restart system',
    '  /api/public/status:',
    '    get:',
    '      summary: Health check'
  ].join('\n');

  fs.writeFileSync(testFile, yamlContent);

  const findings = await scanApiSpecs({
    path: testFile,
    relative: 'openapi.yaml',
    ext: '.yaml',
    name: 'openapi.yaml'
  }, []);

  fs.rmSync(tmpDir, { recursive: true, force: true });

  const yamlUnprotected = findings.find(f => f.ruleId === 'SPEC-001');
  assert.ok(yamlUnprotected, 'Expected SPEC-001 for YAML unprotected admin route');
  assert.ok(yamlUnprotected.title.includes('POST /api/admin/system/restart'));
});
