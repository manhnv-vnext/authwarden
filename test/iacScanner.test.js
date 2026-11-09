import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { scanIaC } from '../src/engines/iacScanner.js';

test('flags Dockerfile running as default root user', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-'));
  const dockerfile = path.join(tmpDir, 'Dockerfile');
  
  fs.writeFileSync(dockerfile, 'FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]\n');

  const mockFile = {
    path: dockerfile,
    relative: 'Dockerfile',
    name: 'Dockerfile',
    ext: ''
  };

  const findings = scanIaC(mockFile);
  assert.equal(findings.length > 0, true);
  assert.equal(findings[0].ruleId, 'IAC-001');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('flags multi-stage Dockerfile when final stage lacks USER directive', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-multistage-'));
  const dockerfile = path.join(tmpDir, 'Dockerfile');
  
  const content = `
FROM node:20 AS builder
USER node
RUN npm run build

FROM alpine:latest
COPY --from=builder /app/dist /app
CMD ["./app"]
`;
  fs.writeFileSync(dockerfile, content);

  const findings = scanIaC({
    path: dockerfile,
    relative: 'Dockerfile',
    name: 'Dockerfile',
    ext: ''
  });

  const rootFinding = findings.find(f => f.ruleId === 'IAC-001');
  assert.ok(rootFinding, 'Expected IAC-001 because final stage runs as root');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('flags Docker socket mount in docker-compose.yml', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-test-'));
  const composeFile = path.join(tmpDir, 'docker-compose.yml');
  
  const yaml = `
services:
  app:
    image: test
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`;
  fs.writeFileSync(composeFile, yaml);

  const mockFile = {
    path: composeFile,
    relative: 'docker-compose.yml',
    name: 'docker-compose.yml',
    ext: '.yml'
  };

  const findings = scanIaC(mockFile);
  assert.equal(findings.length > 0, true);
  assert.equal(findings[0].ruleId, 'IAC-004');
  assert.equal(findings[0].severity, 'CRITICAL');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
