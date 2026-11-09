import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { walkDirectory } from '../src/utils/fileWalker.js';

test('scans a single file directly', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-fw-single-'));
  const singleFile = path.join(tmpDir, 'server.js');
  fs.writeFileSync(singleFile, 'console.log("hello");');

  const files = walkDirectory(singleFile);
  assert.equal(files.length, 1);
  assert.equal(files[0].name, 'server.js');
  assert.equal(files[0].ext, '.js');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('throws an error for non-existent target path', () => {
  assert.throws(
    () => walkDirectory('/path/that/does/not/exist/authwarden'),
    /Target path does not exist/
  );
});

test('respects ignored directories and binary extensions', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-fw-ignore-'));
  fs.mkdirSync(path.join(tmpDir, 'node_modules'));
  fs.writeFileSync(path.join(tmpDir, 'node_modules', 'dep.js'), 'code');
  fs.writeFileSync(path.join(tmpDir, 'image.png'), 'fake-png');
  fs.writeFileSync(path.join(tmpDir, 'app.js'), 'code');

  const files = walkDirectory(tmpDir);
  assert.equal(files.length, 1);
  assert.equal(files[0].name, 'app.js');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('respects root .gitignore patterns and default ignored files (.DS_Store, results.sarif)', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-fw-gitignore-'));
  
  fs.writeFileSync(path.join(tmpDir, '.gitignore'), '*.secret.js\ncustom_build/\n');
  fs.writeFileSync(path.join(tmpDir, 'valid.js'), 'code');
  fs.writeFileSync(path.join(tmpDir, 'my.secret.js'), 'secret');
  fs.writeFileSync(path.join(tmpDir, '.DS_Store'), 'ds-store-data');
  fs.writeFileSync(path.join(tmpDir, 'results.sarif'), '{}');

  fs.mkdirSync(path.join(tmpDir, 'custom_build'));
  fs.writeFileSync(path.join(tmpDir, 'custom_build', 'bundle.js'), 'code');

  const files = walkDirectory(tmpDir);
  assert.equal(files.length, 1);
  assert.equal(files[0].name, 'valid.js');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
