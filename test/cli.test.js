import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { cli } from '../src/cli.js';

test('cli handles --version and --help', async () => {
  const codeV = await cli(['--version']);
  assert.equal(codeV, 0);

  const codeH = await cli(['--help']);
  assert.equal(codeH, 0);

  const codeR = await cli(['rules']);
  assert.equal(codeR, 0);
});

test('cli parses flags before target path correctly', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-cli-order-'));
  const testFile = path.join(tmpDir, 'safe.js');
  fs.writeFileSync(testFile, 'console.log("clean");');

  // Flags placed before positional path argument
  const exitCode = await cli(['scan', '--format', 'json', tmpDir]);
  assert.equal(exitCode, 0);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('cli returns exit code 2 on non-existent path', async () => {
  const exitCode = await cli(['scan', '/tmp/path-that-does-not-exist-authwarden-test']);
  assert.equal(exitCode, 2);
});

test('cli falls back to GitHub Actions INPUT_* environment variables', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-cli-gha-'));
  const testFile = path.join(tmpDir, 'index.js');
  fs.writeFileSync(testFile, 'console.log(1);');

  process.env.INPUT_PATH = tmpDir;
  process.env.INPUT_FORMAT = 'json';

  const exitCode = await cli([]);
  assert.equal(exitCode, 0);

  delete process.env.INPUT_PATH;
  delete process.env.INPUT_FORMAT;
  fs.rmSync(tmpDir, { recursive: true, force: true });
});
