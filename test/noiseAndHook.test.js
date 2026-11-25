import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { spawnSync, execFileSync } from 'child_process';
import { scanSAST } from '../src/engines/sastScanner.js';

const BIN = path.resolve('bin/authwarden.js');

function sast(rel, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-noise-'));
  const full = path.join(dir, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  const out = scanSAST({ path: full, relative: rel, name: path.basename(rel), ext: path.extname(rel) });
  fs.rmSync(dir, { recursive: true, force: true });
  return out.map(f => f.ruleId);
}

test('SAST-001 needs SQL shape, not just the word "delete" next to request input', () => {
  assert.deepEqual(sast('src/a.js', "res.send('delete ' + escapeHtml(req.params.uid) + ' pet ' + escapeHtml(req.params.pid));\n"), []);
  assert.deepEqual(sast('src/b.js', "res.send('update ' + req.body.name + ' select ' + req.query.x);\n"), []);
});

test('SAST-001 still fires on real dynamic SQL in each statement form', () => {
  const q = (s) => sast('src/q.js', s + '\n').includes('SAST-001');
  assert.ok(q('db.query("SELECT * FROM users WHERE id = " + req.query.id);'));
  assert.ok(q('db.query("DELETE FROM users WHERE id = " + req.params.id);'));
  assert.ok(q('db.query("UPDATE users SET name = \'" + req.body.name + "\'");'));
  assert.ok(q('db.query(`INSERT INTO logs VALUES (${req.body.msg})`);'));
});

test('SAST-004 needs request input on the line, not just a variable called url', () => {
  assert.deepEqual(sast('Services/RequestProvider.cs', 'using var response = await httpClient.GetAsync(uri).ConfigureAwait(false);\n'), []);
  assert.deepEqual(sast('lib/shopify.ts', 'const result = await fetch(endpoint, { method: "POST" });\n'), []);
  assert.ok(sast('src/proxy.js', 'const upstream = await fetch(req.query.url);\n').includes('SAST-004'));
});

function gitRepo() {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'aw-hook-')));
  execFileSync('git', ['init', '-q'], { cwd: dir });
  return dir;
}

test('init-hook installs a hook that runs this tool from its GitHub source', () => {
  const dir = gitRepo();
  const res = spawnSync(process.execPath, [BIN, 'init-hook'], { cwd: dir, encoding: 'utf8' });
  const hook = fs.readFileSync(path.join(dir, '.git/hooks/pre-commit'), 'utf8');
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(res.status, 0);
  assert.match(hook, /github:manhnv-vnext\/authwarden/);
  assert.match(hook, /--staged/);
});

test('init-hook refuses to overwrite an existing pre-commit hook', () => {
  const dir = gitRepo();
  const hookPath = path.join(dir, '.git/hooks/pre-commit');
  fs.writeFileSync(hookPath, '#!/bin/sh\necho mine\n');
  const res = spawnSync(process.execPath, [BIN, 'init-hook'], { cwd: dir, encoding: 'utf8' });
  const hook = fs.readFileSync(hookPath, 'utf8');
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(res.status, 1);
  assert.equal(hook, '#!/bin/sh\necho mine\n');
  assert.match(res.stderr, /already exists/);
});
