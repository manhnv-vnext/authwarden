import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

/**
 * Shell-free Git inspection using execFileSync to prevent command injection.
 */

function git(cwd, args, options = {}) {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
    timeout: 30000,
    maxBuffer: 64 * 1024 * 1024,
    ...options
  });
}

export function getGitChangedFiles(repoDir, { stagedOnly = false } = {}) {
  try {
    const args = stagedOnly
      ? ['diff', '--cached', '--name-only', '-z', '--diff-filter=ACMR']
      : ['status', '--porcelain', '-z', '-uall'];
    const entries = git(repoDir, args).split('\0').filter(Boolean);
    if (stagedOnly) return entries;
    // porcelain -z: "XY path"; a rename is followed by its original path as a separate entry
    const files = [];
    for (let i = 0; i < entries.length; i++) {
      const status = entries[i].slice(0, 2);
      files.push(entries[i].slice(3));
      if (status.includes('R') || status.includes('C')) i++;
    }
    return files;
  } catch {
    return null; // Not a git repo or git not found
  }
}

/**
 * Materialises the git index (what would be committed) into a temporary
 * directory, so a staged scan sees staged content rather than the working tree.
 *
 * Returns null outside a git repository. Otherwise:
 *   { scanDir, onlyFiles, cleanup }  - onlyFiles are staged paths relative to scanDir
 */
export function createStagedSnapshot(targetDir) {
  let repoRoot;
  let staged;
  try {
    repoRoot = fs.realpathSync(git(targetDir, ['rev-parse', '--show-toplevel']).trim());
    staged = git(repoRoot, ['diff', '--cached', '--name-only', '-z', '--diff-filter=ACMR']).split('\0').filter(Boolean);
  } catch {
    return null;
  }

  const target = fs.realpathSync(path.resolve(targetDir));
  const relTarget = path.relative(repoRoot, target).split(path.sep).join('/');
  const inTarget = relTarget === '' ? staged : staged.filter(p => p.startsWith(relTarget + '/'));
  const onlyFiles = inTarget.map(p => (relTarget === '' ? p : p.slice(relTarget.length + 1)));
  if (onlyFiles.length === 0) return { scanDir: null, onlyFiles, cleanup: () => {} };

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'authwarden-staged-'));
  const cleanup = () => {
    try {
      fs.rmSync(tmp, { recursive: true, force: true });
    } catch {
      // ignore cleanup error
    }
  };
  try {
    // The whole index is checked out so cross-file context (middleware, lockfiles) is present
    git(repoRoot, ['checkout-index', '-a', '-f', `--prefix=${tmp}${path.sep}`]);
  } catch {
    cleanup();
    return null;
  }
  return { scanDir: relTarget === '' ? tmp : path.join(tmp, relTarget), onlyFiles, cleanup };
}
