import { execSync } from 'child_process';
import path from 'path';

export function getGitChangedFiles(repoDir, { stagedOnly = false } = {}) {
  try {
    const cmd = stagedOnly 
      ? 'git diff --cached --name-only --diff-filter=ACM' 
      : 'git status --porcelain -uall';
    
    const output = execSync(cmd, { cwd: repoDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    const lines = output.trim().split('\n').filter(Boolean);

    if (stagedOnly) {
      return lines.map(l => l.trim());
    }

    // Parse git status --porcelain format (XY <path>)
    return lines.map(line => {
      const parts = line.slice(3).trim();
      return parts.includes(' -> ') ? parts.split(' -> ')[1] : parts;
    }).filter(Boolean);
  } catch {
    return null; // Not a git repo or git not found
  }
}
