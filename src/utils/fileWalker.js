import fs from 'fs';
import path from 'path';

const DEFAULT_IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'dist',
  'build',
  'out',
  'vendor',
  '.next',
  '.nuxt',
  '.output',
  '.venv',
  'venv',
  'env',
  '__pycache__',
  '.turbo',
  '.cache',
  'coverage',
  '.idea',
  '.vscode',
  'tmp',
  'temp'
]);

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.svg', '.mp4', '.mp3', '.pdf',
  '.zip', '.tar', '.gz', '.tgz', '.bz2', '.7z', '.rar',
  '.exe', '.dll', '.dylib', '.so', '.bin', '.iso',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.pyc', '.pyd', '.class', '.jar'
]);

const MAX_FILE_SIZE_BYTES = 4 * 1024 * 1024; // 4MB max per text file

export function walkDirectory(targetDir, options = {}) {
  const files = [];
  const root = path.resolve(targetDir);

  function recurse(currentPath) {
    let entries;
    try {
      entries = fs.readdirSync(currentPath, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);
      const relativePath = path.relative(root, fullPath);

      if (entry.isDirectory()) {
        if (!DEFAULT_IGNORED_DIRS.has(entry.name) && !entry.name.startsWith('.git')) {
          recurse(fullPath);
        }
      } else if (entry.isFile() || entry.isSymbolicLink()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (BINARY_EXTENSIONS.has(ext)) continue;
        if (entry.name.endsWith('.min.js') || entry.name.endsWith('.min.css')) continue;

        try {
          const stat = fs.statSync(fullPath);
          if (stat.size > 0 && stat.size <= MAX_FILE_SIZE_BYTES) {
            files.push({
              path: fullPath,
              relative: relativePath,
              name: entry.name,
              ext,
              size: stat.size
            });
          }
        } catch {
          // Skip inaccessible file
        }
      }
    }
  }

  recurse(root);
  return files;
}
