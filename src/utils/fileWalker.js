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

const DEFAULT_IGNORED_FILES = new Set([
  '.ds_store',
  'thumbs.db',
  'results.sarif',
  'results.json',
  '.gitignore'
]);

const MAX_FILE_SIZE_BYTES = 4 * 1024 * 1024; // 4MB max per text file

function loadGitignoreRules(rootDir) {
  const gitignorePath = path.join(rootDir, '.gitignore');
  if (!fs.existsSync(gitignorePath)) return [];
  try {
    return fs.readFileSync(gitignorePath, 'utf8')
      .split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#'));
  } catch {
    return [];
  }
}

function matchesGitignore(relPath, fileName, isDir, rules) {
  const normRel = relPath.replace(/\\/g, '/');
  for (const rule of rules) {
    const cleanRule = rule.replace(/^\//, '');
    const isDirOnly = cleanRule.endsWith('/');
    const clean = cleanRule.replace(/\/$/, '');

    if (isDirOnly && !isDir) continue;

    if (clean.startsWith('*')) {
      const ext = clean.slice(1);
      if (fileName.endsWith(ext) || normRel.endsWith(ext)) return true;
    } else if (fileName === clean || normRel === clean || normRel.startsWith(clean + '/')) {
      return true;
    }
  }
  return false;
}

export function walkDirectory(targetDir, options = {}) {
  const files = [];
  const root = path.resolve(targetDir);

  if (!fs.existsSync(root)) {
    throw new Error(`Target path does not exist: ${targetDir}`);
  }

  const rootStat = fs.statSync(root);
  if (rootStat.isFile()) {
    const ext = path.extname(root).toLowerCase();
    const name = path.basename(root);
    if (!BINARY_EXTENSIONS.has(ext) && !name.endsWith('.min.js') && !name.endsWith('.min.css')) {
      if (rootStat.size > 0 && rootStat.size <= MAX_FILE_SIZE_BYTES) {
        files.push({
          path: root,
          relative: name,
          name,
          ext,
          size: rootStat.size
        });
      }
    }
    return files;
  }

  const allowedFilter = options.onlyFiles ? new Set(options.onlyFiles.map(f => path.normalize(f))) : null;
  const gitignoreRules = loadGitignoreRules(root);

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
          if (!matchesGitignore(relativePath, entry.name, true, gitignoreRules)) {
            recurse(fullPath);
          }
        }
      } else if (entry.isFile() || entry.isSymbolicLink()) {
        const lowerName = entry.name.toLowerCase();
        if (DEFAULT_IGNORED_FILES.has(lowerName)) continue;

        const ext = path.extname(entry.name).toLowerCase();
        if (BINARY_EXTENSIONS.has(ext)) continue;
        if (entry.name.endsWith('.min.js') || entry.name.endsWith('.min.css')) continue;

        if (matchesGitignore(relativePath, entry.name, false, gitignoreRules)) {
          continue;
        }

        if (allowedFilter && !allowedFilter.has(path.normalize(relativePath))) {
          continue;
        }

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
