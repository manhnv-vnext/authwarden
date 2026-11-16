import fs from 'fs';
import path from 'path';

/**
 * Loads project-level AuthWarden configuration file.
 * Searches for .authwardenrc.json or authwarden.config.json.
 */
export function loadConfig(targetDir = '.') {
  const resolved = path.resolve(targetDir);
  if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
    try {
      const raw = fs.readFileSync(resolved, 'utf8');
      const parsed = JSON.parse(raw);
      return {
        config: parsed,
        configPath: resolved
      };
    } catch (err) {
      console.warn(`[AuthWarden] Warning: Failed to parse config file at ${resolved}: ${err.message}`);
      return { config: {}, configPath: null };
    }
  }

  const candidateDirs = [
    resolved,
    process.cwd()
  ];

  const configNames = [
    '.authwardenrc.json',
    'authwarden.config.json'
  ];

  for (const dir of candidateDirs) {
    for (const name of configNames) {
      const fullPath = path.join(dir, name);
      if (fs.existsSync(fullPath)) {
        try {
          const raw = fs.readFileSync(fullPath, 'utf8');
          const parsed = JSON.parse(raw);
          return {
            config: parsed,
            configPath: fullPath
          };
        } catch (err) {
          console.warn(`[AuthWarden] Warning: Failed to parse config file at ${fullPath}: ${err.message}`);
        }
      }
    }
  }

  return { config: {}, configPath: null };
}
