import fs from 'fs';

/** Single source of truth for the tool version: package.json. */
function loadVersion() {
  try {
    const raw = fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf8');
    return JSON.parse(raw).version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export const VERSION = loadVersion();
