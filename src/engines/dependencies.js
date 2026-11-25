import path from 'path';
import { readText, getLines } from '../utils/fileContext.js';

/**
 * Dependency extraction shared by the offline CVE scanner and the OSV.dev lookup.
 * Reads manifests and lockfiles and returns concrete package versions.
 */

const NPM_LOCKFILES = new Set(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']);
const LOCKFILES = new Set([...NPM_LOCKFILES, 'packages.lock.json', 'composer.lock', 'poetry.lock']);

/** Manifest and lockfile names that carry dependency versions. */
export const DEPENDENCY_FILES = new Set([
  'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  'requirements.txt', 'poetry.lock', 'go.mod', 'composer.json', 'composer.lock',
  'packages.lock.json', 'directory.packages.props', 'pom.xml'
]);

const EXACT_VERSION = /^\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.-]+)?$/;

function lineContaining(file, text) {
  const idx = getLines(file).findIndex(l => l.includes(text));
  return idx === -1 ? 1 : idx + 1;
}

/**
 * Dependencies with a concrete version declared in a manifest or lockfile.
 * Returns [{ ecosystem, name, version, line, declaredRange? }] using OSV ecosystem names.
 */
export function extractDependencies(file, allFiles = []) {
  const name = file.name.toLowerCase();
  const content = readText(file);
  if (content === null) return [];
  const deps = [];
  const add = (ecosystem, pkg, version, extra = {}) => {
    const v = String(version || '').trim().replace(/^v/, '');
    if (!pkg || !EXACT_VERSION.test(v)) return;
    deps.push({ ecosystem, name: pkg, version: v, line: lineContaining(file, pkg), locked: LOCKFILES.has(name), ...extra });
  };
  // "^1.2.3" / "~1.2" / ">=1.2.3 <2" -> lowest admissible version; an upper bound alone says nothing
  const lowerBound = (spec) => {
    const s = String(spec).trim();
    if (/^[<*xX]|\|\||^latest$|^[a-z]+:/i.test(s)) return null;
    return s.replace(/^[\^~>=\s]+/, '').split(/[\s,]/)[0];
  };

  try {
    if (name === 'package-lock.json') {
      const lock = JSON.parse(content);
      if (lock.packages) {
        for (const [pkgPath, info] of Object.entries(lock.packages)) {
          if (!pkgPath || !info || info.link) continue;
          add('npm', pkgPath.replace(/^.*node_modules\//, ''), info.version);
        }
      } else if (lock.dependencies) {
        for (const [dep, info] of Object.entries(lock.dependencies)) add('npm', dep, info?.version);
      }
    } else if (name === 'package.json') {
      // A lockfile next to the manifest is the source of truth; ranges are only a fallback
      const dir = path.dirname(file.path);
      const hasLock = allFiles.some(f => NPM_LOCKFILES.has(f.name.toLowerCase()) && path.dirname(f.path) === dir);
      if (!hasLock) {
        const pkg = JSON.parse(content);
        for (const [dep, spec] of Object.entries({ ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) })) {
          if (typeof spec !== 'string') continue;
          add('npm', dep, lowerBound(spec), { declaredRange: spec });
        }
      }
    } else if (name === 'packages.lock.json') {
      const lock = JSON.parse(content);
      for (const group of Object.values(lock.dependencies || {})) {
        for (const [dep, info] of Object.entries(group || {})) add('NuGet', dep, info?.resolved || info?.version);
      }
    } else if (name === 'composer.json') {
      const dir = path.dirname(file.path);
      const hasLock = allFiles.some(f => f.name.toLowerCase() === 'composer.lock' && path.dirname(f.path) === dir);
      if (!hasLock) {
        const comp = JSON.parse(content);
        for (const [dep, spec] of Object.entries({ ...(comp.require || {}), ...(comp['require-dev'] || {}) })) {
          if (typeof spec !== 'string' || !dep.includes('/')) continue;
          add('Packagist', dep, lowerBound(spec), { declaredRange: spec });
        }
      }
    } else if (name === 'composer.lock') {
      const lock = JSON.parse(content);
      for (const p of [...(lock.packages || []), ...(lock['packages-dev'] || [])]) add('Packagist', p.name, p.version);
    } else if (name === 'yarn.lock') {
      // v1:    lodash@^4.17.15:            \n  version "4.17.15"
      // berry: "lodash@npm:^4.17.15":      \n  version: 4.17.15
      let current = null;
      for (const line of content.split('\n')) {
        if (/^\S/.test(line) && line.trimEnd().endsWith(':') && !line.startsWith('#') && !line.startsWith('__metadata')) {
          const spec = line.split(',')[0].trim().replace(/:$/, '').replace(/^["']|["']$/g, '');
          const at = spec.lastIndexOf('@');
          current = at > 0 && !/@(?:workspace|patch|file|link|portal):/.test(spec) ? spec.slice(0, at) : null;
          const alias = spec.match(/@npm:((?:@[^/@]+\/)?[^/@]+)@/);
          if (current && alias) current = alias[1];
        } else if (current) {
          const m = line.match(/^\s+version:?\s+"?([^"\s]+)"?/);
          if (m) {
            add('npm', current, m[1]);
            current = null;
          }
        }
      }
    } else if (name === 'pnpm-lock.yaml') {
      // v5: /lodash/4.17.15:   v6: /lodash@4.17.15(peer@1):   v9: lodash@4.17.15: (also repeated under snapshots:)
      const seen = new Set();
      let inPackages = false;
      for (const line of content.split('\n')) {
        if (/^\S/.test(line)) {
          inPackages = /^packages:\s*$/.test(line);
          continue;
        }
        if (!inPackages) continue;
        const m = line.match(/^ {2}['"]?\/?((?:@[^/@\s'"]+\/)?[^/@\s'"]+)[@/](\d[^_(:'"\s]*)(?:_[^:'"\s]*)?(?:\([^)]*\))*['"]?:\s*$/);
        if (m && !seen.has(m[1] + '@' + m[2])) {
          seen.add(m[1] + '@' + m[2]);
          add('npm', m[1], m[2]);
        }
      }
    } else if (name === 'poetry.lock') {
      for (const block of content.split(/^\[\[package\]\]\s*$/m).slice(1)) {
        const pkg = (block.match(/^name\s*=\s*"([^"]+)"/m) || [])[1];
        const version = (block.match(/^version\s*=\s*"([^"]+)"/m) || [])[1];
        add('PyPI', pkg, version);
      }
    } else if (name === 'requirements.txt') {
      for (const line of content.split('\n')) {
        const m = line.split('#')[0].trim().match(/^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([^\s;]+)/);
        if (m) add('PyPI', m[1], m[2]);
      }
    } else if (name === 'go.mod') {
      for (const line of content.split('\n')) {
        const m = line.trim().replace(/^require\s+/, '').match(/^([A-Za-z0-9.\-_/~]+\.[A-Za-z0-9.\-_/~]+)\s+v(\d[^\s]*)/);
        if (m) add('Go', m[1], m[2].replace(/\+incompatible$/, ''));
      }
    } else if (name === 'pom.xml') {
      const props = new Map();
      const propsBlock = (content.match(/<properties>([\s\S]*?)<\/properties>/i) || [])[1] || '';
      for (const p of propsBlock.matchAll(/<([\w.-]+)>([^<]+)<\/\1>/g)) props.set(p[1], p[2].trim());
      for (const m of content.matchAll(/<dependency>([\s\S]*?)<\/dependency>/gi)) {
        const group = (m[1].match(/<groupId>([^<]+)<\/groupId>/i) || [])[1];
        const artifact = (m[1].match(/<artifactId>([^<]+)<\/artifactId>/i) || [])[1];
        let version = (m[1].match(/<version>([^<]+)<\/version>/i) || [])[1];
        const ref = version && version.trim().match(/^\$\{([\w.-]+)\}$/);
        if (ref) version = props.get(ref[1]);
        if (group && artifact) add('Maven', `${group.trim()}:${artifact.trim()}`, version, { importName: artifact.trim() });
      }
    } else if (file.ext === '.csproj' || name === 'directory.packages.props') {
      for (const m of content.matchAll(/<(?:PackageReference|PackageVersion)\b[^>]*>/gi)) {
        const inc = (m[0].match(/\bInclude=["']([^"']+)["']/i) || [])[1];
        let ver = (m[0].match(/\bVersion=["']([^"']+)["']/i) || [])[1];
        if (!ver && !m[0].endsWith('/>')) {
          const rest = content.slice(m.index + m[0].length, m.index + m[0].length + 300).split(/<\/Package(?:Reference|Version)>/i)[0];
          ver = (rest.match(/<Version>([^<]+)<\/Version>/i) || [])[1];
        }
        add('NuGet', inc, ver);
      }
    }
  } catch {
    // malformed manifest: nothing to query
  }

  return deps;
}
