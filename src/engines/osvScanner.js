import path from 'path';
import { readText, getLines } from '../utils/fileContext.js';
import { checkPackageReachable } from './cveScanner.js';

/**
 * Online SCA via OSV.dev (opt-in with --online).
 *
 * The built-in CVE database is a small curated list that works offline. This
 * module complements it: resolved dependency versions are looked up in the
 * OSV database. Only { ecosystem, package name, version } leave the machine;
 * no file paths, source code or project identifiers are sent.
 */

const OSV_API = 'https://api.osv.dev';
const BATCH_SIZE = 500;
const DETAIL_CONCURRENCY = 8;
const TIMEOUT_MS = 15000;

const SEVERITY_MAP = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MODERATE: 'MEDIUM', MEDIUM: 'MEDIUM', LOW: 'LOW' };
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
    deps.push({ ecosystem, name: pkg, version: v, line: lineContaining(file, pkg), ...extra });
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
      const hasLock = allFiles.some(f => f.name.toLowerCase() === 'package-lock.json' && path.dirname(f.path) === dir);
      if (!hasLock) {
        const pkg = JSON.parse(content);
        for (const [dep, spec] of Object.entries({ ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) })) {
          if (typeof spec !== 'string') continue;
          add('npm', dep, spec.replace(/^[\^~>=<\s]+/, ''), { declaredRange: spec });
        }
      }
    } else if (name === 'packages.lock.json') {
      const lock = JSON.parse(content);
      for (const group of Object.values(lock.dependencies || {})) {
        for (const [dep, info] of Object.entries(group || {})) add('NuGet', dep, info?.resolved || info?.version);
      }
    } else if (name === 'composer.lock') {
      const lock = JSON.parse(content);
      for (const p of [...(lock.packages || []), ...(lock['packages-dev'] || [])]) add('Packagist', p.name, p.version);
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
      for (const m of content.matchAll(/<dependency>([\s\S]*?)<\/dependency>/gi)) {
        const group = (m[1].match(/<groupId>([^<]+)<\/groupId>/i) || [])[1];
        const artifact = (m[1].match(/<artifactId>([^<]+)<\/artifactId>/i) || [])[1];
        const version = (m[1].match(/<version>([^<]+)<\/version>/i) || [])[1];
        if (group && artifact) add('Maven', `${group.trim()}:${artifact.trim()}`, version, { importName: artifact.trim() });
      }
    } else if (file.ext === '.csproj' || name === 'directory.packages.props') {
      for (const m of content.matchAll(/<(?:PackageReference|PackageVersion)\b[^>]*>/gi)) {
        const inc = (m[0].match(/\bInclude=["']([^"']+)["']/i) || [])[1];
        const ver = (m[0].match(/\bVersion=["']([^"']+)["']/i) || [])[1];
        add('NuGet', inc, ver);
      }
    }
  } catch {
    // malformed manifest: nothing to query
  }

  return deps;
}

async function fetchJson(fetchImpl, url, init) {
  const res = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!res.ok) throw new Error(`OSV API responded with HTTP ${res.status}`);
  return res.json();
}

function fixedVersionFor(vuln, dep) {
  for (const affected of vuln.affected || []) {
    if (affected.package?.name && affected.package.name.toLowerCase() !== dep.name.toLowerCase()) continue;
    for (const range of affected.ranges || []) {
      const fixed = (range.events || []).map(e => e.fixed).filter(Boolean).pop();
      if (fixed) return fixed;
    }
  }
  return null;
}

const REACHABILITY_ECOSYSTEM = { npm: 'npm', NuGet: 'nuget', Maven: 'maven' };

/**
 * Queries OSV.dev for every pinned dependency found in `files`.
 * Never throws: network problems are returned as status.state === 'error'.
 */
export async function scanOsv(files, options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const status = { state: 'ok', packagesQueried: 0, vulnerablePackages: 0 };
  const findings = [];

  const occurrences = [];
  for (const file of files) {
    for (const dep of extractDependencies(file, files)) {
      occurrences.push({ ...dep, file: file.relative.replace(/\\/g, '/') });
    }
  }

  const unique = new Map();
  for (const dep of occurrences) {
    const key = `${dep.ecosystem}|${dep.name}|${dep.version}`;
    if (!unique.has(key)) unique.set(key, dep);
  }
  const queries = [...unique.entries()];
  status.packagesQueried = queries.length;
  if (queries.length === 0) return { findings, status };

  if (typeof fetchImpl !== 'function') {
    return { findings, status: { ...status, state: 'error', message: 'fetch is not available in this Node.js runtime' } };
  }

  try {
    const vulnIdsByKey = new Map();
    for (let i = 0; i < queries.length; i += BATCH_SIZE) {
      const chunk = queries.slice(i, i + BATCH_SIZE);
      const data = await fetchJson(fetchImpl, `${OSV_API}/v1/querybatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          queries: chunk.map(([, d]) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version }))
        })
      });
      (data.results || []).forEach((r, idx) => {
        const ids = (r?.vulns || []).map(v => v.id).filter(Boolean);
        if (ids.length) vulnIdsByKey.set(chunk[idx][0], ids);
      });
    }
    status.vulnerablePackages = vulnIdsByKey.size;

    const allIds = [...new Set([...vulnIdsByKey.values()].flat())];
    const details = new Map();
    for (let i = 0; i < allIds.length; i += DETAIL_CONCURRENCY) {
      await Promise.all(allIds.slice(i, i + DETAIL_CONCURRENCY).map(async (id) => {
        try {
          details.set(id, await fetchJson(fetchImpl, `${OSV_API}/v1/vulns/${encodeURIComponent(id)}`));
        } catch {
          details.set(id, { id }); // keep the advisory even if details are unavailable
        }
      }));
    }

    for (const dep of occurrences) {
      const ids = vulnIdsByKey.get(`${dep.ecosystem}|${dep.name}|${dep.version}`);
      if (!ids) continue;
      const reachEco = REACHABILITY_ECOSYSTEM[dep.ecosystem];
      const isReachable = reachEco ? checkPackageReachable(dep.importName || dep.name, files, reachEco) : undefined;

      for (const id of ids) {
        const vuln = details.get(id) || { id };
        const cve = (vuln.aliases || []).find(a => /^CVE-/.test(a));
        const fixed = fixedVersionFor(vuln, dep);
        const rawSeverity = String(vuln.database_specific?.severity || '').toUpperCase();
        const summary = vuln.summary || 'Known vulnerability';

        findings.push({
          ruleId: cve || id,
          severity: SEVERITY_MAP[rawSeverity] || 'MEDIUM',
          title: `${summary} (${dep.name} ${dep.version})`,
          file: dep.file,
          line: dep.line,
          snippet: `${dep.name}@${dep.version}`,
          source: 'osv.dev',
          advisoryId: id,
          cwe: vuln.database_specific?.cwe_ids?.[0],
          ...(isReachable === undefined ? {} : { isReachable }),
          description: `${summary}. Advisory ${id} from OSV.dev${rawSeverity ? '' : ' (severity not rated; reported as MEDIUM)'}.` +
            (dep.declaredRange ? ` Version taken from declared range "${dep.declaredRange}" because no lockfile was found.` : '') +
            (isReachable ? ' Package is imported in application code.' : ''),
          remediation: fixed
            ? `Upgrade ${dep.name} to ${fixed} or later. See https://osv.dev/vulnerability/${id}`
            : `No fixed version listed. See https://osv.dev/vulnerability/${id}`
        });
      }
    }
  } catch (err) {
    return { findings: [], status: { ...status, state: 'error', message: err.message } };
  }

  return { findings, status };
}
