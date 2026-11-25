import { extractDependencies } from './dependencies.js';
import { checkPackageReachable } from './cveScanner.js';

/**
 * Online SCA via OSV.dev (opt-in with --online).
 *
 * The built-in CVE database is an offline snapshot covering a fixed set of packages. This
 * module complements it: resolved dependency versions are looked up in the
 * OSV database. Only { ecosystem, package name, version } leave the machine;
 * no file paths, source code or project identifiers are sent.
 */

const OSV_API = 'https://api.osv.dev';
const BATCH_SIZE = 500;
const DETAIL_CONCURRENCY = 8;
const TIMEOUT_MS = 15000;

const SEVERITY_MAP = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MODERATE: 'MEDIUM', MEDIUM: 'MEDIUM', LOW: 'LOW' };
export { extractDependencies } from './dependencies.js';

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
