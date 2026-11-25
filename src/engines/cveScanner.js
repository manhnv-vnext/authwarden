import fs from 'fs';
import { extractDependencies } from './dependencies.js';

/**
 * Software Composition Analysis (SCA) & CVE Vulnerability Scanner
 * Matches manifest and lockfile dependencies against an offline OSV.dev snapshot
 * (src/data/cve-db.json) and tags whether the package is imported in source.
 */

/**
 * Offline vulnerability snapshot, generated from OSV.dev by scripts/update-cve-db.mjs.
 * Each entry carries the advisory's real affected ranges for one package.
 */
function loadDatabase() {
  try {
    return JSON.parse(fs.readFileSync(new URL('../data/cve-db.json', import.meta.url), 'utf8'));
  } catch {
    return { source: 'https://osv.dev', generatedAt: null, entries: [] };
  }
}

const DATABASE = loadDatabase();
export const CURATED_CVE_DB = DATABASE.entries;
export const CVE_DB_META = { source: DATABASE.source, generatedAt: DATABASE.generatedAt, advisories: DATABASE.entries.length };

const DB_INDEX = new Map();
for (const entry of CURATED_CVE_DB) {
  const key = entry.ecosystem + '|' + entry.package.toLowerCase();
  if (!DB_INDEX.has(key)) DB_INDEX.set(key, []);
  DB_INDEX.get(key).push(entry);
}

const RELEASE_QUALIFIERS = new Set(['release', 'final', 'ga']);

const POST_RELEASE = new Set(['post', 'sp', 'patch']);

function versionTokens(version) {
  return String(version).trim().replace(/^v/i, '').split('+')[0]
    .split(/[.\-_]|(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])/)
    .filter(t => t !== '' && !RELEASE_QUALIFIERS.has(t.toLowerCase()));
}

/** Negative when a < b, 0 when equal, positive when a > b. Pre-releases sort before their release. */
export function compareVersions(a, b) {
  const ta = versionTokens(a);
  const tb = versionTokens(b);
  for (let i = 0; i < Math.max(ta.length, tb.length); i++) {
    const x = ta[i];
    const y = tb[i];
    if (x === y) continue;
    const xn = x !== undefined && /^\d+$/.test(x);
    const yn = y !== undefined && /^\d+$/.test(y);
    // "2.0" == "2.0.0"; "5.0.0" > "5.0.0-beta"; "2.0.post1" > "2.0"
    if (x === undefined) return yn ? (Number(y) === 0 ? 0 : -1) : POST_RELEASE.has(y.toLowerCase()) ? -1 : 1;
    if (y === undefined) return xn ? (Number(x) === 0 ? 0 : 1) : POST_RELEASE.has(x.toLowerCase()) ? 1 : -1;
    if (xn && yn) {
      if (Number(x) !== Number(y)) return Number(x) - Number(y);
      continue;
    }
    if (xn) return 1; // numeric outranks a pre-release tag
    if (yn) return -1;
    return x.toLowerCase() < y.toLowerCase() ? -1 : 1;
  }
  return 0;
}

/** True when version falls inside any [introduced, fixed) or [introduced, lastAffected] range. */
export function isVersionAffected(version, ranges = []) {
  return ranges.some(r => {
    if (r.introduced && r.introduced !== '0' && compareVersions(version, r.introduced) < 0) return false;
    if (r.fixed !== undefined) return compareVersions(version, r.fixed) < 0;
    if (r.lastAffected !== undefined) return compareVersions(version, r.lastAffected) <= 0;
    return true;
  });
}

/** Reduces a manifest specifier ("^4.17.15", ">=2.0, <3") to its lowest admissible version. */
function baseVersion(spec) {
  const text = String(spec || '');
  if (!/\d/.test(text) || /^(?:git\+|https?:|file:|github:|workspace:|link:|npm:)/i.test(text)) return null;
  if (/^\s*</.test(text)) return null; // an upper bound alone does not name a version
  const clean = text.replace(/[\^~>=<\[\]()]/g, '').trim().split(/\s+|\|\||,/)[0];
  return /^v?\d/.test(clean) ? clean : null;
}

function describeRanges(ranges) {
  return ranges.map(r => {
    const from = r.introduced && r.introduced !== '0' ? `>= ${r.introduced}, ` : '';
    if (r.fixed !== undefined) return `${from}< ${r.fixed}`;
    if (r.lastAffected !== undefined) return `${from}<= ${r.lastAffected}`;
    return `${from}all later versions`.replace(/^all later/, 'all');
  }).join(' or ');
}

/**
 * Every advisory in the offline snapshot affecting this package version.
 * Returns objects shaped for findings: { cve, severity, title, description, affectedVersion, remediation }.
 */
export function findVulns(ecosystem, packageName, versionSpec) {
  let name = String(packageName || '').toLowerCase();
  if (ecosystem === 'pypi') name = name.replace(/[._]+/g, '-');
  const candidates = DB_INDEX.get(ecosystem + '|' + name);
  if (!candidates) return [];
  const version = baseVersion(versionSpec);
  if (!version) return [];

  const hits = [];
  for (const entry of candidates) {
    const range = entry.ranges.find(r => isVersionAffected(version, [r]));
    if (!range) continue;
    hits.push({
      cve: entry.cve,
      advisory: entry.advisory,
      severity: entry.severity,
      title: entry.title,
      description: entry.title.replace(/\.$/, '') + '.',
      affectedVersion: describeRanges(entry.ranges),
      fixedVersion: range.fixed || null,
      remediation: range.fixed
        ? `Upgrade ${entry.package} to ${range.fixed} or later.`
        : `No fixed version is listed for this range; see https://osv.dev/vulnerability/${entry.advisory}.`
    });
  }
  return hits;
}

const ECOSYSTEM_KEYS = { npm: 'npm', PyPI: 'pypi', Go: 'go', Packagist: 'composer', NuGet: 'nuget', Maven: 'maven' };
const REACHABILITY = new Set(['npm', 'nuget', 'maven']);

/**
 * Reports every advisory in the offline snapshot that affects a dependency
 * declared in this manifest or lockfile. Parsing is shared with the OSV.dev
 * lookup (engines/dependencies.js), so both see the same versions.
 */
export async function scanCVEs(file, allFiles = [], options = {}) {
  const findings = [];
  const relPath = file.relative.replace(/\\/g, '/');

  for (const dep of extractDependencies(file, allFiles)) {
    const ecosystem = ECOSYSTEM_KEYS[dep.ecosystem];
    if (!ecosystem) continue;
    const name = ecosystem === 'maven' ? (dep.importName || dep.name) : dep.name;
    const matches = findVulns(ecosystem, name, dep.version);
    if (matches.length === 0) continue;

    const isReachable = REACHABILITY.has(ecosystem) ? checkPackageReachable(name, allFiles, ecosystem) : undefined;
    const origin = dep.locked ? 'Resolved dependency in lockfile' : dep.declaredRange ? `Declared as "${dep.declaredRange}"; no lockfile found, so the lowest allowed version is assumed` : 'Declared dependency';

    for (const match of matches) {
      findings.push({
        ruleId: match.cve,
        severity: match.severity,
        title: `${match.title} (${name} ${dep.version})` + (dep.locked ? ' [lockfile]' : ''),
        file: relPath,
        line: dep.line,
        snippet: dep.declaredRange ? `"${dep.name}": "${dep.declaredRange}"` : `${dep.name}@${dep.version}`,
        ...(isReachable === undefined ? {} : { isReachable }),
        description: `${match.description} (Affected: ${match.affectedVersion}). ${origin}.` +
          (isReachable ? ' Package is imported in application code.' : ''),
        remediation: `${match.remediation} (Current: ${dep.version})`
      });
    }
  }

  return findings;
}

const candidateFilesCache = new WeakMap();

function getCandidateCodes(allFiles, exts = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue']) {
  if (!allFiles || !Array.isArray(allFiles)) return [];
  let fileMap = candidateFilesCache.get(allFiles);
  if (!fileMap) {
    fileMap = new Map();
    candidateFilesCache.set(allFiles, fileMap);
  }
  const extKey = exts.slice().sort().join(',');
  if (fileMap.has(extKey)) {
    return fileMap.get(extKey);
  }

  const codes = [];
  for (const f of allFiles) {
    if (!exts.includes(f.ext)) continue;
    if (f.relative.includes('node_modules') || f.relative.includes('bin/') || f.relative.includes('obj/')) continue;
    try {
      const code = fs.readFileSync(f.path, 'utf8');
      codes.push(code);
    } catch {
      // skip
    }
  }
  fileMap.set(extKey, codes);
  return codes;
}

export function checkPackageReachable(pkgName, allFiles, ecosystem = 'npm') {
  if (ecosystem === 'maven') {
    const javaCodes = getCandidateCodes(allFiles, ['.java']);
    let nsPattern = pkgName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (pkgName.toLowerCase() === 'log4j-core') {
      nsPattern = '(?:org\\.apache\\.logging\\.log4j|LogManager|Logger)';
    } else if (pkgName.toLowerCase() === 'jackson-databind') {
      nsPattern = '(?:com\\.fasterxml\\.jackson|ObjectMapper)';
    } else if (pkgName.toLowerCase() === 'spring-beans' || pkgName.toLowerCase() === 'spring-core') {
      nsPattern = 'org\\.springframework';
    }
    const regex = new RegExp(`(?:import\\s+[^;]*${nsPattern}|\\b${nsPattern}\\b)`, 'i');
    for (const code of javaCodes) {
      if (regex.test(code)) return true;
    }
    return false;
  }

  if (ecosystem === 'nuget') {
    const csCodes = getCandidateCodes(allFiles, ['.cs']);
    let nsPattern = pkgName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (/^AWSSDK\./i.test(pkgName)) {
      nsPattern = '(?:Amazon\\.' + pkgName.replace(/^AWSSDK\./i, '') + '|AmazonS3|IAmazonS3)';
    } else if (pkgName.toLowerCase() === 'newtonsoft.json') {
      nsPattern = '(?:Newtonsoft\\.Json|JsonConvert)';
    } else if (pkgName.toLowerCase() === 'system.text.json') {
      nsPattern = '(?:System\\.Text\\.Json|JsonSerializer)';
    } else if (pkgName.toLowerCase() === 'microsoft.data.sqlclient') {
      nsPattern = '(?:Microsoft\\.Data\\.SqlClient|SqlConnection)';
    } else if (pkgName.toLowerCase() === 'restsharp') {
      nsPattern = '(?:RestSharp|RestClient)';
    } else if (pkgName.toLowerCase() === 'microsoft.aspnetcore.authentication.jwtbearer') {
      nsPattern = '(?:JwtBearer|AddJwtBearer|JwtBearerDefaults)';
    }
    const regex = new RegExp(`(?:using\\s+${nsPattern}|\\b${nsPattern}\\b)`, 'i');
    for (const code of csCodes) {
      if (regex.test(code)) return true;
    }
    return false;
  }

  const escaped = pkgName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const importRegex = new RegExp(`(?:from\\s+['"]${escaped}(?:\\/[^'"]*)?['"]|require\\s*\\(\\s*['"]${escaped}(?:\\/[^'"]*)?['"]\\)|import\\s*\\(['"]${escaped}(?:\\/[^'"]*)?['"]\\))`, 'i');

  const codes = getCandidateCodes(allFiles, ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue']);
  for (const code of codes) {
    if (importRegex.test(code)) return true;
  }
  return false;
}
