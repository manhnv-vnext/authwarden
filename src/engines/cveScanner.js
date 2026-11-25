import fs from 'fs';
import { readText } from '../utils/fileContext.js';
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

function versionTokens(version) {
  return String(version).trim().replace(/^v/i, '').split('+')[0].split(/[.\-_]/)
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
    if (x === undefined) return yn ? (Number(y) === 0 ? 0 : -1) : 1; // "2.0" == "2.0.0", "5.0.0" > "5.0.0-beta"
    if (y === undefined) return xn ? (Number(x) === 0 ? 0 : 1) : -1;
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

export async function scanCVEs(file, allFiles = [], options = {}) {
  const findings = [];
  const fileName = file.name.toLowerCase();
  const relPath = file.relative.replace(/\\/g, '/');

  const content = readText(file);
  if (content === null) return findings;

  // 1. Scan package.json
  if (fileName === 'package.json') {
    try {
      const pkg = JSON.parse(content);
      const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

      for (const [depName, versionSpec] of Object.entries(allDeps)) {
        for (const match of findVulns('npm', depName.toLowerCase(), versionSpec)) {
          const isReachable = checkPackageReachable(depName, allFiles);
          const lineNo = findLineNumber(content, `"${depName}"`);

          findings.push({
            ruleId: match.cve,
            severity: match.severity,
            title: `${match.title} (${depName} ${versionSpec})`,
            file: relPath,
            line: lineNo,
            snippet: `"${depName}": "${versionSpec}"`,
            isReachable,
            description: `${match.description} (Affected: ${match.affectedVersion}).` +
              (isReachable ? ' ⚠️ REACHABLE IN SOURCE: Package is imported in application code.' : ' (Installed dependency)'),
            remediation: `${match.remediation} (Current version: ${versionSpec})`
          });
        }
      }
    } catch {
      // Skip invalid json
    }
  }

  // 1b. Scan package-lock.json (Resolved dependencies including transitive)
  if (fileName === 'package-lock.json') {
    try {
      const lock = JSON.parse(content);
      const scannedPkgs = new Set();
      
      const checkDep = (depName, version) => {
        if (!depName || !version || scannedPkgs.has(depName + '@' + version)) return;
        scannedPkgs.add(depName + '@' + version);

        for (const match of findVulns('npm', depName.toLowerCase(), version)) {
          const isReachable = checkPackageReachable(depName, allFiles);
          const lineNo = findLineNumber(content, `"${depName}"`);

          findings.push({
            ruleId: match.cve,
            severity: match.severity,
            title: `${match.title} (${depName} ${version}) [lockfile]`,
            file: relPath,
            line: lineNo,
            snippet: `"${depName}": "${version}"`,
            isReachable,
            description: `${match.description} (Affected: ${match.affectedVersion}).` +
              (isReachable ? ' ⚠️ REACHABLE IN SOURCE: Package is imported in application code.' : ' (Resolved dependency in lockfile)'),
            remediation: `${match.remediation} (Resolved: ${version})`
          });
        }
      };

      if (lock.packages) {
        for (const [pkgPath, pkgInfo] of Object.entries(lock.packages)) {
          if (!pkgPath || !pkgInfo.version) continue;
          const depName = pkgPath.replace(/^.*node_modules\//, '');
          checkDep(depName, pkgInfo.version);
        }
      } else if (lock.dependencies) {
        for (const [depName, depInfo] of Object.entries(lock.dependencies)) {
          if (depInfo && depInfo.version) {
            checkDep(depName, depInfo.version);
          }
        }
      }
    } catch {
      // Skip invalid json
    }
  }

  // 1c. yarn.lock / pnpm-lock.yaml / poetry.lock (resolved versions)
  if (fileName === 'yarn.lock' || fileName === 'pnpm-lock.yaml' || fileName === 'poetry.lock') {
    for (const dep of extractDependencies(file, allFiles)) {
      const ecosystem = dep.ecosystem === 'PyPI' ? 'pypi' : 'npm';
      const matches = findVulns(ecosystem, dep.name, dep.version);
      if (matches.length === 0) continue;
      const isReachable = ecosystem === 'npm' ? checkPackageReachable(dep.name, allFiles) : undefined;
      for (const match of matches) {
        findings.push({
          ruleId: match.cve,
          severity: match.severity,
          title: `${match.title} (${dep.name} ${dep.version}) [lockfile]`,
          file: relPath,
          line: dep.line,
          snippet: `${dep.name}@${dep.version}`,
          ...(isReachable === undefined ? {} : { isReachable }),
          description: `${match.description} (Affected: ${match.affectedVersion}).` +
            (isReachable ? ' ⚠️ REACHABLE IN SOURCE: Package is imported in application code.' : ' (Resolved dependency in lockfile)'),
          remediation: `${match.remediation} (Resolved: ${dep.version})`
        });
      }
    }
  }

  // 2. Scan requirements.txt
  if (fileName === 'requirements.txt') {
    const lines = content.split('\n');
    lines.forEach((line, idx) => {
      const cleanLine = line.trim().split('#')[0];
      if (!cleanLine) return;

      const matchPart = cleanLine.match(/^([a-zA-Z0-9_\-]+)(?:==|<=|>=|<|>|~=)\s*(.+)$/);
      if (matchPart) {
        const pkgName = matchPart[1].toLowerCase();
        const version = matchPart[2].trim();

        for (const match of findVulns('pypi', pkgName, version)) {
          findings.push({
            ruleId: match.cve,
            severity: match.severity,
            title: `${match.title} (${pkgName} ${version})`,
            file: relPath,
            line: idx + 1,
            snippet: cleanLine,
            description: `${match.description} (Affected: ${match.affectedVersion}).`,
            remediation: `${match.remediation} (Current: ${version})`
          });
        }
      }
    });
  }

  // 3. Scan go.mod
  if (fileName === 'go.mod') {
    const lines = content.split('\n');
    lines.forEach((line, idx) => {
      const matchPart = line.trim().match(/^([a-zA-Z0-9.\-_/]+)\s+v([0-9.]+)/);
      if (matchPart) {
        const modName = matchPart[1];
        const version = matchPart[2];

        for (const match of findVulns('go', modName.toLowerCase(), version)) {
          findings.push({
            ruleId: match.cve,
            severity: match.severity,
            title: `${match.title} (${modName} v${version})`,
            file: relPath,
            line: idx + 1,
            snippet: line.trim(),
            description: `${match.description} (Affected: ${match.affectedVersion}).`,
            remediation: `${match.remediation} (Current: v${version})`
          });
        }
      }
    });
  }

  // 4. Scan composer.json
  if (fileName === 'composer.json') {
    try {
      const comp = JSON.parse(content);
      const reqs = { ...(comp.require || {}), ...(comp['require-dev'] || {}) };

      for (const [depName, versionSpec] of Object.entries(reqs)) {
        for (const match of findVulns('composer', depName.toLowerCase(), versionSpec)) {
          const lineNo = findLineNumber(content, `"${depName}"`);
          findings.push({
            ruleId: match.cve,
            severity: match.severity,
            title: `${match.title} (${depName} ${versionSpec})`,
            file: relPath,
            line: lineNo,
            snippet: `"${depName}": "${versionSpec}"`,
            description: `${match.description} (Affected: ${match.affectedVersion}).`,
            remediation: `${match.remediation} (Current: ${versionSpec})`
          });
        }
      }
    } catch {
      // ignore
    }
  }

  // 5. Scan .csproj and Directory.Packages.props (NuGet / .NET)
  if (file.ext === '.csproj' || fileName === 'directory.packages.props') {
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!/<(?:PackageReference|PackageVersion)\b/i.test(line)) continue;

      const incMatch = line.match(/\bInclude=["']([^"']+)["']/i);
      const verMatch = line.match(/\bVersion=["']([^"']+)["']/i);

      let pkgName = incMatch ? incMatch[1] : null;
      let version = verMatch ? verMatch[1] : null;

      // Check nested <Version> child tag if version attribute not on same line
      if (pkgName && !version) {
        for (let j = i + 1; j < Math.min(lines.length, i + 5); j++) {
          const subVer = lines[j].match(/<Version>([^<]+)<\/Version>/i);
          if (subVer) {
            version = subVer[1].trim();
            break;
          }
          if (lines[j].includes('</PackageReference>') || lines[j].includes('</PackageVersion>')) break;
        }
      }

      if (pkgName && version) {
        for (const match of findVulns('nuget', pkgName.toLowerCase(), version)) {
          const isReachable = checkPackageReachable(pkgName, allFiles, 'nuget');
          findings.push({
            ruleId: match.cve,
            severity: match.severity,
            title: `${match.title} (${pkgName} ${version})`,
            file: relPath,
            line: i + 1,
            snippet: line.trim(),
            isReachable,
            description: `${match.description} (Affected: ${match.affectedVersion}).` +
              (isReachable ? ' ⚠️ REACHABLE IN SOURCE: Package is imported in application code.' : ' (Installed NuGet dependency)'),
            remediation: `${match.remediation} (Current version: ${version})`
          });
        }
      }
    }
  }

  // 6. Scan packages.lock.json (Resolved NuGet dependencies)
  if (fileName === 'packages.lock.json') {
    try {
      const lock = JSON.parse(content);
      const scannedNuget = new Set();

      const checkNuget = (depName, version) => {
        if (!depName || !version || scannedNuget.has(depName + '@' + version)) return;
        scannedNuget.add(depName + '@' + version);

        for (const match of findVulns('nuget', depName.toLowerCase(), version)) {
          const isReachable = checkPackageReachable(depName, allFiles, 'nuget');
          const lineNo = findLineNumber(content, `"${depName}"`);

          findings.push({
            ruleId: match.cve,
            severity: match.severity,
            title: `${match.title} (${depName} ${version}) [NuGet lockfile]`,
            file: relPath,
            line: lineNo,
            snippet: `"${depName}": "${version}"`,
            isReachable,
            description: `${match.description} (Affected: ${match.affectedVersion}).` +
              (isReachable ? ' ⚠️ REACHABLE IN SOURCE: Package is imported in application code.' : ' (Resolved NuGet dependency in lockfile)'),
            remediation: `${match.remediation} (Resolved: ${version})`
          });
        }
      };

      if (lock.dependencies && typeof lock.dependencies === 'object') {
        for (const [tf, deps] of Object.entries(lock.dependencies)) {
          if (deps && typeof deps === 'object') {
            for (const [depName, depInfo] of Object.entries(deps)) {
              const ver = depInfo.resolved || depInfo.version;
              if (ver) checkNuget(depName, ver);
            }
          }
        }
      }
    } catch {
      // skip invalid json
    }
  }

  // 7. Scan pom.xml (Maven / Java dependencies)
  if (fileName === 'pom.xml') {
    const depRegex = /<dependency>([\s\S]*?)<\/dependency>/gi;
    let depMatch;
    while ((depMatch = depRegex.exec(content)) !== null) {
      const block = depMatch[1];
      const artMatch = block.match(/<artifactId>([^<]+)<\/artifactId>/i);
      const verMatch = block.match(/<version>([^<]+)<\/version>/i);

      if (artMatch && verMatch) {
        const artifactId = artMatch[1].trim();
        const version = verMatch[1].trim();

        for (const match of findVulns('maven', artifactId.toLowerCase(), version)) {
          const isReachable = checkPackageReachable(artifactId, allFiles, 'maven');
          const lineNo = content.slice(0, depMatch.index).split('\n').length;

          findings.push({
            ruleId: match.cve,
            severity: match.severity,
            title: `${match.title} (${artifactId} ${version})`,
            file: relPath,
            line: lineNo,
            snippet: `<artifactId>${artifactId}</artifactId>\n<version>${version}</version>`,
            isReachable,
            description: `${match.description} (Affected: ${match.affectedVersion}).` +
              (isReachable ? ' ⚠️ REACHABLE IN SOURCE: Package is imported in application code.' : ' (Installed Maven dependency)'),
            remediation: `${match.remediation} (Current version: ${version})`
          });
        }
      }
    }
  }

  return findings;
}

function findLineNumber(content, text) {
  const idx = content.split('\n').findIndex(l => l.includes(text));
  return idx === -1 ? 1 : idx + 1;
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
