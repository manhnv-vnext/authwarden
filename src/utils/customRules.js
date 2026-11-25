import fs from 'fs';
import path from 'path';
import { Worker } from 'worker_threads';

/**
 * Custom organisation rules (rules/*.json): validated here, executed in a
 * worker with a time limit. Rule files come from the scanned repository, so
 * nothing in them is trusted: ids and severities are restricted, text fields
 * are length-capped, and an invalid rule never affects the others.
 */

const SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const DEFAULT_TIMEOUT_MS = 5000;
const text = (v, fallback, max = 500) => (typeof v === 'string' && v.trim() ? v.slice(0, max) : fallback);

export function loadCustomRules(rulesDir) {
  const rules = [];
  const warnings = [];
  if (!fs.existsSync(rulesDir)) return { rules, warnings };

  let ruleFiles = [];
  try {
    ruleFiles = fs.readdirSync(rulesDir).filter(f => f.endsWith('.json'));
  } catch {
    return { rules, warnings };
  }

  for (const rf of ruleFiles) {
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(path.join(rulesDir, rf), 'utf8'));
    } catch (err) {
      warnings.push(`Custom rule file ${rf} is not valid JSON and was skipped (${err.message}).`);
      continue;
    }
    if (!Array.isArray(parsed)) continue;

    for (const cr of parsed) {
      if (!cr || typeof cr.pattern !== 'string' || typeof cr.id !== 'string') continue;
      if (!/^[A-Za-z][A-Za-z0-9_-]{0,39}$/.test(cr.id)) {
        warnings.push(`Custom rule in ${rf} has an invalid id and was skipped.`);
        continue;
      }
      try {
        new RegExp(cr.pattern, 'i');
      } catch (err) {
        warnings.push(`Custom rule ${cr.id} in ${rf} has an invalid pattern and was skipped (${err.message}).`);
        continue;
      }
      const severity = String(cr.severity || 'HIGH').toUpperCase();
      rules.push({
        id: cr.id,
        pattern: cr.pattern,
        severity: SEVERITIES.has(severity) ? severity : 'HIGH',
        name: text(cr.name, cr.id, 200),
        languages: Array.isArray(cr.languages) ? cr.languages.filter(l => typeof l === 'string') : null,
        description: text(cr.description, 'Matched custom organization security rule.'),
        remediation: text(cr.remediation, 'Inspect code according to internal security guidelines.')
      });
    }
  }
  return { rules, warnings };
}

/** Runs the rules over the files. Resolves with { findings, warnings }; never rejects. */
export function runCustomRules(rules, files, timeoutMs = DEFAULT_TIMEOUT_MS) {
  if (rules.length === 0) return Promise.resolve({ findings: [], warnings: [] });

  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    let worker;
    try {
      worker = new Worker(new URL('./customRulesWorker.js', import.meta.url), {
        workerData: {
          rules,
          files: files.map(f => ({ path: f.path, relative: f.relative.replace(/\\/g, '/'), ext: f.ext }))
        }
      });
    } catch (err) {
      resolve({ findings: [], warnings: [`Custom rules could not be started (${err.message}).`] });
      return;
    }

    const timer = setTimeout(() => {
      worker.terminate();
      finish({
        findings: [],
        warnings: [`Custom rules were stopped after ${timeoutMs} ms: a custom rule pattern is too slow (possible catastrophic backtracking). No custom rule findings are reported.`]
      });
    }, timeoutMs);

    worker.once('message', (findings) => finish({ findings, warnings: [] }));
    worker.once('error', (err) => finish({ findings: [], warnings: [`Custom rules failed (${err.message}).`] }));
    worker.once('exit', () => finish({ findings: [], warnings: [] }));
  });
}
