#!/usr/bin/env node
/**
 * Runs the labelled corpus in test/benchmark/corpus.mjs through the scanner and
 * reports precision and recall per rule.
 *
 *   npm run bench            table
 *   npm run bench -- --json  machine-readable
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { pathToFileURL } from 'url';
import { runScan } from '../src/index.js';
import { CASES } from '../test/benchmark/corpus.mjs';

export async function runBenchmark(cases = CASES) {
  const results = [];
  for (const c of cases) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-bench-'));
    try {
      for (const [rel, content] of Object.entries(c.files)) {
        const full = path.join(dir, rel);
        fs.mkdirSync(path.dirname(full), { recursive: true });
        fs.writeFileSync(full, content);
      }
      const scan = await runScan(dir, {});
      const fired = scan.findings.some(f => f.ruleId === c.rule);
      const outcome = c.kind === 'vulnerable' ? (fired ? 'TP' : 'FN') : (fired ? 'FP' : 'TN');
      results.push({ id: c.id, rule: c.rule, kind: c.kind, outcome, note: c.note || '' });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  const tally = (rows) => {
    const n = { TP: 0, FN: 0, FP: 0, TN: 0 };
    rows.forEach(r => n[r.outcome]++);
    return {
      ...n,
      cases: rows.length,
      precision: n.TP + n.FP === 0 ? null : n.TP / (n.TP + n.FP),
      recall: n.TP + n.FN === 0 ? null : n.TP / (n.TP + n.FN)
    };
  };

  const perRule = {};
  for (const rule of [...new Set(results.map(r => r.rule))]) {
    perRule[rule] = tally(results.filter(r => r.rule === rule));
  }
  return { overall: tally(results), perRule, results };
}

const pct = (v) => (v === null ? '  n/a' : (v * 100).toFixed(0).padStart(4) + '%');

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  const report = await runBenchmark();
  if (process.argv.includes('--json')) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log('\nAuthWarden regression corpus (maintainer-written cases; not a real-world accuracy claim)\n');
    console.log('Rule        Cases   TP  FN  FP  TN  Precision  Recall');
    console.log('─'.repeat(58));
    for (const [rule, t] of Object.entries(report.perRule)) {
      console.log(`${rule.padEnd(11)} ${String(t.cases).padStart(5)}  ${String(t.TP).padStart(3)} ${String(t.FN).padStart(3)} ${String(t.FP).padStart(3)} ${String(t.TN).padStart(3)}      ${pct(t.precision)}   ${pct(t.recall)}`);
    }
    const o = report.overall;
    console.log('─'.repeat(58));
    console.log(`${'ALL'.padEnd(11)} ${String(o.cases).padStart(5)}  ${String(o.TP).padStart(3)} ${String(o.FN).padStart(3)} ${String(o.FP).padStart(3)} ${String(o.TN).padStart(3)}      ${pct(o.precision)}   ${pct(o.recall)}`);
    const wrong = report.results.filter(r => r.outcome === 'FN' || r.outcome === 'FP');
    if (wrong.length) {
      console.log('\nKnown misses:');
      for (const r of wrong) console.log(`  ${r.outcome}  ${r.id}${r.note ? '  — ' + r.note : ''}`);
    }
    console.log('');
  }
}
