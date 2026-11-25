import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runBenchmark } from '../scripts/benchmark.mjs';
import { CASES } from './benchmark/corpus.mjs';
import { getRule } from '../src/rules/catalog.js';

// Cases the pattern-based engine is known to get wrong. Keep this list exact:
// a new entry is a regression, a removed one is an improvement worth recording.
const KNOWN_MISSES = [
  'auth003-public-catalog' // public data has no owner; not decidable statically
];

test('benchmark corpus is well formed', () => {
  const ids = new Set();
  for (const c of CASES) {
    assert.equal(ids.has(c.id), false, `duplicate case id ${c.id}`);
    ids.add(c.id);
    assert.ok(getRule(c.rule), `${c.id}: unknown rule ${c.rule}`);
    assert.ok(['vulnerable', 'safe'].includes(c.kind), c.id);
    assert.ok(Object.keys(c.files).length > 0, c.id);
  }
});

test('scanner outcome on the labelled corpus matches the recorded baseline', async () => {
  const report = await runBenchmark();
  const misses = report.results.filter(r => r.outcome === 'FN' || r.outcome === 'FP').map(r => r.id).sort();
  assert.deepEqual(misses, [...KNOWN_MISSES].sort());
});
