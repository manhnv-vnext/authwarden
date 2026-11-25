#!/usr/bin/env node

import { cli } from '../src/cli.js';

// Exit only after stdout has flushed: process.exit() right after a large
// console.log truncates piped output (e.g. `authwarden scan . --format json | jq`).
function exitAfterFlush(code) {
  process.stdout.write('', () => process.exit(code));
}

cli(process.argv.slice(2))
  .then((exitCode) => {
    exitAfterFlush(exitCode ?? 0);
  })
  .catch((err) => {
    console.error('Fatal:', err);
    exitAfterFlush(1);
  });
