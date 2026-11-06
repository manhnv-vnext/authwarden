#!/usr/bin/env node

import { cli } from '../src/cli.js';

cli(process.argv.slice(2))
  .then((exitCode) => {
    process.exit(exitCode ?? 0);
  })
  .catch((err) => {
    console.error('Fatal:', err);
    process.exit(1);
  });
