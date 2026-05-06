// Bundle size analyzer.
//
// Usage: npm run analyze
//
// Builds an esbuild bundle from src/index.ts with a metafile and prints
// a per-module size breakdown sorted by contribution. Use this when:
//   - you want to know what's contributing to _worker.js size
//   - the CI bundle-size budget warns you the bundle is growing
//   - you're deciding whether to lazy-load or strip a feature
//
// The output bundle goes to /tmp and is discarded — this script does NOT
// modify the committed _worker.js. Run `npm run build` for that.

import * as esbuild from 'esbuild';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const outfile = join(tmpdir(), '_worker.analyze.js');

const result = await esbuild.build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  format: 'esm',
  target: 'es2022',
  platform: 'neutral',
  outfile,
  minify: false,
  metafile: true,
  external: ['cloudflare:sockets'],
});

console.log(await esbuild.analyzeMetafile(result.metafile, { verbose: false }));
console.log(`(transient build at ${outfile} — ignored, not the deployment artifact)`);
