import * as esbuild from 'esbuild';
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync('./package.json', 'utf8'));

await esbuild.build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  format: 'esm',
  target: 'es2022',
  platform: 'neutral',
  outfile: '_worker.js',
  minify: true,
  sourcemap: false,
  legalComments: 'none',
  banner: {
    js: `// Built from src/ - DO NOT EDIT directly. Edit source files in src/ instead.`,
  },
  external: ['cloudflare:sockets'],
});

console.log('Built _worker.js from src/');
