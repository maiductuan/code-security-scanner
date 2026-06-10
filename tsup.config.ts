import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    'index': 'src/index.ts',
    'bin/deepscan': 'src/bin/deepscan.ts',
  },
  format: ['esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'node18',
  outDir: 'dist',
  splitting: true,
});
