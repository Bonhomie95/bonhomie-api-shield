import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.js'],
  format: ['esm'],
  splitting: false,
  sourcemap: false,
  clean: true,
  minify: false,
  dts: false,
  skipNodeModulesBundle: true,
  target: 'node18',
  treeshake: false,
  platform: 'node',
});
