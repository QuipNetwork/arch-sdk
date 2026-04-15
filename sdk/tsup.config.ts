import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  outExtension({ format }) {
    return format === 'cjs' ? { js: '.cjs', dts: '.d.cts' } : { js: '.js', dts: '.d.ts' }
  },
  clean: true,
  sourcemap: true,
  treeshake: true,
  minify: false,
})
