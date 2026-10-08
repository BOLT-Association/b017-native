// Runs the b017 reference's own test suite (unmodified, read-only) with record.setup.ts wrapping its entry
// points. Run from the b017 checkout (its fixtures resolve from process.cwd()):
//   cd ../b017 && B017_VECTORS_OUT=<abs path>.jsonl node node_modules/vitest/vitest.mjs run --config <abs path to this file>
const B017 = 'C:/Users/honoh/Code/ChainBrowsers/b017'
const HERE = 'C:/Users/honoh/Code/ChainBrowsers/b017-native/vectors/gen'

export default {
  root: B017,
  cacheDir: `${HERE}/.cache`,
  resolve: { alias: { '@bsv/sdk': `${B017}/node_modules/@bsv/sdk/dist/esm/mod.js` } },
  server: { fs: { allow: [B017, HERE] } },
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 120000,
    fileParallelism: false,
    setupFiles: [`${HERE}/record.setup.ts`],
  },
}
