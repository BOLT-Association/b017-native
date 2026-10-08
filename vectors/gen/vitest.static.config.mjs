// Writes vectors/static.json (and later explicit flow vectors) from the reference source.
//   cd ../b017 && node node_modules/vitest/vitest.mjs run --config <abs path to this file>
const B017 = 'C:/Users/honoh/Code/ChainBrowsers/b017'
const HERE = 'C:/Users/honoh/Code/ChainBrowsers/b017-native/vectors/gen'

export default {
  root: HERE,
  cacheDir: `${HERE}/.cache`,
  resolve: { alias: { '@bsv/sdk': `${B017}/node_modules/@bsv/sdk/dist/esm/mod.js` } },
  server: { fs: { allow: [B017, HERE] } },
  test: { include: ['*.test.ts'], testTimeout: 120000, fileParallelism: false },
}
