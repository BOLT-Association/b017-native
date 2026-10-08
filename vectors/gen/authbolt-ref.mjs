// authbolt-ref.mjs - run the reference AuthBOLT check (ChainBrowsers packages/bolt verifyIdentity, the code the
// bolt-verify sidecar runs) on cases written by the Go authbolt tests, and print its verdicts as JSON lines.
//   node vectors/gen/authbolt-ref.mjs <cases.json>
// Each case: { package: [hex], appPubKey, data, broadcast: 'already-seen' | 'rejected' }. Headers: none known.
import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

const BOLT = 'C:/Users/honoh/Code/ChainBrowsers/packages/bolt/src'
const { BoltHandler, memoryStore } = await import(pathToFileURL(`${BOLT}/index.js`).href)
const { verifyIdentity } = await import(pathToFileURL(`${BOLT}/identity.js`).href)

const cases = JSON.parse(readFileSync(process.argv[2], 'utf8'))
for (const c of cases) {
  const core = {
    store: memoryStore(),
    isValidRootForHeight: async () => false,
    broadcast: async () => (c.broadcast === 'rejected' ? { status: 'rejected', detail: 'refused by the test' } : { status: 'already-seen', detail: 'test' }),
  }
  const r = await verifyIdentity({ handler: new BoltHandler({ core }), package: c.package, appPubKey: c.appPubKey, data: c.data })
  const { anchors, ...rest } = r
  console.log(JSON.stringify(rest))
}
