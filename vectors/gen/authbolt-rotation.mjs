// authbolt-rotation.mjs - record a genuine AuthBOLT rotation (the wallet registers on chain, moving the token
// to holder 1, then rotates it at the app's request to holder 2), with the reference's verdicts: accepted
// against the outpoint the app recorded at registration, refused against any other outpoint or none.
//   node vectors/gen/authbolt-rotation.mjs > vectors/authbolt-rotation.json      (uses packages/bolt)
import { pathToFileURL } from 'node:url'
const BOLT = 'C:/Users/honoh/Code/ChainBrowsers/packages/bolt'
const { Hash, PrivateKey, Utils } = await import(pathToFileURL(`${BOLT}/node_modules/@bsv/sdk/dist/esm/mod.js`).href)
const { brc100Core, memoryStore, BoltHandler } = await import(pathToFileURL(`${BOLT}/src/index.js`).href)
const { IDENTITY_PROTOCOL, IdentityWallet, encodeAuthData, verifyIdentity } = await import(pathToFileURL(`${BOLT}/src/identity.js`).href)
const { appFunderOn, pretendChain, protoWalletOn } = await import(pathToFileURL(`${BOLT}/test/harness.mjs`).href)

const chain = pretendChain()
const { wallet } = protoWalletOn(chain)
const ids = new IdentityWallet({ core: brc100Core({ wallet, broadcast: chain.broadcast, store: memoryStore(), protocolID: IDENTITY_PROTOCOL }) })
const { funder } = appFunderOn(chain)
const app = PrivateKey.fromHex('08'.padStart(64, '0')).toPublicKey().toString()
const hash = (s) => Utils.toHex(Hash.sha256(Utils.toArray(s, 'utf8')))
const data = (purpose, nonce, count) => encodeAuthData({ purpose, appPubKey: app, challengeHash: hash(`PeerLoop-AuthBOLT/1|${purpose}|https://app.lab:8443|${nonce}|1999999999|`), count })

const id = await ids.create()
const reg = await ids.present({ id: id.id, domain: 'app.lab', appPubKey: app, data: data('register', 'r', 1), keepSignedIn: true, funder })
const rotate = data('rotate', 'rot', 2)
const rot = await ids.rotate({ domain: 'app.lab', appPubKey: app, data: rotate, funder, silent: true })

const core = { store: memoryStore(), isValidRootForHeight: async () => false, broadcast: async () => ({ status: 'already-seen', detail: 'test' }) }
const verdict = async (outpoint) => {
  const { anchors, ...v } = await verifyIdentity({ handler: new BoltHandler({ core }), package: rot.package, appPubKey: app, data: rotate, outpoint })
  return v
}
const cases = []
for (const [name, outpoint] of [['a rotation from the recorded outpoint', reg.id], ['a stale outpoint', rot.id], ['no outpoint', undefined]]) {
  cases.push({ name, package: rot.package, appPubKey: app, data: rotate, ...(outpoint ? { outpoint } : {}), reference: await verdict(outpoint) })
}
console.log(JSON.stringify({
  note: 'Recorded by vectors/gen/authbolt-rotation.mjs from ChainBrowsers packages/bolt: a genuine on-chain rotation and the reference verdicts.',
  cases,
}, null, 1))
