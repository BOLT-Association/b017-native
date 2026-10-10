// authbolt-moved.mjs - record a genuine AuthBOLT presentation of a token that has moved since its mint (the
// wallet registers on chain, which moves the token to holder 1, then register data is presented again from
// holder 1), with the reference's verdict. It must be refused before the network is asked: only a commit that
// spends the token's own mint shows the presenter holds the issuer key (the mint rule, audit V1).
//   node vectors/gen/authbolt-moved.mjs > vectors/authbolt.json      (from anywhere; uses packages/bolt)
import { pathToFileURL } from 'node:url'
const BOLT = 'C:/Users/honoh/Code/ChainBrowsers/packages/bolt'
const { Hash, PrivateKey, Utils } = await import(pathToFileURL(`${BOLT}/node_modules/@bsv/sdk/dist/esm/mod.js`).href)
const { brc100Core, memoryStore, BoltHandler } = await import(pathToFileURL(`${BOLT}/src/index.js`).href)
const { IDENTITY_PROTOCOL, IdentityWallet, encodeAuthData, verifyIdentity } = await import(pathToFileURL(`${BOLT}/src/identity.js`).href)
const { appFunderOn, pretendChain, protoWalletOn } = await import(pathToFileURL(`${BOLT}/test/harness.mjs`).href)

const chain = pretendChain()
const { wallet } = protoWalletOn(chain)
const store = memoryStore()
const ids = new IdentityWallet({ core: brc100Core({ wallet, broadcast: chain.broadcast, store, protocolID: IDENTITY_PROTOCOL }) })
const app = PrivateKey.fromHex('08'.padStart(64, '0')).toPublicKey().toString()
const hash = (s) => Utils.toHex(Hash.sha256(Utils.toArray(s, 'utf8')))
const register = (nonce) => encodeAuthData({ purpose: 'register', appPubKey: app, challengeHash: hash(`PeerLoop-AuthBOLT/1|register|https://app.lab:8443|${nonce}|1999999999|`), count: 1 })

const id = await ids.create()
await ids.present({ id: id.id, domain: 'app.lab', appPubKey: app, data: register('first'), funder: appFunderOn(chain).funder })
const [moved] = await ids.identities()
// The same register data presented from holder 1 (the wallet refuses to build it; a raw handler does not).
const raw = new BoltHandler({ core: brc100Core({ wallet, broadcast: chain.broadcast, store, protocolID: IDENTITY_PROTOCOL }), keyId: moved.holderKeyId })
const data = register('moved')
const { package: pkg } = await raw.present(moved.id, { data })
const core = { store: memoryStore(), isValidRootForHeight: async () => false, broadcast: async () => ({ status: 'already-seen', detail: 'test' }) }
const { anchors, ...verdict } = await verifyIdentity({ handler: new BoltHandler({ core }), package: pkg, appPubKey: app, data })
console.log(JSON.stringify({
  note: 'Recorded by vectors/gen/authbolt-moved.mjs from ChainBrowsers packages/bolt: register data presented from a token moved since its mint.',
  cases: [{ name: 'a token moved since its mint', package: pkg, appPubKey: app, data, issuer: id.issuer, reference: verdict }],
}, null, 1))
