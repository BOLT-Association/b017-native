// authbolt-moved.mjs - record a genuine AuthBOLT presentation of a token that has moved since its mint (the
// wallet's on-chain rotate, then a sign-in), with the reference's verdict. It must be refused: only a commit
// that spends the token's own mint shows the presenter holds the issuer key (the mint rule, audit V1).
//   node vectors/gen/authbolt-moved.mjs > vectors/authbolt.json      (from anywhere; uses packages/bolt)
import { pathToFileURL } from 'node:url'
const BOLT = 'C:/Users/honoh/Code/ChainBrowsers/packages/bolt'
const { Hash, PrivateKey, Utils } = await import(pathToFileURL(`${BOLT}/node_modules/@bsv/sdk/dist/esm/mod.js`).href)
const { brc100Core, memoryStore, BoltHandler } = await import(pathToFileURL(`${BOLT}/src/index.js`).href)
const { IDENTITY_PROTOCOL, IdentityWallet, encodeAuthData, verifyIdentity } = await import(pathToFileURL(`${BOLT}/src/identity.js`).href)
const { pretendChain, protoWalletOn } = await import(pathToFileURL(`${BOLT}/test/harness.mjs`).href)

const chain = pretendChain()
const { wallet } = protoWalletOn(chain)
const ids = new IdentityWallet({ core: brc100Core({ wallet, broadcast: chain.broadcast, store: memoryStore(), protocolID: IDENTITY_PROTOCOL }) })
const app = PrivateKey.fromHex('08'.padStart(64, '0')).toPublicKey().toString()
const challenge = Utils.toHex(Hash.sha256(Utils.toArray('PeerLoop-AuthBOLT/1|signin|https://app.lab:8443|moved|1999999999|', 'utf8')))
const data = encodeAuthData({ purpose: 'signin', appPubKey: app, challengeHash: challenge })

const id = await ids.create()
const moved = await ids.rotate(id.id)
const { package: pkg } = await ids.present({ id: moved.id, domain: 'app.lab', appPubKey: app, data })
const core = { store: memoryStore(), isValidRootForHeight: async () => false, broadcast: async () => ({ status: 'already-seen', detail: 'test' }) }
const { anchors, ...verdict } = await verifyIdentity({ handler: new BoltHandler({ core }), package: pkg, appPubKey: app, data })
console.log(JSON.stringify({
  note: 'Recorded by vectors/gen/authbolt-moved.mjs from ChainBrowsers packages/bolt: a genuine presentation of a token moved since its mint.',
  cases: [{ name: 'a token moved since its mint', package: pkg, appPubKey: app, data, issuer: id.issuer, reference: verdict }],
}, null, 1))
