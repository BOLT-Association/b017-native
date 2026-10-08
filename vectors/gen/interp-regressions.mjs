// The interpreter cases a port once got wrong, with the reference's verdict (written to vectors/interp-regressions.json).
// Run from the b017 checkout: node ../b017-native/vectors/gen/interp-regressions.mjs ../b017-native/vectors/interp-regressions.json
import { writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
const require = createRequire('C:/Users/honoh/Code/ChainBrowsers/b017/package.json')
const { LockingScript, Spend, UnlockingScript } = require('@bsv/sdk')
const [out] = process.argv.slice(2)
const pairs = [
  // interpreter seed 7 (30000 cases) #21955: OP_LSHIFT by a 20-byte hash (go-sdk read its low 64 bits as negative)
  { u: '04aa3931c1', l: '5f8d029de5a79802b26c', v: 2 },
  // seed 103 (20000 cases) #10309: OP_SPLIT at a 32-byte hash (go-sdk's Int32 clamp came after a 64-bit wrap: panic)
  { u: '5205f549c7f950', l: '03eab690a87f95e0', v: 2 },
  // OP_SPLIT at 2^63 and at 2^64+1 (low 64 bits: negative, and 1)
  { u: '', l: '03616263' + '09000000000000008000' + '7f' + '7551', v: 2 },
  { u: '', l: '03616263' + '09010000000000000001' + '7f' + '7551', v: 2 },
  // OP_PICK and OP_ROLL at 2^64 (low 64 bits: 0)
  { u: '', l: '51' + '09000000000000000001' + '79', v: 2 },
  { u: '', l: '51' + '09000000000000000001' + '7a', v: 2 },
  { u: '', l: '0107' + '09010000000000000001' + '98' + '0100' + '87', v: 2 },
  { u: '', l: '0107' + '09000000000000008000' + '99' + '0100' + '87', v: 2 },
  { u: '', l: '00' + '00' + '09000000000000000001' + 'ae', v: 2 },
  { u: '', l: '0107' + '09010000000000000001' + '98' + '0100' + '87', v: 1 },
  // 21 keys, 0 signatures: valid without flags (key limit INT_MAX, not 20)
  { u: '', l: '00' + '00' + '00'.repeat(21) + '0115' + 'ae', v: 2 },
  // 2^64 signatures against 1 key
  { u: '', l: '00' + '09000000000000000001' + '00' + '51' + 'ae', v: 2 },
]
const cases = pairs.map(({ u, l, v }) => {
  let ok = false, err = ''
  try {
    ok = new Spend({ sourceTXID: 'ab'.repeat(32), sourceOutputIndex: 0, sourceSatoshis: 1000,
      lockingScript: LockingScript.fromHex(l), unlockingScript: UnlockingScript.fromHex(u),
      transactionVersion: v, otherInputs: [], inputIndex: 0, inputSequence: 0xffffffff, outputs: [], lockTime: 0 }).validate()
  } catch (e) { err = String(e?.message ?? e).split('\n')[0] }
  return { u, l, v, ok, err }
})
writeFileSync(out, JSON.stringify(cases))
console.log(cases)
