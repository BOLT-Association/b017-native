// interp.test.ts - interpreter differential: random unlocking / locking script pairs run through @bsv/sdk Spend
// (no explicit flags, as b017 runs it), versions 1 and 2. The ports' Spend wrappers must reach the same verdict
// (valid, or an error) on each. Written to vectors/interp.json.
//   B017_INTERP_CASES (default 20000), B017_INTERP_SEED (default 5), B017_INTERP_OUT
import { writeFileSync } from 'node:fs'
import { test } from 'vitest'
import { LockingScript, Spend, UnlockingScript } from '@bsv/sdk'

const N = Number(process.env.B017_INTERP_CASES ?? 20000)
const SEED = Number(process.env.B017_INTERP_SEED ?? 5)
const OUT = process.env.B017_INTERP_OUT ?? 'C:/Users/honoh/Code/ChainBrowsers/b017-native/vectors/interp.json'

function rng(seed: number) {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

test('write interpreter vectors', () => {
  const r = rng(SEED)
  const rint = (n: number) => Math.floor(r() * n)
  // opcodes weighted towards the ones scripts use: small pushes, numbers, stack, arithmetic, splice, flow
  const common = [0x00, 0x4f, 0x51, 0x52, 0x53, 0x54, 0x60, 0x61, 0x63, 0x64, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x81, 0x82, 0x83, 0x84,
    0x85, 0x86, 0x87, 0x88, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
    0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xb0, 0xb1, 0xb2, 0xb3, 0xb8,
    0xb9, 0xba, 0xe0, 0xff, 0x62, 0x65, 0x66, 0x89, 0x8a]
  const script = (len: number): number[] => {
    const out: number[] = []
    while (out.length < len) {
      const k = rint(10)
      if (k < 3) {
        const n = 1 + rint(6)
        out.push(n, ...Array.from({ length: n }, () => rint(256)))
      } else if (k < 4) {
        out.push(rint(256))
      } else {
        out.push(common[rint(common.length)])
      }
    }
    return out
  }
  const cases: any[] = []
  for (let k = 0; k < N; k++) {
    const unlock = script(rint(8))
    const lock = script(1 + rint(12))
    const version = rint(3) === 0 ? 1 : 2
    let ok = false
    let err = ''
    try {
      ok = new Spend({
        sourceTXID: 'ab'.repeat(32), sourceOutputIndex: 0, sourceSatoshis: 1000,
        lockingScript: LockingScript.fromBinary(lock), unlockingScript: UnlockingScript.fromBinary(unlock),
        transactionVersion: version, otherInputs: [], inputIndex: 0, inputSequence: 0xffffffff,
        outputs: [], lockTime: 0,
      }).validate()
    } catch (e: any) {
      err = String(e?.message ?? e).split('\n')[0]
    }
    cases.push({ u: Buffer.from(unlock).toString('hex'), l: Buffer.from(lock).toString('hex'), v: version, ok, err })
  }
  writeFileSync(OUT, JSON.stringify(cases))
  console.log(`interp: ${cases.length} cases, ${cases.filter((c) => c.ok).length} valid`)
})
