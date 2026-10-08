// flows.test.ts - SimpleMultiBOLT class flows (the scenarios of b017's test/tokens/MultiBOLT.test.ts, with fixed
// keys instead of BRC-42 derivation), written to vectors/flows.json: every tx each step produced, as hex, plus the
// balances and errors. The ports run the same scenarios and must produce the same bytes.
import { writeFileSync } from 'node:fs'
import { test } from 'vitest'
import { Hash, P2PKH, PrivateKey, Transaction } from '@bsv/sdk'
import { SimpleMultiBOLT } from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/tokens/MultiBOLT.ts'

const OUT = 'C:/Users/honoh/Code/ChainBrowsers/b017-native/vectors/flows.json'
const MASK64 = (1n << 64n) - 1n
const bal = (amount: bigint): number[] => {
  const x = amount & ((1n << 128n) - 1n)
  const buf = Buffer.alloc(16)
  buf.writeBigUInt64LE(x & MASK64, 0)
  buf.writeBigUInt64LE((x >> 64n) & MASK64, 8)
  return Array.from(buf)
}
const key = (n: number) => PrivateKey.fromString(n.toString(16).padStart(64, '0'), 'hex')
const issuerKey = key(1)
const SIM = BigInt('0x1ffffffffffffe')
const pkhOf = (k: PrivateKey) => Hash.hash160(k.toPublicKey().encode(true))
const freshSource = (k = issuerKey, change = true): Transaction =>
  new Transaction(1, [], [{ satoshis: 1000, ...(change ? { change: true } : {}), lockingScript: new P2PKH().lock(pkhOf(k)) }])
const hexOf = (t?: Transaction) => (t ? t.toHex() : null)
const balHex = (b: number[]) => Buffer.from(b).toString('hex')

type Step = { step: string; tx?: string | null; prevTxs?: string[]; balance?: string; error?: string }

test('write SimpleMultiBOLT flow vectors', async () => {
  const flows: Record<string, Step[]> = {}
  const run = async (name: string, body: (log: (s: Step) => void) => Promise<void>) => {
    const steps: Step[] = []
    try {
      await body((s) => steps.push(s))
    } catch (e: any) {
      steps.push({ step: 'error', error: String(e?.message ?? e) })
    }
    flows[name] = steps
  }
  const snap = (step: string, t: SimpleMultiBOLT): Step =>
    ({ step, tx: hexOf(t.tx), prevTxs: t.prevTxs.map((p) => p.toHex()), balance: balHex(t.balance) })

  await run('lifecycle', async (log) => {
    let t = await new SimpleMultiBOLT().mint(issuerKey, freshSource(), '', bal(SIM))
    log(snap('mint', t))
    t = await t.transfer(key(101))
    log(snap('transfer1', t))
    t = await t.transfer(key(102))
    log(snap('transfer2', t))
    const [main, piece] = await t.split(key(110), key(111), bal(1n))
    log(snap('split.main', main))
    log(snap('split.piece', piece))
  })

  await run('merge-melt', async (log) => {
    let a = await new SimpleMultiBOLT().mint(issuerKey, freshSource(), '', bal(SIM))
    let b = await new SimpleMultiBOLT().mint(issuerKey, freshSource(), '', bal(1n))
    log(snap('mintA', a))
    log(snap('mintB', b))
    a = await a.transfer(key(101))
    b = await b.transfer(key(102))
    log(snap('transferA', a))
    log(snap('transferB', b))
    const merged = await a.merge(b, key(400))
    log(snap('merge', merged))
    log(snap('merge.other', b))
    const melted = await merged.melt()
    log(snap('melt', melted))
  })

  await run('builder-branches', async (log) => {
    const a = await new SimpleMultiBOLT().mint(issuerKey, freshSource(), '', bal(SIM))
    a.skipVerify = true
    await a.transfer(key(901), '', '', false, true, undefined, true)
    log(snap('noChange.noFund', a))
    const b = await new SimpleMultiBOLT().mint(issuerKey, freshSource(), '', bal(SIM))
    b.skipVerify = true
    const fundOverride: any = {
      sourceTransaction: freshSource(), sourceOutputIndex: 0,
      unlockingScriptTemplate: new P2PKH().unlock(issuerKey), sequence: 0xffffffff,
    }
    await b.transfer(key(902), '', '', false, false, fundOverride, false)
    log(snap('fundOverride', b))
    const c = await new SimpleMultiBOLT().mint(issuerKey, freshSource(), '', bal(SIM))
    await c.melt(pkhOf(key(901)))
    log(snap('melt.pkh', c))
  })

  await run('funding-source', async (log) => {
    const fundingSource = () => ({ tx: freshSource(), vout: 0, key: issuerKey })
    let t = await new SimpleMultiBOLT().mint(issuerKey, freshSource(), '', bal(SIM))
    t = await t.transfer(key(101))
    const [main, piece] = await t.split(key(110), key(111), bal(1n), fundingSource())
    log(snap('split.main', main))
    log(snap('split.piece', piece))
    let a = await new SimpleMultiBOLT().mint(issuerKey, freshSource(), '', bal(SIM))
    let b = await new SimpleMultiBOLT().mint(issuerKey, freshSource(), '', bal(1n))
    a = await a.transfer(key(101))
    b = await b.transfer(key(102))
    const merged = await a.merge(b, key(400), fundingSource())
    log(snap('merge', merged))
  })

  await run('second-piece', async (log) => {
    const kA = key(110)
    const kB = key(111)
    const fundB = () => freshSource(kB, false)
    let t = await new SimpleMultiBOLT().mint(issuerKey, freshSource(), '', bal(1000n))
    t = await t.transfer(key(101))
    const [, pieceB] = await t.split(kA, kB, bal(300n))
    const pieceB2 = Object.assign(new SimpleMultiBOLT(), { ...pieceB, prevTxs: [...pieceB.prevTxs] })
    await pieceB.commit(key(120), '', false, {
      sourceTransaction: fundB(), sourceOutputIndex: 0,
      unlockingScriptTemplate: new P2PKH().unlock(kB), sequence: 0xffffffff,
    } as any)
    log(snap('pieceB.commit', pieceB))
    await pieceB.settle(key(120))
    log(snap('pieceB.settle', pieceB))
    const [b1, b2] = await pieceB2.split(key(130), key(131), bal(100n), { tx: fundB(), vout: 0, key: kB })
    log(snap('pieceB2.split.main', b1))
    log(snap('pieceB2.split.piece', b2))
  })

  await run('inflated-balance', async (log) => {
    const t = await new SimpleMultiBOLT().mint(issuerKey, freshSource(), '', bal(1000n))
    t.balance = bal(1001n)
    log(snap('mint', t))
    await t.transfer(key(101))
    log(snap('transfer', t))
  })

  writeFileSync(OUT, JSON.stringify(flows, null, 1))
})
