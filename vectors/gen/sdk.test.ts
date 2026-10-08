// sdk.test.ts - vectors for the parts of @bsv/sdk 2.8.11 the ports re-implement (MerklePath, Beef, Script chunk
// parsing, Transaction parsing / EF, the BIP143 preimage for every scope), taken straight from the SDK, seeded.
// b017's own suite only drives these along its happy paths (every recorded merkle path has one leaf, for
// instance); these vectors cover the rest. Written to vectors/sdk.json.
import { writeFileSync } from 'node:fs'
import { test } from 'vitest'
import { Beef, Hash, LockingScript, MerklePath, P2PKH, PrivateKey, Script, Transaction, TransactionSignature, UnlockingScript, Utils } from '@bsv/sdk'

const OUT = 'C:/Users/honoh/Code/ChainBrowsers/b017-native/vectors/sdk.json'

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
const r = rng(17)
const rint = (n: number) => Math.floor(r() * n)
const rbytes = (n: number) => Array.from({ length: n }, () => rint(256))
const hex = (b: number[]) => Utils.toHex(b)
const tryRun = <T>(f: () => T): { ok: T } | { throws: string } => {
  try {
    return { ok: f() }
  } catch (e: any) {
    return { throws: String(e?.message ?? e) }
  }
}

// ---- merkle trees: the full tree of n random txids, and the BUMP of a subset ----
const hashPair = (l: string, rr: string) => Utils.toHex(Hash.hash256(Utils.toArray(l + rr, 'hex').reverse()).reverse())
function tree(n: number): string[][] {
  const levels = [Array.from({ length: n }, () => hex(rbytes(32)))]
  while (levels[levels.length - 1].length > 1) {
    const prev = levels[levels.length - 1]
    const next: string[] = []
    for (let i = 0; i < prev.length; i += 2) next.push(hashPair(prev[i + 1] ?? prev[i], prev[i]))
    levels.push(next)
  }
  return levels
}
function bump(levels: string[][], idxs: number[], height: number): MerklePath {
  const path: any[][] = levels.slice(0, Math.max(1, levels.length - 1)).map(() => [])
  for (const idx of idxs) {
    let o = idx
    for (let h = 0; h < path.length; h++) {
      const add = (leaf: any) => { if (!path[h].some((x) => x.offset === leaf.offset)) path[h].push(leaf) }
      if (h === 0) add({ offset: o, hash: levels[0][o], txid: true })
      const sib = o ^ 1
      if (sib < levels[h].length) add({ offset: sib, hash: levels[h][sib] })
      else add({ offset: sib, duplicate: true })
      o >>= 1
    }
  }
  for (const level of path) level.sort((a, b) => a.offset - b.offset)
  return new MerklePath(height, path, false)
}

test('write sdk vectors', () => {
  const merkle: any[] = []
  for (let k = 0; k < 60; k++) {
    const n = 1 + rint(40)
    const levels = tree(n)
    const pick = Array.from(new Set(Array.from({ length: 1 + rint(3) }, () => rint(n))))
    const mp = tryRun(() => bump(levels, pick, 100 + rint(1000)))
    if ('throws' in mp) continue
    const m = mp.ok
    const entry: any = { hex: m.toHex(), txids: pick.map((i) => levels[0][i]), root: levels[levels.length - 1][0] }
    entry.roots = entry.txids.map((t: string) => tryRun(() => m.computeRoot(t)))
    entry.rootNoArg = tryRun(() => m.computeRoot())
    entry.missing = tryRun(() => m.computeRoot(hex(rbytes(32))))
    // combine with a second path of the same block, and trim
    const other = tryRun(() => bump(levels, [rint(n)], m.blockHeight))
    if ('ok' in other) {
      const c = MerklePath.fromHex(m.toHex())
      entry.combineWith = other.ok.toHex()
      entry.combined = tryRun(() => { c.combine(other.ok); return c.toHex() })
    }
    const w = MerklePath.fromHex(m.toHex())
    entry.trimmed = tryRun(() => { w.trim(); return w.toHex() })
    // a corrupted copy: parse (legal offsets on / off) and compute
    const bad = Utils.toArray(m.toHex(), 'hex')
    bad[rint(bad.length)] ^= 1 + rint(255)
    entry.corrupt = hex(bad)
    entry.corruptLegal = tryRun(() => MerklePath.fromBinary(bad).toHex())
    entry.corruptLoose = tryRun(() => MerklePath.fromBinary(bad, false).toHex())
    merkle.push(entry)
  }

  // ---- scripts: random bytes parsed into chunks and serialised back ----
  const scripts: any[] = []
  for (let k = 0; k < 300; k++) {
    const b = rbytes(rint(40))
    if (k % 5 === 0) b.unshift([0x4c, 0x4d, 0x4e, 0x6a, 0x63][rint(5)])
    const s = Script.fromBinary(b)
    const chunks = s.chunks.map((c) => ({ op: c.op, data: c.data === undefined ? null : hex(c.data as number[]) }))
    scripts.push({ hex: hex(b), chunks, rewritten: new Script(s.chunks.map((c) => ({ ...c }))).toHex() })
  }
  const scriptHexErrors = ['abc', 'zz', '0g'].map((h) => ({ hex: h, result: tryRun(() => Script.fromHex(h).toHex()) }))

  // ---- transactions: parse random / truncated / padded bytes; EF of a signed tx ----
  const k1 = PrivateKey.fromString('11'.repeat(32), 'hex')
  const pkh = Hash.hash160(k1.toPublicKey().encode(true))
  const src = new Transaction(1, [], [{ satoshis: 5000, lockingScript: new P2PKH().lock(pkh) }, { satoshis: 7, lockingScript: new P2PKH().lock(pkh) }])
  const txs: any[] = []
  for (let k = 0; k < 40; k++) {
    const t = new Transaction(1 + rint(2), [], [], rint(3) === 0 ? rint(1e6) : 0)
    for (let i = 0; i < 1 + rint(3); i++) t.addInput({ sourceTransaction: src, sourceOutputIndex: rint(2), unlockingScript: UnlockingScript.fromBinary(rbytes(rint(80))), sequence: rint(2) ? 0xffffffff : rint(1e9) })
    for (let o = 0; o < 1 + rint(4); o++) t.addOutput({ satoshis: rint(1e8), lockingScript: LockingScript.fromBinary(rbytes(rint(300))) })
    const raw = t.toBinary()
    const cut = raw.slice(0, rint(raw.length))
    txs.push({
      hex: hex(raw), id: t.id('hex'), ef: tryRun(() => Utils.toHex(t.toEF())),
      truncated: hex(cut), truncatedResult: tryRun(() => Transaction.fromBinary(cut).id('hex')),
      padded: hex([...raw, 0]), paddedResult: tryRun(() => Transaction.fromBinary([...raw, 0]).id('hex')),
      // every sighash scope, for every input
      preimages: t.inputs.map((inp: any, i: number) =>
        [0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3].map((scope) => hex(TransactionSignature.format({
          sourceTXID: inp.sourceTXID ?? src.id('hex'), sourceOutputIndex: inp.sourceOutputIndex,
          sourceSatoshis: src.outputs[inp.sourceOutputIndex].satoshis as number, transactionVersion: t.version,
          otherInputs: t.inputs.filter((_, j) => j !== i), inputIndex: i, outputs: t.outputs, inputSequence: inp.sequence,
          subscript: src.outputs[inp.sourceOutputIndex].lockingScript, lockTime: t.lockTime, scope,
        })))),
    })
  }

  // ---- BEEF: random graphs of proven and unproven txs; V1, V2, Atomic; sorting and validity ----
  const beefs: any[] = []
  for (let k = 0; k < 40; k++) {
    const pool: Transaction[] = []
    const n = 2 + rint(6)
    for (let i = 0; i < n; i++) {
      const t = new Transaction(2, [], [{ satoshis: 1000, lockingScript: new P2PKH().lock(pkh) }, { satoshis: 1000, lockingScript: new P2PKH().lock(pkh) }])
      const parents = pool.length === 0 || rint(3) === 0 ? [] : [pool[rint(pool.length)], pool[rint(pool.length)]]
      for (const p of new Set(parents)) t.addInput({ sourceTransaction: p, sourceOutputIndex: rint(2), unlockingScript: UnlockingScript.fromBinary(rbytes(10)), sequence: 0xffffffff })
      if (parents.length === 0) {
        if (rint(4) !== 0) t.merklePath = new MerklePath(10 + rint(3), [[{ offset: 0, hash: t.id('hex'), txid: true }]])
        else t.addInput({ sourceTXID: hex(rbytes(32)), sourceOutputIndex: 0, unlockingScript: UnlockingScript.fromBinary([]), sequence: 0xffffffff })
      }
      pool.push(t)
    }
    const subject = pool[pool.length - 1]
    const beef = new Beef()
    tryRun(() => beef.mergeTransaction(subject))
    const v2 = tryRun(() => hex(beef.toBinary()))
    const atomic = tryRun(() => hex(beef.toBinaryAtomic(subject.id('hex'))))
    const v1beef = new Beef(4022206465)
    tryRun(() => v1beef.mergeTransaction(subject))
    const v1 = tryRun(() => hex(v1beef.toBinary()))
    const parsed = (h: string) => tryRun(() => {
      const b = Beef.fromBinary(Utils.toArray(h, 'hex'))
      const valid = b.isValid(false)
      const validTxidOnly = b.isValid(true)
      return { valid, validTxidOnly, order: b.txs.map((t) => t.txid), atomic: b.atomicTxid ?? null }
    })
    beefs.push({ v2, atomic, v1, v2parsed: 'ok' in v2 ? parsed(v2.ok) : null, atomicParsed: 'ok' in atomic ? parsed(atomic.ok) : null, v1parsed: 'ok' in v1 ? parsed(v1.ok) : null, subject: subject.id('hex') })
  }

  writeFileSync(OUT, JSON.stringify({ merkle, scripts, scriptHexErrors, txs, srcHex: src.toHex(), beefs }))
})
