// sdk.test.ts - vectors for the parts of @bsv/sdk 2.8.11 the ports re-implement (MerklePath, Beef, Script chunk
// parsing, Transaction parsing / EF, the BIP143 preimage for every scope), taken straight from the SDK, seeded.
// b017's own suite only drives these along its happy paths (every recorded merkle path has one leaf, for
// instance); these vectors cover the rest. Written to vectors/sdk.json.
import { writeFileSync } from 'node:fs'
import { test } from 'vitest'
import { Graph } from './ser-plain.ts'
import { fromBeef } from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/lib/scanner/beef.ts'
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

test('write sdk vectors', async () => {
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

  // ---- BEEF graphs over real multi-leaf trees: proven txs sharing a block (bumps combine), txid-only entries,
  // a BEEF that is not atomic for its subject, change split across several change outputs ----
  const g = new Graph()
  const atomics: any[] = []
  for (let k = 0; k < 25; k++) {
    const roots: Transaction[] = []
    for (let i = 0; i < 2 + rint(5); i++) {
      const t = new Transaction(1, [], [{ satoshis: 1000 + i, lockingScript: new P2PKH().lock(pkh) }, { satoshis: 50, lockingScript: new P2PKH().lock(pkh) }])
      t.addInput({ sourceTXID: hex(rbytes(32)), sourceOutputIndex: 0, unlockingScript: UnlockingScript.fromBinary(rbytes(4)), sequence: 0xffffffff })
      roots.push(t)
    }
    // the roots' txids, padded with random siblings, form one block; each root carries its own path
    const ids = roots.map((t) => t.id('hex'))
    const n = ids.length + rint(6)
    const levels = tree(n)
    const slots = Array.from({ length: n }, (_, i) => i).sort(() => r() - 0.5).slice(0, ids.length)
    slots.forEach((slot, i) => { levels[0][slot] = ids[i] })
    for (let h = 1; h < levels.length; h++) for (let i = 0; i < levels[h].length; i++) levels[h][i] = hashPair(levels[h - 1][2 * i + 1] ?? levels[h - 1][2 * i], levels[h - 1][2 * i])
    const height = 500 + rint(50)
    roots.forEach((t, i) => { t.merklePath = bump(levels, [slots[i]], height) })
    // a child spending several of them, and a grandchild
    const child = new Transaction(2, [], [{ satoshis: 10, lockingScript: new P2PKH().lock(pkh) }])
    for (const p of roots.slice(0, 2 + rint(Math.max(1, roots.length - 1)))) child.addInput({ sourceTransaction: p, sourceOutputIndex: rint(2), unlockingScript: UnlockingScript.fromBinary(rbytes(3)), sequence: 0xffffffff })
    const grand = new Transaction(2, [], [{ satoshis: 1, lockingScript: new P2PKH().lock(pkh) }])
    grand.addInput({ sourceTransaction: child, sourceOutputIndex: 0, unlockingScript: UnlockingScript.fromBinary([]), sequence: 0xffffffff })
    const subject = rint(2) ? grand : child
    const id = g.tx(subject)
    const atomic = tryRun(() => { const b = new Beef(); b.mergeTransaction(subject); return hex(b.toBinaryAtomic(subject.id('hex'))) })
    // the same BEEF with a txid-only entry and an unrelated tx (V2 only)
    const extra = tryRun(() => {
      const b = new Beef(); b.mergeTransaction(subject); b.mergeTxidOnly(hex(rbytes(32)))
      const stray = new Transaction(1, [], [{ satoshis: 1, lockingScript: new P2PKH().lock(pkh) }]); stray.addInput({ sourceTXID: hex(rbytes(32)), sourceOutputIndex: 0, unlockingScript: UnlockingScript.fromBinary([]), sequence: 0xffffffff })
      b.mergeTransaction(stray)
      const bytes = b.toBinary()
      const p = Beef.fromBinary(bytes)
      return { hex: hex(bytes), valid: p.isValid(false), validTxidOnly: p.isValid(true), order: p.txs.map((t) => t.txid), atomicForSubject: p.isAtomic(subject.id('hex')) }
    })
    atomics.push({ tx: id, atomic, extra })
  }
  // fee(0) over several change outputs
  const fees: any[] = []
  for (let k = 0; k < 8; k++) {
    const t = new Transaction(2, [], [])
    const s1 = new Transaction(1, [], [{ satoshis: 100 + rint(1000), lockingScript: new P2PKH().lock(pkh) }])
    t.addInput({ sourceTransaction: s1, sourceOutputIndex: 0, unlockingScript: UnlockingScript.fromBinary([]), sequence: 0xffffffff })
    t.addOutput({ satoshis: rint(100), lockingScript: new P2PKH().lock(pkh) })
    const nc = 1 + rint(4)
    for (let c = 0; c < nc; c++) t.addOutput({ change: true, lockingScript: new P2PKH().lock(pkh) })
    const before = { in: s1.outputs[0].satoshis, fixed: t.outputs[0].satoshis, changes: nc }
    const res = await (async () => { try { await t.fee(0); return { ok: t.outputs.map((o) => o.satoshis ?? null) } } catch (e: any) { return { throws: String(e?.message ?? e) } } })()
    fees.push({ before, res })
  }

  // ---- corruption: truncated and byte-flipped BEEF (through b017's fromBeef) and raw txs ----
  const corrupt: any[] = []
  for (const a of atomics.slice(0, 6)) {
    if (!('ok' in a.atomic)) continue
    const bytes = Utils.toArray(a.atomic.ok, 'hex')
    const cuts = new Set<number>(Array.from({ length: 30 }, () => rint(bytes.length)))
    for (const c of cuts) {
      const h = hex(bytes.slice(0, c))
      corrupt.push({ kind: 'beef', hex: h, result: tryRun(() => fromBeef(h).id('hex')) })
    }
    for (let k = 0; k < 30; k++) {
      const b2 = bytes.slice()
      b2[rint(b2.length)] ^= 1 + rint(255)
      const h = hex(b2)
      corrupt.push({ kind: 'beef', hex: h, result: tryRun(() => fromBeef(h).id('hex')) })
    }
  }
  for (const t of txs.slice(0, 4)) {
    const bytes = Utils.toArray(t.hex, 'hex')
    for (let c = 0; c < bytes.length; c += 1 + rint(9)) {
      const h = hex(bytes.slice(0, c))
      corrupt.push({ kind: 'tx', hex: h, result: tryRun(() => Transaction.fromHex(h).id('hex')) })
    }
  }
  // varint rules: non-canonical widths and values beyond 2^53 in a tx's input count
  for (const vi of ['fd0100', 'fdfd00', 'fe00000100', 'feffff0000', 'ff0000000001000000', 'ffffffffffffff1f00', 'ffffffffffffffffff', 'ff0000000000002000']) {
    const h = '02000000' + vi + '00000000'
    corrupt.push({ kind: 'tx', hex: h, result: tryRun(() => Transaction.fromHex(h).id('hex')) })
  }
  // ---- MerklePath constructor rules ----
  const shapes: any[] = []
  const leaf = (offset: number, extra: any = {}) => ({ offset, hash: hex(rbytes(32)), ...extra })
  const cands: [any[], boolean][] = [
    [[], true], [[[]], true], [Array.from({ length: 55 }, () => [leaf(0)]), true],
    [[[leaf(0), leaf(0)]], true], [[[leaf(0, { txid: true }), leaf(1)], [leaf(5)]], true], [[[leaf(0, { txid: true }), leaf(1)], [leaf(5)]], false],
    [[[leaf(0, { txid: true }), leaf(1)], [leaf(1)]], true], [[[leaf(2, { txid: true }), { offset: 3, duplicate: true }], [leaf(0)]], true],
    [[[leaf(0, { txid: true }), leaf(1, { txid: true })]], true],
  ]
  for (const [path, legal] of cands) {
    shapes.push({ path, legal, result: tryRun(() => new MerklePath(7, path, legal).toHex()) })
  }

  writeFileSync(OUT, JSON.stringify({ merkle, scripts, scriptHexErrors, txs, srcHex: src.toHex(), beefs, atomics, fees, corrupt, shapes, nodes: g.nodes }))
})
