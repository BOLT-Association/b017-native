// fuzz.test.ts - differential corpus. Take the batches the reference ACCEPTED in its own suite (recorded
// verifyEvents / verifyEvent calls with ok: true), apply one seeded mutation to one tx of the batch graph, run the
// reference scanner on it, and write the case and the verdict. The Go and Rust ports replay the corpus and must
// reach the same verdict (ok, reason, and every other field). This is also the "flip one byte" negative control.
//   B017_FUZZ_CASES=600 B017_FUZZ_SEED=1 B017_FUZZ_OUT=../vectors/fuzz.json  (defaults)
import { readFileSync, writeFileSync } from 'node:fs'
import { test } from 'vitest'
import { Transaction, Script, MerklePath, UnlockingScript, LockingScript } from '@bsv/sdk'
import { verifyEvents, verifyEvent } from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/lib/scanner/verifyEvents.ts'
import { Graph } from './ser-plain.ts'

const ROOT = 'C:/Users/honoh/Code/ChainBrowsers/b017-native/vectors'
const CASES = Number(process.env.B017_FUZZ_CASES ?? 600)
const SEED = Number(process.env.B017_FUZZ_SEED ?? 1)
const OUT = process.env.B017_FUZZ_OUT ?? `${ROOT}/fuzz.json`

// mulberry32: a small seeded PRNG.
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

const nodes: Record<string, any> = JSON.parse(readFileSync(`${ROOT}/nodes.json`, 'utf8'))

/** Rebuild a node id into Transactions (one object per id), as the ports' test harnesses do. */
function build(id: string, memo = new Map<string, Transaction>()): Transaction {
  const hit = memo.get(id)
  if (hit) return hit
  const n = nodes[id]
  const tx = new Transaction()
  memo.set(id, tx)
  tx.version = n.v
  tx.lockTime = n.lt
  tx.inputs = n.ins.map((i: any) => {
    const input: any = { sourceOutputIndex: i.vout }
    if (i.txid !== null) input.sourceTXID = i.txid
    if (i.seq !== null) input.sequence = i.seq
    if (i.us !== null) input.unlockingScript = UnlockingScript.fromHex(i.us)
    if (i.src !== null) input.sourceTransaction = build(i.src, memo)
    return input
  })
  tx.outputs = n.outs.map((o: any) => {
    const out: any = {}
    if (o.sat !== null) out.satoshis = o.sat
    if (o.ls !== null) out.lockingScript = LockingScript.fromHex(o.ls)
    return out
  })
  if (n.mp !== null) tx.merklePath = MerklePath.fromHex(n.mp)
  return tx
}

/** Every tx reachable from the batch (the batch txs and their attached sources). */
function reachable(batch: Transaction[]): Transaction[] {
  const seen = new Set<Transaction>()
  const walk = (t: Transaction) => {
    if (seen.has(t)) return
    seen.add(t)
    for (const i of t.inputs as any[]) if (i.sourceTransaction) walk(i.sourceTransaction)
  }
  batch.forEach(walk)
  return [...seen]
}

const flipByte = (hex: string, r: () => number): string => {
  if (hex.length === 0) return '00'
  const b = Buffer.from(hex, 'hex')
  const k = Math.floor(r() * b.length)
  b[k] ^= 1 + Math.floor(r() * 255)
  return b.toString('hex')
}

/** One mutation of one tx; returns a label, or null when the chosen mutation does not apply. */
function mutate(tx: Transaction, r: () => number): string | null {
  const ins = tx.inputs as any[]
  const outs = tx.outputs as any[]
  switch (Math.floor(r() * 9)) {
    case 0: {
      const i = ins[Math.floor(r() * ins.length)]
      if (!i?.unlockingScript) return null
      i.unlockingScript = UnlockingScript.fromHex(flipByte(i.unlockingScript.toHex(), r))
      return 'unlock byte'
    }
    case 1: {
      const o = outs[Math.floor(r() * outs.length)]
      if (!o?.lockingScript) return null
      o.lockingScript = LockingScript.fromHex(flipByte(o.lockingScript.toHex(), r))
      return 'lock byte'
    }
    case 2: {
      const o = outs[Math.floor(r() * outs.length)]
      if (o?.satoshis === undefined) return null
      o.satoshis = Math.max(0, o.satoshis + (r() < 0.5 ? -1 : 1))
      return 'amount'
    }
    case 3: {
      const i = ins[Math.floor(r() * ins.length)]
      if (!i) return null
      i.sequence = r() < 0.5 ? 0 : 0xfffffffe
      return 'sequence'
    }
    case 4: {
      const i = ins[Math.floor(r() * ins.length)]
      if (!i) return null
      i.sourceOutputIndex = i.sourceOutputIndex + 1
      return 'vout'
    }
    case 5:
      tx.version = tx.version === 2 ? 1 : 2
      return 'version'
    case 6: {
      if (!tx.merklePath) return null
      try {
        tx.merklePath = MerklePath.fromHex(flipByte(tx.merklePath.toHex(), r))
      } catch {
        return null
      }
      return 'merkle path byte'
    }
    case 7: {
      if (outs.length < 2) return null
      outs.pop()
      return 'drop last output'
    }
    default: {
      const i = ins[Math.floor(r() * ins.length)]
      if (!i?.sourceTransaction || !i.sourceTXID) return null
      delete i.sourceTransaction
      return 'detach source'
    }
  }
}

test('write the differential corpus', () => {
  const r = rng(SEED)
  const recs: any[] = []
  for (const kind of ['verifyEvents', 'verifyEvent']) {
    for (const rec of JSON.parse(readFileSync(`${ROOT}/calls/${kind}.json`, 'utf8'))) {
      if (rec.result?.ok !== true || rec.batch?.t !== 'array') continue
      if (!rec.batch.items.every((x: any) => x.t === 'tx')) continue
      recs.push({ kind, rec })
    }
  }
  const g = new Graph()
  const cases: any[] = []
  let attempts = 0
  while (cases.length < CASES && attempts < CASES * 20) {
    attempts++
    const { kind, rec } = recs[Math.floor(r() * recs.length)]
    const memo = new Map<string, Transaction>()
    const batch = rec.batch.items.map((x: any) => build(x.id, memo))
    const all = reachable(batch)
    const target = all[Math.floor(r() * all.length)]
    const what = mutate(target, r)
    if (!what) continue
    // The recorded header answers, replayed; a root the recording never saw is unknown.
    const answers = new Map<string, boolean>()
    for (const c of rec.calls) if (c.cb === 'isKnownBlockRoot' && c.ans === true) answers.set(`${c.height}:${c.root}`, true)
    const opts: any = {}
    if (rec.opts && typeof rec.opts === 'object' && !rec.opts.t) {
      if (rec.opts.expectedType) opts.expectedType = rec.opts.expectedType
      if (rec.opts.requireBroadcastable) opts.requireBroadcastable = rec.opts.requireBroadcastable
      if (rec.opts.trustedIssuerPubKey?.t === 'str') opts.trustedIssuerPubKey = rec.opts.trustedIssuerPubKey.v
      if (rec.opts.trustedIssuerPubKey?.t === 'bytes') opts.trustedIssuerPubKey = Array.from(Buffer.from(rec.opts.trustedIssuerPubKey.hex, 'hex'))
      if (rec.opts.isKnownBlockRoot === 'fn') opts.isKnownBlockRoot = (root: string, h: number) => answers.get(`${h}:${root}`) === true
    }
    let ids: any[]
    try {
      ids = batch.map((t: Transaction) => ({ t: 'tx', id: g.tx(t) }))
    } catch {
      continue // a mutation the recorder cannot serialise
    }
    const fn = kind === 'verifyEvents' ? verifyEvents : verifyEvent
    const result = JSON.parse(JSON.stringify(fn(batch, opts)))
    cases.push({ kind, base: `${rec.file} :: ${rec.test}`, mutation: what, batch: ids, opts: rec.opts, known: [...answers.keys()], result })
  }
  const fresh = Object.fromEntries(Object.entries(g.nodes).filter(([k]) => !(k in nodes)))
  writeFileSync(OUT, JSON.stringify({ seed: SEED, cases, nodes: fresh }))
  const refused = cases.filter((c) => !c.result.ok).length
  console.log(`fuzz: ${cases.length} cases (${refused} refused, ${cases.length - refused} still accepted), ${Object.keys(fresh).length} new nodes`)
})
