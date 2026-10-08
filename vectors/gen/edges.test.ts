// edges.test.ts - the reference's behaviour on edge inputs its own suite does not reach: out-of-range indexes,
// absent sources / scripts / amounts, short CTX pushes, varint widths, fee shortfalls, every ancestor piece of
// every tx shape. Each record: { fn, args, result | throws }. Written to vectors/edges.json.
import { readFileSync, writeFileSync } from 'node:fs'
import { test } from 'vitest'
import { Hash, LockingScript, P2PKH, PrivateKey, Script, Transaction, UnlockingScript } from '@bsv/sdk'
import * as lib from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/lib/boltLib.ts'
import * as multi from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/lib/multi/multiBoltLib.ts'
import * as single from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/lib/single/singleAncestor.ts'
import { recognizeType, recognizeP2P } from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/lib/scanner/fingerprints.ts'
import { isBeef, fromBeef } from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/lib/scanner/beef.ts'
import MinSimpleTemplate from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/tokens/templates/MinSimple.sx.template.ts'
import Pay2ProofTemplate from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/tokens/templates/pay2Proof.ts'
import { singleSpendUnlock } from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/lib/single/singleSpend.ts'
import SimpleMultiTemplate from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/tokens/templates/SimpleMulti.sx.template.ts'
import { SimpleMultiBOLT } from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/tokens/MultiBOLT.ts'
import { Graph } from './ser-plain.ts'

const ROOT = 'C:/Users/honoh/Code/ChainBrowsers/b017-native/vectors'
const g = new Graph()
const out: any[] = []
const hex = (b: number[]) => Buffer.from(b).toString('hex')
const enc = (v: any): any =>
  Array.isArray(v) && v.length > 0 && v.every((x) => x instanceof Transaction) ? { txs: v.map((t) => g.tx(t)) }
    : Array.isArray(v) && v.every((x) => Number.isInteger(x)) ? { bytes: hex(v) } : v instanceof Transaction ? { tx: g.tx(v) } : v
async function rec(fn: string, args: any[], run: () => any) {
  const a = args.map(enc)
  try {
    const r = await run()
    out.push({ fn, args: a, result: enc(r) })
  } catch (e: any) {
    out.push({ fn, args: a, throws: String(e?.message ?? e) })
  }
}

const flows = JSON.parse(readFileSync(`${ROOT}/flows.json`, 'utf8'))
const fromFlow = (name: string, step: string) => {
  const s = flows[name].find((x: any) => x.step === step)
  const txs = s.prevTxs.map((h: string) => Transaction.fromHex(h))
  // re-attach each input's source from the lineage when it is there (as the class holds them)
  const byId = new Map(txs.map((t: Transaction) => [t.id('hex'), t]))
  for (const t of txs) for (const i of t.inputs as any[]) if (byId.has(i.sourceTXID)) i.sourceTransaction = byId.get(i.sourceTXID)
  return txs as Transaction[]
}

test('write edge vectors', async () => {
  const key = PrivateKey.fromString('22'.repeat(32), 'hex')
  const pkh = Hash.hash160(key.toPublicKey().encode(true))
  const src = new Transaction(1, [], [{ satoshis: 1000, lockingScript: new P2PKH().lock(pkh) }])
  const tx = new Transaction(2, [], [{ satoshis: 5, lockingScript: new P2PKH().lock(pkh) }, { lockingScript: new P2PKH().lock(pkh) } as any])
  tx.addInput({ sourceTransaction: src, sourceOutputIndex: 0, unlockingScript: UnlockingScript.fromHex('0102'), sequence: 7 })
  tx.addInput({ sourceTXID: 'ab'.repeat(32), sourceOutputIndex: 3, unlockingScript: UnlockingScript.fromHex('') })
  ;(tx.inputs as any).push({ sourceOutputIndex: 1 }) // no txid, no source, no script, no sequence
  ;(tx.inputs as any).push({ sourceTXID: 'zz1', sourceOutputIndex: 2 }) // malformed txid

  for (const i of [0, 1, 2, 3, 9]) {
    await rec('spentOutpoint', [tx, i], () => lib.spentOutpoint(tx, i))
    await rec('vinSequence', [tx, i], () => lib.vinSequence(tx, i))
    await rec('vinScript', [tx, i], () => lib.vinScript(tx, i))
    for (const c of [0, 1, 5]) await rec('vinChunk', [tx, i, c], () => lib.vinChunk(tx, i, c))
  }
  for (const i of [0, 1, 2, 9]) {
    await rec('outputValue', [tx, i], () => lib.outputValue(tx, i))
    await rec('outputScript', [tx, i], () => lib.outputScript(tx, i))
    await rec('buildChangeOutput', [tx, i], () => lib.buildChangeOutput(tx, i))
    await rec('voutChunk', [tx, i, 2], () => lib.voutChunk(tx, i, 2))
  }
  // splitCtx over every scriptCode length prefix, and short / truncated preimages
  for (const [len, ub] of [[10, 2], [300, 2], [70000, 2], [3, 9], [0, 2]] as [number, number][]) {
    const pre = new Array(104).fill(1)
    const w = new Script().writeBin(new Array(len).fill(2))
    const varint = (n: number) => (n < 0xfd ? [n] : n <= 0xffff ? [0xfd, n & 255, n >> 8] : [0xfe, n & 255, (n >> 8) & 255, (n >> 16) & 255, n >>> 24])
    const ctx = [...pre, ...varint(len), ...new Array(len).fill(2), ...new Array(52).fill(3)]
    void w
    await rec('splitCtx', [ctx, ub], () => Object.fromEntries(Object.entries(lib.splitCtx(ctx, ub)).map(([k, v]) => [k, hex(v as number[])])))
  }
  const p104 = new Array(104).fill(1)
  for (const short of [[], new Array(50).fill(1), new Array(106).fill(0xfd), p104,
    // a declared length past the data; 0xff lengths (small, past the data, past 2^63, cut short)
    [...p104, 0x10, 2, 2, 2], [...p104, 0xff, 3, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, ...new Array(52).fill(3)],
    [...p104, 0xff, 0, 1, 0, 0, 0, 0, 0, 0, 2, 2], [...p104, 0xff, ...new Array(8).fill(0xff), 2, 2], [...p104, 0xff, 1, 2]]) {
    await rec('splitCtx', [short, 2], () => Object.fromEntries(Object.entries(lib.splitCtx(short, 2)).map(([k, v]) => [k, hex(v as number[])])))
  }
  for (const n of [0, 0xfc, 0xfd, 0xffff, 0x10000, 0xffffffff]) await rec('le32', [n], () => lib.le32(n))
  for (const n of [0, 1, 2 ** 40]) await rec('le64', [n], () => lib.le64(n))

  // fingerprints and BEEF detection on odd input
  for (const h of ['', '00', '6a', '76a914' + '00'.repeat(20) + '88ac', '02b0178876a914' + '00'.repeat(19) + '88ac', '02b0178876a914' + '00'.repeat(20) + '88ac']) {
    await rec('recognizeType', [h], () => recognizeType(Script.fromHex(h)))
    await rec('recognizeP2P', [h], () => recognizeP2P(Script.fromHex(h)))
  }
  for (const h of ['0100beef', '0200BEEF00', '01010101', 'beef', '']) await rec('isBeef', [h], () => isBeef(h))
  for (const b of [[1, 0, 0xbe, 0xef], [2, 0, 0xbe, 0xef, 0, 0]]) await rec('isBeefBytes', [b], () => isBeef(Uint8Array.from(b)))
  for (const h of ['0100beef0000', '0200beef00', '0200beef0001000000', '01010101' + '00'.repeat(32) + '0200beef0000']) await rec('fromBeef', [h], () => fromBeef(h).id('hex'))

  // every SimpleMultiBolt ancestor piece of every tx shape in the flows, and of a broken tx
  const shapes: Transaction[] = []
  for (const [name, step] of [['lifecycle', 'split.main'], ['merge-melt', 'melt'], ['merge-melt', 'merge']]) shapes.push(...fromFlow(name, step))
  const broken = Transaction.fromHex(shapes[1].toHex())
  delete (broken.inputs[0] as any).unlockingScript
  const shortCtx = Transaction.fromHex(shapes[1].toHex())
  shortCtx.inputs[0].unlockingScript = new UnlockingScript(new Array(195).fill(0).map(() => ({ op: 0 })))
  const meltOnly = new Transaction(2, [], [{ satoshis: 1, lockingScript: new P2PKH().lock(pkh) }])
  // crafted CTX pushes (chunk 192 header, 195 scriptCode, 197 scriptCode length): every varint width, a length
  // past the data, a length past 2^53, a short header, and a scriptCode of OP_0, a bare opcode and one push
  const ctxTx = (header: number[], len: number[], code: number[]) => {
    const t = Transaction.fromHex(shapes[1].toHex())
    const cs = t.inputs[0].unlockingScript!.chunks
    for (const [i, d] of [[192, header], [195, code], [197, len]] as [number, number[]][]) cs[i] = new Script().writeBin(d).chunks[0]
    t.inputs[0].unlockingScript = new UnlockingScript(cs)
    return t
  }
  const hdr = new Array(104).fill(7)
  const code = [0x00, 0x76, 0x01, 0xaa]
  const crafted = [
    ctxTx(hdr, [0xfe, 4, 0, 0, 0], code),
    ctxTx(hdr, [0xff, 4, 0, 0, 0, 0, 0, 0, 0], code),
    ctxTx(hdr, [0xfe, 0xff, 0xff, 0xff, 0x7f], code),
    ctxTx(hdr, [0xff, 0, 0, 0, 0, 0, 0, 0x40, 0], code),
    ctxTx(hdr, [0xfd, 4], code),
    ctxTx(hdr, [4], code),
    ctxTx(hdr.slice(0, 50), [4], code),
    ctxTx(hdr, [0xfe, 4], []),
  ]
  for (const t of [...new Set(shapes.map((s) => s.toHex()))].map((h) => Transaction.fromHex(h)).concat([broken, shortCtx, meltOnly, new Transaction(2, [], []), ...crafted])) {
    for (const name of multi.PIECE_NAMES) await rec('smbAncestorPiece', [name, t], () => multi.ancestorPiece(name, t))
  }
  // every NFT ancestor piece of commits with and without a funding input / change output
  for (const t of [...shapes.slice(0, 3), meltOnly, broken]) {
    for (const [layout, names] of [[single.MIN_SIMPLE_LAYOUT, single.PIECE_NAMES], [single.AUTH_BOLT_LAYOUT, single.AUTH_PIECE_NAMES]] as any[]) {
      for (const name of names) await rec(layout.hasAuth ? 'authAncestorPiece' : 'nftAncestorPiece', [name, t], () => single.ancestorPiece(name, t, 0, layout))
    }
  }

  // SimpleMulti lock over odd lineages, and unlock / melt input errors
  const tpl = new SimpleMultiTemplate()
  const pub = key.toPublicKey().encode(true) as number[]
  const noData = new Transaction(2, [], [{ satoshis: 1, lockingScript: Script.fromHex('00'.repeat(12)) as any }])
  for (const [prev, vout] of [[[], 0], [[shapes[0]], 0], [[shapes[0]], 5], [[noData], 0]] as [Transaction[], number][]) {
    await rec('smbLock', [{ bytes: hex(pub) }, prev, vout], () => tpl.lock(pub, prev, undefined, undefined, undefined, undefined, undefined, undefined, undefined, vout).toHex())
  }
  const spend = new Transaction(2, [], [{ satoshis: 1, lockingScript: new P2PKH().lock(pkh) }])
  spend.addInput({ sourceTXID: 'cd'.repeat(32), sourceOutputIndex: 0, unlockingScript: UnlockingScript.fromHex('') })
  await rec('smbUnlockSign', [spend], () => tpl.unlock(key, pub, []).sign(spend, 0).then((s) => s.toHex()))
  await rec('smbMeltSign', [spend], () => tpl.melt(key).sign(spend, 0).then((s) => s.toHex()))
  const zero = new Transaction(1, [], [{ satoshis: 0, lockingScript: new P2PKH().lock(pkh) }])
  const spend0 = new Transaction(2, [], [{ satoshis: 1, lockingScript: new P2PKH().lock(pkh) }])
  spend0.addInput({ sourceTransaction: zero, sourceOutputIndex: 0, unlockingScript: UnlockingScript.fromHex('') })
  await rec('smbUnlockSign', [spend0], () => tpl.unlock(key, pub, []).sign(spend0, 0).then((s) => s.toHex()))

  // fee(0) shortfalls and missing sources, through the class (the builder's own paths)
  await rec('mintNoMatchingOutput', [], () => new SimpleMultiBOLT().mint(key, new Transaction(1, [], [{ satoshis: 1000, lockingScript: new P2PKH().lock(new Array(20).fill(9)) }])).then(() => 'minted'))
  await rec('mintTooPoor', [], () => new SimpleMultiBOLT().mint(key, new Transaction(1, [], [{ satoshis: 0, lockingScript: new P2PKH().lock(pkh) }])).then(() => 'minted'))
  await rec('mintOddSource', [], () => new SimpleMultiBOLT().mint(key, new Transaction(1, [], [{ satoshis: 10, lockingScript: Script.fromHex('51') as any }])).then(() => 'minted'))

  // template sign() error paths and overrides, on crafted spends
  const ms = new MinSimpleTemplate()
  const lockMs = ms.lock(pkh, pub)
  const withSrc = (sats: any, lock: any) => {
    const s0 = new Transaction(1, [], [{ satoshis: sats, lockingScript: lock } as any])
    const t = new Transaction(2, [], [{ satoshis: 1, lockingScript: new P2PKH().lock(pkh) }])
    t.addInput({ sourceTransaction: s0, sourceOutputIndex: 0, unlockingScript: UnlockingScript.fromHex(''), sequence: 0xffffffff })
    return t
  }
  const noRef = new Transaction(2, [], [{ satoshis: 1, lockingScript: new P2PKH().lock(pkh) }])
  ;(noRef.inputs as any).push({ sourceOutputIndex: 0, unlockingScript: UnlockingScript.fromHex(''), sequence: 0xffffffff })
  const txidOnly = new Transaction(2, [], [{ satoshis: 1, lockingScript: new P2PKH().lock(pkh) }])
  txidOnly.addInput({ sourceTXID: 'ef'.repeat(32), sourceOutputIndex: 0, unlockingScript: UnlockingScript.fromHex(''), sequence: 0xffffffff })
  const unfundedSrc = withSrc(1, lockMs)
  unfundedSrc.addInput({ sourceTXID: 'aa'.repeat(32), sourceOutputIndex: 0, unlockingScript: UnlockingScript.fromHex(''), sequence: 0xffffffff })
  unfundedSrc.addOutput({ satoshis: 1, lockingScript: new P2PKH().lock(pkh) })
  const cases: [string, Transaction, any][] = [
    ['noRef', noRef, {}], ['txidOnly', txidOnly, {}], ['txidOnlyWithAmount', txidOnly, { sourceSatoshis: 5 }],
    ['txidOnlyWithAmountAndLock', txidOnly, { sourceSatoshis: 5, lockingScript: lockMs }], ['noAmount', withSrc(undefined, lockMs), {}],
    ['fundWithoutSource', unfundedSrc, {}], ['zeroAmount', withSrc(0, lockMs), {}],
  ]
  for (const [name, t, over] of cases) {
    await rec('singleSpendSign', [name], () => singleSpendUnlock({ privateKey: key, beneficiaryPubKeyHash: pkh, unlockScriptSuffixASM: (ms as any).UNLOCK_SCRIPT_SUFFIX, ...over }).sign(t, 0).then((x) => x.toHex()))
    await rec('p2pkhUnlockSign', [name], () => lib.p2pkhUnlock(key).sign(t, 0).then((x) => x.toHex()))
    await rec('pay2ProofSign', [name], () => new Pay2ProofTemplate().unlock(key, over.sourceSatoshis, over.lockingScript).sign(t, 0).then((x) => x.toHex()))
  }

  writeFileSync(`${ROOT}/edges.json`, JSON.stringify({ records: out, nodes: g.nodes }))
  console.log(`edges: ${out.length} records`)
})
