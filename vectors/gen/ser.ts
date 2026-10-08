// ser.ts - serialise the b017 reference's in-memory objects into content-addressed JSON the Go and Rust
// ports can rebuild. A Transaction becomes a node {v, lt, ins, outs, mp}; an input's attached source is a
// reference to another node, so a tx graph (a package, a BEEF's ancestry, a deliberately broken tx object)
// survives exactly as the reference saw it. Missing fields are null, never invented.
import { createHash } from 'node:crypto'
import { appendFileSync } from 'node:fs'
import { PrivateKey, Transaction, Script } from '@bsv/sdk'
import { expect } from 'vitest'

export type NodeId = string
export interface TxNode {
  v: number | null
  lt: number | null
  ins: { txid: string | null; vout: number | null; seq: number | null; us: string | null; src: NodeId | null }[]
  outs: { sat: number | null; ls: string | null }[]
  mp: string | null
}

const OUT = process.env.B017_VECTORS_OUT
if (!OUT) throw new Error('B017_VECTORS_OUT is not set')

/** Every private key the reference touched, by compressed pubkey hex: lets a port re-sign a call made
 *  through a Signer object that wraps a PrivateKey (MultiBOLT holds Signers, not keys). */
export const KEYS = new Map<string, string>()
const origToPub = PrivateKey.prototype.toPublicKey
PrivateKey.prototype.toPublicKey = function (this: PrivateKey) {
  const pub = origToPub.call(this)
  try { KEYS.set(pub.toString(), this.toHex()) } catch { /* not a valid key */ }
  return pub
}

const scriptHex = (s: any): string | null => {
  if (s == null) return null
  if (typeof s.toHex === 'function') return s.toHex()
  return new Script(s.chunks).toHex()
}

export class Graph {
  nodes: Record<NodeId, TxNode> = {}
  private memo = new Map<object, NodeId>()
  tx(t: Transaction): NodeId {
    const hit = this.memo.get(t)
    if (hit) return hit
    this.memo.set(t, 'cycle')
    const node: TxNode = {
      v: t.version ?? null,
      lt: t.lockTime ?? null,
      ins: (t.inputs ?? []).map((i: any) => ({
        txid: i.sourceTXID ?? null,
        vout: i.sourceOutputIndex ?? null,
        seq: i.sequence ?? null,
        us: scriptHex(i.unlockingScript),
        src: i.sourceTransaction ? this.tx(i.sourceTransaction) : null,
      })),
      outs: (t.outputs ?? []).map((o: any) => ({ sat: o.satoshis ?? null, ls: scriptHex(o.lockingScript) })),
      mp: t.merklePath ? t.merklePath.toHex() : null,
    }
    const id = createHash('sha256').update(JSON.stringify(node)).digest('hex').slice(0, 32)
    this.nodes[id] = node
    this.memo.set(t, id)
    return id
  }
  /** A value the reference was handed: a Transaction, a hex string, bytes, or something else. */
  input(x: any): any {
    if (x instanceof Transaction) return { t: 'tx', id: this.tx(x) }
    if (typeof x === 'string') return { t: 'str', v: x }
    if (x instanceof Uint8Array) return { t: 'u8', hex: Buffer.from(x).toString('hex') }
    if (Array.isArray(x)) {
      if (x.every((b) => Number.isInteger(b) && b >= 0 && b <= 255)) return { t: 'bytes', hex: Buffer.from(x).toString('hex') }
      return { t: 'list', items: x.map((y) => this.input(y)) }
    }
    if (x instanceof PrivateKey) return { t: 'key', hex: x.toHex() }
    if (x instanceof Script || (x && Array.isArray(x.chunks))) return { t: 'script', hex: scriptHex(x) }
    if (x && Array.isArray(x.publicKey) && typeof x.sign === 'function') {
      const pub = Buffer.from(x.publicKey).toString('hex')
      return { t: 'signer', pub, key: KEYS.get(pub) ?? null }
    }
    if (x === undefined) return { t: 'undefined' }
    if (x === null || typeof x === 'number' || typeof x === 'boolean') return { t: 'json', v: x }
    return { t: 'other', js: typeof x }
  }
}

export const errText = (e: unknown): string => String((e as any)?.message ?? e)

let seq = 0
export function record(kind: string, body: Record<string, unknown>, g: Graph): void {
  let test: string | undefined
  let file: string | undefined
  try {
    const st = expect.getState()
    test = st?.currentTestName
    file = st?.testPath ? String(st.testPath).replace(/\\/g, '/').replace(/^.*\/test\//, 'test/') : undefined
  } catch { /* outside a test */ }
  const line = JSON.stringify({ kind, n: seq++, file, test, ...body, nodes: g.nodes })
  appendFileSync(OUT, line + '\n')
}

/** Plain JSON copy of a result (drops functions, keeps undefined-free structure). */
export const plain = (r: unknown) => JSON.parse(JSON.stringify(r ?? null))
