// ser-plain.ts - the tx-node serialiser of ser.ts without the recorder's side effects (no output file, no
// PrivateKey patch), for generators that only need content-addressed nodes.
import { createHash } from 'node:crypto'
import { PrivateKey, Transaction, Script } from '@bsv/sdk'
import type { NodeId, TxNode } from './ser.ts'

const KEYS = new Map<string, string>()
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

