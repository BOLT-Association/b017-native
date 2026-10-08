// record.setup.ts - runs before every b017 test file. It wraps the reference's entry points so each call
// the reference's own test suite makes is written down (inputs, the answers its callbacks gave, the result),
// without changing what the call returns. The Go and Rust ports replay these records.
import { vi } from 'vitest'

const SRC = 'C:/Users/honoh/Code/ChainBrowsers/b017/src'

vi.mock('C:/Users/honoh/Code/ChainBrowsers/b017/src/lib/scanner/verifyEvents.ts', async (importOriginal) => {
  const orig: any = await importOriginal()
  const { Graph, record, plain, errText } = await import('./ser.ts')

  // isKnownBlockRoot / chainTracker answers are recorded so the replay can give the same answers.
  const wrapOpts = (g: InstanceType<typeof Graph>, opts: any, calls: any[]) => {
    if (opts == null || typeof opts !== 'object') return { rec: { t: 'json', v: opts ?? null }, run: opts }
    const rec: any = {}
    const run: any = { ...opts }
    for (const [k, v] of Object.entries(opts)) {
      if (k === 'isKnownBlockRoot') {
        rec.isKnownBlockRoot = typeof v === 'function' ? 'fn' : { t: typeof v }
        if (typeof v === 'function') {
          run.isKnownBlockRoot = (root: string, height: number) => {
            try {
              const ans = (v as any)(root, height)
              calls.push({ cb: 'isKnownBlockRoot', root, height, ans })
              return ans
            } catch (e) {
              calls.push({ cb: 'isKnownBlockRoot', root, height, throws: errText(e) })
              throw e
            }
          }
        }
      } else if (k === 'chainTracker') {
        rec.chainTracker = v && typeof (v as any).isValidRootForHeight === 'function' ? 'fn' : { t: typeof v }
        if (rec.chainTracker === 'fn') {
          run.chainTracker = {
            isValidRootForHeight: async (root: string, height: number) => {
              try {
                const ans = await (v as any).isValidRootForHeight(root, height)
                calls.push({ cb: 'chainTracker', root, height, ans })
                return ans
              } catch (e) {
                calls.push({ cb: 'chainTracker', root, height, throws: errText(e) })
                throw e
              }
            },
          }
        }
      } else if (k === 'trustedIssuerPubKey') {
        rec[k] = g.input(v)
      } else {
        rec[k] = v === undefined ? { t: 'undefined' } : v
      }
    }
    return { rec, run }
  }
  const batch = (g: InstanceType<typeof Graph>, txs: any) =>
    Array.isArray(txs) ? { t: 'array', items: txs.map((x: any) => g.input(x)) } : g.input(txs)

  const sync = (name: string) => (txs: any, opts?: any) => {
    const g = new Graph()
    const calls: any[] = []
    let inb: any, o: any
    try {
      inb = batch(g, txs)
      o = wrapOpts(g, opts, calls)
    } catch (e) {
      record(name, { unserializable: errText(e) }, g)
      return orig[name](txs, opts)
    }
    const res = orig[name](txs, o.run ?? opts)
    record(name, { batch: inb, opts: o.rec, optsGiven: opts !== undefined, calls, result: plain(res) }, g)
    return res
  }
  return {
    ...orig,
    verifyEvents: sync('verifyEvents'),
    verifyEvent: sync('verifyEvent'),
    verifyAndBroadcast: async (txs: any, broadcaster: any, opts?: any) => {
      const g = new Graph()
      const calls: any[] = []
      let inb: any, o: any
      try {
        inb = batch(g, txs)
        o = wrapOpts(g, opts, calls)
      } catch (e) {
        record('verifyAndBroadcast', { unserializable: errText(e) }, g)
        return orig.verifyAndBroadcast(txs, broadcaster, opts)
      }
      const bc = typeof broadcaster === 'function'
        ? async (tx: any) => {
            const id = g.tx(tx)
            try {
              const r = await broadcaster(tx)
              calls.push({ cb: 'broadcast', tx: id, ans: plain(r) === null && r === undefined ? { t: 'undefined' } : plain(r) })
              return r
            } catch (e) {
              calls.push({ cb: 'broadcast', tx: id, throws: errText(e) })
              throw e
            }
          }
        : broadcaster
      const res = await orig.verifyAndBroadcast(txs, bc, o.run ?? opts)
      record('verifyAndBroadcast', {
        batch: inb, broadcaster: typeof broadcaster === 'function' ? 'fn' : { t: typeof broadcaster },
        opts: o.rec, optsGiven: opts !== undefined, calls, result: plain(res),
      }, g)
      return res
    },
  }
})

vi.mock('C:/Users/honoh/Code/ChainBrowsers/b017/src/lib/scanner/beef.ts', async (importOriginal) => {
  const orig: any = await importOriginal()
  const { Graph, record, errText } = await import('./ser.ts')
  return {
    ...orig,
    toAtomicBeef: (tx: any) => {
      const g = new Graph()
      const id = g.tx(tx)
      try {
        const out = orig.toAtomicBeef(tx)
        record('toAtomicBeef', { tx: id, result: Buffer.from(out).toString('hex') }, g)
        return out
      } catch (e) {
        record('toAtomicBeef', { tx: id, throws: errText(e) }, g)
        throw e
      }
    },
    fromBeef: (input: any) => {
      const g = new Graph()
      const inp = g.input(input)
      try {
        const tx = orig.fromBeef(input)
        const g2 = new Graph()
        const out = g2.tx(tx)
        record('fromBeef', { input: inp, result: out, resultNodes: g2.nodes }, g)
        return tx
      } catch (e) {
        record('fromBeef', { input: inp, throws: errText(e) }, g)
        throw e
      }
    },
  }
})

vi.mock('C:/Users/honoh/Code/ChainBrowsers/b017/src/lib/boltLib.ts', async (importOriginal) => {
  const orig: any = await importOriginal()
  const { Graph, record, errText } = await import('./ser.ts')
  const { wrapTemplate } = await import('./templates.ts')
  return {
    ...orig,
    verifyTx: (tx: any, skipOutputCheck?: boolean) => {
      const g = new Graph()
      let id: string
      try { id = g.tx(tx) } catch (e) {
        record('verifyTx', { unserializable: errText(e) }, g)
        return orig.verifyTx(tx, skipOutputCheck)
      }
      try {
        const r = orig.verifyTx(tx, skipOutputCheck)
        record('verifyTx', { tx: id, skipOutputCheck: skipOutputCheck ?? null, result: { valid: r.valid, executions: r.scriptExecutions.map((x: any) => x.valid) } }, g)
        return r
      } catch (e) {
        record('verifyTx', { tx: id, skipOutputCheck: skipOutputCheck ?? null, throws: errText(e) }, g)
        throw e
      }
    },
    p2pkhUnlock: (k: any) => wrapTemplate('p2pkhUnlock', 'unlock', [k], orig.p2pkhUnlock(k)),
  }
})

// Template classes are shared objects: wrap their prototypes (lock outputs + every sign() call).
const { patchTemplates } = await import('./templates.ts')
await patchTemplates(SRC)
