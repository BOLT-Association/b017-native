// templates.ts - record the reference's script templates: every lock() output and every unlock/melt sign()
// (the tx as it stood when the input was signed, which input, the template arguments, the unlocking script).
import { Graph, record, errText } from './ser.ts'

/** Wrap an unlock template {sign, estimateLength} so each sign() is recorded. */
export function wrapTemplate(template: string, method: string, args: unknown[], tpl: any): any {
  return {
    ...tpl,
    sign: async (tx: any, inputIndex: number) => {
      const g = new Graph()
      let rec: any
      try {
        rec = { template, method, args: args.map((a) => g.input(a)), tx: g.tx(tx), inputIndex }
      } catch (e) {
        record('sign', { template, method, unserializable: errText(e) }, g)
        return tpl.sign(tx, inputIndex)
      }
      try {
        const us = await tpl.sign(tx, inputIndex)
        record('sign', { ...rec, result: us.toHex() }, g)
        return us
      } catch (e) {
        record('sign', { ...rec, throws: errText(e) }, g)
        throw e
      }
    },
  }
}

export async function patchTemplates(src: string): Promise<void> {
  const mods: [string, string][] = [
    ['MinSimple', `${src}/tokens/templates/MinSimple.sx.template.ts`],
    ['AuthBolt', `${src}/tokens/templates/AuthBolt.sx.template.ts`],
    ['SimpleMulti', `${src}/tokens/templates/SimpleMulti.sx.template.ts`],
    ['Pay2Proof', `${src}/tokens/templates/pay2Proof.ts`],
  ]
  for (const [name, path] of mods) {
    const cls = (await import(/* @vite-ignore */ path)).default
    const proto = cls.prototype
    if (proto.__b017Recorded) continue
    proto.__b017Recorded = true
    const lock = proto.lock
    proto.lock = function (...args: unknown[]) {
      const g = new Graph()
      let ins: unknown
      try { ins = args.map((a) => g.input(a)) } catch (e) { ins = { unserializable: errText(e) } }
      try {
        const out = lock.apply(this, args)
        record('lock', { template: name, args: ins, result: out.toHex() }, g)
        return out
      } catch (e) {
        record('lock', { template: name, args: ins, throws: errText(e) }, g)
        throw e
      }
    }
    for (const m of ['unlock', 'melt']) {
      const f = proto[m]
      if (typeof f !== 'function') continue
      proto[m] = function (...args: unknown[]) {
        let tpl: any
        try {
          tpl = f.apply(this, args)
        } catch (e) {
          const g = new Graph()
          let ins: unknown
          try { ins = args.map((a) => g.input(a)) } catch (e2) { ins = { unserializable: errText(e2) } }
          record('template', { template: name, method: m, args: ins, throws: errText(e) }, g)
          throw e
        }
        return wrapTemplate(name, m, args, tpl)
      }
    }
  }
}
