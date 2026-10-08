// pack.mjs - turn the raw call log (vectors/raw/calls.jsonl, gitignored) into the committed vectors:
//   vectors/nodes.json         every tx node, content-addressed (shared by all records)
//   vectors/<kind>.json        the records of one kind, de-duplicated, in first-seen order
// Usage: node vectors/gen/pack.mjs   (from the repo root)
import { createReadStream, writeFileSync, mkdirSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { createHash } from 'node:crypto'

const RAW = 'vectors/raw/calls.jsonl'
const nodes = {}
const kinds = {}
const seen = new Set()
const rl = createInterface({ input: createReadStream(RAW) })
for await (const line of rl) {
  const rec = JSON.parse(line)
  Object.assign(nodes, rec.nodes)
  delete rec.nodes
  if (rec.resultNodes) { Object.assign(nodes, rec.resultNodes); delete rec.resultNodes }
  const { n, file, test, ...body } = rec
  const key = createHash('sha256').update(JSON.stringify(body)).digest('hex')
  if (seen.has(key)) continue
  seen.add(key)
  const kind = rec.kind === 'sign' || rec.kind === 'lock' || rec.kind === 'template' ? `${rec.kind}.${rec.template}` : rec.kind
  ;(kinds[kind] ??= []).push({ file, test, ...body })
}
mkdirSync('vectors/calls', { recursive: true })
const sorted = Object.fromEntries(Object.keys(nodes).sort().map((k) => [k, nodes[k]]))
writeFileSync('vectors/nodes.json', JSON.stringify(sorted))
for (const [k, list] of Object.entries(kinds)) writeFileSync(`vectors/calls/${k}.json`, JSON.stringify(list, null, 0))
console.log(Object.fromEntries(Object.entries(kinds).map(([k, v]) => [k, v.length])), 'nodes', Object.keys(nodes).length)
