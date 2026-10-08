// cover.mjs - Go statement coverage on the same footing as the reference's (vitest v8, 99% statements):
//   - a block that only propagates an error (`return …, err` / `return err` under `if err != nil`) is not counted:
//     TS propagates a throw implicitly, so the reference has no statement there to cover;
//   - a block whose first line carries `// unreachable: <reason>` is not counted (the reference's `v8 ignore next`);
//   - files that port @bsv/sdk (not b017) are reported apart: the reference's floor does not cover its SDK.
// Usage (from b017-native): go test -coverprofile=vectors/raw/cover.out ./go/... && node tools/cover.mjs vectors/raw/cover.out [--list]
import { readFileSync } from 'node:fs'

const [profile, flag] = process.argv.slice(2)
const SDK = new Set(['script.go', 'tx.go', 'sighash.go', 'merklepath.go', 'beefsdk.go', 'spend.go', 'txbuild.go'])
const src = new Map()
const lines = (f) => {
  if (!src.has(f)) src.set(f, readFileSync(f, 'utf8').split('\n'))
  return src.get(f)
}
const groups = {}
const missed = []
for (const row of readFileSync(profile, 'utf8').trim().split('\n').slice(1)) {
  const m = row.match(/^github\.com\/BOLT-Association\/b017-native\/(.+?):(\d+)\.(\d+),(\d+)\.(\d+) (\d+) (\d+)$/)
  if (!m) continue
  const [, path, l1, c1, l2, c2, n, count] = m
  if (path.endsWith('_gen.go')) continue
  const file = path.split('/').pop()
  const text = lines(path).slice(+l1 - 1, +l2)
  // a block starts at its opening brace and ends at its closing one
  const body = text.join('\n').slice(+c1 - 1).replace(/^\{/, '').replace(/\}\s*$/, '').trim()
  const propagate = /^return\s+(?:[\w.{}\[\]*&]+\s*,\s*)*err$/.test(body) &&
    /if\s+(?:[^;{]+;\s*)?err\s*!=\s*nil\s*$/.test(lines(path)[+l1 - 1].slice(0, +c1 - 1))
  const marked = /\/\/ unreachable: \S/.test(lines(path)[+l1 - 1]) || /\/\/ unreachable: \S/.test(lines(path)[+l1 - 2] ?? '')
  const g = (groups[SDK.has(file) && !path.includes('authbolt/') ? 'sdk ports' : path.includes('authbolt/') ? 'authbolt' : 'b017 ports'] ??= { n: 0, cov: 0, prop: 0, marked: 0 })
  if (propagate) { g.prop += +n; continue }
  if (marked) { g.marked += +n; continue }
  g.n += +n
  if (+count > 0) g.cov += +n
  else missed.push(`${path}:${l1}  ${lines(path)[+l1 - 1].trim()}`)
}
for (const [k, g] of Object.entries(groups)) {
  console.log(`${k.padEnd(11)} ${(100 * g.cov / g.n).toFixed(1)}% of ${g.n} statements (not counted: ${g.prop} error propagation, ${g.marked} marked unreachable)`)
}
if (flag === '--list') for (const m of missed) console.log(m)
