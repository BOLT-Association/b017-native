// static.test.ts - the reference's static data, written to vectors/static.json: every contract suffix (lock and
// unlock, as script hex), the REGISTRY, the p2Proof reference lock and constants. The ports embed the suffix hex
// from this file and never re-parse the ASM.
import { writeFileSync } from 'node:fs'
import { test } from 'vitest'
import { Script, Hash, Utils } from '@bsv/sdk'
import MinSimpleTemplate from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/tokens/templates/MinSimple.sx.template.ts'
import AuthBoltTemplate, { AUTH_DATA_MAX_BYTES } from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/tokens/templates/AuthBolt.sx.template.ts'
import SimpleMultiTemplate from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/tokens/templates/SimpleMulti.sx.template.ts'
import Pay2ProofTemplate from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/tokens/templates/pay2Proof.ts'
import { REGISTRY } from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/lib/scanner/fingerprints.ts'
import { PIECE_NAMES, AUTH_PIECE_NAMES } from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/lib/single/singleAncestor.ts'
import * as multi from 'C:/Users/honoh/Code/ChainBrowsers/b017/src/lib/multi/multiBoltLib.ts'

const OUT = 'C:/Users/honoh/Code/ChainBrowsers/b017-native/vectors/static.json'
const hex = (s: Script) => s.toHex()
const sha = (s: Script) => Utils.toHex(Hash.sha256(s.toBinary()))

test('write static vectors', () => {
  const tpls: Record<string, any> = {
    MinSimple: new MinSimpleTemplate(),
    AuthBolt: new AuthBoltTemplate(),
    SimpleMulti: new SimpleMultiTemplate(),
  }
  const suffixes: Record<string, any> = {}
  for (const [name, t] of Object.entries(tpls)) {
    const lock = t.staticSuffix() as Script
    const unlock = Script.fromASM(t.UNLOCK_SCRIPT_SUFFIX)
    suffixes[name] = {
      lockHex: hex(lock), lockSha256: sha(lock), lockChunks: lock.chunks.length,
      unlockHex: hex(unlock), unlockSha256: sha(unlock), unlockChunks: unlock.chunks.length,
    }
  }
  const p2p = new Pay2ProofTemplate().lock(new Array(20).fill(0))
  const ocs = Script.fromASM('OP_CHECKSIGVERIFY OP_ENDIF')
  const b017 = Script.fromASM('b017')
  writeFileSync(OUT, JSON.stringify({
    suffixes,
    registry: REGISTRY,
    p2pZeroLockHex: hex(p2p),
    ocsPrefixHex: hex(ocs),
    b017MarkerHex: hex(b017),
    authDataMaxBytes: AUTH_DATA_MAX_BYTES,
    pieceNames: PIECE_NAMES,
    authPieceNames: AUTH_PIECE_NAMES,
    multi: Object.fromEntries(Object.entries(multi).filter(([, v]) => typeof v !== 'function')),
  }, null, 1))
})
