# b017-native: progress log

Plan: `C:/Users/honoh/.claude/plans/https-claude-ai-artifact-6nautc1rbkcsv9a-sequential-whisper.md`.
Reference: `../b017` (branch `async-signer`, commit `a305f58`), read-only. Its `@bsv/sdk` is 2.8.11.

## Status

| Phase | State |
|---|---|
| 0 vectors + Rust SDK fix | vectors recorded and packed; SDK fix committed locally (patch in `third_party/patches`) |
| 1 primitives | Go done (Rust pending) |
| 2 NFT path | Go done (Rust pending) |
| 3 scanner | Go done (Rust pending) |
| 4 fungible | Go done (Rust pending) |
| 5 hardening + p2p adapter | not started |

## Vectors (Phase 0)

- `vectors/gen/vitest.record.config.mjs` runs b017's own suite (35 files, 629 tests, all pass) with
  `record.setup.ts`, which wraps the reference's entry points through `vi.mock` / prototype patches and writes
  every call to `vectors/raw/calls.jsonl` (gitignored, ~315 MB). `pack.mjs` de-duplicates it into
  `vectors/nodes.json` (913 content-addressed tx nodes) and `vectors/calls/<kind>.json`.
- Recorded kinds (distinct calls): verifyEvents 261, verifyEvent 102, verifyAndBroadcast 76, verifyTx 379,
  fromBeef 63, toAtomicBeef 46, lock.{MinSimple 61, AuthBolt 81, SimpleMulti 136, Pay2Proof 49},
  sign.{MinSimple 82, AuthBolt 142, SimpleMulti 141, Pay2Proof 56, p2pkhUnlock 132}, template.AuthBolt 1.
- Every Signer seen in a sign() call is backed by a recorded private key (`KEYS`, from patching
  `PrivateKey.prototype.toPublicKey`), so every recorded signature can be reproduced.
- `vectors/static.json` (`vitest.static.config.mjs` + `static.test.ts`): lock/unlock suffix hex for the 3
  contracts, REGISTRY, piece names, p2Proof reference lock, constants.

Regenerate (from `../b017`):
```
B017_VECTORS_OUT=C:/Users/honoh/Code/ChainBrowsers/b017-native/vectors/raw/calls.jsonl \
  node node_modules/vitest/vitest.mjs run --config C:/Users/honoh/Code/ChainBrowsers/b017-native/vectors/gen/vitest.record.config.mjs
node node_modules/vitest/vitest.mjs run --config C:/Users/honoh/Code/ChainBrowsers/b017-native/vectors/gen/vitest.static.config.mjs
cd ../b017-native && node vectors/gen/pack.mjs
```

## Decisions

- **Tx node format** (`vectors/gen/ser.ts`): `{v, lt, ins:[{txid, vout, seq, us, src}], outs:[{sat, ls}], mp}`,
  nulls for absent fields; `src` is another node id. This carries what hex cannot: an input with an attached
  source but no `sourceTXID`, a missing unlocking script, an attached source that is not the tx its outpoint
  names. Node id = first 32 hex of sha256(JSON).
- **Reasons:** text b017 writes itself must match exactly. Where a reason ends in an SDK's own error text (the
  tail after `script execution failed: tx … input …: `, `malformed transaction hex: `, `invalid BEEF: ` when the
  inner error is not one of b017's four BEEF errors, `unverifiable input: `, and a merkle path error inside
  `its merkle path does not prove it (…)`), only the b017 prefix is compared: three SDKs word their internals
  differently. `"the script evaluated false"` and `"no unlocking script"` are b017's and compared exactly.
- **Random keys:** a few reference tests use `PrivateKey.fromRandom`, so a re-recording differs byte-wise from the
  committed vectors. CI therefore re-records and runs the ports on the fresh set; it does not diff the files.
- **Rust SDK:** `b1narydt/bsv-rust-sdk` 0.8.1 (what crates.io publishes as `bsv-sdk`), base in
  `third_party/patches/BASE`, fix in `0001-…patch`, applied by `third_party/setup.sh` on local branch
  `b017-codesep`. The fix: `get_subscript` takes the subscript from the running script, and for CHECKSIG taken
  in the unlocking script continues into the whole locking script (ts-sdk `Spend.js` ~L1518, go-sdk
  `thread.subScript` after Chronicle). The crate's own 181 `script::` tests pass with it.
- go-sdk v1.7.1 requires `go 1.26.0`; local Go is 1.25.3, so the toolchain directive downloads 1.26 on first build.

## For the user (prepared, not done: no pushes, repos, forks, PRs or issues were created)

1. Create `BOLT-Association/b017-native` and push this repo.
2. Fork `b1narydt/bsv-rust-sdk` to `BOLT-Association/bsv-rust-sdk`, push branch `b017-codesep`, open the PR
   upstream with `third_party/patches/0001-…patch`, and file an issue on `bsv-blockchain/rs-sdk` (same bug:
   `src/script/spend_ops.rs` `get_subscript`).

## Go port (phases 1-3)

- Model: `script.go` (ts-sdk Script chunk semantics), `tx.go` (TS Transaction: an input may carry a txid, an
  attached source, both or neither; missing unlocking script / amount / sequence representable), `sighash.go`
  (formatBip143, DER as TS writes it: S not normalised, Signer / Recipient), `merklepath.go` + `beefsdk.go`
  (ts-sdk MerklePath and Beef ported: go-sdk's map-based Beef loses the order b017's checks and bytes depend on),
  `spend.go` (TS Spend on go-sdk's interpreter: v>1 after-Chronicle with no policy flags; v1 pre-Genesis with
  SIGPUSHONLY/CLEANSTACK/MINIMALDATA/LOW_S/NULLDUMMY/STRICTENC/DERSIG, plus BIP16 because go-sdk refuses CLEANSTACK
  without it).
- b017: `boltlib.go`, `fingerprints.go`, `beef.go`, `pay2proof.go`, `singleancestor.go`, `singlespend.go`,
  `nfttemplates.go`, `verifyevents.go`; `suffixes_gen.go` from `vectors/gen/embed.mjs`.
- Replay (`go test ./...`): verifyTx 379/379; toAtomicBeef 46/46 byte-equal; fromBeef 63/63 (graph node ids
  equal); lock.* all; sign.MinSimple 82, sign.AuthBolt 142, sign.Pay2Proof 56, sign.p2pkhUnlock 132 byte-equal;
  verifyEvents 260/261, verifyEvent 101/102, verifyAndBroadcast 76/76 field for field (the 2 not run hand the
  scanner a non-array batch, which Go's `[]any` cannot express). Reasons: all exact except 44 whose tail is an
  SDK's error text (script engine, hex parse), which match on b017's prefix.
- Recorded callbacks (isKnownBlockRoot, chainTracker, broadcaster) are replayed from the recorded answers; a
  question the reference never asked is a test failure.

- Phase 4 (Go): `simplemulti.go`, `multiboltlib.go`, `multibolt.go` (the class; `TokenType` constants are
  `TokenMinSimpleBOLT` etc. so the class keeps the reference's name), `txbuild.go` (ts-sdk `fee(0)` and `sign()`:
  change split equally, dropped at 0; every input signs a snapshot of the unsigned tx). lock.SimpleMulti 136 and
  sign.SimpleMulti 141 byte-equal; `vectors/flows.json` (`vectors/gen/flows.test.ts`: the scenarios of b017's
  test/tokens/MultiBOLT.test.ts with fixed keys instead of BRC-42 derivation: lifecycle, merge-melt,
  builder-branches, funding-source, second-piece, inflated-balance) reproduced tx for tx, prevTxs and balances
  included; the inflated-balance scenario fails in both on the covenant.

## Next

The Rust port of phases 1-4 (`rust/`, on the patched bsv-sdk), then Phase 5.
