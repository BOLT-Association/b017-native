# b017-native: progress log

Plan: `C:/Users/honoh/.claude/plans/https-claude-ai-artifact-6nautc1rbkcsv9a-sequential-whisper.md`.
Reference: `../b017` (branch `async-signer`, commit `a305f58`, public), read-only. Its `@bsv/sdk` is 2.8.11.

## Status (2026-10-09)

| Phase | State |
|---|---|
| 0 vectors + Rust SDK fix | done: vectors recorded from the reference; Rust SDK fixed in `third_party/patches` (7 patches) |
| 1 primitives | done, Go and Rust |
| 2 NFT path | done, Go and Rust |
| 3 scanner | done, Go and Rust |
| 4 fungible | done, Go and Rust |
| 5 hardening + p2p adapter | done: differential fuzzing, negative controls, coverage (accepted below the plan's 99%, see Coverage), Go AuthBOLT verifier, p2p adapter (`docs/p2p-integration.md`; p2p runs it in boltverifyd), CI |

`go test ./...` (in `go/`) and `cargo test -p b017` pass against every vector file; `go vet`, `gofmt`,
`cargo fmt --check` and `cargo clippy -D warnings` are clean.

## Vectors

All generated from the TS reference by `vectors/gen/*` (run from `../b017` with vitest; commands in each file's
header). Both ports replay every file.

| File | What | Count |
|---|---|---|
| `calls/*.json` + `nodes.json` | every call b017's own suite (629 tests) makes to the ported entry points, recorded by `record.setup.ts`, packed by `pack.mjs` | verifyEvents 261, verifyEvent 102, verifyAndBroadcast 76, verifyTx 379, fromBeef 63, toAtomicBeef 46, lock.* 327, sign.* 553; 913 tx nodes |
| `static.json` | suffix hex, REGISTRY, piece names, constants (also embedded as `*_gen.go` / `*_gen.rs`) | |
| `flows.json` | SimpleMultiBOLT scenarios with fixed keys: 5 succeed, 5 must fail (inflated balance, wrong keys, bad merge/split/melt) | 10 |
| `sdk.json` | ts-sdk behaviour b017 relies on: merkle paths, scripts, tx EF and preimages, BEEF / Atomic BEEF, fees, 759 corrupt inputs | |
| `edges.json` | edge inputs the suite does not reach: indexes, absent fields, crafted CTX pushes, splitCtx lengths, every ancestor piece of every tx shape, template sign() on crafted spends | 2257 |
| `fuzz.json` | differential corpus: batches the reference accepted, one seeded mutation each, with its verdict | 600 |
| `interp.json` | random unlock/lock pairs through ts-sdk `Spend` (v1 and v2) | 20000 |
| `fuzz-regressions.json`, `interp-regressions.json` | every case a port or SDK once got wrong | 2, 12 |

Regenerate the recorded calls (from `../b017`):
```
B017_VECTORS_OUT=C:/Users/honoh/Code/ChainBrowsers/b017-native/vectors/raw/calls.jsonl \
  node node_modules/vitest/vitest.mjs run --config C:/Users/honoh/Code/ChainBrowsers/b017-native/vectors/gen/vitest.record.config.mjs
node node_modules/vitest/vitest.mjs run --config C:/Users/honoh/Code/ChainBrowsers/b017-native/vectors/gen/vitest.static.config.mjs
cd ../b017-native && node vectors/gen/pack.mjs
```

## Results

- Recorded calls: verifyTx 379/379; toAtomicBeef 46/46 byte-equal; fromBeef 63/63; every lock.* and sign.* byte-equal;
  scanner 437/439 records field for field (the 2 skipped hand the scanner a non-array batch, which a typed slice
  cannot express).
- Flows: every tx, prevTxs and balance equal; the 5 failing scenarios fail with the reference's error.
- SDK and corruption vectors: 750/759 corrupt-input errors with the exact text, the rest on b017's prefix (see Decisions).
- Edges: 2257/2257.
- Differential (TS / Go / Rust):
  - scanner corpora 600 (committed) + seeds 7, 11, 23, 37 (2500 each) + 41 (4000);
  - interpreter corpora 20000 (committed) + seeds 6, 7 (30000 each);
  - `vectors/gen/differential.sh 600`: an unbroken 10-minute run, seeds 103-111, 13500 scanner and 180000
    interpreter cases, no disagreement.
- Native fuzzing: Go `FuzzScript`, `FuzzTransaction`, `FuzzFromBeef`, `FuzzVerifyEvents` about 5.4M executions, no
  panic; Rust seeded random fuzz (`tests/fuzz_random.rs`) 300k iterations, no panic.
- AuthBOLT: `go/authbolt` agrees with the JS sidecar (`packages/bolt` `verifyIdentity`) on all 8 cases
  (`TestAgreesWithTheSidecar`, reference outputs from `vectors/gen/authbolt-ref.mjs`), including `mintTxid` and
  `holderPubKey`. The mint rule (2026-10-09, `docs/p2p-integration.md`): a presentation must spend its token's own
  mint; `vectors/authbolt.json` is the recorded refusal of a token moved since its mint.

## Negative controls (plan, Verification)

1. **Byte flips refused alike:** the scanner corpora are seeded mutations (byte flips in unlocks, locks, amounts,
   outpoints, merkle paths, BEEF); TS, Go and Rust refuse the same ones with the same reason (e.g. seed 41: 2844 of
   4000 refused by all three).
2. **Unpatched Rust SDK:** with `bsv-sdk` at the unpatched base, 256 verifyTx replays fail (the first token spend
   fails on the CHECKSIG subscript); with the patches, all pass.
3. **Unpatched go-sdk (v1.7.1):** the b017 vectors still pass (b017's own scripts never hit the bug), but 5 of the
   12 interpreter regressions fail (wide shift/split/multisig counts); with go-sdk master 511b58c all pass.
4. Not run, by instruction: `go test` in p2p and the PeerLoop live test (another agent works in `p2p/`).

## SDK bugs found (all made to agree with ts-sdk)

- Rust `bsv-sdk` 0.8.1 (`third_party/patches`, PR https://github.com/b1narydt/bsv-rust-sdk/pull/57):
  1. CHECKSIG in the unlocking script hashed only the lock (every b017 spend failed);
  2. OP_2MUL / OP_2DIV disabled;
  3. undefined opcodes above OP_NOP10 ran as NOPs (+ test);
  5. shifts tried 39 GB allocations, splice operands panicked, truncated pushes passed, an IF left open across
     unlock/lock, alt stack not cleared;
  6. PICK/ROLL/SPLIT/NUM2BIN operands wider than an i64 read as 0, OP_VER encoding, signature/pubkey encoding,
     minimal pushes under the v1 policy;
  7. CHECKMULTISIG counts wrapped; key limit 20 instead of INT_MAX.
- go-sdk v1.7.1: script numbers wider than 64 bits read by their low 64 bits (a wide OP_SPLIT position
  panicked). Already fixed on go-sdk master (GHSA-rh54-8fpg-8wwf), unreleased; `go/go.mod` pins master 511b58c.

## Coverage

The plan asked for b017's floor (99% statements). Measured and accepted as enough (user, 2026-10-09):

- Go (`go test -coverprofile`, then `node tools/cover.mjs`, which counts statements the way the reference's v8
  coverage does: Go's explicit `if err != nil { return …, err }` propagation is not counted, as TS has no
  statement there):
  - files that port b017: 96.9%;
  - files that port ts-sdk: 89.5%;
  - `authbolt`: 87.7%;
  - raw `go test -cover`: 91.0% core, 85.9% authbolt.
- Rust (`cargo llvm-cov`): 94.1% of lines.
- The reference itself is at 99.71% statements / 98.13% branches. Some of its uncovered lines are also uncovered in
  the ports, because they are dead in both languages: the `!valid` throws, since ts-sdk's `Spend.validate` throws
  rather than returning false. Most of the remaining Go residual is defensive: recover() guards at entry points,
  and the re-checks TS marks `v8 ignore`.

## Decisions

- **Tx node format** (`vectors/gen/ser.ts`): `{v, lt, ins:[{txid, vout, seq, us, src}], outs:[{sat, ls}], mp}`,
  nulls for absent fields; `src` is another node id; node id = first 32 hex of sha256(JSON). It carries what hex
  cannot (an attached source without a txid, a missing unlocking script, a source that is not the outpoint's tx).
- **Reasons:** text b017 writes itself must match exactly. Where a reason ends in an SDK's own error text
  (`script execution failed: tx … input …: `, `unverifiable input: `, `malformed transaction hex: `,
  `invalid BEEF: `, `its merkle path does not prove it (`), only b017's prefix is compared. A JS engine TypeError
  only requires that the port errors too.
- **Spend:** TS `Spend` without flags runs after-Chronicle rules for every version; version 1 adds the malleability
  policy (SIGPUSHONLY, CLEANSTACK, MINIMALDATA, LOW_S, NULLDUMMY); strict DER and pubkey encoding always.
- **Model:** each port has its own TS-shaped Script (lazy chunks, raw bytes kept until changed) and Transaction
  (optional txid / source / sequence / amount); ts-sdk MerklePath and Beef are ported (go-sdk's map-based Beef
  loses order). `fee(0)` / `sign()` builder behaviour emulated (`txbuild`).
- **Rust:** transactions are `Rc<RefCell<Transaction>>`; the Signer returns boxed futures, driven by `block_on`;
  nothing panics on input.
- **Names:** Go type constants `TypeMinSimple`, `TypeAuth`, `TypeSimpleMulti`; Rust `TokenType::SimpleMultiBOLT`;
  the class keeps the reference's name `SimpleMultiBOLT`. OP_2MUL / OP_2DIV are implemented as named.
- **Random keys:** a few reference tests use random keys, so CI re-records and replays rather than diffing files.

## Published (at the user's request, 2026-10-08)

1. This repo: https://github.com/BOLT-Association/b017-native (public). Pushed; CI (go, rust,
   vectors re-recorded from b017 and replayed) is green.
2. Rust SDK fork https://github.com/BOLT-Association/bsv-rust-sdk, branch `spend-ts-sdk-parity`
   (= `third_party/patches`); upstream PR https://github.com/b1narydt/bsv-rust-sdk/pull/57.
3. go-sdk: no fork or PR needed (fixed upstream).

Left for the user: an issue on `bsv-blockchain/rs-sdk` (its interpreter has the same CHECKSIG subscript bug);
Hodos use of the crate. (p2p uses the Go verifier in boltverifyd, see `docs/p2p-integration.md`.)
