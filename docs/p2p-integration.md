# Verifying AuthBOLT for p2pd: boltverifyd

p2pd (ChainBrowsers `p2p/`, F1r3Hydr4nt/p2p branch `inprocess-verifier`) links no token-script code and stays
standard-library only. It asks a loopback verifier service, and the default one is **boltverifyd**: p2p's nested Go
module `p2p/boltverifyd`, built on this repo's `github.com/BOLT-Association/b017-native/go/authbolt`. The Node
sidecar `bolt-verify` (packages/bolt) is the alternative. (On 2026-10-09 p2p first used this package in process,
`dac8d3b`; it then moved into boltverifyd so p2pd keeps zero dependencies.)

What boltverifyd takes from this package:

- `Verifier.Verify(ctx, pkg []string, appKey, data string) (Result, error)`, with `Result` fields
  `OK, Reason, Issuer, Holder, TokenID, Purpose`.
- `HeadersOf(x)` for anything with `RootActive(height uint32, root string) bool`: boltverifyd answers it by asking
  p2pd's own verified header chain over loopback (`-headers-url`, p2pd's `-internal-addr`); only an active root counts.
- `Arcade{URL, Headers}.Broadcaster()`: an anchor proven into those headers is "already seen" without asking Arcade;
  otherwise Arcade's status (GET `/tx/{txid}`), else a submission in Extended Format and a wait for a network status
  (20 s).

boltverifyd pins this module at `448de4a` (tag 04, purpose "write") and carries its own copy of the mint rule below;
bumping it to `e5348fe` would let it drop that copy. Do not pin go-sdk v1.7.1 there: it reads script numbers wider
than 64 bits by their low 64 bits (GHSA-rh54-8fpg-8wwf).

Verified here: `go test ./authbolt/` builds real presentations (mint, commit carrying the auth data, settle to the same
key) and runs them, and seven refusals, through this package; `TestAgreesWithTheSidecar` runs the same packages
through packages/bolt `verifyIdentity` (the sidecar's code) and requires the same verdict and reason for every case.
In p2p, `p2p/testdata/contract/verify/recorded.json` holds real presentations and the sidecar's answers, and
`boltverifyd/contract_test.go` holds boltverifyd to every one. Live: ChainBrowsers `tests/authbolt/peerloop.live.mjs`
starts boltverifyd by default (`VERIFIER=sidecar` for the sidecar); its negative control (`NC_NO_VERIFIER=1`) cuts
the verifier off from Arcade and from p2pd's headers and must fail at registration.

## The mint rule (2026-10-09)

`Verify` refuses a presentation unless its commit (the transaction whose first input carries the auth data)
spends a mint the package carries. A mint transaction alone does not show its sender holds the issuer key, and a
token moved since its mint proves no ownership; a commit + settle presentation that spends the mint does, because
spending a mint needs the issuer key (the covenant's genesis guard), which the full verify then executes. The check
runs before any network call; an accepted verdict names `mintTxid` and `holderPubKey` (the key that signed the
commit). It matches the reference (`packages/bolt` `verifyIdentity`) and p2p's boltverifyd. Test:
`TestAPresentationMustSpendItsMint` on `vectors/authbolt.json` (a genuine presentation of a token rotated on chain,
recorded by `vectors/gen/authbolt-moved.mjs`); negative control: drop the `IsMint` check and it is accepted.

## Registration on chain (2026-10-10)

ChainBrowsers `docs/authbolt-onchain-holder-keys.md`: registration moves the token from its mint to the
identity's first holder key in a funded commit and settle the network has seen. `Verify` therefore takes only
register (01) and reissue (06) data (70 bytes, with the holder count), refuses V1's unfunded shape ("a
registration must be on chain: this move was never funded or broadcast"), drops the self-transfer rule, and its
`Result` gives `Holder` = the new holder key's hash and `Count`; `HolderPubKey` is no longer set (the key comes
with the holder's first signature). The mint rule stays. Tests build funded moves (`move` in authbolt_test.go);
`TestAgreesWithTheSidecar` holds Go to packages/bolt's `verifyIdentity` on every case; `vectors/authbolt.json`
is re-recorded (register data presented from a token already moved to holder 1).

## What p2p asks of this package next

p2p keeps p2pd standard-library only by running this package in boltverifyd, a separate loopback-only verifier
process (`docs/claude-memory/plans/peerloop-holder-signatures.md` in p2p), and asks here for:

- ~~the data check before `VerifyAndBroadcast`~~: done by the mint rule (a package with no commit carrying the
  data is refused before any network call);
- dropping the `transaction` import in `spend.go` (it pulls in go-sdk's chaintracker and go-whatsonchain) if the
  interpreter can be fed without it;
- tagged releases instead of pseudo-versions.

A security audit of the whole AuthBOLT path comes first; the sidecar is kept until it decides.
