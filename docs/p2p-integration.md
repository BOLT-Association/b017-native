# Verifying AuthBOLT in p2pd, in process

p2pd (ChainBrowsers `p2p/`) verifies presentations in process with this package by default; the Node sidecar
`bolt-verify` (packages/bolt) stays selectable with `-bolt-verify-url`. The Go package
`github.com/BOLT-Association/b017-native/go/authbolt` is the same check in Go, on the Go b017 port:

- `Verifier.Verify(ctx, pkg []string, appKey, data string) (Result, error)` is p2p's `authbolt.Verifier` method, and
  `Result` has exactly p2p's fields (`OK, Reason, Issuer, Holder, TokenID, Purpose`), so a plain struct conversion
  adapts it.
- `HeadersOf(chain)` takes anything with `RootActive(height uint32, root string) bool`, which p2p's
  `*headers.Chain` has: roots are judged against p2pd's own verified chain, as the sidecar's `headersTracker` does
  over the loopback port today (only an active root counts).
- `Arcade{URL, Headers}.Broadcaster()` is the sidecar's `arcadeBroadcaster`: an anchor proven into p2pd's headers is
  "already seen" without asking Arcade; otherwise Arcade's status (GET `/tx/{txid}`), else a submission in Extended
  Format and a wait for a network status (20 s).

Verified here: `go test ./authbolt/` builds real presentations (mint, commit carrying the auth data, settle to the same
key) and runs them, and seven refusals, through this package; `TestAgreesWithTheSidecar` runs the same packages
through packages/bolt `verifyIdentity` (the sidecar's code) and requires the same verdict and reason for every case.

## How p2p uses it (applied 2026-10-09)

p2p branch `inprocess-verifier` (F1r3Hydr4nt/p2p): `dac8d3b` (in process), `5346205` (bumped to `448de4a`, tag 04).

1. **`go.mod`** requires `github.com/BOLT-Association/b017-native/go` at `448de4a`. It is p2pd's first dependency
   (go-sdk at master 511b58c, go-whatsonchain, pkg/errors, x/crypto come with it). Do not pin go-sdk v1.7.1 in p2p:
   v1.7.1 reads script numbers wider than 64 bits by their low 64 bits (GHSA-rh54-8fpg-8wwf). p2p's `labctl check`
   replaces its zero-deps gate with `allowed-deps`, an allowlist of exactly these modules (tests included).
2. **`internal/authbolt/inprocess.go`**: `InProcess{V *native.Verifier}`, whose `Verify` converts `Result` directly.
3. **`cmd/p2pd/accounts.go`**: in process is the default. `headerChain()` returns p2pd's `*headers.Chain`; roots go
   through `native.HeadersOf(chain)`, anchors through `native.Arcade{URL: -arcade-url, Headers}.Broadcaster()`.
   With `-bolt-verify-url` (plus `-bolt-secret-file`) p2pd asks the sidecar instead and only then opens the loopback
   root listener (`-internal-addr`). Each mode refuses the other's flags.
4. **Contract test**: `p2p/testdata/contract/verify/recorded.json` holds real presentations and the sidecar's answers
   (recorded by packages/bolt `scripts/record-verify-contract.mjs`). `internal/authbolt/inprocess_test.go` holds this
   package to every verdict and reason, the write (tag 04) included since `448de4a`.
5. **Live**: `tests/authbolt/peerloop.live.mjs` (ChainBrowsers) passes with p2pd in process: registration, sign-in,
   keep-alive, a signed write and refusals, in Hodos on the regtest stack. Its negative control
   (`NC_NO_VERIFIER=1`) cuts p2pd off from Arcade and chaintracks and fails at registration. `VERIFIER=sidecar`
   runs the same test through the sidecar.

## What p2p asks of this package next

p2p's plan (`docs/claude-memory/plans/peerloop-holder-signatures.md`) wants to keep p2pd standard-library only by
moving this package into a separate loopback-only verifier process, and asks here for:

- the data check (auth data in the commit's unlocking script) before `VerifyAndBroadcast`, so a package carrying
  the wrong data makes no network call;
- dropping the `transaction` import in `spend.go` (it pulls in go-sdk's chaintracker and go-whatsonchain) if the
  interpreter can be fed without it;
- tagged releases instead of pseudo-versions.

A security audit of the whole AuthBOLT path comes first; the sidecar is kept until it decides.
