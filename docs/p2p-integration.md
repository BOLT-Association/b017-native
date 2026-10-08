# Verifying AuthBOLT in p2pd, in process

Today p2pd (ChainBrowsers `p2p/`) asks the Node sidecar `bolt-verify` (packages/bolt) over HTTP. The Go package
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

## The change in p2p (not applied: another session works in p2p/)

1. `p2p/go.mod`: depend on the module. Until BOLT-Association/b017-native is pushed, a replace to the local clone:

```
require github.com/BOLT-Association/b017-native/go v0.0.0
replace github.com/BOLT-Association/b017-native/go => ../b017-native/go
replace github.com/bsv-blockchain/go-sdk => ../b017-native/third_party/go-sdk
```

   This is p2pd's first dependency (it pulls in go-sdk). `go mod tidy` writes the `go.sum`. The second replace
   is needed because Go does not pass replace directives on to dependents: without it p2pd would build b017 on
   unpatched go-sdk v1.7.1, which reads shift and multisig counts wider than 64 bits wrongly
   (`third_party/go-sdk-patches/0001`). Run `sh b017-native/third_party/setup.sh` first. Drop the line once the
   fix is in a go-sdk release and b017-native requires that release.

2. `p2p/internal/authbolt/inprocess.go` (new):

```go
package authbolt

import (
	"context"

	native "github.com/BOLT-Association/b017-native/go/authbolt"
)

// InProcess verifies presentations in this process (the Go b017 port) instead of asking the sidecar.
type InProcess struct{ V *native.Verifier }

func (p InProcess) Verify(ctx context.Context, pkg []string, appKey, data string) (Result, error) {
	r, err := p.V.Verify(ctx, pkg, appKey, data)
	return Result(r), err
}
```

3. `p2p/cmd/p2pd/accounts.go`: `headerChain()` returns the `*headers.Chain` it builds (it is local today), and the
   verifier is chosen by flag:

```go
	chain, err := c.headerChain() // now returns (*headers.Chain, error)
	if err != nil {
		return nil, err
	}
	var verifier authbolt.Verifier = &authbolt.Client{URL: c.boltVerifyURL, Secret: c.boltSecret}
	if c.boltVerifyURL == "inprocess" {
		h := native.HeadersOf(chain)
		verifier = authbolt.InProcess{V: &native.Verifier{
			Broadcast: native.Arcade{URL: c.arcadeURL, Headers: h}.Broadcaster(),
			Headers:   h,
		}}
	}
	acc.Verifier = verifier
```

   with a new flag `-arcade-url` (default `http://localhost:8080`, Arcade's API; `-chaintracks-url` is its headers
   port) and `checkAuthBOLT` accepting `-bolt-verify-url inprocess` without a secret file. The loopback root listener
   (`-internal-addr`) is only needed by the sidecar and can stay for it.

4. `tests/authbolt/peerloop.live.mjs`: with `-bolt-verify-url inprocess -arcade-url http://localhost:8080` the
   `start('bolt-verify', …)` step goes. The negative control (`NC_NO_VERIFIER=1`) becomes
   `-arcade-url http://127.0.0.1:1`: the anchor cannot be shown to the network, so registration must fail.

Not run here: the PeerLoop live test (it needs p2pd rebuilt with the change above).
