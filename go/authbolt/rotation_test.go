package authbolt

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	b017 "github.com/BOLT-Association/b017-native/go"
)

// A rotation (the app asks; the current holder moves the token on chain to the next holder) is checked
// against the token's outpoint the app recorded: the commit must spend it (before any network call), and
// the move must be funded and seen. vectors/authbolt-rotation.json holds a genuine rotation recorded from
// the reference (vectors/gen/authbolt-rotation.mjs) with its verdicts, which VerifyAt must give word for
// word. NC: drop the outpoint comparison in spendsOutpoint; the stale-outpoint case goes red.
func TestRotationAgreesWithTheReference(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "vectors", "authbolt-rotation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Name      string
			Package   []string
			AppPubKey string
			Data      string
			Outpoint  string
			Reference Result
		}
	}
	if err := json.Unmarshal(b, &f); err != nil || len(f.Cases) != 3 {
		t.Fatalf("vectors/authbolt-rotation.json: %v (%d cases)", err, len(f.Cases))
	}
	for _, c := range f.Cases {
		asked := 0
		v := &Verifier{Broadcast: func(context.Context, *b017.Transaction) (b017.AnchorBroadcastResult, error) {
			asked++
			return b017.AnchorBroadcastResult{Status: "already-seen"}, nil
		}}
		got, err := v.VerifyAt(context.Background(), c.Package, c.AppPubKey, c.Data, c.Outpoint)
		if err != nil {
			t.Fatal(err)
		}
		want := c.Reference
		if got.OK != want.OK || got.Reason != want.Reason || got.Issuer != want.Issuer || got.Holder != want.Holder ||
			got.Count != want.Count || got.TokenID != want.TokenID || got.Purpose != want.Purpose || got.MintTxid != "" {
			t.Errorf("%s: Go %+v, reference %+v", c.Name, got, want)
		}
		if !want.OK && asked != 0 {
			t.Errorf("%s: the network was asked %d times before the outpoint rule refused", c.Name, asked)
		}
	}
	// Verify (no outpoint) is VerifyAt with none: a rotation always needs one.
	c := f.Cases[0]
	if r, _ := (&Verifier{Broadcast: seenBroadcaster("already-seen")}).Verify(context.Background(), c.Package, c.AppPubKey, c.Data); r.OK {
		t.Errorf("a rotation verified without an outpoint: %+v", r)
	}
}
