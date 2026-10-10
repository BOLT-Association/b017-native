package authbolt

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	b017 "github.com/BOLT-Association/b017-native/go"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func key(n int) b017.KeySigner {
	k, err := ec.PrivateKeyFromHex(fmt.Sprintf("%064x", n))
	if err != nil {
		panic(err)
	}
	return b017.KeySigner{Key: k}
}

const statement = "PeerLoop-AuthBOLT/1|signin|https://app.lab:8443|nonce|1999999999|"

func authData(tag string, app b017.KeySigner) string {
	h := sha256.Sum256([]byte(statement))
	d := tag + hex.EncodeToString(app.PublicKey()) + hex.EncodeToString(h[:])
	if tag == "01" || tag == "05" || tag == "06" {
		d += "00000001" // register, rotate and reissue carry the holder count
	}
	return d
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func purposeOr(p string) string {
	if p == "" {
		return "register"
	}
	return p
}

// identity mints an AuthBOLT for `owner` and returns the mint (its funding is header-proven).
func identity(t *testing.T, owner b017.KeySigner) *b017.Transaction {
	return identityFrom(t, owner, 1000)
}

// identityFrom mints from a funding output of `sats` (another amount, another mint: a reissue).
func identityFrom(t *testing.T, owner b017.KeySigner, sats uint64) *b017.Transaction {
	pkh := b017.Hash160(owner.PublicKey())
	funding := coin(t, owner, sats)
	mint := &b017.Transaction{Version: 2,
		Inputs: []*b017.Input{{SourceTransaction: funding, SourceOutputIndex: 0, Template: b017.P2PKHUnlock(owner), Sequence: b017.U32(0xffffffff)}},
		Outputs: []*b017.Output{
			{Satoshis: b017.U64(1), LockingScript: b017.AuthBoltTemplate{}.Lock(pkh, owner.PublicKey(), nil, nil, nil, nil)},
			{Satoshis: b017.U64(sats - 1), LockingScript: b017.P2PKHLock(pkh)},
		}}
	if err := b017.SignTx(context.Background(), mint); err != nil {
		t.Fatal(err)
	}
	return mint
}

// coin is a header-proven P2PKH output of `sats` for `owner`.
func coin(t *testing.T, owner b017.KeySigner, sats uint64) *b017.Transaction {
	tx := &b017.Transaction{Version: 1, Inputs: []*b017.Input{}, Outputs: []*b017.Output{{Satoshis: b017.U64(sats), LockingScript: b017.P2PKHLock(b017.Hash160(owner.PublicKey()))}}}
	id, _ := tx.ID()
	// Its own block (height = sats): one BEEF holds several coins, and a block has one merkle root.
	mp, err := b017.NewMerklePath(sats, [][]*b017.Leaf{{{Offset: 0, Hash: id, HasHash: true, Txid: true}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	tx.MerklePath = mp
	return tx
}

// move is identity.js #move from a freshly minted token: a commit carrying `auth` and a settle to `toPkh`. Funded,
// each spends a coin of the owner's and returns change, so both could be broadcast (a registration);
// unfunded, neither can (V1's off-chain presentation).
func move(t *testing.T, mint *b017.Transaction, owner b017.KeySigner, toPkh []byte, auth []byte, funded bool) []string {
	ctx := context.Background()
	pkh := b017.Hash160(owner.PublicKey())
	tpl := b017.AuthBoltTemplate{}
	// fund adds a coin of `sats` (coins of different amounts are different outpoints) and `change`.
	fund := func(tx *b017.Transaction, sats, change uint64) {
		if !funded {
			return
		}
		c := coin(t, owner, sats)
		tx.Inputs = append(tx.Inputs, &b017.Input{SourceTransaction: c, SourceOutputIndex: 0, Template: b017.P2PKHUnlock(owner), Sequence: b017.U32(0xffffffff)})
		tx.Outputs = append(tx.Outputs, &b017.Output{Satoshis: b017.U64(change), LockingScript: b017.P2PKHLock(pkh)})
	}
	unlock, err := tpl.Unlock(owner, toPkh, []*b017.Transaction{}, auth, false, false)
	if err != nil {
		t.Fatal(err)
	}
	mintOut := b017.BuildOutpoint(mint, 0)
	commit := &b017.Transaction{Version: 2,
		Inputs: []*b017.Input{{SourceTransaction: mint, SourceOutputIndex: 0, Template: unlock, Sequence: b017.U32(0xffffffff)}},
		Outputs: []*b017.Output{
			{Satoshis: b017.U64(1), LockingScript: tpl.Lock(pkh, owner.PublicKey(), toPkh, []byte{0x21}, mintOut, make([]byte, 36))},
			{Satoshis: b017.U64(1), LockingScript: b017.Pay2ProofLock(toPkh)},
		}}
	fund(commit, 2000, 1998) // in: token 1 + 2000; out: token 1, proof 1, change; fee 1
	if err := b017.SignTx(ctx, commit); err != nil {
		t.Fatal(err)
	}
	unlock2, _ := tpl.Unlock(owner, toPkh, []*b017.Transaction{mint, commit}, nil, false, false)
	settle := &b017.Transaction{Version: 2,
		Inputs:  []*b017.Input{{SourceTransaction: commit, SourceOutputIndex: 0, Template: unlock2, Sequence: b017.U32(0xffffffff)}},
		Outputs: []*b017.Output{{Satoshis: b017.U64(1), LockingScript: tpl.Lock(toPkh, owner.PublicKey(), make([]byte, 20), []byte{0x00}, b017.BuildOutpoint(commit, 0), mintOut)}}}
	fund(settle, 2001, 2000) // in: token 1 + 2001; out: token 1, change; fee 1
	if err := b017.SignTx(ctx, settle); err != nil {
		t.Fatal(err)
	}
	var pkg []string
	for _, tx := range []*b017.Transaction{commit, settle} {
		b, err := b017.ToAtomicBeef(tx)
		if err != nil {
			t.Fatal(err)
		}
		pkg = append(pkg, hex.EncodeToString(b))
	}
	return pkg
}

func seenBroadcaster(status string) b017.AnchorBroadcaster {
	return func(context.Context, *b017.Transaction) (b017.AnchorBroadcastResult, error) {
		d := "test"
		if status == "rejected" {
			d = "refused by the test"
		}
		return b017.AnchorBroadcastResult{Status: status, Detail: &d}, nil
	}
}

type tcase struct {
	name       string
	Package    []string `json:"package"`
	AppPubKey  string   `json:"appPubKey"`
	Data       string   `json:"data"`
	Broadcast  string   `json:"broadcast"`
	wantOK     bool
	wantWhy    string
	wantPurp   string // purpose of an accepted registration ("" = register)
	wantHolder []byte // the new holder key's hash an accepted registration names
	wantCount  uint32
}

func cases(t *testing.T) []tcase {
	owner, app, other, holder1, holder2 := key(7), key(8), key(9), key(10), key(11)
	h1, h2 := b017.Hash160(holder1.PublicKey()), b017.Hash160(holder2.PublicKey())
	mint := identity(t, owner)
	data := authData("01", app) // register, holder 1
	good := move(t, mint, owner, h1, mustHex(data), true)
	appHex := hex.EncodeToString(app.PublicKey())
	reissue := authData("06", app)[:132] + "00000002"
	other01 := authData("01", app)[:68] + strings.Repeat("ab", 32) + "00000001" // this app, another challenge
	signin, unknownData := authData("02", app), authData("07", app)
	return []tcase{
		{name: "a registration moved on chain to holder 1", Package: good, AppPubKey: appHex, Data: data, Broadcast: "already-seen", wantOK: true, wantHolder: h1, wantCount: 1},
		{name: "data for another challenge", Package: good, AppPubKey: appHex, Data: other01, Broadcast: "already-seen",
			wantWhy: "the presentation carries other data than this challenge"},
		{name: "auth data naming another app", Package: good, AppPubKey: hex.EncodeToString(other.PublicKey()), Data: data, Broadcast: "already-seen",
			wantWhy: "the auth data names another app"},
		{name: "an unfunded move (V1's shape)", Package: move(t, mint, owner, h1, mustHex(data), false), AppPubKey: appHex, Data: data, Broadcast: "already-seen",
			wantWhy: "a registration must be on chain: this move was never funded or broadcast"},
		{name: "a move the network refuses", Package: good, AppPubKey: appHex, Data: data, Broadcast: "rejected"},
		{name: "a malformed app key", Package: good, AppPubKey: "04ab", Data: data, Broadcast: "already-seen",
			wantWhy: "the app key must be a 33-byte compressed public key (hex)"},
		{name: "short auth data", Package: good, AppPubKey: appHex, Data: data[:20], Broadcast: "already-seen",
			wantWhy: "register auth data must be exactly 70 bytes (hex)"},
		{name: "not BEEF", Package: []string{"00", "01"}, AppPubKey: appHex, Data: data, Broadcast: "already-seen"},
		{name: "sign-in data", Package: move(t, mint, owner, h1, mustHex(signin), true), AppPubKey: appHex, Data: signin, Broadcast: "already-seen",
			wantWhy: "signin data does not register an identity"},
		{name: "an unknown purpose tag", Package: good, AppPubKey: appHex, Data: unknownData, Broadcast: "already-seen"},
		{name: "a reissue: a new mint of the same issuer, moved to holder 2", Package: move(t, identityFrom(t, owner, 1500), owner, h2, mustHex(reissue), true),
			AppPubKey: appHex, Data: reissue, Broadcast: "already-seen", wantOK: true, wantPurp: "reissue", wantHolder: h2, wantCount: 2},
	}
}

func TestVerify(t *testing.T) {
	for _, c := range cases(t) {
		t.Run(c.name, func(t *testing.T) {
			v := &Verifier{Broadcast: seenBroadcaster(c.Broadcast)}
			r, err := v.Verify(context.Background(), c.Package, c.AppPubKey, c.Data)
			if err != nil {
				t.Fatal(err)
			}
			if r.OK != c.wantOK {
				t.Fatalf("ok %v (%s), want %v", r.OK, r.Reason, c.wantOK)
			}
			if c.wantWhy != "" && r.Reason != c.wantWhy {
				t.Fatalf("reason %q, want %q", r.Reason, c.wantWhy)
			}
			if c.wantOK {
				if r.Issuer != hex.EncodeToString(key(7).PublicKey()) || r.Purpose != purposeOr(c.wantPurp) || r.Holder != hex.EncodeToString(c.wantHolder) || r.Count != c.wantCount {
					t.Fatalf("result %+v", r)
				}
			}
		})
	}
}

// TestAgreesWithTheSidecar runs the same cases through the reference (packages/bolt verifyIdentity, the code the
// bolt-verify sidecar runs) and requires the same verdict and reason. Skipped when node or packages/bolt is absent.
func TestAgreesWithTheSidecar(t *testing.T) {
	ref, err := filepath.Abs(filepath.Join("..", "..", "vectors", "gen", "authbolt-ref.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not found")
	}
	if _, err := os.Stat("C:/Users/honoh/Code/ChainBrowsers/packages/bolt/src/identity.js"); err != nil {
		t.Skip("packages/bolt not present")
	}
	cs := cases(t)
	b, _ := json.Marshal(cs)
	f := filepath.Join(t.TempDir(), "cases.json")
	if err := os.WriteFile(f, b, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", ref, f)
	cmd.Dir = "C:/Users/honoh/Code/ChainBrowsers/packages/bolt"
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("reference: %v\n%s", err, stderr.String())
	}
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	i := 0
	for sc.Scan() {
		var want Result
		if err := json.Unmarshal(sc.Bytes(), &want); err != nil {
			t.Fatalf("reference line %q: %v", sc.Text(), err)
		}
		c := cs[i]
		v := &Verifier{Broadcast: seenBroadcaster(c.Broadcast)}
		got, _ := v.Verify(context.Background(), c.Package, c.AppPubKey, c.Data)
		if got.OK != want.OK || got.Issuer != want.Issuer || got.Holder != want.Holder || got.TokenID != want.TokenID || got.Purpose != want.Purpose ||
			got.MintTxid != want.MintTxid || got.Count != want.Count {
			t.Errorf("%s: Go %+v, reference %+v", c.name, got, want)
		}
		if got.Reason != want.Reason {
			t.Errorf("%s: reason %q, reference %q", c.name, got.Reason, want.Reason)
		}
		i++
	}
	if i != len(cs) {
		t.Fatalf("reference answered %d of %d cases", i, len(cs))
	}
}

// The mint rule (audit V1 in PeerLoop's security audit): a presentation proves the presenter holds the issuer
// key only when its commit spends the token's own mint, carried in the package (the covenant's genesis guard needs
// the issuer key to spend a mint). A token that has moved since its mint proves no ownership. vectors/authbolt.json
// holds a genuine such presentation, recorded from the reference with its verdict (vectors/gen/authbolt-moved.mjs).
// The rule is checked before the network is asked. NC: drop the IsMint check in mintProvenance; this goes red.
func TestAPresentationMustSpendItsMint(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "vectors", "authbolt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Name      string
			Package   []string
			AppPubKey string
			Data      string
			Reference Result
		}
	}
	if err := json.Unmarshal(b, &f); err != nil || len(f.Cases) == 0 {
		t.Fatalf("vectors/authbolt.json: %v", err)
	}
	for _, c := range f.Cases {
		asked := 0
		v := &Verifier{Broadcast: func(context.Context, *b017.Transaction) (b017.AnchorBroadcastResult, error) {
			asked++
			return b017.AnchorBroadcastResult{Status: "already-seen"}, nil
		}}
		r, err := v.Verify(context.Background(), c.Package, c.AppPubKey, c.Data)
		if err != nil {
			t.Fatal(err)
		}
		if r.OK || r.Reason != c.Reference.Reason {
			t.Errorf("%s: %+v, want the reference's refusal %q", c.Name, r, c.Reference.Reason)
		}
		if asked != 0 {
			t.Errorf("%s: the network was asked %d times before the mint rule refused", c.Name, asked)
		}
	}
	// A genuine registration names the mint it spends.
	cs := cases(t)
	r, _ := (&Verifier{Broadcast: seenBroadcaster("already-seen")}).Verify(context.Background(), cs[0].Package, cs[0].AppPubKey, cs[0].Data)
	mint, _ := identity(t, key(7)).ID()
	if !r.OK || r.MintTxid != mint {
		t.Errorf("a genuine registration: %+v, want mint %s", r, mint)
	}
}
