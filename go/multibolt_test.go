package b017

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func (a arg) txOrNil(g *graph) *Transaction {
	if a.T == "tx" {
		return g.tx(a.ID)
	}
	return nil
}

func TestVectorsLockSimpleMulti(t *testing.T) {
	for i, rec := range loadCalls(t, "lock.SimpleMulti") {
		g := newGraph(t)
		var args []arg
		_ = json.Unmarshal(rec["args"], &args)
		la := SMBLockArgs{Balance: argAt(args, 2).bytes(t), BalanceCommit: argAt(args, 3).bytes(t), PubKeyHashCommit: argAt(args, 4).bytes(t),
			PubKeyHashCommit2: argAt(args, 5).bytes(t), OtherGrandparentOutpoint: argAt(args, 6).bytes(t), TxoType: argAt(args, 7).bytes(t),
			OutputIndexN: argAt(args, 8).bytes(t)}
		if a := argAt(args, 9); a.T == "json" {
			la.PrevVoutIdx = int(a.number())
		}
		s, err := SimpleMultiTemplate{}.Lock(argAt(args, 0).bytes(t), argAt(args, 1).txList(t, g), la)
		if _, threw := rec["throws"]; threw {
			if err == nil {
				t.Errorf("%s: TS threw, Go succeeded", label(rec, i))
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", label(rec, i), err)
			continue
		}
		if got := s.ToHex(); got != str(rec["result"]) {
			t.Errorf("%s: lock differs", label(rec, i))
		}
	}
}

func init() {
	signBuilders["sign.SimpleMulti"] = func(t *testing.T, g *graph, method string, args []arg) (UnlockTemplate, error) {
		if method == "melt" {
			var sats *uint64
			if a := argAt(args, 1); a.T == "json" {
				sats = U64(a.number())
			}
			var lock *Script
			if a := argAt(args, 2); a.T == "script" {
				lock = MustScriptFromHex(a.Hex)
			}
			return SimpleMultiTemplate{}.Melt(args[0].signer(t), sats, lock), nil
		}
		ua := SMBUnlockArgs{ForceNoChange: argAt(args, 3).boolean(), ForceNoFund: argAt(args, 4).boolean(),
			NextBalanceCommit: argAt(args, 5).bytes(t), NextTxoType: argAt(args, 6).bytes(t), InputIndexN: argAt(args, 7).bytes(t),
			PubKeyHash2: argAt(args, 8).bytes(t), GrandparentBoltVoutIdx: argAt(args, 9).bytes(t), InteropBoltVoutIdx: argAt(args, 10).bytes(t),
			InteropPubKeyHash: argAt(args, 11).bytes(t), InteropOutpoint: argAt(args, 12).bytes(t), InteropParentOutpoint: argAt(args, 13).bytes(t),
			AncestorTxBRef: argAt(args, 14).txOrNil(g)}
		return SimpleMultiTemplate{}.Unlock(args[0].signer(t), argAt(args, 1).bytes(t), argAt(args, 2).txList(t, g), ua), nil
	}
}

// ---- SimpleMultiBOLT class flows (vectors/flows.json) ----

type flowStep struct {
	Step    string   `json:"step"`
	Tx      *string  `json:"tx"`
	PrevTxs []string `json:"prevTxs"`
	Balance string   `json:"balance"`
	Error   string   `json:"error"`
}

func fkey(n int) KeySigner {
	k, err := ec.PrivateKeyFromHex(fmt.Sprintf("%064x", n))
	if err != nil {
		panic(err)
	}
	return KeySigner{Key: k}
}

func bal(n *big.Int) []byte { return bigToBalance(n) }

func freshSource(k KeySigner) *Transaction {
	return &Transaction{Version: 1, Outputs: []*Output{{Satoshis: U64(1000), LockingScript: P2PKHLock(Hash160(k.PublicKey()))}}}
}

func snapOf(step string, b *SimpleMultiBOLT) flowStep {
	s := flowStep{Step: step, Balance: hex.EncodeToString(b.Balance)}
	if b.Tx != nil {
		h, _ := b.Tx.ToHex()
		s.Tx = &h
	}
	for _, p := range b.PrevTxs {
		h, _ := p.ToHex()
		s.PrevTxs = append(s.PrevTxs, h)
	}
	return s
}

var flowScenarios = map[string]func(ctx context.Context, log func(flowStep)) error{
	"lifecycle": func(ctx context.Context, log func(flowStep)) error {
		issuer := fkey(1)
		sim, _ := new(big.Int).SetString("1ffffffffffffe", 16)
		t, err := NewSimpleMultiBOLT().Mint(ctx, issuer, freshSource(issuer), bal(sim))
		if err != nil {
			return err
		}
		log(snapOf("mint", t))
		if _, err = t.Transfer(ctx, fkey(101), false, TransferOpts{}); err != nil {
			return err
		}
		log(snapOf("transfer1", t))
		if _, err = t.Transfer(ctx, fkey(102), false, TransferOpts{}); err != nil {
			return err
		}
		log(snapOf("transfer2", t))
		main, piece, err := t.Split(ctx, fkey(110), fkey(111), bal(big.NewInt(1)), nil)
		if err != nil {
			return err
		}
		log(snapOf("split.main", main))
		log(snapOf("split.piece", piece))
		return nil
	},
	"merge-melt": func(ctx context.Context, log func(flowStep)) error {
		issuer := fkey(1)
		sim, _ := new(big.Int).SetString("1ffffffffffffe", 16)
		a, err := NewSimpleMultiBOLT().Mint(ctx, issuer, freshSource(issuer), bal(sim))
		if err != nil {
			return err
		}
		b, err := NewSimpleMultiBOLT().Mint(ctx, issuer, freshSource(issuer), bal(big.NewInt(1)))
		if err != nil {
			return err
		}
		log(snapOf("mintA", a))
		log(snapOf("mintB", b))
		if _, err = a.Transfer(ctx, fkey(101), false, TransferOpts{}); err != nil {
			return err
		}
		if _, err = b.Transfer(ctx, fkey(102), false, TransferOpts{}); err != nil {
			return err
		}
		log(snapOf("transferA", a))
		log(snapOf("transferB", b))
		merged, err := a.Merge(ctx, b, fkey(400), nil)
		if err != nil {
			return err
		}
		log(snapOf("merge", merged))
		log(snapOf("merge.other", b))
		melted, err := merged.Melt(ctx, nil)
		if err != nil {
			return err
		}
		log(snapOf("melt", melted))
		return nil
	},
	"builder-branches": func(ctx context.Context, log func(flowStep)) error {
		issuer := fkey(1)
		sim, _ := new(big.Int).SetString("1ffffffffffffe", 16)
		a, err := NewSimpleMultiBOLT().Mint(ctx, issuer, freshSource(issuer), bal(sim))
		if err != nil {
			return err
		}
		a.SkipVerify = true
		if _, err = a.Transfer(ctx, fkey(901), false, TransferOpts{ForceNoChange: true, ForceNoFund: true}); err != nil {
			return err
		}
		log(snapOf("noChange.noFund", a))
		b, err := NewSimpleMultiBOLT().Mint(ctx, issuer, freshSource(issuer), bal(sim))
		if err != nil {
			return err
		}
		b.SkipVerify = true
		ov := &Input{SourceTransaction: freshSource(issuer), SourceOutputIndex: 0, Template: P2PKHUnlock(issuer), Sequence: U32(0xffffffff)}
		if _, err = b.Transfer(ctx, fkey(902), false, TransferOpts{FundOverride: ov}); err != nil {
			return err
		}
		log(snapOf("fundOverride", b))
		c, err := NewSimpleMultiBOLT().Mint(ctx, issuer, freshSource(issuer), bal(sim))
		if err != nil {
			return err
		}
		if _, err = c.Melt(ctx, Hash160(fkey(901).PublicKey())); err != nil {
			return err
		}
		log(snapOf("melt.pkh", c))
		return nil
	},
	"funding-source": func(ctx context.Context, log func(flowStep)) error {
		issuer := fkey(1)
		sim, _ := new(big.Int).SetString("1ffffffffffffe", 16)
		zero := 0
		fsrc := func() *FundingSource { return &FundingSource{Tx: freshSource(issuer), Vout: &zero, Key: issuer} }
		t, err := NewSimpleMultiBOLT().Mint(ctx, issuer, freshSource(issuer), bal(sim))
		if err != nil {
			return err
		}
		if _, err = t.Transfer(ctx, fkey(101), false, TransferOpts{}); err != nil {
			return err
		}
		main, piece, err := t.Split(ctx, fkey(110), fkey(111), bal(big.NewInt(1)), fsrc())
		if err != nil {
			return err
		}
		log(snapOf("split.main", main))
		log(snapOf("split.piece", piece))
		a, err := NewSimpleMultiBOLT().Mint(ctx, issuer, freshSource(issuer), bal(sim))
		if err != nil {
			return err
		}
		b, err := NewSimpleMultiBOLT().Mint(ctx, issuer, freshSource(issuer), bal(big.NewInt(1)))
		if err != nil {
			return err
		}
		if _, err = a.Transfer(ctx, fkey(101), false, TransferOpts{}); err != nil {
			return err
		}
		if _, err = b.Transfer(ctx, fkey(102), false, TransferOpts{}); err != nil {
			return err
		}
		merged, err := a.Merge(ctx, b, fkey(400), fsrc())
		if err != nil {
			return err
		}
		log(snapOf("merge", merged))
		return nil
	},
	"second-piece": func(ctx context.Context, log func(flowStep)) error {
		issuer := fkey(1)
		kA, kB := fkey(110), fkey(111)
		zero := 0
		t, err := NewSimpleMultiBOLT().Mint(ctx, issuer, freshSource(issuer), bal(big.NewInt(1000)))
		if err != nil {
			return err
		}
		if _, err = t.Transfer(ctx, fkey(101), false, TransferOpts{}); err != nil {
			return err
		}
		_, pieceB, err := t.Split(ctx, kA, kB, bal(big.NewInt(300)), nil)
		if err != nil {
			return err
		}
		cp := *pieceB
		pieceB2 := &cp
		pieceB2.PrevTxs = append([]*Transaction{}, pieceB.PrevTxs...)
		fund := &Input{SourceTransaction: freshSource(kB), SourceOutputIndex: 0, Template: P2PKHUnlock(kB), Sequence: U32(0xffffffff)}
		if _, err = pieceB.Commit(ctx, fkey(120), TransferOpts{FundOverride: fund}); err != nil {
			return err
		}
		log(snapOf("pieceB.commit", pieceB))
		if _, err = pieceB.Settle(ctx, fkey(120), TransferOpts{}); err != nil {
			return err
		}
		log(snapOf("pieceB.settle", pieceB))
		b1, b2, err := pieceB2.Split(ctx, fkey(130), fkey(131), bal(big.NewInt(100)), &FundingSource{Tx: freshSource(kB), Vout: &zero, Key: kB})
		if err != nil {
			return err
		}
		log(snapOf("pieceB2.split.main", b1))
		log(snapOf("pieceB2.split.piece", b2))
		return nil
	},
	"inflated-balance": func(ctx context.Context, log func(flowStep)) error {
		issuer := fkey(1)
		t, err := NewSimpleMultiBOLT().Mint(ctx, issuer, freshSource(issuer), bal(big.NewInt(1000)))
		if err != nil {
			return err
		}
		t.Balance = bal(big.NewInt(1001))
		log(snapOf("mint", t))
		if _, err = t.Transfer(ctx, fkey(101), false, TransferOpts{}); err != nil {
			return err
		}
		log(snapOf("transfer", t))
		return nil
	},
}

func TestVectorsFlows(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(vectorsDir(), "flows.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want map[string][]flowStep
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	for name, steps := range want {
		run, ok := flowScenarios[name]
		if !ok {
			t.Errorf("no Go scenario for %s", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			var got []flowStep
			if err := run(context.Background(), func(s flowStep) { got = append(got, s) }); err != nil {
				got = append(got, flowStep{Step: "error", Error: err.Error()})
			}
			if len(got) != len(steps) {
				t.Fatalf("%d steps, want %d (last: %+v)", len(got), len(steps), got[len(got)-1].Error)
			}
			for i, w := range steps {
				g := got[i]
				if g.Step != w.Step {
					t.Fatalf("step %d is %s, want %s", i, g.Step, w.Step)
				}
				if w.Step == "error" {
					// The reference's error here is its script engine's own text; a b017 text must match exactly.
					if isB017Error(w.Error) && g.Error != w.Error {
						t.Errorf("error %q, want %q", g.Error, w.Error)
					}
					continue
				}
				if (g.Tx == nil) != (w.Tx == nil) || (g.Tx != nil && *g.Tx != *w.Tx) {
					t.Errorf("%s: tx differs", w.Step)
				}
				if len(g.PrevTxs) != len(w.PrevTxs) {
					t.Errorf("%s: %d prevTxs, want %d", w.Step, len(g.PrevTxs), len(w.PrevTxs))
				} else {
					for k := range w.PrevTxs {
						if g.PrevTxs[k] != w.PrevTxs[k] {
							t.Errorf("%s: prevTxs[%d] differs", w.Step, k)
						}
					}
				}
				if g.Balance != w.Balance {
					t.Errorf("%s: balance %s, want %s", w.Step, g.Balance, w.Balance)
				}
			}
		})
	}
}
