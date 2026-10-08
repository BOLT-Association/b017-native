package b017

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStaticSuffixesMatchRegistry(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(vectorsDir(), "static.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Registry map[string]struct {
			SuffixHashHex string `json:"suffixHashHex"`
			PushLengths   []int  `json:"pushLengths"`
		} `json:"registry"`
		P2pZeroLockHex string `json:"p2pZeroLockHex"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	for name, spec := range s.Registry {
		got := REGISTRY[TokenType(name)]
		if got.SuffixHashHex != spec.SuffixHashHex {
			t.Errorf("%s suffix hash %s, want %s", name, got.SuffixHashHex, spec.SuffixHashHex)
		}
		if len(got.PushLengths) != len(spec.PushLengths) {
			t.Errorf("%s push layout differs", name)
		}
	}
	if got := Pay2ProofLock(make([]byte, 20)).ToHex(); got != s.P2pZeroLockHex {
		t.Errorf("p2p zero lock %s, want %s", got, s.P2pZeroLockHex)
	}
}

func TestVectorsVerifyTx(t *testing.T) {
	for i, rec := range loadCalls(t, "verifyTx") {
		g := newGraph(t)
		var id string
		_ = json.Unmarshal(rec["tx"], &id)
		var skip *bool
		_ = json.Unmarshal(rec["skipOutputCheck"], &skip)
		tx := g.tx(id)
		res, err := VerifyTx(tx, skip != nil && *skip)
		if want, threw := rec["throws"]; threw {
			if err == nil {
				t.Errorf("%s: TS threw %q, Go returned %+v", label(rec, i), str(want), res)
			} else if isB017Error(str(want)) && err.Error() != str(want) {
				t.Errorf("%s: error %q, want %q", label(rec, i), err, str(want))
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: Go error %v, TS returned %s", label(rec, i), err, rec["result"])
			continue
		}
		var want struct {
			Valid bool `json:"valid"`
		}
		_ = json.Unmarshal(rec["result"], &want)
		if want.Valid != res.Valid {
			t.Errorf("%s: valid %v, want %v", label(rec, i), res.Valid, want.Valid)
		}
	}
}

// isB017Error says whether a thrown message is one b017 (or this port's transcription of the reference's own
// texts) writes, and so must match exactly; anything else is an SDK's wording.
func isB017Error(msg string) bool {
	for _, p := range []string{"Verification failed:", "Every output must have", "Output total greater", "BEEF ", "p2pkhUnlock requires",
		"The input sourceTXID", "The sourceSatoshis", "The lockingScript", "input sourceTXID or", "sourceSatoshis or", "lockingScript or",
		"authOrMiscData is", "an unfunded spend", "Mint tx not valid"} {
		if len(msg) >= len(p) && msg[:len(p)] == p {
			return true
		}
	}
	return false
}

func TestVectorsBeef(t *testing.T) {
	for i, rec := range loadCalls(t, "toAtomicBeef") {
		g := newGraph(t)
		var id string
		_ = json.Unmarshal(rec["tx"], &id)
		out, err := ToAtomicBeef(g.tx(id))
		if want, threw := rec["throws"]; threw {
			if err == nil {
				t.Errorf("%s: TS threw %q, Go succeeded", label(rec, i), str(want))
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", label(rec, i), err)
			continue
		}
		if got := hex.EncodeToString(out); got != str(rec["result"]) {
			t.Errorf("%s: atomic BEEF differs\n got %s\nwant %s", label(rec, i), got, str(rec["result"]))
		}
	}
	for i, rec := range loadCalls(t, "fromBeef") {
		var in arg
		_ = json.Unmarshal(rec["input"], &in)
		var input any
		switch in.T {
		case "str":
			input = str(in.V)
		case "bytes", "u8":
			input = in.bytes(t)
		default:
			t.Errorf("%s: input kind %s", label(rec, i), in.T)
			continue
		}
		tx, err := FromBeef(input)
		if want, threw := rec["throws"]; threw {
			if err == nil {
				t.Errorf("%s: TS threw %q, Go succeeded", label(rec, i), str(want))
			} else if isB017Error(str(want)) && err.Error() != str(want) {
				t.Errorf("%s: error %q, want %q", label(rec, i), err, str(want))
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", label(rec, i), err)
			continue
		}
		if got := nodeID(tx, map[*Transaction]string{}); got != str(rec["result"]) {
			t.Errorf("%s: parsed graph %s, want %s", label(rec, i), got, str(rec["result"]))
		}
	}
}

// replaySign signs the recorded tx state with the template the record names and compares the unlocking script.
func replaySign(t *testing.T, name string, build func(t *testing.T, g *graph, args []arg) (UnlockTemplate, error)) {
	for i, rec := range loadCalls(t, name) {
		t.Run(label(rec, i), func(t *testing.T) {
			g := newGraph(t)
			var args []arg
			_ = json.Unmarshal(rec["args"], &args)
			var id string
			_ = json.Unmarshal(rec["tx"], &id)
			var idx int
			_ = json.Unmarshal(rec["inputIndex"], &idx)
			tpl, err := build(t, g, args)
			var us *Script
			if err == nil {
				us, err = tpl.Sign(context.Background(), g.tx(id), idx)
			}
			if want, threw := rec["throws"]; threw {
				if err == nil {
					t.Fatalf("TS threw %q, Go succeeded", str(want))
				}
				if isB017Error(str(want)) && err.Error() != str(want) {
					t.Fatalf("error %q, want %q", err, str(want))
				}
				return
			}
			if err != nil {
				t.Fatalf("Go error: %v", err)
			}
			if got := us.ToHex(); got != str(rec["result"]) {
				t.Fatalf("unlocking script differs\n got %s\nwant %s", got, str(rec["result"]))
			}
		})
	}
}

func TestVectorsSignP2PKH(t *testing.T) {
	replaySign(t, "sign.p2pkhUnlock", func(t *testing.T, g *graph, args []arg) (UnlockTemplate, error) {
		return P2PKHUnlock(args[0].signer(t)), nil
	})
}

func TestVectorsSignPay2Proof(t *testing.T) {
	replaySign(t, "sign.Pay2Proof", func(t *testing.T, g *graph, args []arg) (UnlockTemplate, error) {
		var sats uint64
		var lock *Script
		if len(args) > 1 && args[1].T == "json" {
			sats = args[1].number()
		}
		if len(args) > 2 && args[2].T == "script" {
			lock = MustScriptFromHex(args[2].Hex)
		}
		return Pay2ProofUnlock(args[0].signer(t), sats, lock), nil
	})
}

func TestVectorsLockPay2Proof(t *testing.T) {
	for i, rec := range loadCalls(t, "lock.Pay2Proof") {
		var args []arg
		_ = json.Unmarshal(rec["args"], &args)
		if got := Pay2ProofLock(args[0].bytes(t)).ToHex(); got != str(rec["result"]) {
			t.Errorf("%s: %s, want %s", label(rec, i), got, str(rec["result"]))
		}
	}
}
