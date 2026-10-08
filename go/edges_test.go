package b017

// edges_test.go - the reference's behaviour on edge inputs (vectors/edges.json, vectors/gen/edges.test.ts).

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type edgeArg struct {
	Txs   []string
	Bytes *string
	Tx    *string
	Num   *float64
	Str   *string
}

func (a *edgeArg) UnmarshalJSON(b []byte) error {
	var list struct {
		Txs []string `json:"txs"`
	}
	if json.Unmarshal(b, &list) == nil && list.Txs != nil {
		a.Txs = list.Txs
		return nil
	}
	var obj map[string]string
	if json.Unmarshal(b, &obj) == nil {
		if v, ok := obj["bytes"]; ok {
			a.Bytes = &v
		}
		if v, ok := obj["tx"]; ok {
			a.Tx = &v
		}
		return nil
	}
	var n float64
	if json.Unmarshal(b, &n) == nil {
		a.Num = &n
		return nil
	}
	var s string
	if json.Unmarshal(b, &s) == nil {
		a.Str = &s
	}
	return nil
}

func TestVectorsEdges(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(vectorsDir(), "edges.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Records []struct {
			Fn     string          `json:"fn"`
			Args   []edgeArg       `json:"args"`
			Result json.RawMessage `json:"result"`
			Throws *string         `json:"throws"`
		} `json:"records"`
		Nodes map[string]vNode `json:"nodes"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	k, _ := ec.PrivateKeyFromHex(fmt.Sprintf("%064s", "2222222222222222222222222222222222222222222222222222222222222222"))
	key := KeySigner{Key: k}
	bytesOf := func(s string) []byte { v, _ := hex.DecodeString(s); return v }
	hexRes := func(v []byte) any { return map[string]string{"bytes": hex.EncodeToString(v)} }
	for i, r := range file.Records {
		g := newGraph(t)
		g.extra = file.Nodes
		tx := func(a edgeArg) *Transaction { return g.tx(*a.Tx) }
		num := func(a edgeArg) int { return int(*a.Num) }
		var got any
		var err error
		func() {
			defer func() {
				if p := recover(); p != nil {
					err = panicError(p)
				}
			}()
			switch r.Fn {
			case "spentOutpoint":
				got = hexRes(SpentOutpoint(tx(r.Args[0]), num(r.Args[1])))
			case "vinSequence":
				got = hexRes(VinSequence(tx(r.Args[0]), num(r.Args[1])))
			case "vinScript":
				got = hexRes(VinScript(tx(r.Args[0]), num(r.Args[1])))
			case "vinChunk":
				got = hexRes(VinChunk(tx(r.Args[0]), num(r.Args[1]), num(r.Args[2])))
			case "outputValue":
				got = hexRes(OutputValue(tx(r.Args[0]), num(r.Args[1])))
			case "outputScript":
				got = hexRes(OutputScript(tx(r.Args[0]), num(r.Args[1])))
			case "buildChangeOutput":
				got = hexRes(BuildChangeOutput(tx(r.Args[0]), num(r.Args[1])))
			case "voutChunk":
				got = hexRes(VoutChunk(tx(r.Args[0]), num(r.Args[1]), num(r.Args[2])))
			case "splitCtx":
				var c Ctx
				c, err = SplitCtx(bytesOf(*r.Args[0].Bytes), num(r.Args[1]))
				if err == nil {
					got = map[string]string{"ctxHeader": hex.EncodeToString(c.Header), "ctxCodeUnlockScriptCode": hex.EncodeToString(c.UnlockScriptCode),
						"ctxCodeLen": hex.EncodeToString(c.CodeLen), "ctxFooter": hex.EncodeToString(c.Footer),
						"ctxCodeLockScriptCode": hex.EncodeToString(c.LockScriptCode), "ctxCodeLockLen": hex.EncodeToString(c.LockLen)}
				}
			case "le32":
				got = hexRes(le32(uint32(*r.Args[0].Num)))
			case "le64":
				got = hexRes(le64(uint64(*r.Args[0].Num)))
			case "recognizeType":
				got = string(RecognizeType(MustScriptFromHex(*r.Args[0].Str), ""))
				if got == "" {
					got = nil
				}
			case "recognizeP2P":
				got = RecognizeP2P(MustScriptFromHex(*r.Args[0].Str))
			case "isBeef":
				got = IsBeef(*r.Args[0].Str)
			case "isBeefBytes":
				got = IsBeef(bytesOf(*r.Args[0].Bytes))
			case "fromBeef":
				var tx *Transaction
				tx, err = FromBeef(*r.Args[0].Str)
				if err == nil {
					got, err = tx.ID()
				}
			case "smbAncestorPiece":
				got = hexRes(SMBAncestorPiece(*r.Args[0].Str, tx(r.Args[1])))
			case "nftAncestorPiece":
				got = hexRes(AncestorPiece(*r.Args[0].Str, tx(r.Args[1]), 0, MinSimpleLayout))
			case "authAncestorPiece":
				got = hexRes(AncestorPiece(*r.Args[0].Str, tx(r.Args[1]), 0, AuthBoltLayout))
			case "smbLock":
				var prev []*Transaction
				for _, id := range r.Args[1].Txs {
					prev = append(prev, g.tx(id))
				}
				var s *Script
				s, err = SimpleMultiTemplate{}.Lock(bytesOf(*r.Args[0].Bytes), prev, SMBLockArgs{PrevVoutIdx: num(r.Args[2])})
				if err == nil {
					got = s.ToHex()
				}
			case "smbUnlockSign":
				var s *Script
				s, err = SimpleMultiTemplate{}.Unlock(key, key.PublicKey(), nil, SMBUnlockArgs{}).Sign(context.Background(), tx(r.Args[0]), 0)
				if err == nil {
					got = s.ToHex()
				}
			case "smbMeltSign":
				var s *Script
				s, err = SimpleMultiTemplate{}.Melt(key, nil, nil).Sign(context.Background(), tx(r.Args[0]), 0)
				if err == nil {
					got = s.ToHex()
				}
			case "mintNoMatchingOutput", "mintTooPoor", "mintOddSource":
				var pkhOut *Script
				switch r.Fn {
				case "mintNoMatchingOutput":
					pkhOut = P2PKHLock(bytesOf("0909090909090909090909090909090909090909"))
				case "mintTooPoor":
					pkhOut = P2PKHLock(Hash160(key.PublicKey()))
				default:
					pkhOut = MustScriptFromHex("51")
				}
				sats := uint64(1000)
				if r.Fn == "mintTooPoor" {
					sats = 0
				} else if r.Fn == "mintOddSource" {
					sats = 10
				}
				src := &Transaction{Version: 1, Outputs: []*Output{{Satoshis: U64(sats), LockingScript: pkhOut}}}
				_, err = NewSimpleMultiBOLT().Mint(context.Background(), key, src, nil)
				if err == nil {
					got = "minted"
				}
			default:
				t.Fatalf("no Go mapping for %s", r.Fn)
			}
		}()
		if r.Throws != nil {
			if err == nil {
				t.Errorf("#%d %s: reference threw %q, Go returned %v", i, r.Fn, *r.Throws, got)
			} else if err.Error() != *r.Throws && !strings.HasPrefix(*r.Throws, "Cannot read properties of") {
				// A JS engine TypeError ("Cannot read properties of undefined") is the engine's text: the port must
				// fail there too, in its own words.
				t.Errorf("#%d %s: error %q, reference %q", i, r.Fn, err.Error(), *r.Throws)
			}
			continue
		}
		if err != nil {
			t.Errorf("#%d %s: Go error %v, reference %s", i, r.Fn, err, r.Result)
			continue
		}
		gb, _ := json.Marshal(got)
		var gv, wv any
		_ = json.Unmarshal(gb, &gv)
		_ = json.Unmarshal(r.Result, &wv)
		if !reflect.DeepEqual(gv, wv) {
			t.Errorf("#%d %s %v: %s, reference %s", i, r.Fn, r.Args[0].Str, gb, r.Result)
		}
	}
}
